/**
 * The job queue, backed by the `jobs` table (no Redis, no extra service).
 *
 * Claiming uses `SELECT ... FOR UPDATE SKIP LOCKED`, which is the standard portable
 * PostgreSQL way to run several workers without them fighting over the same row —
 * it works identically on a VPS, on Render, on RDS or on Neon. Everything the
 * queue needs is in the table, so a worker crash cannot lose a job:
 *
 *   queued --claim--> running --complete--> completed
 *                        |--fail (attempts left)--> queued  (after backoff)
 *                        |--fail (attempts used up)--> failed
 *                        |--cancel--> cancelled
 *
 * A running job whose worker stopped heartbeating is reclaimed by
 * `recoverStaleJobs()` after `DOMIRA_JOB_STALE_SECONDS` (default 300 s).
 *
 * Every job that produces tenant data carries organization_id AND domain_id, so a
 * worker can never be tricked into working across tenants (docs/multi-tenancy.md).
 */
import { query, type QueryRunner } from "~/db";
import { jobMaxAttempts, jobRetryBackoffSeconds, jobStaleSeconds } from "~/server/env";

export type JobType = "scan_domain" | "scheduler_tick";
export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface JobRecord {
  id: string;
  organization_id: string | null;
  domain_id: string | null;
  scan_id: string | null;
  type: string;
  status: JobStatus;
  priority: number;
  payload: Record<string, unknown>;
  result: Record<string, unknown> | null;
  attempts: number;
  max_attempts: number;
  available_at: Date | string;
  locked_at: Date | string | null;
  locked_by: string | null;
  heartbeat_at: Date | string | null;
  started_at: Date | string | null;
  last_error: string | null;
  created_by: string | null;
  created_at: Date | string;
  updated_at: Date | string;
  finished_at: Date | string | null;
}

export interface EnqueueJobInput {
  type: JobType;
  organizationId?: string | null;
  domainId?: string | null;
  scanId?: string | null;
  payload?: Record<string, unknown>;
  priority?: number;
  maxAttempts?: number;
  availableAt?: Date;
  createdBy?: string | null;
  runner?: QueryRunner;
}

export async function enqueueJob(input: EnqueueJobInput): Promise<JobRecord> {
  const text = `insert into jobs
      (organization_id, domain_id, scan_id, type, status, priority, payload,
       max_attempts, available_at, created_by)
     values ($1, $2, $3, $4, 'queued', $5, $6::jsonb, $7, coalesce($8, now()), $9)
     returning *`;
  const params = [
    input.organizationId ?? null,
    input.domainId ?? null,
    input.scanId ?? null,
    input.type,
    input.priority ?? 100,
    JSON.stringify(input.payload ?? {}),
    input.maxAttempts ?? jobMaxAttempts(),
    input.availableAt ?? null,
    input.createdBy ?? null,
  ];
  const result = input.runner
    ? await input.runner.query<JobRecord>(text, params)
    : await query<JobRecord>(text, params);
  return result.rows[0]!;
}

/**
 * Atomically claims the oldest due job of an allowed type.
 * Returns null when there is nothing to do.
 */
export async function claimNextJob(
  workerId: string,
  types: readonly JobType[]
): Promise<JobRecord | null> {
  const result = await query<JobRecord>(
    `with claimed as (
       select id from jobs
        where status = 'queued'
          and available_at <= now()
          and type = any($1::text[])
        order by priority asc, available_at asc, created_at asc
        limit 1
        for update skip locked
     )
     update jobs
        set status = 'running',
            locked_at = now(),
            locked_by = $2,
            heartbeat_at = now(),
            started_at = coalesce(started_at, now()),
            attempts = attempts + 1,
            updated_at = now()
       from claimed
      where jobs.id = claimed.id
      returning jobs.*`,
    [types as unknown as string[], workerId]
  );
  return result.rows[0] ?? null;
}

/** Reads one job. Used by the queue tests and by the worker before dispatching. */
export async function getJob(jobId: string, runner?: QueryRunner): Promise<JobRecord | null> {
  const text = "select * from jobs where id = $1";
  const result = runner
    ? await runner.query<JobRecord>(text, [jobId])
    : await query<JobRecord>(text, [jobId]);
  return result.rows[0] ?? null;
}

/** Heartbeat so `recoverStaleJobs()` can tell a slow job from a dead worker. */
export async function heartbeatJob(jobId: string, workerId: string): Promise<boolean> {
  const result = await query(
    `update jobs set heartbeat_at = now(), updated_at = now()
      where id = $1 and locked_by = $2 and status = 'running'`,
    [jobId, workerId]
  );
  return result.rowCount > 0;
}

export async function completeJob(
  jobId: string,
  workerId: string,
  result: Record<string, unknown>
): Promise<void> {
  await query(
    `update jobs
        set status = 'completed', result = $3::jsonb, finished_at = now(),
            heartbeat_at = now(), last_error = null, updated_at = now()
      where id = $1 and locked_by = $2 and status = 'running'`,
    [jobId, workerId, JSON.stringify(result)]
  );
}

export function backoffSeconds(attempts: number): number {
  // 30s, 60s, 120s, ... capped at one hour. `attempts` is the number already used.
  const base = jobRetryBackoffSeconds();
  return Math.min(base * 2 ** Math.max(0, attempts - 1), 3600);
}

export interface FailJobOutcome {
  status: "queued" | "failed";
  attempts: number;
  retryInSeconds: number | null;
}

/**
 * Records a failed attempt. While attempts remain the job goes back to `queued`
 * with exponential backoff; once `max_attempts` is reached it is terminally
 * `failed`. The worker never throws away a failure silently.
 */
export async function failJob(
  jobId: string,
  workerId: string,
  error: string
): Promise<FailJobOutcome | null> {
  const job = await getJob(jobId);
  if (!job) return null;
  if (job.status === "cancelled") return { status: "failed", attempts: job.attempts, retryInSeconds: null };

  const attempts = Number(job.attempts);
  const maxAttempts = Number(job.max_attempts);
  if (attempts >= maxAttempts) {
    await query(
      `update jobs set status = 'failed', last_error = $3, finished_at = now(), updated_at = now()
        where id = $1 and locked_by = $2 and status = 'running'`,
      [jobId, workerId, error]
    );
    return { status: "failed", attempts, retryInSeconds: null };
  }

  const delay = backoffSeconds(attempts);
  await query(
    `update jobs
        set status = 'queued', last_error = $3, locked_at = null, locked_by = null,
            available_at = now() + make_interval(secs => $4::double precision), updated_at = now()
      where id = $1 and locked_by = $2 and status = 'running'`,
    [jobId, workerId, error, delay]
  );
  return { status: "queued", attempts, retryInSeconds: delay };
}

/** Cancels a queued or running job; a running job's worker sees the status change. */
export async function cancelJob(jobId: string, reason: string): Promise<boolean> {
  const result = await query(
    `update jobs
        set status = 'cancelled', finished_at = now(), last_error = $2, updated_at = now()
      where id = $1 and status in ('queued', 'running')`,
    [jobId, reason]
  );
  return result.rowCount > 0;
}

export interface StaleRecoveryResult {
  requeued: number;
  failed: number;
  scanIds: string[];
}

/**
 * Recovers jobs whose worker died. A job is stale when it is `running` and its
 * heartbeat is older than `DOMIRA_JOB_STALE_SECONDS`.
 *
 * Recovery re-uses the normal attempt accounting: with attempts left the job is
 * requeued, otherwise it is failed and its scan is marked failed too — otherwise a
 * scan would sit in `running` forever and the "one active scan per domain" index
 * would block the domain from ever being scanned again.
 */
export async function recoverStaleJobs(staleSeconds = jobStaleSeconds()): Promise<StaleRecoveryResult> {
  const stale = await query<{ id: string; attempts: number; max_attempts: number; scan_id: string | null }>(
    `select id, attempts, max_attempts, scan_id from jobs
      where status = 'running'
        and coalesce(heartbeat_at, locked_at, updated_at) < now() - make_interval(secs => $1::double precision)`,
    [staleSeconds]
  );

  const result: StaleRecoveryResult = { requeued: 0, failed: 0, scanIds: [] };
  for (const job of stale.rows) {
    const attempts = Number(job.attempts);
    const maxAttempts = Number(job.max_attempts);
    if (attempts >= maxAttempts) {
      await query(
        `update jobs set status = 'failed', finished_at = now(), locked_at = null, locked_by = null,
                last_error = coalesce(last_error, 'The worker stopped responding.'), updated_at = now()
          where id = $1 and status = 'running'`,
        [job.id]
      );
      result.failed += 1;
      if (job.scan_id) {
        await query(
          `update scans set status = 'failed', finished_at = now(),
                  error_message = coalesce(error_message, 'The worker stopped responding.'), updated_at = now()
            where id = $1 and status in ('queued', 'running')`,
          [job.scan_id]
        );
        result.scanIds.push(job.scan_id);
      }
      continue;
    }
    const delay = backoffSeconds(attempts);
    await query(
      `update jobs
          set status = 'queued', locked_at = null, locked_by = null, heartbeat_at = null,
              available_at = now() + make_interval(secs => $2::double precision), updated_at = now()
        where id = $1 and status = 'running'`,
      [job.id, delay]
    );
    result.requeued += 1;
  }
  return result;
}

/** Queue depth, per status. Used by the admin dashboard and by the tests. */
export async function jobCounts(): Promise<Record<string, number>> {
  const result = await query<{ status: string; count: number }>(
    "select status, count(*)::int as count from jobs group by status"
  );
  const counts: Record<string, number> = {};
  for (const row of result.rows) counts[row.status] = Number(row.count);
  return counts;
}
