/**
 * The scan worker.
 *
 * A worker loop claims jobs from the `jobs` table, runs the handler and records
 * the outcome. It can run in two ways, with the SAME code:
 *
 *   * in-process — started by the app (`ensureRuntime()` in ./runtime.ts), so the
 *     published site scans with no extra process and no extra cost;
 *   * standalone — `bun run worker` (scripts/worker.ts) for real deployments that
 *     want the scanner in its own process/container so a heavy scan can never slow
 *     the web tier down. This is the recommended production setup and is
 *     documented in docs/deployment.md.
 *
 * While a handler runs, a heartbeat timer keeps `jobs.heartbeat_at` fresh so
 * `recoverStaleJobs()` can tell "slow" from "dead".
 *
 * Failure policy (documented in docs/scanning.md):
 *   * an exception in a handler consumes one attempt → exponential backoff →
 *     retry; after `DOMIRA_JOB_MAX_ATTEMPTS` the job is `failed` and the linked
 *     scan is marked failed, so the domain is never left blocked by a scan stuck
 *     in `running`;
 *   * a scan that runs to completion but *fails* (unreachable domain, refusal) is
 *     a recorded result, not a queue error: the job is `completed` and the failure
 *     lives in the scan row where the customer can see it.
 */
import { query } from "~/db";
import {
  jobStaleSeconds,
  schedulerIntervalSeconds,
  workerConcurrency,
  workerPollIntervalMs,
} from "~/server/env";
import { executeScan } from "~/server/scanning/engine";
import { runSchedulerTick } from "./scheduler";
import {
  claimNextJob,
  completeJob,
  failJob,
  heartbeatJob,
  recoverStaleJobs,
  type JobRecord,
  type JobType,
} from "./jobs";

export interface JobContext {
  job: JobRecord;
  workerId: string;
  /** Sends an immediate heartbeat; the worker also heartbeats on a timer. */
  heartbeat: () => Promise<unknown>;
}

export type JobHandler = (context: JobContext) => Promise<Record<string, unknown>>;

/** Default handlers. Tests may override them with registerJobHandler(). */
function defaultHandlers(): Map<string, JobHandler> {
  return new Map<string, JobHandler>([
    [
      "scan_domain",
      async ({ job, workerId }) => {
        if (!job.scan_id) throw new Error("scan_domain job without a scan_id.");
        const outcome = await executeScan(job.scan_id, workerId);
        return {
          scanId: outcome.scanId,
          scanStatus: outcome.status,
          score: outcome.score,
          checksFailed: outcome.checksFailed,
          findings: outcome.findings,
          error: outcome.error,
        };
      },
    ],
    [
      "scheduler_tick",
      async () => {
        const tick = await runSchedulerTick();
        return { ...tick };
      },
    ],
  ]);
}

let handlers = defaultHandlers();

/** Test seam: replace one handler. Pass null to restore the default. */
export function registerJobHandler(type: JobType, handler: JobHandler | null): void {
  if (handler === null) handlers.delete(type);
  else handlers.set(type, handler);
}

export function resetJobHandlers(): void {
  handlers = defaultHandlers();
}

export const WORKER_JOB_TYPES: readonly JobType[] = ["scan_domain", "scheduler_tick"];

export interface ProcessOutcome {
  jobId: string;
  type: string;
  status: "completed" | "failed" | "requeued" | "cancelled";
  error: string | null;
  attempts: number;
  result: Record<string, unknown> | null;
}

function heartbeatIntervalMs(): number {
  return Math.max(5, Math.floor(jobStaleSeconds() / 3)) * 1000;
}

/** Runs one already-claimed job and records its outcome. */
export async function processClaimedJob(job: JobRecord, workerId: string): Promise<ProcessOutcome> {
  const handler = handlers.get(job.type);
  const timer = setInterval(() => {
    void heartbeatJob(job.id, workerId).catch(() => undefined);
  }, heartbeatIntervalMs());
  if (typeof timer === "object" && "unref" in timer) timer.unref();

  try {
    if (!handler) {
      const failure = await failJob(job.id, workerId, `No handler is registered for job type '${job.type}'.`);
      return {
        jobId: job.id,
        type: job.type,
        status: failure?.status === "failed" ? "failed" : "requeued",
        error: `No handler is registered for job type '${job.type}'.`,
        attempts: failure?.attempts ?? job.attempts,
        result: null,
      };
    }
    const result = await handler({ job, workerId, heartbeat: () => heartbeatJob(job.id, workerId) });
    // A job cancelled while it ran stays cancelled: completeJob only touches running jobs.
    const current = await query<{ status: string }>("select status from jobs where id = $1", [job.id]);
    if (current.rows[0]?.status === "cancelled") {
      return { jobId: job.id, type: job.type, status: "cancelled", error: null, attempts: job.attempts, result };
    }
    await completeJob(job.id, workerId, result);
    return {
      jobId: job.id,
      type: job.type,
      status: "completed",
      error: null,
      attempts: job.attempts,
      result,
    };
  } catch (error) {
    const message = `${(error as { code?: string }).code ?? "JOB_ERROR"}: ${(error as Error).message}`;
    const failure = await failJob(job.id, workerId, message);
    if (failure?.status === "failed" && job.scan_id) {
      // Terminal failure: never leave a scan sitting in queued/running, because the
      // unique index on active scans would block the domain from being scanned again.
      await query(
        `update scans set status = 'failed', finished_at = now(),
                error_message = coalesce(error_message, $2), updated_at = now()
          where id = $1 and status in ('queued', 'running')`,
        [job.scan_id, message]
      );
    }
    return {
      jobId: job.id,
      type: job.type,
      status: failure?.status === "failed" ? "failed" : "requeued",
      error: message,
      attempts: failure?.attempts ?? job.attempts,
      result: null,
    };
  } finally {
    clearInterval(timer);
  }
}

export interface WorkerStats {
  workerId: string;
  claimed: number;
  completed: number;
  failed: number;
  requeued: number;
  cancelled: number;
  lastClaimAt: string | null;
  lastError: string | null;
}

const stats: Omit<WorkerStats, "workerId"> = {
  claimed: 0,
  completed: 0,
  failed: 0,
  requeued: 0,
  cancelled: 0,
  lastClaimAt: null,
  lastError: null,
};

export function workerStats(): WorkerStats {
  return { workerId: activeWorkerId ?? "(not started)", ...stats };
}

export function resetWorkerStats(): void {
  stats.claimed = 0;
  stats.completed = 0;
  stats.failed = 0;
  stats.requeued = 0;
  stats.cancelled = 0;
  stats.lastClaimAt = null;
  stats.lastError = null;
}

/** Claims and runs at most one job. Returns null when the queue is empty. */
export async function runWorkerOnce(
  workerId: string,
  types: readonly JobType[] = WORKER_JOB_TYPES
): Promise<ProcessOutcome | null> {
  const job = await claimNextJob(workerId, types);
  if (!job) return null;
  stats.claimed += 1;
  stats.lastClaimAt = new Date().toISOString();
  const outcome = await processClaimedJob(job, workerId);
  if (outcome.status === "completed") stats.completed += 1;
  else if (outcome.status === "failed") stats.failed += 1;
  else if (outcome.status === "requeued") stats.requeued += 1;
  else stats.cancelled += 1;
  if (outcome.error) stats.lastError = outcome.error;
  return outcome;
}

let activeWorkerId: string | null = null;
let loopRunning = false;
let loopTimer: ReturnType<typeof setTimeout> | null = null;
let inFlight = 0;

export function currentWorkerId(): string | null {
  return activeWorkerId;
}

function scheduleNext(delayMs: number, tick: () => void): void {
  loopTimer = setTimeout(tick, delayMs);
  if (typeof loopTimer === "object" && loopTimer !== null && "unref" in loopTimer) {
    (loopTimer as { unref: () => void }).unref();
  }
}

/**
 * Starts the polling loop. Idempotent: a second call while a loop is running is a
 * no-op, so the app can call it from several places safely.
 */
export function startWorkerLoop(options: { workerId?: string } = {}): string {
  const workerId = options.workerId ?? `worker-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
  activeWorkerId = workerId;
  if (loopRunning) return workerId;
  loopRunning = true;

  let recoveryCounter = 0;
  const tick = async (): Promise<void> => {
    if (!loopRunning) return;
    let ranSomething = false;
    try {
      // Cheap housekeeping first: reclaim jobs whose worker died, every ~10 ticks.
      recoveryCounter += 1;
      if (recoveryCounter >= 10) {
        recoveryCounter = 0;
        const recovered = await recoverStaleJobs();
        if (recovered.requeued + recovered.failed > 0) {
          console.warn(
            `[domira] worker ${workerId}: recovered ${recovered.requeued} stale job(s), failed ${recovered.failed}.`
          );
        }
      }
      const concurrency = workerConcurrency();
      const slots = Math.max(1, concurrency - inFlight);
      const outcomes = await Promise.all(
        Array.from({ length: slots }, async () => {
          inFlight += 1;
          try {
            return await runWorkerOnce(workerId);
          } finally {
            inFlight -= 1;
          }
        })
      );
      ranSomething = outcomes.some((outcome) => outcome !== null);
    } catch (error) {
      console.error(
        `[domira] worker ${workerId} loop error:`,
        error instanceof Error ? error.message : error
      );
    }
    scheduleNext(ranSomething ? 0 : workerPollIntervalMs(), () => void tick());
  };

  scheduleNext(0, () => void tick());
  return workerId;
}

export function stopWorkerLoop(): void {
  loopRunning = false;
  activeWorkerId = null;
  if (loopTimer) clearTimeout(loopTimer);
  loopTimer = null;
}

export function workerLoopRunning(): boolean {
  return loopRunning;
}

/** Interval (ms) between scheduler ticks, derived from the documented env var. */
export function schedulerTickIntervalMs(): number {
  return schedulerIntervalSeconds() * 1000;
}
