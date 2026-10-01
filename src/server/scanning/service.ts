/**
 * The scan service: the one place that turns a customer request (or a scheduler
 * tick) into a queued scan + job.
 *
 * Nothing here performs any analysis. The API returns 202 as soon as the rows
 * exist; a worker does the real work later. This is the boundary that keeps a
 * slow TLS handshake or a hanging HTTP request out of an HTTP request/response
 * cycle (docs/architecture.md).
 *
 * Guarantees enforced here:
 *   * only VERIFIED domains are ever queued (the ownership gate);
 *   * a domain in paused/error/archived/suspended state is refused;
 *   * per-organisation and per-domain hourly quotas bound how hard one tenant can
 *     drive the scanner;
 *   * one active scan per domain — clicking "scan" twice reuses the first one
 *     instead of creating duplicates (the `scans_domain_active_key` index in
 *     migration 004 is the database-level backstop).
 */
import { transaction, query, type QueryRunner } from "~/db";
import { errors } from "~/server/http/errors";
import { scanQuotaPerDomainPerHour, scanQuotaPerOrgPerHour } from "~/server/env";
import { enqueueJob, type JobRecord } from "~/server/queue/jobs";
import { frequencyInterval } from "./engine";

export type ScanTriggerSource = "manual" | "scheduled" | "api";

export interface ScanTarget {
  id: string;
  organization_id: string;
  normalized_hostname: string;
  status: string;
  monitoring_enabled: boolean;
  check_frequency: string;
}

export interface DomainRefusal {
  code: string;
  message: string;
  status: number;
}

/**
 * The authorisation gate, evaluated before anything is queued. Returns null when
 * the domain may be scanned.
 */
export function scanRefusal(domain: Pick<ScanTarget, "status">): DomainRefusal | null {
  switch (domain.status) {
    case "verified":
      return null;
    case "pending_verification":
      return {
        code: "DOMAIN_NOT_VERIFIED",
        message:
          "This domain is not verified yet. Publish the DNS TXT record shown for it and run the verification check first.",
        status: 409,
      };
    case "paused":
      return {
        code: "DOMAIN_PAUSED",
        message: "Monitoring for this domain is paused. Resume it before scanning.",
        status: 409,
      };
    case "error":
      return {
        code: "DOMAIN_IN_ERROR",
        message:
          "The last scans for this domain failed repeatedly, so monitoring is stopped. Review the errors and re-enable it.",
        status: 409,
      };
    case "suspended":
      return {
        code: "DOMAIN_SUSPENDED",
        message: "This domain is suspended and cannot be scanned.",
        status: 409,
      };
    case "archived":
      return {
        code: "DOMAIN_ARCHIVED",
        message: "This domain is archived and cannot be scanned.",
        status: 409,
      };
    default:
      return {
        code: "DOMAIN_NOT_SCANNABLE",
        message: `A domain in status '${domain.status}' cannot be scanned.`,
        status: 409,
      };
  }
}

export interface ScanQuotaUsage {
  organizationScansLastHour: number;
  organizationLimit: number;
  domainScansLastHour: number;
  domainLimit: number;
  retryAfterSeconds: number;
}

/** Reads real scan counts for the last hour and throws 429 when a quota is used up. */
export async function assertScanQuota(
  organizationId: string,
  domainId: string,
  runner?: QueryRunner
): Promise<ScanQuotaUsage> {
  const text = `select
      (select count(*)::int from scans
        where organization_id = $1 and created_at > now() - interval '1 hour') as org_count,
      (select count(*)::int from scans
        where organization_id = $1 and domain_id = $2 and created_at > now() - interval '1 hour') as domain_count,
      (select extract(epoch from (min(created_at) + interval '1 hour' - now()))
         from scans
        where organization_id = $1 and created_at > now() - interval '1 hour') as org_retry_after,
      (select extract(epoch from (min(created_at) + interval '1 hour' - now()))
         from scans
        where organization_id = $1 and domain_id = $2 and created_at > now() - interval '1 hour') as domain_retry_after`;
  const result = runner
    ? await runner.query<Record<string, unknown>>(text, [organizationId, domainId])
    : await query<Record<string, unknown>>(text, [organizationId, domainId]);
  const row = result.rows[0] ?? {};
  const usage: ScanQuotaUsage = {
    organizationScansLastHour: Number(row.org_count ?? 0),
    organizationLimit: scanQuotaPerOrgPerHour(),
    domainScansLastHour: Number(row.domain_count ?? 0),
    domainLimit: scanQuotaPerDomainPerHour(),
    retryAfterSeconds: Math.max(
      1,
      Math.ceil(Math.max(Number(row.org_retry_after ?? 0), Number(row.domain_retry_after ?? 0)))
    ),
  };
  if (usage.organizationScansLastHour >= usage.organizationLimit) {
    throw errors.rateLimited(usage.retryAfterSeconds);
  }
  if (usage.domainScansLastHour >= usage.domainLimit) {
    throw errors.rateLimited(usage.retryAfterSeconds);
  }
  return usage;
}

export interface QueuedScan {
  scan: {
    id: string;
    organization_id: string;
    domain_id: string;
    status: string;
    trigger_source: string;
    job_id: string | null;
    created_at: Date | string;
  };
  job: JobRecord;
  reused: boolean;
}

/**
 * Creates the scan row and its job. Safe to call twice: the second call reuses the
 * active scan (and its job) rather than queueing a duplicate.
 */
export async function enqueueDomainScan(input: {
  domain: ScanTarget;
  triggerSource: ScanTriggerSource;
  requestedBy?: string | null;
  skipQuota?: boolean;
}): Promise<QueuedScan> {
  const { domain } = input;
  const refusal = scanRefusal(domain);
  if (refusal) {
    throw errors.conflict(refusal.message);
  }
  if (!input.skipQuota) {
    await assertScanQuota(domain.organization_id, domain.id);
  }

  return transaction(async (tx) => {
    const inserted = await tx.query<{
      id: string;
      organization_id: string;
      domain_id: string;
      status: string;
      trigger_source: string;
      job_id: string | null;
      created_at: Date | string;
    }>(
      `insert into scans (organization_id, domain_id, status, trigger_source, requested_by)
       values ($1, $2, 'queued', $3, $4)
       on conflict (domain_id) where status in ('queued', 'running') do nothing
       returning id, organization_id, domain_id, status, trigger_source, job_id, created_at`,
      [domain.organization_id, domain.id, input.triggerSource, input.requestedBy ?? null]
    );

    const existing = inserted.rows[0];
    if (!existing) {
      // A scan for this domain is already queued or running — reuse it.
      const active = await tx.query<{
        id: string;
        organization_id: string;
        domain_id: string;
        status: string;
        trigger_source: string;
        job_id: string | null;
        created_at: Date | string;
      }>(
        `select id, organization_id, domain_id, status, trigger_source, job_id, created_at
           from scans where domain_id = $1 and status in ('queued', 'running')
          order by created_at desc limit 1`,
        [domain.id]
      );
      const scan = active.rows[0];
      if (!scan) {
        // The row disappeared between the insert and the read (cancelled/deleted).
        throw errors.conflict("That scan was cancelled before it started. Try again.");
      }
      const job = scan.job_id
        ? await tx.query<JobRecord>("select * from jobs where id = $1", [scan.job_id])
        : null;
      const existingJob = job?.rows[0];
      if (existingJob) return { scan, job: existingJob, reused: true };
      const created = await enqueueJob({
        type: "scan_domain",
        organizationId: domain.organization_id,
        domainId: domain.id,
        scanId: scan.id,
        payload: { scanId: scan.id, domainId: domain.id, hostname: domain.normalized_hostname },
        createdBy: input.requestedBy ?? null,
        runner: tx,
      });
      await tx.query("update scans set job_id = $2, updated_at = now() where id = $1", [scan.id, created.id]);
      return { scan: { ...scan, job_id: created.id }, job: created, reused: true };
    }

    const job = await enqueueJob({
      type: "scan_domain",
      organizationId: domain.organization_id,
      domainId: domain.id,
      scanId: existing.id,
      payload: { scanId: existing.id, domainId: domain.id, hostname: domain.normalized_hostname },
      createdBy: input.requestedBy ?? null,
      runner: tx,
    });
    await tx.query("update scans set job_id = $2, updated_at = now() where id = $1", [existing.id, job.id]);
    return { scan: { ...existing, job_id: job.id }, job, reused: false };
  });
}

/** Loads a domain for scanning, scoped to the organisation. */
export async function loadScanTarget(
  organizationId: string,
  domainId: string,
  runner?: QueryRunner
): Promise<ScanTarget | null> {
  const text = `select id, organization_id, normalized_hostname, status, monitoring_enabled, check_frequency
                  from domains where id = $1 and organization_id = $2 and deleted_at is null`;
  const result = runner
    ? await runner.query<ScanTarget>(text, [domainId, organizationId])
    : await query<ScanTarget>(text, [domainId, organizationId]);
  return result.rows[0] ?? null;
}

/** Moves the domain's next scheduled scan forward after a monitoring change. */
export async function scheduleNextScan(domainId: string, frequency: string): Promise<void> {
  const interval = frequencyInterval(frequency);
  await query(
    `update domains
        set next_scan_at = case when monitoring_enabled and $2::text is not null
                                then now() + ($2::text)::interval else null end,
            updated_at = now()
      where id = $1`,
    [domainId, interval]
  );
}
