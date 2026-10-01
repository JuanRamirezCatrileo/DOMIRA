/**
 * The scheduler: a cron-style tick that turns each domain's monitoring frequency
 * into queued scans.
 *
 * It is a plain function so it can be driven three ways without any special-casing:
 *
 *   * by the in-process runtime (every `DOMIRA_SCHEDULER_INTERVAL_SECONDS`);
 *   * by the standalone worker (`bun run worker`), same as above;
 *   * by an external cron enqueuing a `scheduler_tick` job, or by `bun run scheduler`
 *     for a one-shot tick — the portable option for platforms with native cron.
 *
 * A due domain is one that is verified, has monitoring enabled, is not on 'manual'
 * frequency and whose `next_scan_at` has passed. `next_scan_at` is advanced as soon
 * as the scan is queued, so a tick can never queue the same scan twice, and a
 * failure to queue one domain never stops the others.
 */
import { query } from "~/db";
import { enqueueDomainScan } from "~/server/scanning/service";

export interface SchedulerTickResult {
  due: number;
  enqueued: number;
  reused: number;
  refused: number;
  errors: number;
}

interface DueDomain {
  id: string;
  organization_id: string;
  normalized_hostname: string;
  status: string;
  monitoring_enabled: boolean;
  check_frequency: string;
}

/**
 * Enqueues a scan for every domain that is due. `limit` bounds one tick so a large
 * backlog is spread over several ticks instead of one long-running pass.
 */
export async function runSchedulerTick(options: { limit?: number } = {}): Promise<SchedulerTickResult> {
  const limit = options.limit ?? 50;
  const due = await query<DueDomain>(
    `select d.id, d.organization_id, d.normalized_hostname, d.status,
            d.monitoring_enabled, d.check_frequency
       from domains d
      where d.deleted_at is null
        and d.status = 'verified'
        and d.monitoring_enabled
        and d.check_frequency <> 'manual'
        and (d.next_scan_at is null or d.next_scan_at <= now())
        and not exists (
              select 1 from scans s
               where s.domain_id = d.id and s.status in ('queued', 'running'))
      order by d.next_scan_at asc nulls first
      limit $1`,
    [limit]
  );

  const result: SchedulerTickResult = {
    due: due.rows.length,
    enqueued: 0,
    reused: 0,
    refused: 0,
    errors: 0,
  };

  for (const domain of due.rows) {
    try {
      const queued = await enqueueDomainScan({
        domain,
        triggerSource: "scheduled",
        requestedBy: null,
        // The frequency itself already bounds scheduled work; the manual quota is
        // there to stop a human hammering the scanner, not the scheduler.
        skipQuota: true,
      });
      if (queued.reused) result.reused += 1;
      else result.enqueued += 1;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === "DOMAIN_NOT_VERIFIED" || code === "DOMAIN_PAUSED" || code === "DOMAIN_ARCHIVED") {
        result.refused += 1;
      } else {
        result.errors += 1;
        console.error(
          `[domira] scheduler could not queue a scan for domain ${domain.id}:`,
          error instanceof Error ? error.message : error
        );
      }
    }
    // Advance the schedule regardless of the outcome: a domain that keeps failing
    // must not be retried on every tick.
    try {
      await advanceSchedule(domain.id, domain.check_frequency);
    } catch (error) {
      console.error(
        `[domira] scheduler could not advance next_scan_at for domain ${domain.id}:`,
        error instanceof Error ? error.message : error
      );
    }
  }

  return result;
}

/**
 * Sets `next_scan_at` from the frequency and mirrors the run into
 * `monitoring_configs` (the row deliverable 4 uses for alerting).
 */
export async function advanceSchedule(domainId: string, frequency: string): Promise<void> {
  await query(
    `update domains
        set next_scan_at = case when monitoring_enabled and $2::text is not null
                                then now() + ($2::text)::interval else null end,
            updated_at = now()
      where id = $1`,
    [domainId, intervalFor(frequency)]
  );
  const config = await query(
    `update monitoring_configs
        set last_run_at = now(),
            next_run_at = case when $2::text is not null then now() + ($2::text)::interval else null end,
            updated_at = now()
      where domain_id = $1 and is_enabled`,
    [domainId, intervalFor(frequency)]
  );
  void config;
}

function intervalFor(frequency: string): string | null {
  switch (frequency) {
    case "hourly":
      return "1 hour";
    case "6h":
      return "6 hours";
    case "daily":
      return "1 day";
    case "weekly":
      return "7 days";
    default:
      return null;
  }
}
