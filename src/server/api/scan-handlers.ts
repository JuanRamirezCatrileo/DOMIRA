/**
 * Scan status endpoints.
 *
 * A scan is always read through its `organization_id`: the id in the URL grants
 * nothing, and a scan of another tenant answers 404 exactly like a non-existent
 * one. Nothing here computes anything — the values returned are the rows the
 * worker wrote.
 */
import { query } from "~/db";
import { writeAuditLog } from "~/server/audit";
import { errors } from "~/server/http/errors";
import { jsonResponse } from "~/server/http/http";
import { requireActor, requireOrgRole, type Actor } from "~/server/rbac/guard";
import { paginationSchema, uuidSchema } from "~/server/validation";
import { resolveOrganization } from "./domain-handlers";
import { findingToJson, scanToJson, type FindingRow, type ScanRow } from "./serializers";
import type { ApiRouteContext } from "./types";
import { toIso, toNumber } from "./types";

async function withActor(
  ctx: ApiRouteContext,
  fn: (actor: Actor) => Promise<Response>
): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  return fn(actor);
}

function parseUuidParam(ctx: ApiRouteContext, name: string): string {
  const parsed = uuidSchema.safeParse(ctx.params[name]);
  if (!parsed.success) throw errors.notFound();
  return parsed.data;
}

/** Loads a scan and enforces membership of the organisation that owns it. */
export async function loadScanForActor(
  actor: Actor,
  scanId: string,
  permission: Parameters<typeof requireOrgRole>[2]
): Promise<{ scan: ScanRow; role: string }> {
  const result = await query<ScanRow>("select * from scans where id = $1", [scanId]);
  const scan = result.rows[0];
  if (!scan) throw errors.notFound();
  const access = await requireOrgRole(actor, scan.organization_id, permission);
  return { scan, role: access.role };
}

export async function handleGetScan(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const scanId = parseUuidParam(ctx, "id");
    const { scan } = await loadScanForActor(actor, scanId, "domain:read");

    const domain = await query<{ id: string; hostname: string; status: string; display_name: string | null }>(
      "select id, hostname, status, display_name from domains where id = $1 and organization_id = $2",
      [scan.domain_id, scan.organization_id]
    );
    const results = await query<{
      category: string;
      status: string;
      score: number | null;
      not_collected: boolean;
      error_message: string | null;
      duration_ms: number | null;
    }>(
      `select category, status, score, not_collected, error_message, duration_ms
         from scan_results where organization_id = $1 and scan_id = $2 order by category asc`,
      [scan.organization_id, scan.id]
    );
    const findings = await query<FindingRow>(
      `select * from findings where organization_id = $1 and last_scan_id = $2
        order by case severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2
                               when 'low' then 3 else 4 end, code asc`,
      [scan.organization_id, scan.id]
    );
    const job = await query<{
      id: string;
      status: string;
      attempts: number;
      max_attempts: number;
      last_error: string | null;
      available_at: Date | string;
      locked_by: string | null;
    }>(
      "select id, status, attempts, max_attempts, last_error, available_at, locked_by from jobs where id = $1",
      [scan.job_id]
    );

    return jsonResponse({
      scan: scanToJson(scan),
      domain: domain.rows[0]
        ? {
            id: domain.rows[0].id,
            hostname: domain.rows[0].hostname,
            displayName: domain.rows[0].display_name,
            status: domain.rows[0].status,
          }
        : null,
      job: job.rows[0]
        ? {
            id: job.rows[0].id,
            status: job.rows[0].status,
            attempts: toNumber(job.rows[0].attempts),
            maxAttempts: toNumber(job.rows[0].max_attempts),
            lastError: job.rows[0].last_error,
            availableAt: toIso(job.rows[0].available_at),
            workerId: job.rows[0].locked_by,
          }
        : null,
      checks: results.rows.map((row) => ({
        category: row.category,
        status: row.not_collected ? "not_collected" : row.status,
        score: row.score === null ? null : toNumber(row.score),
        error: row.error_message,
        durationMs: row.duration_ms === null ? null : toNumber(row.duration_ms),
      })),
      findings: findings.rows.map((row) => findingToJson(row)),
    });
  });
}

export async function handleCancelScan(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const scanId = parseUuidParam(ctx, "id");
    const { scan } = await loadScanForActor(actor, scanId, "scan:run");

    if (scan.status === "completed" || scan.status === "failed") {
      throw errors.conflict(`A scan that is already ${scan.status} cannot be cancelled.`);
    }
    if (scan.status === "cancelled") {
      return jsonResponse({ scan: scanToJson(scan), cancelled: true, alreadyCancelled: true });
    }

    await query(
      `update scans set status = 'cancelled', cancelled_at = now(), finished_at = now(),
              error_message = coalesce(error_message, 'Cancelled by the customer.'), updated_at = now()
        where id = $1 and organization_id = $2 and status in ('queued', 'running')`,
      [scan.id, scan.organization_id]
    );
    const job = await query<{ id: string }>(
      `update jobs set status = 'cancelled', finished_at = now(),
              last_error = coalesce(last_error, 'The scan was cancelled.'), updated_at = now()
        where id = $1 and status in ('queued', 'running') returning id`,
      [scan.job_id]
    );
    // A worker that is mid-scan re-reads the scan status before persisting, so a
    // cancelled scan never writes results (see docs/scanning.md).

    await writeAuditLog({
      action: "scan.cancelled",
      organizationId: scan.organization_id,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "scan",
      targetId: scan.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { jobId: scan.job_id, jobCancelled: job.rows.length > 0 },
    });

    const refreshed = await query<ScanRow>("select * from scans where id = $1", [scan.id]);
    return jsonResponse({ scan: scanToJson(refreshed.rows[0]!), cancelled: true, alreadyCancelled: false });
  });
}

export async function handleListScans(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const pagination = paginationSchema.parse({
      page: ctx.url.searchParams.get("page") ?? undefined,
      perPage: ctx.url.searchParams.get("perPage") ?? undefined,
    });
    const access = await resolveOrganization(actor, {
      explicitId: ctx.url.searchParams.get("organizationId"),
      permission: "domain:read",
    });
    const domainId = ctx.url.searchParams.get("domainId");
    const status = ctx.url.searchParams.get("status");
    if (domainId && !uuidSchema.safeParse(domainId).success) {
      throw errors.validation({ domainId: "Invalid domain identifier." });
    }

    const total = await query<{ count: number }>(
      `select count(*)::int as count from scans
        where organization_id = $1
          and ($2::uuid is null or domain_id = $2::uuid)
          and ($3::text is null or status = $3::text)`,
      [access.organizationId, domainId, status]
    );
    const rows = await query<ScanRow & { hostname: string }>(
      `select s.*, d.hostname from scans s
         join domains d on d.id = s.domain_id
        where s.organization_id = $1
          and ($2::uuid is null or s.domain_id = $2::uuid)
          and ($3::text is null or s.status = $3::text)
        order by s.created_at desc
        limit $4 offset $5`,
      [access.organizationId, domainId, status, pagination.perPage, (pagination.page - 1) * pagination.perPage]
    );
    const count = toNumber(total.rows[0]?.count);
    return jsonResponse({
      scans: rows.rows.map((row) => ({ ...scanToJson(row), hostname: row.hostname })),
      pagination: {
        page: pagination.page,
        perPage: pagination.perPage,
        total: count,
        totalPages: Math.max(1, Math.ceil(count / pagination.perPage)),
      },
    });
  });
}
