/**
 * Findings and certificates.
 *
 * Findings are what the customer actually reads: title, plain-language
 * explanation, impact and recommendation in both locales — all of it produced by
 * the scan engine and stored in the row, so nothing is translated or invented at
 * read time. This module only reads and transitions them.
 *
 * The status lifecycle is deliberately human-owned: a rescan updates `last_seen_at`
 * and `occurrences` but never touches the status a person set (see
 * src/server/scanning/findings.ts), and only this endpoint changes it.
 */
import { query } from "~/db";
import { writeAuditLog } from "~/server/audit";
import { errors } from "~/server/http/errors";
import { jsonResponse, readJsonBody } from "~/server/http/http";
import { requireActor, requireOrgRole, type Actor } from "~/server/rbac/guard";
import { certificateToJson, findingToJson, type CertificateRow, type FindingRow } from "./serializers";
import type { ApiRouteContext } from "./types";
import { toIso, toNumber } from "./types";
import {
  findingCategorySchema,
  findingSeveritySchema,
  findFindingStatusSchema,
  paginationSchema,
  updateFindingSchema,
  uuidSchema,
} from "~/server/validation";
import { resolveOrganization } from "./domain-handlers";

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

export async function handleListFindings(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const pagination = paginationSchema.parse({
      page: ctx.url.searchParams.get("page") ?? undefined,
      perPage: ctx.url.searchParams.get("perPage") ?? undefined,
    });
    const access = await resolveOrganization(actor, {
      explicitId: ctx.url.searchParams.get("organizationId"),
      permission: "domain:read",
    });

    const severityParam = ctx.url.searchParams.get("severity");
    const categoryParam = ctx.url.searchParams.get("category");
    const statusParam = ctx.url.searchParams.get("status");
    const domainIdParam = ctx.url.searchParams.get("domainId");
    const severity = severityParam ? findingSeveritySchema.safeParse(severityParam) : null;
    const category = categoryParam ? findingCategorySchema.safeParse(categoryParam) : null;
    const status = statusParam ? findFindingStatusSchema.safeParse(statusParam) : null;
    if (severity && !severity.success) throw errors.validation({ severity: "Unknown severity." });
    if (category && !category.success) throw errors.validation({ category: "Unknown category." });
    if (status && !status.success) throw errors.validation({ status: "Unknown status." });
    if (domainIdParam && !uuidSchema.safeParse(domainIdParam).success) {
      throw errors.validation({ domainId: "Invalid domain identifier." });
    }

    const where = `f.organization_id = $1
        and ($2::text is null or f.severity = $2::text)
        and ($3::text is null or f.category = $3::text)
        and ($4::text is null or f.status = $4::text)
        and ($5::uuid is null or f.domain_id = $5::uuid)`;
    const filterParams = [
      access.organizationId,
      severity?.success ? severity.data : null,
      category?.success ? category.data : null,
      status?.success ? status.data : null,
      domainIdParam,
    ] as const;

    const total = await query<{ count: number }>(
      `select count(*)::int as count from findings f where ${where}`,
      [...filterParams]
    );
    const rows = await query<FindingRow & { hostname: string }>(
      `select f.*, d.hostname from findings f
         join domains d on d.id = f.domain_id
        where ${where}
        order by case f.severity when 'critical' then 0 when 'high' then 1 when 'medium' then 2
                                 when 'low' then 3 else 4 end,
                 f.last_seen_at desc
        limit $6 offset $7`,
      [...filterParams, pagination.perPage, (pagination.page - 1) * pagination.perPage]
    );
    const count = toNumber(total.rows[0]?.count);
    return jsonResponse({
      findings: rows.rows.map((row) => findingToJson(row, { hostname: row.hostname })),
      pagination: {
        page: pagination.page,
        perPage: pagination.perPage,
        total: count,
        totalPages: Math.max(1, Math.ceil(count / pagination.perPage)),
      },
      organizationId: access.organizationId,
    });
  });
}

export async function handleUpdateFinding(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const findingId = parseUuidParam(ctx, "id");
    const body = await readJsonBody(ctx.request, updateFindingSchema);

    const result = await query<FindingRow>("select * from findings where id = $1", [findingId]);
    const finding = result.rows[0];
    // A finding of another tenant is answered exactly like a missing one.
    if (!finding) throw errors.notFound();
    const access = await requireOrgRole(actor, finding.organization_id, "finding:manage");

    const previousStatus = finding.status;
    const updated = await query<FindingRow>(
      `update findings
          set status = $2,
              status_changed_at = now(),
              status_changed_by = $3,
              acknowledged_at = case when $2 = 'acknowledged' then coalesce(acknowledged_at, now())
                                     when $2 in ('resolved','ignored') then acknowledged_at
                                     else null end,
              acknowledged_by = case when $2 = 'acknowledged' then coalesce(acknowledged_by, $3)
                                     when $2 in ('resolved','ignored') then acknowledged_by
                                     else null end,
              resolved_at = case when $2 = 'resolved' then now() else null end,
              updated_at = now()
        where id = $1 and organization_id = $4
        returning *`,
      [finding.id, body.status, actor.user.id, access.organizationId]
    );

    await writeAuditLog({
      action: "finding.status_changed",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "finding",
      targetId: finding.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { code: finding.code, from: previousStatus, to: body.status },
    });

    return jsonResponse({
      finding: findingToJson(updated.rows[0]!),
      previousStatus,
    });
  });
}

/**
 * GET /api/certificates — the certificate inventory, newest observation per domain.
 * Expiring-before filtering uses `not_after`, i.e. the value the certificate itself
 * declares; nothing is estimated.
 */
export async function handleListCertificates(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const pagination = paginationSchema.parse({
      page: ctx.url.searchParams.get("page") ?? undefined,
      perPage: ctx.url.searchParams.get("perPage") ?? undefined,
    });
    const access = await resolveOrganization(actor, {
      explicitId: ctx.url.searchParams.get("organizationId"),
      permission: "domain:read",
    });
    const domainIdParam = ctx.url.searchParams.get("domainId");
    if (domainIdParam && !uuidSchema.safeParse(domainIdParam).success) {
      throw errors.validation({ domainId: "Invalid domain identifier." });
    }
    const withinDaysParam = ctx.url.searchParams.get("withinDays");
    let withinDays: number | null = null;
    if (withinDaysParam !== null) {
      const parsed = Number.parseInt(withinDaysParam, 10);
      if (!Number.isFinite(parsed) || parsed < 0 || parsed > 3650) {
        throw errors.validation({ withinDays: "Use a number of days between 0 and 3650." });
      }
      withinDays = parsed;
    }

    const text = `with latest as (
        select distinct on (domain_id) * from certificates
         where organization_id = $1
           and ($2::uuid is null or domain_id = $2::uuid)
         order by domain_id, observed_at desc
      )
      select l.*, d.hostname from latest l
        join domains d on d.id = l.domain_id
       where d.deleted_at is null
         and ($3::int is null or (l.not_after is not null
              and l.not_after <= now() + make_interval(days => $3::int)))
       order by l.not_after asc nulls last
       limit $4 offset $5`;
    const params = [
      access.organizationId,
      domainIdParam,
      withinDays,
      pagination.perPage,
      (pagination.page - 1) * pagination.perPage,
    ];
    const rows = await query<CertificateRow & { hostname: string }>(text, params);
    const total = await query<{ count: number }>(
      `select count(*)::int as count from (
          select distinct on (domain_id) id, not_after from certificates
           where organization_id = $1 and ($2::uuid is null or domain_id = $2::uuid)
           order by domain_id, observed_at desc) latest
        where ($3::int is null or (not_after is not null
               and not_after <= now() + make_interval(days => $3::int)))`,
      [access.organizationId, domainIdParam, withinDays]
    );

    const count = toNumber(total.rows[0]?.count);
    return jsonResponse({
      certificates: rows.rows.map((row) =>
        certificateToJson(row, {
          hostname: row.hostname,
          daysRemaining: row.not_after
            ? Math.floor((new Date(row.not_after).getTime() - Date.now()) / 86_400_000)
            : null,
          expiringSoon: row.not_after
            ? (new Date(row.not_after).getTime() - Date.now()) / 86_400_000 <= 30
            : null,
        })
      ),
      pagination: {
        page: pagination.page,
        perPage: pagination.perPage,
        total: count,
        totalPages: Math.max(1, Math.ceil(count / pagination.perPage)),
      },
      observedAt: toIso(new Date()),
    });
  });
}
