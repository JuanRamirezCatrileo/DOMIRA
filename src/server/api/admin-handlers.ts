/**
 * Platform administration endpoints (SUPER_ADMIN only) and the explicit
 * "not implemented yet" endpoints.
 *
 * The 501 endpoints exist so the API surface is honest: they are listed by
 * GET /api with implemented: false, and they never return fake data.
 */
import { query } from "~/db";
import { jsonResponse } from "~/server/http/http";
import { requireActor, requirePlatformAdmin } from "~/server/rbac/guard";
import type { ApiRouteContext } from "./types";
import { toIso } from "./types";

/**
 * GET /api/admin/outbox — messages that would have been e-mailed.
 *
 * DOMIRA has no e-mail integration: verification and password-reset links are
 * stored here as 'pending' so a platform administrator can complete the flow
 * manually. SUPER_ADMIN only; the body contains single-use links, so this endpoint
 * is as sensitive as the e-mail inbox it replaces.
 */
export async function handleAdminOutbox(ctx: ApiRouteContext): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  requirePlatformAdmin(actor);
  const url = ctx.url;
  const kind = url.searchParams.get("kind");
  const limit = Math.min(Number(url.searchParams.get("limit") ?? 50) || 50, 200);
  const result = await query<{
    id: string;
    kind: string;
    to_email: string;
    subject: string;
    action_url: string | null;
    status: string;
    created_at: Date | string;
    sent_at: Date | string | null;
  }>(
    `select id, kind, to_email, subject, action_url, status, created_at, sent_at
       from outbox_messages
      where ($1::text is null or kind = $1::text)
      order by created_at desc
      limit $2`,
    [kind, limit]
  );
  return jsonResponse({
    emailIntegrationConfigured: false,
    messages: result.rows.map((row) => ({
      id: row.id,
      kind: row.kind,
      toEmail: row.to_email,
      subject: row.subject,
      actionUrl: row.action_url,
      status: row.status,
      createdAt: toIso(row.created_at),
      sentAt: toIso(row.sent_at),
    })),
  });
}

/** GET /api/admin/audit — recent audit trail entries for the platform. */
export async function handleAdminAudit(ctx: ApiRouteContext): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  requirePlatformAdmin(actor);
  const limit = Math.min(Number(ctx.url.searchParams.get("limit") ?? 50) || 50, 200);
  const result = await query<{
    id: string;
    organization_id: string | null;
    actor_email: string | null;
    action: string;
    target_type: string | null;
    target_id: string | null;
    outcome: string;
    created_at: Date | string;
  }>(
    `select id, organization_id, actor_email, action, target_type, target_id, outcome, created_at
       from audit_logs order by created_at desc limit $1`,
    [limit]
  );
  return jsonResponse({
    entries: result.rows.map((row) => ({
      id: row.id,
      organizationId: row.organization_id,
      actorEmail: row.actor_email,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      outcome: row.outcome,
      createdAt: toIso(row.created_at),
    })),
  });
}

function notImplemented(feature: string, deliverable: string, ctx: ApiRouteContext): Response {
  return jsonResponse(
    {
      error: {
        code: "NOT_IMPLEMENTED",
        message: `${feature} is not implemented yet.`,
        details: { plannedIn: deliverable, endpoint: `${ctx.request.method} ${ctx.url.pathname}` },
      },
    },
    { status: 501 }
  );
}

export async function handleDomainsNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Domain management", "deliverable 2", ctx);
}
export async function handleDomainVerificationNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Domain verification", "deliverable 2", ctx);
}
export async function handleScansNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Domain scanning", "deliverable 2", ctx);
}
export async function handleFindingsNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Findings", "deliverable 2", ctx);
}
export async function handleCertificatesNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Certificate monitoring", "deliverable 2", ctx);
}
export async function handleAlertsNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Alerts", "deliverable 4", ctx);
}
export async function handleReportsNotImplemented(ctx: ApiRouteContext): Promise<Response> {
  return notImplemented("Reports", "deliverable 4", ctx);
}
