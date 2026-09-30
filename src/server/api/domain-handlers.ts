/**
 * Domain management, ownership verification and the scan request endpoint.
 *
 * Every handler here follows the same rules as the rest of the API:
 *   * the caller is resolved from the session (never from the body);
 *   * the organisation is resolved from the caller's memberships, and the
 *     permission check runs through `requireOrgRole` — the UI never authorises;
 *   * a resource of another tenant is answered with 404, never 403, so ids cannot
 *     be probed for existence;
 *   * every read is filtered by `organization_id` in SQL, so even a bug in a
 *     handler cannot return another tenant's rows.
 *
 * Role rules (docs/api.md and docs/security.md):
 *   VIEWER  read only
 *   MEMBER  create domains, request scans, pause/resume, change frequency
 *   ADMIN   everything a MEMBER can, plus rename and delete/archive
 */
import { query, transaction } from "~/db";
import { writeAuditLog } from "~/server/audit";
import { RATE_LIMITS, enforceRateLimit } from "~/server/auth/rate-limit";
import { domainCreateQuotaPerOrgPerHour, verificationMaxAttempts } from "~/server/env";
import { HostnameRejectedError, assertValidHostname, registeredDomain } from "~/server/api/domain-validation";
import { errors } from "~/server/http/errors";
import { jsonResponse, readJsonBody } from "~/server/http/http";
import { listMemberships, requireActor, requireOrgRole, type Actor, type OrganizationAccess } from "~/server/rbac/guard";
import { roleRank, type RoleCode } from "~/server/rbac/permissions";
import { SCAN_HISTORY_DEFAULT_LIMIT, scanToJson, type ScanRow } from "~/server/api/serializers";
import { scanRefusal, enqueueDomainScan, scheduleNextScan } from "~/server/scanning/service";
import {
  VERIFICATION_RECORD_PREFIX,
  VERIFICATION_VALUE_PREFIX,
  checkVerification,
  ensureVerification,
  type VerificationRow,
} from "~/server/scanning/verification";
import {
  createDomainSchema,
  paginationSchema,
  updateDomainSchema,
  uuidSchema,
} from "~/server/validation";
import type { ApiRouteContext } from "./types";
import { toIso, toNumber } from "./types";

export interface DomainRow {
  id: string;
  organization_id: string;
  hostname: string;
  normalized_hostname: string;
  display_name: string | null;
  status: string;
  authorization_note: string | null;
  monitoring_enabled: boolean;
  check_frequency: string;
  added_by: string | null;
  verified_at: Date | string | null;
  last_scan_at: Date | string | null;
  next_scan_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  deleted_at: Date | string | null;
  consecutive_failures: number;
  paused_at: Date | string | null;
  archived_at: Date | string | null;
}

const DOMAIN_COLUMNS = `id, organization_id, hostname, normalized_hostname, display_name, status,
  authorization_note, monitoring_enabled, check_frequency, added_by, verified_at, last_scan_at,
  next_scan_at, created_at, updated_at, deleted_at, consecutive_failures, paused_at, archived_at`;

function parseUuidParam(ctx: ApiRouteContext, name: string): string {
  const parsed = uuidSchema.safeParse(ctx.params[name]);
  if (!parsed.success) throw errors.notFound();
  return parsed.data;
}

async function withActor(
  ctx: ApiRouteContext,
  fn: (actor: Actor) => Promise<Response>
): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  return fn(actor);
}

/**
 * Resolves the organisation a request acts on.
 *
 * `organizationId` may come from the query string or the body, but it grants
 * nothing: it is only used to look up the caller's membership, and a caller who is
 * not a member gets 404. When it is omitted, the caller's first organisation is
 * used — the "single organisation" case, which is what the customer dashboard does.
 */
export async function resolveOrganization(
  actor: Actor,
  options: { explicitId?: string | null; permission: Parameters<typeof requireOrgRole>[2] }
): Promise<OrganizationAccess> {
  const explicit = options.explicitId ?? null;
  if (explicit) {
    const parsed = uuidSchema.safeParse(explicit);
    if (!parsed.success) throw errors.validation({ organizationId: "Invalid organisation identifier." });
    return requireOrgRole(actor, parsed.data, options.permission);
  }
  const memberships = await listMemberships(actor.user.id);
  const first = memberships[0];
  if (!first) {
    throw errors.notFound(
      "You are not a member of any organisation yet. Create one first (POST /api/organizations)."
    );
  }
  return requireOrgRole(actor, first.organizationId, options.permission);
}

function assertRoleAtLeast(role: RoleCode, minimum: RoleCode, action: string): void {
  if (roleRank(role) < roleRank(minimum)) {
    throw errors.forbidden(`Your role (${role}) cannot ${action}. ${minimum} or above is required.`);
  }
}

export function domainToJson(row: DomainRow, extras: Record<string, unknown> = {}) {
  return {
    id: row.id,
    hostname: row.hostname,
    normalizedHostname: row.normalized_hostname,
    registeredDomain: registeredDomain(row.normalized_hostname),
    displayName: row.display_name,
    status: row.status,
    authorizationNote: row.authorization_note,
    monitoringEnabled: Boolean(row.monitoring_enabled),
    checkFrequency: row.check_frequency,
    consecutiveFailures: toNumber(row.consecutive_failures),
    verifiedAt: toIso(row.verified_at),
    lastScanAt: toIso(row.last_scan_at),
    nextScanAt: toIso(row.next_scan_at),
    pausedAt: toIso(row.paused_at),
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
    ...extras,
  };
}

export function verificationToJson(verification: VerificationRow) {
  return {
    id: verification.id,
    method: verification.method,
    status: verification.status,
    // The stored values are what the customer must publish; the fallback only
    // covers rows written before record_name/record_value existed.
    recordName: verification.record_name ?? `${VERIFICATION_RECORD_PREFIX}${verification.challenge_token}`,
    recordType: "TXT" as const,
    recordValue: verification.record_value ?? `${VERIFICATION_VALUE_PREFIX}${verification.challenge_token}`,
    attempts: toNumber(verification.attempts),
    maxAttempts: verificationMaxAttempts(),
    expiresAt: toIso(verification.expires_at),
    lastCheckedAt: toIso(verification.last_checked_at),
    verifiedAt: toIso(verification.verified_at),
    lastError: verification.last_error,
  };
}

/** Loads a domain by id and enforces organisation membership + permission. */
export async function loadDomainForActor(
  actor: Actor,
  domainId: string,
  permission: Parameters<typeof requireOrgRole>[2],
  options: { includeDeleted?: boolean } = {}
): Promise<{ domain: DomainRow; access: OrganizationAccess }> {
  const result = await query<DomainRow>(
    `select ${DOMAIN_COLUMNS} from domains where id = $1${options.includeDeleted ? "" : " and deleted_at is null"}`,
    [domainId]
  );
  const domain = result.rows[0];
  if (!domain) throw errors.notFound();
  const access = await requireOrgRole(actor, domain.organization_id, permission);
  return { domain, access };
}

export async function handleCreateDomain(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const body = await readJsonBody(ctx.request, createDomainSchema);
    const access = await resolveOrganization(actor, {
      explicitId: body.organizationId ?? null,
      permission: "domain:manage",
    });

    await enforceRateLimit(`domain-create|org:${access.organizationId}`, RATE_LIMITS.authenticatedWrite);
    const recent = await query<{ count: number }>(
      "select count(*)::int as count from domains where organization_id = $1 and created_at > now() - interval '1 hour'",
      [access.organizationId]
    );
    const limit = domainCreateQuotaPerOrgPerHour();
    if (toNumber(recent.rows[0]?.count) >= limit) {
      throw errors.rateLimited(3600);
    }

    // --- Hostname validation (SSRF first filter, see domain-validation.ts) ----
    let hostname: string;
    let domain: string;
    try {
      const validated = assertValidHostname(body.hostname);
      hostname = validated.hostname;
      domain = validated.registeredDomain;
    } catch (error) {
      if (error instanceof HostnameRejectedError) {
        throw errors.validation({ hostname: error.message }, "That hostname cannot be monitored.");
      }
      throw error;
    }

    const created = await transaction(async (tx) => {
      const existing = await tx.query<DomainRow & { deleted_at: Date | string | null }>(
        `select ${DOMAIN_COLUMNS} from domains
          where organization_id = $1 and normalized_hostname = $2
          for update`,
        [access.organizationId, hostname]
      );
      const current = existing.rows[0];
      if (current) {
        if (current.deleted_at === null) {
          throw errors.conflict("That domain is already monitored by this organisation.");
        }
        // Re-adding a previously removed domain revives it, which also re-issues a
        // verification token — control of the domain must be proven again.
        await tx.query(
          `update domains
              set deleted_at = null, archived_at = null, status = 'pending_verification',
                  verified_at = null, monitoring_enabled = $3, check_frequency = $4,
                  display_name = $5, authorization_note = $6, updated_by = $7,
                  consecutive_failures = 0, next_scan_at = null, updated_at = now()
            where id = $1`,
          [
            current.id,
            access.organizationId,
            body.monitoringEnabled ?? false,
            body.checkFrequency ?? "daily",
            body.displayName ?? null,
            body.authorizationNote ?? null,
            actor.user.id,
          ]
        );
        const revived = await tx.query<DomainRow>(`select ${DOMAIN_COLUMNS} from domains where id = $1`, [
          current.id,
        ]);
        return revived.rows[0]!;
      }

      const inserted = await tx.query<DomainRow>(
        `insert into domains
           (organization_id, hostname, normalized_hostname, display_name, status,
            authorization_note, monitoring_enabled, check_frequency, added_by, updated_by)
         values ($1, $2, $3, $4, 'pending_verification', $5, $6, $7, $8, $8)
         returning ${DOMAIN_COLUMNS}`,
        [
          access.organizationId,
          hostname,
          hostname,
          body.displayName ?? null,
          body.authorizationNote ?? null,
          body.monitoringEnabled ?? false,
          body.checkFrequency ?? "daily",
          actor.user.id,
        ]
      );
      return inserted.rows[0]!;
    });

    const { verification } = await ensureVerification(access.organizationId, created.id, hostname);
    if (created.monitoring_enabled) {
      await scheduleNextScan(created.id, created.check_frequency);
    }

    await writeAuditLog({
      action: "domain.created",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "domain",
      targetId: created.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { hostname, registeredDomain: domain },
    });

    return jsonResponse(
      {
        domain: domainToJson(created),
        verification: verificationToJson(verification),
        instructions:
          "Publish the TXT record above, then call POST /api/domains/{id}/verify. " +
          "Until it matches, DOMIRA refuses every scan of this domain.",
      },
      { status: 201 }
    );
  });
}

export async function handleListDomains(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const pagination = paginationSchema.parse({
      page: ctx.url.searchParams.get("page") ?? undefined,
      perPage: ctx.url.searchParams.get("perPage") ?? undefined,
    });
    const access = await resolveOrganization(actor, {
      explicitId: ctx.url.searchParams.get("organizationId"),
      permission: "domain:read",
    });
    const status = ctx.url.searchParams.get("status");

    const total = await query<{ count: number }>(
      `select count(*)::int as count from domains
        where organization_id = $1 and deleted_at is null
          and ($2::text is null or status = $2::text)`,
      [access.organizationId, status]
    );
    const rows = await query<DomainRow & { open_findings: number; latest_score: number | null }>(
      `select d.id, d.organization_id, d.hostname, d.normalized_hostname, d.display_name, d.status,
              d.authorization_note, d.monitoring_enabled, d.check_frequency, d.added_by, d.verified_at,
              d.last_scan_at, d.next_scan_at, d.created_at, d.updated_at, d.deleted_at,
              d.consecutive_failures, d.paused_at, d.archived_at,
              (select count(*)::int from findings f
                where f.domain_id = d.id and f.status in ('new', 'acknowledged')) as open_findings,
              (select s.score from security_scores s
                where s.domain_id = d.id order by s.computed_at desc limit 1) as latest_score
         from domains d
        where d.organization_id = $1 and d.deleted_at is null
          and ($2::text is null or d.status = $2::text)
        order by d.created_at desc
        limit $3 offset $4`,
      [access.organizationId, status, pagination.perPage, (pagination.page - 1) * pagination.perPage]
    );

    const count = toNumber(total.rows[0]?.count);
    return jsonResponse({
      domains: rows.rows.map((row) =>
        domainToJson(row as DomainRow, {
          openFindings: toNumber(row.open_findings),
          latestScore: row.latest_score === null ? null : toNumber(row.latest_score),
        })
      ),
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

export async function handleGetDomain(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:read");

    const verification = await query<VerificationRow>(
      `select * from domain_verifications
        where organization_id = $1 and domain_id = $2
        order by case when status = 'verified' then 0 when status = 'pending' then 1 else 2 end,
                 created_at desc
        limit 1`,
      [access.organizationId, domain.id]
    );
    const latestScan = await query<ScanRow>(
      `select * from scans where organization_id = $1 and domain_id = $2
        order by created_at desc limit 1`,
      [access.organizationId, domain.id]
    );
    const counts = await query<{ open_findings: number; critical_findings: number; latest_score: number | null }>(
      `select
         (select count(*)::int from findings where domain_id = $1 and status in ('new','acknowledged')) as open_findings,
         (select count(*)::int from findings where domain_id = $1 and status in ('new','acknowledged')
            and severity in ('high','critical')) as critical_findings,
         (select score from security_scores where domain_id = $1 order by computed_at desc limit 1) as latest_score`,
      [domain.id]
    );
    const row = counts.rows[0];

    return jsonResponse({
      domain: domainToJson(domain, {
        openFindings: toNumber(row?.open_findings),
        highOrCriticalFindings: toNumber(row?.critical_findings),
        latestScore: row?.latest_score === null || row?.latest_score === undefined
          ? null
          : toNumber(row.latest_score),
      }),
      verification: verification.rows[0] ? verificationToJson(verification.rows[0]) : null,
      latestScan: latestScan.rows[0] ? scanToJson(latestScan.rows[0]) : null,
      role: access.role,
      canScan: scanRefusal(domain) === null,
      scanRefusal: scanRefusal(domain),
    });
  });
}

export async function handleUpdateDomain(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const body = await readJsonBody(ctx.request, updateDomainSchema);
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:manage");

    // Renaming and archiving are administrative actions; monitoring changes are not.
    if (body.displayName !== undefined || body.authorizationNote !== undefined) {
      assertRoleAtLeast(access.role, "ADMIN", "rename a domain");
    }
    if (body.status === "archived") {
      assertRoleAtLeast(access.role, "ADMIN", "archive a domain");
    }

    if (body.status === "verified" && !domain.verified_at) {
      throw errors.conflict(
        "This domain has never been verified, so it cannot be resumed. Publish the DNS TXT record and verify it first."
      );
    }
    if (body.status === "verified" && (domain.status === "suspended" || domain.status === "archived")) {
      throw errors.conflict("A suspended or archived domain must be re-verified before monitoring resumes.");
    }

    const updates: string[] = [];
    const params: unknown[] = [];
    const push = (column: string, value: unknown) => {
      params.push(value);
      updates.push(column + " = $" + String(params.length));
    };

    if (body.displayName !== undefined) push("display_name", body.displayName);
    if (body.authorizationNote !== undefined) push("authorization_note", body.authorizationNote);
    if (body.monitoringEnabled !== undefined) push("monitoring_enabled", body.monitoringEnabled);
    if (body.checkFrequency !== undefined) push("check_frequency", body.checkFrequency);
    if (body.status === "paused") {
      updates.push("status = 'paused'", "paused_at = now()", "monitoring_enabled = false", "next_scan_at = null");
    }
    if (body.status === "archived") {
      updates.push("status = 'archived'", "archived_at = now()", "monitoring_enabled = false", "next_scan_at = null");
    }
    if (body.status === "verified") {
      updates.push("status = 'verified'", "paused_at = null", "archived_at = null");
    }
    if (updates.length === 0) throw errors.validation({ body: "Nothing to update." });

    const idIndex = params.push(domain.id);
    const orgIndex = params.push(access.organizationId);
    const actorIndex = params.push(actor.user.id);
    updates.push("updated_by = $" + String(actorIndex), "updated_at = now()");

    const updated = await query<DomainRow>(
      "update domains set " +
        updates.join(", ") +
        " where id = $" +
        String(idIndex) +
        " and organization_id = $" +
        String(orgIndex) +
        " returning " +
        DOMAIN_COLUMNS,
      params
    );
    const row = updated.rows[0];
    if (!row) throw errors.notFound();

    // Keep monitoring_configs (deliverable 4's alerting row) in step with the domain.
    await query(
      `insert into monitoring_configs (organization_id, domain_id, is_enabled, frequency)
       values ($1, $2, $3, $4)
       on conflict (domain_id) do update
         set is_enabled = excluded.is_enabled, frequency = excluded.frequency, updated_at = now()`,
      [
        access.organizationId,
        row.id,
        Boolean(row.monitoring_enabled) && row.status === "verified",
        row.check_frequency === "manual" ? "daily" : row.check_frequency === "6h" ? "hourly" : row.check_frequency,
      ]
    );
    if (row.monitoring_enabled && row.status === "verified") {
      await scheduleNextScan(row.id, row.check_frequency);
    } else {
      await query("update domains set next_scan_at = null where id = $1", [row.id]);
    }

    await writeAuditLog({
      action: "domain.updated",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "domain",
      targetId: row.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { fields: Object.keys(body).filter((key) => key !== "organizationId") },
    });

    const refreshed = await query<DomainRow>(`select ${DOMAIN_COLUMNS} from domains where id = $1`, [row.id]);
    return jsonResponse({ domain: domainToJson(refreshed.rows[0]!) });
  });
}

export async function handleDeleteDomain(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:delete");

    await transaction(async (tx) => {
      // Soft delete: the scan history and the findings stay readable for audit, but
      // the domain stops being monitored and disappears from every listing.
      await tx.query(
        `update domains
            set deleted_at = now(), archived_at = now(), status = 'archived',
                monitoring_enabled = false, next_scan_at = null, updated_by = $2, updated_at = now()
          where id = $1 and organization_id = $3`,
        [domain.id, actor.user.id, access.organizationId]
      );
      await tx.query(
        `update monitoring_configs set is_enabled = false, next_run_at = null, updated_at = now()
          where domain_id = $1`,
        [domain.id]
      );
      await tx.query(
        `update scans set status = 'cancelled', cancelled_at = now(), finished_at = now(),
                error_message = coalesce(error_message, 'The domain was removed.'), updated_at = now()
          where domain_id = $1 and status in ('queued', 'running')`,
        [domain.id]
      );
      await tx.query(
        `update jobs set status = 'cancelled', finished_at = now(), updated_at = now()
          where domain_id = $1 and status in ('queued', 'running')`,
        [domain.id]
      );
    });

    await writeAuditLog({
      action: "domain.deleted",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "domain",
      targetId: domain.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { hostname: domain.normalized_hostname },
    });

    return jsonResponse({ ok: true, domainId: domain.id, deletedAt: toIso(new Date()) });
  });
}

export async function handleVerifyDomain(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:manage");

    if (domain.status === "archived" || domain.status === "suspended") {
      throw errors.conflict(`A ${domain.status} domain cannot be verified. Re-add or contact support.`);
    }
    await enforceRateLimit(
      `domain-verify|org:${access.organizationId}|domain:${domain.id}`,
      { limit: 30, windowSeconds: 3600 }
    );

    if (domain.status === "verified") {
      return jsonResponse({
        domain: domainToJson(domain),
        verified: true,
        alreadyVerified: true,
        message: "This domain is already verified.",
      });
    }

    const { verification, issued } = await ensureVerification(
      access.organizationId,
      domain.id,
      domain.normalized_hostname
    );
    const result = await checkVerification(verification);

    if (result.verified) {
      await query(
        `update domains set status = 'verified', verified_at = now(), updated_by = $2, updated_at = now()
          where id = $1 and organization_id = $3`,
        [domain.id, actor.user.id, access.organizationId]
      );
      if (domain.monitoring_enabled) await scheduleNextScan(domain.id, domain.check_frequency);
      await writeAuditLog({
        action: "domain.verified",
        organizationId: access.organizationId,
        actorUserId: actor.user.id,
        actorEmail: actor.user.email,
        targetType: "domain",
        targetId: domain.id,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
        metadata: { hostname: domain.normalized_hostname, recordName: verification.record_name },
      });
      const refreshed = await query<DomainRow>(`select ${DOMAIN_COLUMNS} from domains where id = $1`, [domain.id]);
      return jsonResponse({
        domain: domainToJson(refreshed.rows[0]!),
        verified: true,
        alreadyVerified: false,
        observedRecords: result.observedRecords,
        message: "Ownership confirmed. You can start scanning this domain.",
      });
    }

    await writeAuditLog({
      action: "domain.verification_failed",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "domain",
      targetId: domain.id,
      outcome: "failure",
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { reason: result.reason, attempts: result.attempts },
    });

    const refreshedVerification = await query<VerificationRow>(
      "select * from domain_verifications where id = $1",
      [verification.id]
    );
    return jsonResponse(
      {
        verified: false,
        reason: result.reason,
        observedRecords: result.observedRecords,
        error: result.error,
        attempts: result.attempts,
        maxAttempts: result.maxAttempts,
        tokenReissued: issued,
        verification: refreshedVerification.rows[0]
          ? verificationToJson(refreshedVerification.rows[0])
          : null,
        message: verificationFailureMessage(result.reason),
      },
      { status: 409 }
    );
  });
}

export function verificationFailureMessage(reason: string | null): string {
  switch (reason) {
    case "record_not_found":
      return "The TXT record was not found (or does not contain the DOMIRA token yet). DNS changes can take a few minutes to propagate.";
    case "token_expired":
      return "The verification token expired. A new one has been issued — publish it and try again.";
    case "attempts_exhausted":
      return "Too many failed attempts. A new token is required; request verification again to get one.";
    case "dns_lookup_failed":
      return "The DNS lookup could not be completed. This is a temporary failure on our side; try again in a moment.";
    case "no_token":
      return "No verification token exists for this domain yet.";
    default:
      return "The domain could not be verified.";
  }
}

/* -------------------------------------------------------------------------- */
/* Scanning                                                                   */
/* -------------------------------------------------------------------------- */

export async function handleRequestDomainScan(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "scan:run");

    await enforceRateLimit(
      `scan-request|org:${access.organizationId}|user:${actor.user.id}`,
      RATE_LIMITS.authenticatedWrite
    );

    // No analysis happens in this request: it creates the scan row and the job and
    // returns 202. The worker does the real work (docs/architecture.md).
    const queued = await enqueueDomainScan({
      domain,
      triggerSource: "manual",
      requestedBy: actor.user.id,
    });

    await writeAuditLog({
      action: "scan.requested",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "scan",
      targetId: queued.scan.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { hostname: domain.normalized_hostname, reused: queued.reused, jobId: queued.job.id },
    });

    return jsonResponse(
      {
        scan: scanToJson(queued.scan as ScanRow),
        job: {
          id: queued.job.id,
          type: queued.job.type,
          status: queued.job.status,
          attempts: toNumber(queued.job.attempts),
          maxAttempts: toNumber(queued.job.max_attempts),
        },
        reused: queued.reused,
        message: queued.reused
          ? "A scan for this domain is already queued or running; that one was returned."
          : "Scan queued. Poll GET /api/scans/{id} until its status is completed or failed.",
        pollAfterMs: 2000,
      },
      { status: 202 }
    );
  });
}

export async function handleListDomainScans(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:read");
    const pagination = paginationSchema.parse({
      page: ctx.url.searchParams.get("page") ?? undefined,
      perPage: ctx.url.searchParams.get("perPage") ?? undefined,
    });
    const total = await query<{ count: number }>(
      "select count(*)::int as count from scans where organization_id = $1 and domain_id = $2",
      [access.organizationId, domain.id]
    );
    const rows = await query<ScanRow>(
      `select * from scans where organization_id = $1 and domain_id = $2
        order by created_at desc limit $3 offset $4`,
      [access.organizationId, domain.id, pagination.perPage, (pagination.page - 1) * pagination.perPage]
    );
    const count = toNumber(total.rows[0]?.count);
    return jsonResponse({
      domainId: domain.id,
      scans: rows.rows.map(scanToJson),
      pagination: {
        page: pagination.page,
        perPage: pagination.perPage,
        total: count,
        totalPages: Math.max(1, Math.ceil(count / pagination.perPage)),
      },
    });
  });
}

/**
 * GET /api/domains/:id/security — the score and the per-category breakdown.
 *
 * Categories that are not collected yet (e-mail, HTTP headers) are reported as
 * `not_collected` with `score: null`; they are never presented as full marks and
 * never fabricated. When no scan has run, the answer says so instead of inventing
 * a score.
 */
export async function handleDomainSecurity(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const domainId = parseUuidParam(ctx, "id");
    const { domain, access } = await loadDomainForActor(actor, domainId, "domain:read");

    const scoreRow = await query<{
      id: string;
      score: number;
      grade: string;
      previous_score: number | null;
      delta: number | null;
      category_scores: Record<string, { score: number | null; collected: boolean; weight: number }>;
      factors: unknown;
      coverage: Record<string, unknown>;
      methodology_version: string;
      trigger_source: string | null;
      computed_at: Date | string;
      scan_id: string | null;
    }>(
      `select id, score, grade, previous_score, delta, category_scores, factors, coverage,
              methodology_version, trigger_source, computed_at, scan_id
         from security_scores where organization_id = $1 and domain_id = $2
        order by computed_at desc limit 1`,
      [access.organizationId, domain.id]
    );
    const latest = scoreRow.rows[0] ?? null;

    const history = await query<{ score: number; grade: string; computed_at: Date | string }>(
      `select score, grade, computed_at from security_scores
        where organization_id = $1 and domain_id = $2
        order by computed_at desc limit $3`,
      [access.organizationId, domain.id, SCAN_HISTORY_DEFAULT_LIMIT]
    );

    const checks = await query<{
      category: string;
      status: string;
      score: number | null;
      not_collected: boolean;
      error_message: string | null;
      data: Record<string, unknown>;
      created_at: Date | string;
    }>(
      `select category, status, score, not_collected, error_message, data, created_at
         from scan_results
        where organization_id = $1 and domain_id = $2
          and scan_id = (select id from scans where domain_id = $2 and status in ('completed','failed')
                          order by created_at desc limit 1)
        order by created_at asc`,
      [access.organizationId, domain.id]
    );

    const collected = new Set<string>();
    const categories = checks.rows.map((row) => {
      collected.add(row.category);
      return {
        category: row.category,
        status: row.not_collected ? "not_collected" : row.status,
        score: row.score === null ? null : toNumber(row.score),
        error: row.error_message,
        observedAt: toIso(row.created_at),
      };
    });
    // Every category is always reported, so the UI never has to guess what is
    // missing: an uncollected one is explicit.
    for (const category of ["tls", "certificate", "dns", "email", "http", "availability"]) {
      if (!collected.has(category)) {
        categories.push({
          category,
          status: category === "email" || category === "http" ? "not_collected" : "no_data",
          score: null,
          error: null,
          observedAt: null,
        });
      }
    }

    return jsonResponse({
      domainId: domain.id,
      hostname: domain.normalized_hostname,
      score: latest
        ? {
            value: toNumber(latest.score),
            grade: latest.grade,
            previousScore: latest.previous_score === null ? null : toNumber(latest.previous_score),
            delta: latest.delta === null ? null : toNumber(latest.delta),
            methodologyVersion: latest.methodology_version,
            triggerSource: latest.trigger_source,
            scanId: latest.scan_id,
            computedAt: toIso(latest.computed_at),
            coverage: latest.coverage,
            factors: latest.factors,
          }
        : null,
      categories: categories.sort(
        (a, b) => ["tls", "certificate", "dns", "email", "http", "availability"].indexOf(a.category) -
          ["tls", "certificate", "dns", "email", "http", "availability"].indexOf(b.category)
      ),
      history: history.rows
        .map((row) => ({ score: toNumber(row.score), grade: row.grade, computedAt: toIso(row.computed_at) }))
        .reverse(),
      note: latest
        ? null
        : "No scan has completed for this domain yet, so there is no score. Nothing is estimated.",
      notCollectedNote:
        "E-mail security (SPF/DMARC/DKIM) and HTTP security headers are not collected yet (deliverable 2b). " +
        "They are excluded from the score and reported as not_collected — never counted as full marks.",
    });
  });
}

