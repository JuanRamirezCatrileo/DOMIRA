/**
 * Organisation and membership endpoints.
 *
 * Every handler in this file funnels through `requireOrgRole(actor, id, permission)`
 * from src/server/rbac/guard.ts. The organisation id in the URL is client input and
 * grants nothing by itself: if the caller has no membership row, the answer is 404
 * (so ids cannot be probed) and if the caller's role lacks the permission it is 403.
 */
import { query, transaction } from "~/db";
import { writeAuditLog } from "~/server/audit";
import { RATE_LIMITS, enforceRateLimit } from "~/server/auth/rate-limit";
import { errors } from "~/server/http/errors";
import { jsonResponse, readJsonBody } from "~/server/http/http";
import { listMemberships, requireActor, requireOrgRole, type Actor } from "~/server/rbac/guard";
import { ROLE_PERMISSIONS, type RoleCode } from "~/server/rbac/permissions";
import {
  addMemberSchema,
  createOrganizationSchema,
  organizationNameSchema,
  updateMemberSchema,
  uuidSchema,
} from "~/server/validation";
import type { ApiRouteContext } from "./types";
import { publicUser, toIso, toNumber } from "./types";

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

async function loadOrganization(organizationId: string) {
  const result = await query<{
    id: string;
    name: string;
    slug: string;
    status: string;
    created_at: Date | string;
  }>("select id, name, slug, status, created_at from organizations where id = $1 and deleted_at is null", [
    organizationId,
  ]);
  return result.rows[0] ?? null;
}

export async function handleListOrganizations(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizations = await listMemberships(actor.user.id);
    return jsonResponse({ organizations });
  });
}

export async function handleCreateOrganization(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    await enforceRateLimit(
      `org-create|user:${actor.user.id}`,
      RATE_LIMITS.authenticatedWrite
    );
    const body = await readJsonBody(ctx.request, createOrganizationSchema);

    const slugBase = body.name
      .toLowerCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 48);

    const created = await transaction(async (tx) => {
      let slug = slugBase.length >= 2 ? slugBase : "organization";
      for (let attempt = 0; attempt < 6; attempt += 1) {
        const exists = await tx.query("select 1 from organizations where slug = $1", [slug]);
        if (exists.rows.length === 0) break;
        slug = `${slugBase.slice(0, 40)}-${Math.random().toString(36).slice(2, 6)}`;
      }
      const orgResult = await tx.query<{ id: string; name: string; slug: string; status: string }>(
        `insert into organizations (name, slug, created_by) values ($1, $2, $3)
         returning id, name, slug, status`,
        [body.name, slug, actor.user.id]
      );
      const organization = orgResult.rows[0]!;
      const memberResult = await tx.query<{ id: string; role_code: RoleCode }>(
        `insert into organization_members (organization_id, user_id, role_code)
         values ($1, $2, 'ADMIN') returning id, role_code`,
        [organization.id, actor.user.id]
      );
      await tx.query(
        `insert into subscriptions (organization_id, plan_code, status) values ($1, 'FREE', 'active')`,
        [organization.id]
      );
      return { organization, membership: memberResult.rows[0]! };
    });

    await writeAuditLog({
      action: "organization.created",
      organizationId: created.organization.id,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "organization",
      targetId: created.organization.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { slug: created.organization.slug },
    });

    return jsonResponse(
      {
        organization: created.organization,
        membership: { role: created.membership.role_code },
      },
      { status: 201 }
    );
  });
}

export async function handleGetOrganization(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const access = await requireOrgRole(actor, organizationId, "org:read");
    const organization = await loadOrganization(access.organizationId);
    if (!organization) throw errors.notFound();
    const counts = await query<{
      members: number;
      domains: number;
      scans: number;
      open_findings: number;
      open_alerts: number;
    }>(
      `select
         (select count(*) from organization_members where organization_id = $1) as members,
         (select count(*) from domains where organization_id = $1 and deleted_at is null) as domains,
         (select count(*) from scans where organization_id = $1) as scans,
         (select count(*) from findings where organization_id = $1 and status in ('new','acknowledged')) as open_findings,
         (select count(*) from alerts where organization_id = $1 and status = 'open') as open_alerts`,
      [access.organizationId]
    );
    const row = counts.rows[0];
    return jsonResponse({
      organization: {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        status: organization.status,
        createdAt: toIso(organization.created_at),
      },
      role: access.role,
      permissions: ROLE_PERMISSIONS[access.role],
      counts: {
        members: toNumber(row?.members),
        domains: toNumber(row?.domains),
        scans: toNumber(row?.scans),
        openFindings: toNumber(row?.open_findings),
        openAlerts: toNumber(row?.open_alerts),
      },
    });
  });
}

interface MemberRow {
  membership_id: string;
  user_id: string;
  role_code: RoleCode;
  joined_at: Date | string;
  email: string;
  full_name: string | null;
  email_verified_at: Date | string | null;
  status: string;
}

function memberToJson(row: MemberRow) {
  return {
    membershipId: row.membership_id,
    userId: row.user_id,
    email: row.email,
    fullName: row.full_name,
    role: row.role_code,
    joinedAt: toIso(row.joined_at),
    ...publicUser({
      id: row.user_id,
      email: row.email,
      fullName: row.full_name,
      emailVerifiedAt: row.email_verified_at,
    }),
    accountStatus: row.status,
  };
}

async function listMemberRows(organizationId: string): Promise<MemberRow[]> {
  const result = await query<MemberRow>(
    `select m.id as membership_id, m.user_id, m.role_code, m.joined_at,
            u.email, u.full_name, u.email_verified_at, u.status
       from organization_members m
       join users u on u.id = m.user_id
      where m.organization_id = $1
      order by m.joined_at asc`,
    [organizationId]
  );
  return result.rows;
}

export async function handleListMembers(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const access = await requireOrgRole(actor, organizationId, "org:read");
    const members = await listMemberRows(access.organizationId);
    return jsonResponse({ members: members.map(memberToJson) });
  });
}

export async function handleAddMember(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const access = await requireOrgRole(actor, organizationId, "org:manage_members");
    const body = await readJsonBody(ctx.request, addMemberSchema);

    const userResult = await query<{ id: string; email: string }>(
      "select id, email from users where lower(email) = $1",
      [body.email]
    );
    const user = userResult.rows[0];
    if (!user) {
      // Honest, documented trade-off: adding a member is by e-mail, so the
      // administrator must be told the address has no account yet. Rate limiting
      // and the org:manage_members permission bound the enumeration surface.
      throw errors.notFound("That e-mail address has no DOMIRA account yet.");
    }
    const existing = await query(
      "select 1 from organization_members where organization_id = $1 and user_id = $2",
      [access.organizationId, user.id]
    );
    if (existing.rows.length > 0) throw errors.conflict("That user is already a member of this organisation.");

    const inserted = await query<{ id: string }>(
      `insert into organization_members (organization_id, user_id, role_code, invited_by)
       values ($1, $2, $3, $4) returning id`,
      [access.organizationId, user.id, body.role, actor.user.id]
    );

    await writeAuditLog({
      action: "membership.added",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "user",
      targetId: user.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { role: body.role },
    });

    const members = await listMemberRows(access.organizationId);
    const row = members.find((member) => member.membership_id === inserted.rows[0]!.id);
    return jsonResponse({ member: row ? memberToJson(row) : { userId: user.id, role: body.role } }, {
      status: 201,
    });
  });
}

/** Guard rails that keep an organisation administrable. */
async function assertNotLastAdmin(
  organizationId: string,
  targetUserId: string,
  nextRole: RoleCode | null
): Promise<void> {
  const target = await query<{ role_code: RoleCode }>(
    "select role_code from organization_members where organization_id = $1 and user_id = $2",
    [organizationId, targetUserId]
  );
  const currentRole = target.rows[0]?.role_code;
  if (currentRole !== "ADMIN") return;
  if (nextRole === "ADMIN") return;
  const admins = await query<{ count: number }>(
    "select count(*) as count from organization_members where organization_id = $1 and role_code = 'ADMIN'",
    [organizationId]
  );
  if (toNumber(admins.rows[0]?.count) <= 1) {
    throw errors.conflict("An organisation must keep at least one administrator.");
  }
}

export async function handleUpdateMember(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const targetUserId = parseUuidParam(ctx, "userId");
    const access = await requireOrgRole(actor, organizationId, "org:manage_members");
    const body = await readJsonBody(ctx.request, updateMemberSchema);

    const target = await query<{ role_code: RoleCode }>(
      "select role_code from organization_members where organization_id = $1 and user_id = $2",
      [access.organizationId, targetUserId]
    );
    if (target.rows.length === 0) throw errors.notFound("That user is not a member of this organisation.");
    if (targetUserId === actor.user.id) {
      throw errors.conflict("You cannot change your own role.");
    }
    await assertNotLastAdmin(access.organizationId, targetUserId, body.role);

    await query(
      "update organization_members set role_code = $3, updated_at = now() where organization_id = $1 and user_id = $2",
      [access.organizationId, targetUserId, body.role]
    );

    await writeAuditLog({
      action: "membership.role_changed",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "user",
      targetId: targetUserId,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { from: target.rows[0]!.role_code, to: body.role },
    });

    const members = await listMemberRows(access.organizationId);
    const row = members.find((member) => member.user_id === targetUserId);
    return jsonResponse({ member: row ? memberToJson(row) : null });
  });
}

export async function handleRemoveMember(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const targetUserId = parseUuidParam(ctx, "userId");
    const access = await requireOrgRole(actor, organizationId, "org:manage_members");

    const target = await query(
      "select 1 from organization_members where organization_id = $1 and user_id = $2",
      [access.organizationId, targetUserId]
    );
    if (target.rows.length === 0) throw errors.notFound("That user is not a member of this organisation.");
    if (targetUserId === actor.user.id) {
      throw errors.conflict("You cannot remove your own membership. Leaving an organisation is not implemented yet.");
    }
    await assertNotLastAdmin(access.organizationId, targetUserId, null);

    await query(
      "delete from organization_members where organization_id = $1 and user_id = $2",
      [access.organizationId, targetUserId]
    );

    await writeAuditLog({
      action: "membership.removed",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "user",
      targetId: targetUserId,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
    });

    return jsonResponse({ ok: true });
  });
}

/** Used by the /app overview to resolve the organisation the UI shows. */
export async function resolveDefaultOrganization(actor: Actor) {
  const memberships = await listMemberships(actor.user.id);
  return memberships[0] ?? null;
}

export async function handleRenameOrganization(ctx: ApiRouteContext): Promise<Response> {
  return withActor(ctx, async (actor) => {
    const organizationId = parseUuidParam(ctx, "id");
    const access = await requireOrgRole(actor, organizationId, "org:update");
    const body = await readJsonBody(ctx.request, createOrganizationSchema.pick({ name: true }));
    const name = organizationNameSchema.parse(body.name);
    await query("update organizations set name = $2, updated_at = now() where id = $1", [
      access.organizationId,
      name,
    ]);
    await writeAuditLog({
      action: "organization.updated",
      organizationId: access.organizationId,
      actorUserId: actor.user.id,
      actorEmail: actor.user.email,
      targetType: "organization",
      targetId: access.organizationId,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { name },
    });
    return jsonResponse({ organization: { id: access.organizationId, name } });
  });
}
