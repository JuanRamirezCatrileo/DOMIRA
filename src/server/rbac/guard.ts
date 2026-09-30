/**
 * The single server-side authorisation layer.
 *
 * Every API handler and every server function resolves the caller through this
 * module: session → user → organisation membership → permission. Rules:
 *
 *  1. `organization_id` is NEVER taken from the client as a fact. The client may
 *     pass it, but it is only ever used to look up the caller's membership; the
 *     stored `organization_members` row is what grants access.
 *  2. A caller who is not a member of the organisation gets 404 NOT_FOUND, not 403,
 *     so IDs cannot be probed for existence.
 *  3. A caller who IS a member but lacks the permission gets 403 FORBIDDEN.
 *  4. State-changing requests authenticated by cookie must pass the CSRF check
 *     (same-origin + session-bound token) before any business logic runs.
 *  5. Platform super admins (`users.is_super_admin`) resolve as SUPER_ADMIN on any
 *     organisation; this is the support/administration path and is documented in
 *     docs/security.md.
 */
import { query, type QueryRunner } from "~/db";
import { errors } from "~/server/http/errors";
import { assertSameOrigin, isUnsafeMethod } from "~/server/http/http";
import {
  assertCsrfToken,
  resolveSession,
  type AuthenticatedUser,
} from "~/server/auth/sessions";
import { isRoleCode, roleHasPermission, type Permission, type RoleCode } from "./permissions";

export interface Actor {
  user: AuthenticatedUser;
  sessionId: string;
  ip: string;
  userAgent: string;
}

export interface OrganizationAccess {
  organizationId: string;
  role: RoleCode;
  membershipId: string | null;
  organization: { id: string; name: string; slug: string; status: string };
}

/**
 * Resolves the caller and enforces CSRF for state-changing methods.
 * Returns null when there is no valid session (public endpoints).
 */
export async function authenticate(
  request: Request,
  context: { ip: string; userAgent: string }
): Promise<Actor | null> {
  if (isUnsafeMethod(request.method)) assertSameOrigin(request);
  const session = await resolveSession(request);
  if (!session) return null;
  if (session.user.status !== "active") {
    throw errors.forbidden("This account is suspended.");
  }
  if (isUnsafeMethod(request.method)) assertCsrfToken(request, session.session);
  return {
    user: session.user,
    sessionId: session.session.sessionId,
    ip: context.ip,
    userAgent: context.userAgent,
  };
}

/** Session or 401. */
export async function requireActor(
  request: Request,
  context: { ip: string; userAgent: string }
): Promise<Actor> {
  const actor = await authenticate(request, context);
  if (!actor) throw errors.unauthenticated();
  return actor;
}

export async function getMembership(
  userId: string,
  organizationId: string,
  runner?: QueryRunner
): Promise<OrganizationAccess | null> {
  const text = `select m.id as membership_id, m.role_code,
                       o.id as organization_id, o.name, o.slug, o.status
                  from organization_members m
                  join organizations o on o.id = m.organization_id
                 where m.organization_id = $1 and m.user_id = $2 and o.deleted_at is null`;
  const params = [organizationId, userId];
  interface Row {
    membership_id: string;
    role_code: string;
    organization_id: string;
    name: string;
    slug: string;
    status: string;
  }
  const result = runner
    ? await runner.query<Row>(text, params)
    : await query<Row>(text, params);
  const row = result.rows[0];
  if (!row || !isRoleCode(row.role_code)) return null;
  return {
    organizationId: row.organization_id,
    role: row.role_code,
    membershipId: row.membership_id,
    organization: { id: row.organization_id, name: row.name, slug: row.slug, status: row.status },
  };
}

/**
 * The guard every organisation-scoped handler must call. `organizationId` is the
 * value the client supplied; it grants nothing by itself.
 */
export async function requireOrgRole(
  actor: Actor,
  organizationId: string,
  permission: Permission
): Promise<OrganizationAccess> {
  const access = await getMembership(actor.user.id, organizationId);
  if (!access) {
    if (!actor.user.isSuperAdmin) {
      // Not a member: pretend the organisation does not exist.
      throw errors.notFound();
    }
    const org = await query<{ id: string; name: string; slug: string; status: string }>(
      "select id, name, slug, status from organizations where id = $1 and deleted_at is null",
      [organizationId]
    );
    const row = org.rows[0];
    if (!row) throw errors.notFound();
    return {
      organizationId: row.id,
      role: "SUPER_ADMIN",
      membershipId: null,
      organization: { id: row.id, name: row.name, slug: row.slug, status: row.status },
    };
  }
  if (!roleHasPermission(access.role, permission)) {
    throw errors.forbidden(`Your role (${access.role}) cannot perform this action.`);
  }
  return access;
}

/** Platform-level administration (SUPER_ADMIN only). */
export function requirePlatformAdmin(actor: Actor): void {
  if (!actor.user.isSuperAdmin) throw errors.forbidden("Platform administrator access is required.");
}

export async function listMemberships(userId: string): Promise<
  Array<{ organizationId: string; name: string; slug: string; role: RoleCode; status: string }>
> {
  const result = await query<{
    organization_id: string;
    name: string;
    slug: string;
    role_code: string;
    status: string;
  }>(
    `select m.organization_id, o.name, o.slug, m.role_code, o.status
       from organization_members m
       join organizations o on o.id = m.organization_id
      where m.user_id = $1 and o.deleted_at is null
      order by o.name asc`,
    [userId]
  );
  return result.rows
    .filter((row) => isRoleCode(row.role_code))
    .map((row) => ({
      organizationId: row.organization_id,
      name: row.name,
      slug: row.slug,
      role: row.role_code as RoleCode,
      status: row.status,
    }));
}
