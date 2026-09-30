/**
 * Authentication endpoints: register, login, logout, e-mail verification and
 * password reset. Behaviour that is not obvious:
 *
 *  - Failed logins are indistinguishable from unknown accounts: same status, same
 *    message, and the same password-verification cost (see burnPasswordTime).
 *  - A successful login mints a fresh session row; logout revokes exactly that row.
 *  - Password reset revokes every existing session of the account.
 *  - No e-mail is sent anywhere (there is no e-mail integration). The verification
 *    and reset links are written to the outbox and logged; the verification token is
 *    also returned to the account's own owner right after signup so a human can
 *    complete the flow. Both facts are stated in the UI and in docs/security.md.
 */
import { query, transaction } from "~/db";
import { writeAuditLog } from "~/server/audit";
import { burnPasswordTime, hashPassword, verifyPassword } from "~/server/auth/passwords";
import { RATE_LIMITS, enforceRateLimit } from "~/server/auth/rate-limit";
import {
  createSession,
  revokeAllUserSessions,
  revokeSession,
} from "~/server/auth/sessions";
import {
  consumeEmailVerificationToken,
  consumePasswordResetToken,
  issueEmailVerificationToken,
  issuePasswordResetToken,
} from "~/server/auth/tokens";
import { SESSION_COOKIE_NAME, CSRF_COOKIE_NAME, sessionTtlSeconds } from "~/server/env";
import { errors } from "~/server/http/errors";
import {
  clearedCookieHeader,
  jsonResponse,
  readJsonBody,
  readableCookieHeader,
  sessionCookieHeader,
} from "~/server/http/http";
import { listMemberships, requireActor } from "~/server/rbac/guard";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
  verifyEmailSchema,
} from "~/server/validation";
import type { ApiRouteContext } from "./types";
import { publicUser } from "./types";

/** Session cookie (HttpOnly) + CSRF double-submit cookie (readable by the page). */
function authCookies(
  request: Request,
  token: string,
  csrfToken: string
): Record<string, string[]> {
  const ttl = sessionTtlSeconds();
  return {
    "set-cookie": [
      sessionCookieHeader(request, SESSION_COOKIE_NAME, token, ttl),
      readableCookieHeader(request, CSRF_COOKIE_NAME, csrfToken, ttl),
    ],
  };
}

function slugify(name: string): string {
  const base = name
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return base.length >= 2 ? base : "organization";
}

async function uniqueSlug(name: string): Promise<string> {
  const base = slugify(name);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const candidate = attempt === 0 ? base : `${base}-${generateToken(3).token.slice(0, 4).toLowerCase().replace(/[^a-z0-9]/g, "0")}`;
    const existing = await query("select 1 from organizations where slug = $1", [candidate]);
    if (existing.rows.length === 0) return candidate;
  }
  return `${base}-${Date.now().toString(36)}`;
}

export async function handleRegister(ctx: ApiRouteContext): Promise<Response> {
  const body = await readJsonBody(ctx.request, registerSchema);
  await enforceRateLimit(`register|ip:${ctx.ip}`, RATE_LIMITS.register);

  const existing = await query("select 1 from users where lower(email) = $1", [body.email]);
  if (existing.rows.length > 0) {
    await writeAuditLog({
      action: "user.register.failed",
      actorEmail: body.email,
      outcome: "failure",
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { reason: "email_taken" },
    });
    throw errors.conflict("An account with that e-mail address already exists.");
  }

  const passwordHash = await hashPassword(body.password);
  const organization = body.organizationName
    ? { name: body.organizationName, slug: await uniqueSlug(body.organizationName) }
    : null;

  const created = await transaction(async (tx) => {
    const userResult = await tx.query<{
      id: string;
      email: string;
      full_name: string | null;
      locale: "es" | "en";
      is_super_admin: boolean;
      email_verified_at: Date | null;
      created_at: Date;
    }>(
      `insert into users (email, password_hash, full_name, locale)
       values ($1, $2, $3, $4)
       returning id, email, full_name, locale, is_super_admin, email_verified_at, created_at`,
      [body.email, passwordHash, body.fullName ?? null, body.locale ?? "es"]
    );
    const user = userResult.rows[0]!;

    let organizationRow: { id: string; name: string; slug: string } | null = null;
    if (organization) {
      const orgResult = await tx.query<{ id: string; name: string; slug: string }>(
        `insert into organizations (name, slug, created_by) values ($1, $2, $3)
         returning id, name, slug`,
        [organization.name, organization.slug, user.id]
      );
      organizationRow = orgResult.rows[0]!;
      await tx.query(
        `insert into organization_members (organization_id, user_id, role_code) values ($1, $2, 'ADMIN')`,
        [organizationRow.id, user.id]
      );
      // Plan bookkeeping only: no payment provider is connected, so every
      // organisation starts on FREE and no billing feature exists yet.
      await tx.query(
        `insert into subscriptions (organization_id, plan_code, status) values ($1, 'FREE', 'active')`,
        [organizationRow.id]
      );
    }
    return { user, organization: organizationRow };
  });

  const verification = await issueEmailVerificationToken(
    ctx.request,
    created.user.id,
    created.user.email
  );
  const session = await createSession({
    userId: created.user.id,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });

  await writeAuditLog({
    action: "user.register",
    organizationId: created.organization?.id ?? null,
    actorUserId: created.user.id,
    actorEmail: created.user.email,
    targetType: "user",
    targetId: created.user.id,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
    metadata: { organizationCreated: Boolean(created.organization) },
  });
  if (created.organization) {
    await writeAuditLog({
      action: "organization.created",
      organizationId: created.organization.id,
      actorUserId: created.user.id,
      actorEmail: created.user.email,
      targetType: "organization",
      targetId: created.organization.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
    });
  }

  return jsonResponse(
    {
      user: publicUser(created.user),
      organization: created.organization,
      membership: created.organization ? { role: "ADMIN" } : null,
      csrfToken: session.csrfToken,
      emailVerification: {
        emailSent: false,
        // No e-mail integration exists: the link is returned to the account owner
        // (and logged, and stored in the admin outbox) so the flow is usable.
        link: `/verify-email?token=${verification.token}`,
        token: verification.token,
        expiresAt: verification.expiresAt.toISOString(),
      },
    },
    {
      status: 201,
      headers: authCookies(ctx.request, session.token, session.csrfToken),
    }
  );
}

export async function handleLogin(ctx: ApiRouteContext): Promise<Response> {
  const body = await readJsonBody(ctx.request, loginSchema);
  await enforceRateLimit(`login|ip:${ctx.ip}`, RATE_LIMITS.login);
  await enforceRateLimit(`login|email:${body.email}`, RATE_LIMITS.loginPerEmail);

  const result = await query<{
    id: string;
    email: string;
    password_hash: string;
    full_name: string | null;
    locale: "es" | "en";
    is_super_admin: boolean;
    email_verified_at: Date | null;
    status: "active" | "suspended";
    failed_login_count: number;
    locked_until: Date | null;
    created_at: Date;
  }>(
    `select id, email, password_hash, full_name, locale, is_super_admin, email_verified_at,
            status, failed_login_count, locked_until, created_at
       from users where lower(email) = $1`,
    [body.email]
  );
  const user = result.rows[0];

  const locked = user?.locked_until ? new Date(user.locked_until).getTime() > Date.now() : false;
  const passwordOk = user && !locked ? await verifyPassword(user.password_hash, body.password) : false;

  if (!user || locked || !passwordOk || user.status !== "active") {
    if (user && !locked && user.status === "active" && !passwordOk) {
      const failures = user.failed_login_count + 1;
      await query(
        `update users set failed_login_count = $2,
                locked_until = case when $2 >= 10 then now() + interval '15 minutes' else locked_until end,
                updated_at = now()
          where id = $1`,
        [user.id, failures]
      );
    }
    if (!user) {
      // Equalise timing so an unknown address costs the same as a known one.
      await burnPasswordTime(body.password);
    }
    await writeAuditLog({
      action: "user.login.failed",
      actorUserId: user?.id ?? null,
      actorEmail: body.email,
      outcome: "failure",
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata: { reason: !user ? "unknown_account" : locked ? "locked" : "bad_credentials" },
    });
    throw errors.invalidCredentials();
  }

  await query(
    `update users set failed_login_count = 0, locked_until = null, last_login_at = now(), updated_at = now()
      where id = $1`,
    [user.id]
  );
  const session = await createSession({ userId: user.id, ip: ctx.ip, userAgent: ctx.userAgent });
  const memberships = await listMemberships(user.id);

  await writeAuditLog({
    action: "user.login",
    actorUserId: user.id,
    actorEmail: user.email,
    targetType: "session",
    targetId: session.sessionId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });

  return jsonResponse(
    { user: publicUser(user), memberships, csrfToken: session.csrfToken },
    { headers: authCookies(ctx.request, session.token, session.csrfToken) }
  );
}

export async function handleLogout(ctx: ApiRouteContext): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  await revokeSession(actor.sessionId, "user_logout");
  await writeAuditLog({
    action: "user.logout",
    actorUserId: actor.user.id,
    actorEmail: actor.user.email,
    targetType: "session",
    targetId: actor.sessionId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });
  return jsonResponse({ ok: true }, {
    headers: {
      "set-cookie": [
        clearedCookieHeader(ctx.request, SESSION_COOKIE_NAME),
        readableCookieHeader(ctx.request, CSRF_COOKIE_NAME, "", 0),
      ],
    },
  });
}

export async function handleVerifyEmail(ctx: ApiRouteContext): Promise<Response> {
  const body = await readJsonBody(ctx.request, verifyEmailSchema);
  await enforceRateLimit(`verify-email|ip:${ctx.ip}`, RATE_LIMITS.verifyEmail);
  const { userId, email } = await consumeEmailVerificationToken(body.token);
  await writeAuditLog({
    action: "user.email_verified",
    actorUserId: userId,
    actorEmail: email,
    targetType: "user",
    targetId: userId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });
  return jsonResponse({ verified: true, email });
}

export async function handleForgotPassword(ctx: ApiRouteContext): Promise<Response> {
  const body = await readJsonBody(ctx.request, forgotPasswordSchema);
  await enforceRateLimit(`forgot-password|ip:${ctx.ip}`, RATE_LIMITS.forgotPassword);
  await enforceRateLimit(`forgot-password|email:${body.email}`, RATE_LIMITS.forgotPassword);

  const result = await query<{ id: string; email: string; status: string }>(
    "select id, email, status from users where lower(email) = $1",
    [body.email]
  );
  const user = result.rows[0];
  if (user && user.status === "active") {
    await issuePasswordResetToken(ctx.request, user.id, user.email);
    await writeAuditLog({
      action: "user.password_reset_requested",
      actorUserId: user.id,
      actorEmail: user.email,
      targetType: "user",
      targetId: user.id,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
    });
  }

  // Always the same answer, whether or not the account exists.
  return jsonResponse(
    {
      message:
        "If that account exists, a password reset link has been generated. DOMIRA cannot send e-mail yet, " +
        "so a platform administrator retrieves the link from the internal outbox.",
      emailSent: false,
    },
    { status: 202 }
  );
}

export async function handleResetPassword(ctx: ApiRouteContext): Promise<Response> {
  const body = await readJsonBody(ctx.request, resetPasswordSchema);
  await enforceRateLimit(`reset-password|ip:${ctx.ip}`, RATE_LIMITS.resetPassword);

  const { userId } = await consumePasswordResetToken(body.token);
  const passwordHash = await hashPassword(body.password);
  await query(
    "update users set password_hash = $2, failed_login_count = 0, locked_until = null, updated_at = now() where id = $1",
    [userId, passwordHash]
  );
  await revokeAllUserSessions(userId, "password_reset");
  await writeAuditLog({
    action: "user.password_reset_completed",
    actorUserId: userId,
    targetType: "user",
    targetId: userId,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
  });
  return jsonResponse({ ok: true, sessionsRevoked: true });
}

export async function handleMe(ctx: ApiRouteContext): Promise<Response> {
  const actor = await requireActor(ctx.request, { ip: ctx.ip, userAgent: ctx.userAgent });
  const memberships = await listMemberships(actor.user.id);
  // The CSRF token itself lives in the readable `domira_csrf` cookie; only its
  // hash is stored server-side (see assertCsrfToken).
  return jsonResponse({
    user: publicUser(actor.user),
    memberships,
    sessionId: actor.sessionId,
  });
}
