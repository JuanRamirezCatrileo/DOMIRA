/**
 * Server-side sessions.
 *
 * Design (see docs/security.md):
 *  - the browser only ever holds an opaque random token in an HttpOnly cookie;
 *  - the database stores the SHA-256 hash of that token, so a database dump does
 *    not yield usable session tokens;
 *  - sessions are rows: they can be listed, revoked individually (logout) or all at
 *    once (password reset revokes every other session);
 *  - the CSRF token is bound to the session row, and its hash is compared in
 *    constant time. State-changing cookie-authenticated requests must send it in
 *    the `x-csrf-token` header;
 *  - expiry is enforced in SQL (`expires_at > now()`), so clock drift in one
 *    process cannot resurrect an expired session.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { query, type QueryRunner } from "~/db";
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME, sessionTtlSeconds } from "~/server/env";
import { ApiError, errors } from "~/server/http/errors";
import { parseCookies } from "~/server/http/http";

export interface SessionRecord {
  sessionId: string;
  userId: string;
  csrfTokenHash: string;
  expiresAt: Date;
}

export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string | null;
  locale: "es" | "en";
  isSuperAdmin: boolean;
  emailVerifiedAt: Date | null;
  status: "active" | "suspended";
}

export interface AuthenticatedSession {
  session: SessionRecord;
  user: AuthenticatedUser;
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function generateToken(bytes = 32): { token: string; hash: string } {
  const token = randomBytes(bytes).toString("base64url");
  return { token, hash: sha256(token) };
}

export function constantTimeEquals(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, "utf8");
  const bufferB = Buffer.from(b, "utf8");
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

export async function createSession(
  input: {
    userId: string;
    ip: string;
    userAgent: string;
  },
  runner?: QueryRunner
): Promise<{ token: string; csrfToken: string; sessionId: string; expiresAt: Date }> {
  const sessionToken = generateToken();
  const csrfToken = generateToken(24);
  const ttl = sessionTtlSeconds();
  const expiresAt = new Date(Date.now() + ttl * 1000);
  const sqlText = `insert into sessions (user_id, token_hash, csrf_token_hash, ip, user_agent, expires_at)
                   values ($1, $2, $3, $4, $5, $6)
                   returning id, expires_at`;
  const params = [
    input.userId,
    sessionToken.hash,
    sha256(csrfToken.token),
    input.ip,
    input.userAgent,
    expiresAt,
  ];
  const result = runner
    ? await runner.query<{ id: string; expires_at: Date | string }>(sqlText, params)
    : await query<{ id: string; expires_at: Date | string }>(sqlText, params);
  const row = result.rows[0]!;
  return {
    token: sessionToken.token,
    csrfToken: csrfToken.token,
    sessionId: row.id,
    expiresAt: new Date(row.expires_at),
  };
}

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  await query(
    "update sessions set revoked_at = now(), revoked_reason = $2 where id = $1 and revoked_at is null",
    [sessionId, reason]
  );
}

export async function revokeAllUserSessions(
  userId: string,
  reason: string,
  exceptSessionId?: string
): Promise<number> {
  const result = await query(
    `update sessions set revoked_at = now(), revoked_reason = $2
     where user_id = $1 and revoked_at is null and ($3::uuid is null or id <> $3::uuid)`,
    [userId, reason, exceptSessionId ?? null]
  );
  return result.rowCount;
}

export function readSessionToken(request: Request): string | null {
  return parseCookies(request.headers.get("cookie"))[SESSION_COOKIE_NAME] ?? null;
}

interface SessionJoinRow {
  session_id: string;
  csrf_token_hash: string;
  expires_at: Date | string;
  user_id: string;
  email: string;
  full_name: string | null;
  locale: "es" | "en";
  is_super_admin: boolean;
  email_verified_at: Date | string | null;
  status: "active" | "suspended";
}

/** Resolves the caller's session, or null when there is no valid session. */
export async function resolveSession(request: Request): Promise<AuthenticatedSession | null> {
  const token = readSessionToken(request);
  if (!token) return null;
  const result = await query<SessionJoinRow>(
    `select s.id as session_id, s.csrf_token_hash, s.expires_at,
            u.id as user_id, u.email, u.full_name, u.locale, u.is_super_admin,
            u.email_verified_at, u.status
     from sessions s
     join users u on u.id = s.user_id
     where s.token_hash = $1 and s.revoked_at is null and s.expires_at > now()`,
    [sha256(token)]
  );
  const row = result.rows[0];
  if (!row) return null;
  await query("update sessions set last_seen_at = now() where id = $1", [row.session_id]);
  return {
    session: {
      sessionId: row.session_id,
      userId: row.user_id,
      csrfTokenHash: row.csrf_token_hash,
      expiresAt: new Date(row.expires_at),
    },
    user: {
      id: row.user_id,
      email: row.email,
      fullName: row.full_name,
      locale: row.locale,
      isSuperAdmin: row.is_super_admin,
      emailVerifiedAt: row.email_verified_at ? new Date(row.email_verified_at) : null,
      status: row.status,
    },
  };
}

/** Session or 401. Never returns partial data. */
export async function requireSession(request: Request): Promise<AuthenticatedSession> {
  const session = await resolveSession(request);
  if (!session) throw errors.unauthenticated();
  if (session.user.status !== "active") {
    throw new ApiError(403, "FORBIDDEN", "This account is suspended.");
  }
  return session;
}

/**
 * CSRF, layer two: double submit.
 *
 *  - `domira_csrf` is a readable cookie holding the CSRF token; the page's own
 *    JavaScript echoes it back in the `x-csrf-token` header.
 *  - The session row stores the token's SHA-256 hash, so the value must match BOTH
 *    the cookie/header pair and the session row.
 *  - A cross-site attacker can neither read the cookie (same-origin policy) nor
 *    guess the header, and SameSite=Lax already blocks the cookie on cross-site
 *    form posts. Three independent barriers for every state-changing request.
 */
export function assertCsrfToken(request: Request, session: SessionRecord): void {
  const cookies = parseCookies(request.headers.get("cookie"));
  const cookieToken = cookies[CSRF_COOKIE_NAME];
  const headerToken = request.headers.get(CSRF_HEADER_NAME);
  if (!cookieToken || !headerToken) throw errors.csrf();
  if (!constantTimeEquals(cookieToken, headerToken)) throw errors.csrf();
  if (!constantTimeEquals(sha256(cookieToken), session.csrfTokenHash)) throw errors.csrf();
}
