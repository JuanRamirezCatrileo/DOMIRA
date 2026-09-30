/**
 * E-mail verification and password-reset tokens: hashed at rest, single-use,
 * expiring, and bound to the account and address they were issued for.
 *
 * IMPORTANT (documented, not hidden): DOMIRA has no e-mail integration. Nothing is
 * sent. Every message that would have been e-mailed is written to `outbox_messages`
 * as 'pending' and can be read by a platform administrator through
 * GET /api/admin/outbox; the link is also written to the server log. This is the
 * temporary, honest substitute for e-mail delivery until the business has an
 * e-mail provider.
 */
import { createHash } from "node:crypto";

import { query, type QueryRunner } from "~/db";
import { emailVerificationTtlSeconds, passwordResetTtlSeconds, publicBaseUrl } from "~/server/env";
import { ApiError } from "~/server/http/errors";
import { generateToken } from "./sessions";

export interface IssuedToken {
  token: string;
  expiresAt: Date;
}

const INVALID_TOKEN_MESSAGE = "This link is invalid or has expired. Request a new one.";

async function insertOutbox(
  runner: QueryRunner | undefined,
  entry: {
    userId: string;
    kind: "email_verification" | "password_reset";
    toEmail: string;
    subject: string;
    body: string;
    actionUrl: string;
  }
): Promise<void> {
  const text = `insert into outbox_messages (user_id, kind, to_email, subject, body, action_url)
                values ($1, $2, $3, $4, $5, $6)`;
  const params = [
    entry.userId,
    entry.kind,
    entry.toEmail,
    entry.subject,
    entry.body,
    entry.actionUrl,
  ];
  if (runner) await runner.query(text, params);
  else await query(text, params);
}

export async function issueEmailVerificationToken(
  request: Request,
  userId: string,
  email: string,
  runner?: QueryRunner
): Promise<IssuedToken> {
  const { token, hash } = generateToken();
  const expiresAt = new Date(Date.now() + emailVerificationTtlSeconds() * 1000);
  const insert = `insert into email_verification_tokens (user_id, email, token_hash, expires_at)
                  values ($1, $2, $3, $4)`;
  const params = [userId, email, hash, expiresAt];
  if (runner) await runner.query(insert, params);
  else await query(insert, params);

  const actionUrl = `${publicBaseUrl(request)}/verify-email?token=${token}`;
  await insertOutbox(runner, {
    userId,
    kind: "email_verification",
    toEmail: email,
    subject: "Verify your DOMIRA account",
    body:
      `Confirm the e-mail address for your DOMIRA account.\n\n${actionUrl}\n\n` +
      `This link expires in ${Math.round(emailVerificationTtlSeconds() / 3600)} hours.`,
    actionUrl,
  });
  // No e-mail provider is connected; the link is logged so an operator can use it.
  console.info(`[domira] e-mail verification link (no e-mail sent): ${actionUrl}`);
  return { token, expiresAt };
}

export async function issuePasswordResetToken(
  request: Request,
  userId: string,
  email: string
): Promise<IssuedToken> {
  const { token, hash } = generateToken();
  const expiresAt = new Date(Date.now() + passwordResetTtlSeconds() * 1000);
  await query(
    `insert into password_reset_tokens (user_id, token_hash, expires_at) values ($1, $2, $3)`,
    [userId, hash, expiresAt]
  );
  const actionUrl = `${publicBaseUrl(request)}/reset-password?token=${token}`;
  await insertOutbox(undefined, {
    userId,
    kind: "password_reset",
    toEmail: email,
    subject: "Reset your DOMIRA password",
    body:
      `A password reset was requested for your DOMIRA account.\n\n${actionUrl}\n\n` +
      `This link expires in ${Math.round(passwordResetTtlSeconds() / 60)} minutes. ` +
      "If you did not request it, ignore this message.",
    actionUrl,
  });
  console.info(`[domira] password reset link (no e-mail sent): ${actionUrl}`);
  return { token, expiresAt };
}

/**
 * Consumes an e-mail verification token. The UPDATE ... WHERE used_at IS NULL
 * makes the operation atomic and single-use: a second call finds no row.
 */
export async function consumeEmailVerificationToken(token: string): Promise<{
  userId: string;
  email: string;
}> {
  const result = await query<{ user_id: string; email: string }>(
    `update email_verification_tokens
        set used_at = now(), attempts = attempts + 1
      where token_hash = $1 and used_at is null and expires_at > now()
      returning user_id, email`,
    [generateTokenHash(token)]
  );
  const row = result.rows[0];
  if (!row) throw new ApiError(400, "VALIDATION_ERROR", INVALID_TOKEN_MESSAGE);
  await query(
    "update users set email_verified_at = coalesce(email_verified_at, now()), updated_at = now() where id = $1",
    [row.user_id]
  );
  return { userId: row.user_id, email: row.email };
}

export async function consumePasswordResetToken(token: string): Promise<{ userId: string }> {
  const result = await query<{ user_id: string }>(
    `update password_reset_tokens
        set used_at = now(), attempts = attempts + 1
      where token_hash = $1 and used_at is null and expires_at > now()
      returning user_id`,
    [generateTokenHash(token)]
  );
  const row = result.rows[0];
  if (!row) throw new ApiError(400, "VALIDATION_ERROR", INVALID_TOKEN_MESSAGE);
  return { userId: row.user_id };
}

/** Marks an unused token as consumed (used when a token is deliberately invalidated). */
export async function invalidatePasswordResetTokens(userId: string): Promise<void> {
  await query(
    "update password_reset_tokens set used_at = now() where user_id = $1 and used_at is null",
    [userId]
  );
}

export function invalidTokenError(): ApiError {
  return new ApiError(400, "VALIDATION_ERROR", INVALID_TOKEN_MESSAGE);
}

/** Local hash helper so callers only ever pass the raw token around. */
function generateTokenHash(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
