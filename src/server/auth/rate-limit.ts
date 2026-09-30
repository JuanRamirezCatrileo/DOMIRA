/**
 * Database-backed rate limiting (fixed window, atomic upsert).
 *
 * Counters live in Postgres so the limit is shared by every process, worker and
 * replica — an in-memory limiter would reset on deploy and would not compose with
 * the queue workers that arrive in deliverable 2.
 */
import { query } from "~/db";
import { errors } from "~/server/http/errors";

export interface RateLimitRule {
  limit: number;
  windowSeconds: number;
}

export const RATE_LIMITS = {
  register: { limit: 5, windowSeconds: 3600 },
  login: { limit: 10, windowSeconds: 900 },
  loginPerEmail: { limit: 5, windowSeconds: 900 },
  forgotPassword: { limit: 5, windowSeconds: 900 },
  resetPassword: { limit: 10, windowSeconds: 900 },
  verifyEmail: { limit: 20, windowSeconds: 900 },
  authenticatedWrite: { limit: 120, windowSeconds: 60 },
} as const satisfies Record<string, RateLimitRule>;

export interface RateLimitResult {
  count: number;
  limit: number;
  retryAfterSeconds: number;
}

/**
 * Counts one hit against `bucket` and throws 429 when the rule is exceeded.
 * `bucket` must already include the caller identity (ip, e-mail, user id).
 */
export async function enforceRateLimit(
  bucket: string,
  rule: RateLimitRule
): Promise<RateLimitResult> {
  const key = `${bucket}|${rule.windowSeconds}s|${rule.limit}`;
  const result = await query<{ count: number; expires_at: Date | string }>(
    `insert into rate_limits (key, window_started_at, count, expires_at, updated_at)
     values ($1, now(), 1, now() + make_interval(secs => $2::double precision), now())
     on conflict (key) do update set
       count = case when rate_limits.expires_at <= now() then 1 else rate_limits.count + 1 end,
       window_started_at = case when rate_limits.expires_at <= now() then now() else rate_limits.window_started_at end,
       expires_at = case when rate_limits.expires_at <= now()
                         then now() + make_interval(secs => $2::double precision)
                         else rate_limits.expires_at end,
       updated_at = now()
     returning count, expires_at`,
    [key, rule.windowSeconds]
  );
  const row = result.rows[0]!;
  const retryAfterSeconds = Math.max(0, (new Date(row.expires_at).getTime() - Date.now()) / 1000);
  if (Number(row.count) > rule.limit) throw errors.rateLimited(retryAfterSeconds);

  if (Number(row.count) === 1) {
    // Opportunistic cleanup of stale windows; cheap because it only runs when a
    // fresh window is opened.
    await query("delete from rate_limits where expires_at < now() - interval '1 day'");
  }
  return { count: Number(row.count), limit: rule.limit, retryAfterSeconds };
}
