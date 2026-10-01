/**
 * Domain ownership verification — the gate that makes DOMIRA an *authorised*
 * monitoring product rather than a scanner anyone can point at any host.
 *
 * The customer proves control of the domain by publishing one DNS TXT record:
 *
 *     _domira-verification.<domain>   TXT   "domira-site-verification=<token>"
 *
 * The token is per (organisation, domain) row in `domain_verifications` and is a
 * public challenge, not a secret — it is meant to be published. Everything else
 * about it is strict:
 *
 *   * one usable token at a time per domain (partial unique index, migration 005);
 *   * tokens expire (`DOMIRA_VERIFICATION_TTL_SECONDS`, default 7 days) and an
 *     expired token can never verify a domain;
 *   * every check is a REAL DNS TXT lookup through the resolver seam in
 *     ./dns.ts — tests inject fixtures, production queries a real resolver;
 *   * failed attempts are counted and, once `DOMIRA_VERIFICATION_MAX_ATTEMPTS`
 *     (default 10) is reached, the token is marked `failed` and a new one must be
 *     issued. That bounds the DNS-query cost a single tenant can cause;
 *   * a domain of organisation A can only ever be verified with a token of
 *     organisation A: the lookup is keyed by (organization_id, domain_id).
 */
import { query, type QueryRunner } from "~/db";
import { generateToken } from "~/server/auth/sessions";
import { verificationTtlSeconds, verificationMaxAttempts } from "~/server/env";
import { getDnsResolver, DnsLookupError } from "./dns";

export const VERIFICATION_RECORD_PREFIX = "_domira-verification.";
export const VERIFICATION_VALUE_PREFIX = "domira-site-verification=";
export const VERIFICATION_METHOD = "dns_txt" as const;

export interface VerificationRow {
  id: string;
  organization_id: string;
  domain_id: string;
  method: string;
  challenge_token: string;
  record_name: string | null;
  record_value: string | null;
  status: "pending" | "verified" | "failed" | "expired";
  attempts: number;
  last_checked_at: Date | string | null;
  verified_at: Date | string | null;
  expires_at: Date | string;
  last_error: string | null;
  evidence: Record<string, unknown>;
  created_at: Date | string;
}

/** The exact TXT record the customer has to publish. */
export function verificationRecord(hostname: string, token: string): {
  recordName: string;
  recordType: "TXT";
  recordValue: string;
} {
  return {
    recordName: `${VERIFICATION_RECORD_PREFIX}${hostname}`,
    recordType: "TXT",
    recordValue: `${VERIFICATION_VALUE_PREFIX}${token}`,
  };
}

function newToken(): string {
  // 32 bytes of CSPRNG entropy, hex encoded — unambiguous in DNS TXT (no case or
  // character-set gotchas) and far beyond guessing.
  return generateToken(32).token;
}

function run<T>(runner: QueryRunner | undefined, text: string, params?: readonly unknown[]) {
  return runner ? runner.query<T>(text, params) : query<T>(text, params);
}

/**
 * Returns the current usable token for a domain, issuing one when there is none,
 * when the token expired or when the attempt limit was exhausted.
 */
export async function ensureVerification(
  organizationId: string,
  domainId: string,
  hostname: string,
  runner?: QueryRunner
): Promise<{ verification: VerificationRow; issued: boolean }> {
  const existing = await run<VerificationRow>(
    runner,
    `select * from domain_verifications
      where organization_id = $1 and domain_id = $2 and status = 'pending'
        and expires_at > now()
      order by created_at desc limit 1`,
    [organizationId, domainId]
  );
  const usable = existing.rows[0];
  if (usable) return { verification: usable, issued: false };

  // Retire anything stale so the partial unique index cannot collide.
  await run(
    runner,
    `update domain_verifications
        set status = case when status = 'pending' then 'expired' else status end,
            updated_at = now()
      where organization_id = $1 and domain_id = $2 and status = 'pending'`,
    [organizationId, domainId]
  );

  const token = newToken();
  const record = verificationRecord(hostname, token);
  const inserted = await run<VerificationRow>(
    runner,
    `insert into domain_verifications
       (organization_id, domain_id, method, challenge_token, record_name, record_value,
        status, expires_at)
     values ($1, $2, $3, $4, $5, $6, 'pending', now() + make_interval(secs => $7::double precision))
     returning *`,
    [
      organizationId,
      domainId,
      VERIFICATION_METHOD,
      token,
      record.recordName,
      record.recordValue,
      verificationTtlSeconds(),
    ]
  );
  return { verification: inserted.rows[0]!, issued: true };
}

export type VerificationFailureReason =
  | "no_token"
  | "token_expired"
  | "attempts_exhausted"
  | "record_not_found"
  | "dns_lookup_failed";

export interface VerificationCheckResult {
  verified: boolean;
  reason: VerificationFailureReason | null;
  attempts: number;
  maxAttempts: number;
  /** TXT values actually observed at the record name — real data, never invented. */
  observedRecords: string[];
  error: string | null;
  verificationId: string;
  expiresAt: string | null;
}

/**
 * Performs the real DNS TXT lookup and updates the verification row.
 * Never trusts anything but the resolver's answer.
 */
export async function checkVerification(
  verification: VerificationRow,
  runner?: QueryRunner
): Promise<VerificationCheckResult> {
  const maxAttempts = verificationMaxAttempts();
  const recordName =
    verification.record_name ??
    `${VERIFICATION_RECORD_PREFIX}${verification.record_value ?? ""}`;
  const expected =
    verification.record_value ?? `${VERIFICATION_VALUE_PREFIX}${verification.challenge_token}`;

  if (new Date(verification.expires_at).getTime() <= Date.now()) {
    await run(
      runner,
      `update domain_verifications set status = 'expired', last_checked_at = now(),
              last_error = $2, updated_at = now() where id = $1`,
      [verification.id, "The verification token expired."]
    );
    return {
      verified: false,
      reason: "token_expired",
      attempts: verification.attempts,
      maxAttempts,
      observedRecords: [],
      error: null,
      verificationId: verification.id,
      expiresAt: new Date(verification.expires_at).toISOString(),
    };
  }

  let observed: string[] = [];
  let lookupError: string | null = null;
  try {
    const answers = await getDnsResolver().query(recordName, "TXT");
    observed = answers.map((answer) => answer.value);
  } catch (error) {
    // A missing record name is a normal "not published yet"; a broken resolver is
    // reported as such and does not consume an attempt.
    const code = (error as { code?: string }).code;
    const missing = code === "ENODATA" || code === "ENOTFOUND" || code === "NXDOMAIN";
    lookupError = error instanceof DnsLookupError ? error.message : String((error as Error).message);
    if (!missing) {
      await run(
        runner,
        `update domain_verifications set last_checked_at = now(), last_error = $2, updated_at = now()
          where id = $1`,
        [verification.id, lookupError]
      );
      return {
        verified: false,
        reason: "dns_lookup_failed",
        attempts: verification.attempts,
        maxAttempts,
        observedRecords: [],
        error: lookupError,
        verificationId: verification.id,
        expiresAt: new Date(verification.expires_at).toISOString(),
      };
    }
    observed = [];
  }

  const token = verification.challenge_token;
  const matched = observed.some((value) => {
    const trimmed = value.trim();
    return (
      trimmed === expected ||
      trimmed === `${VERIFICATION_VALUE_PREFIX}${token}` ||
      // Some DNS providers split long TXT records; accept the token appearing as a
      // whole word inside a concatenated value.
      trimmed.split(/\s+/).includes(`${VERIFICATION_VALUE_PREFIX}${token}`)
    );
  });

  if (matched) {
    await run(
      runner,
      `update domain_verifications
          set status = 'verified', verified_at = now(), last_checked_at = now(),
              attempts = attempts + 1, last_error = null, evidence = $2::jsonb, updated_at = now()
        where id = $1`,
      [verification.id, JSON.stringify({ recordName, observed })]
    );
    return {
      verified: true,
      reason: null,
      attempts: verification.attempts + 1,
      maxAttempts,
      observedRecords: observed,
      error: null,
      verificationId: verification.id,
      expiresAt: new Date(verification.expires_at).toISOString(),
    };
  }

  const attempts = verification.attempts + 1;
  const exhausted = attempts >= maxAttempts;
  await run(
    runner,
    `update domain_verifications
        set attempts = $2, last_checked_at = now(), status = $3, last_error = $4,
            evidence = $5::jsonb, updated_at = now()
      where id = $1`,
    [
      verification.id,
      attempts,
      exhausted ? "failed" : "pending",
      lookupError ?? `No TXT record at ${recordName} matched the DOMIRA token.`,
      JSON.stringify({ recordName, observed }),
    ]
  );
  return {
    verified: false,
    reason: exhausted ? "attempts_exhausted" : "record_not_found",
    attempts,
    maxAttempts,
    observedRecords: observed,
    error: lookupError,
    verificationId: verification.id,
    expiresAt: new Date(verification.expires_at).toISOString(),
  };
}
