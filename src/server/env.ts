/**
 * Runtime configuration. Everything comes from process.env — never from a .env
 * file (a value that only lives in a .env is missing on the published site) and
 * never hardcoded. Values are read at call time so tests and scripts can adjust
 * them per run.
 */

function intFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export const SESSION_COOKIE_NAME = process.env.DOMIRA_SESSION_COOKIE ?? "domira_session";
export const CSRF_COOKIE_NAME = process.env.DOMIRA_CSRF_COOKIE ?? "domira_csrf";
export const LOCALE_COOKIE_NAME = "domira_locale";
export const CSRF_HEADER_NAME = "x-csrf-token";

export function sessionTtlSeconds(): number {
  return intFromEnv("DOMIRA_SESSION_TTL_SECONDS", 60 * 60 * 24 * 7);
}

export function sessionIdleRefreshSeconds(): number {
  return 300;
}

export function emailVerificationTtlSeconds(): number {
  return intFromEnv("DOMIRA_EMAIL_TOKEN_TTL_SECONDS", 60 * 60 * 24);
}

export function passwordResetTtlSeconds(): number {
  return intFromEnv("DOMIRA_RESET_TOKEN_TTL_SECONDS", 60 * 60);
}

/** Maximum accepted JSON body size for API requests, in bytes. */
export const MAX_JSON_BODY_BYTES = 64 * 1024;

/** True when the app is running in the managed/published environment. */
export function isProduction(): boolean {
  return process.env.NODE_ENV === "production";
}

/** Absolute base URL used to build the links shown for token flows. */
export function publicBaseUrl(request: Request): string {
  const configured = process.env.DOMIRA_PUBLIC_URL;
  if (configured) return configured.replace(/\/+$/, "");
  const url = new URL(request.url);
  const forwardedHost = request.headers.get("x-forwarded-host");
  const forwardedProto = request.headers.get("x-forwarded-proto");
  const host = forwardedHost ?? url.host;
  const scheme = forwardedProto ?? url.protocol.replace(":", "");
  return `${scheme}://${host}`;
}

/* -------------------------------------------------------------------------- */
/* Passive scanner, job queue and scheduler (deliverable 2a)                  */
/*                                                                            */
/* Every value below is configurable by environment variable and documented in */
/* docs/deployment.md. Defaults are the values this build was verified with.   */
/* -------------------------------------------------------------------------- */

function envFlag(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  return !["0", "false", "no", "off"].includes(raw.toLowerCase());
}

/** TCP/TLS handshake budget for the certificate check. */
export function tlsTimeoutMs(): number {
  return intFromEnv("DOMIRA_TLS_TIMEOUT_MS", 10000);
}

/** Budget for one DNS query (DoH over HTTPS or the system resolver). */
export function dnsTimeoutMs(): number {
  return intFromEnv("DOMIRA_DNS_TIMEOUT_MS", 5000);
}

/** Budget for the HTTPS availability request and the plain-HTTP redirect probe. */
export function httpTimeoutMs(): number {
  return intFromEnv("DOMIRA_HTTP_TIMEOUT_MS", 10000);
}

export function httpMaxRedirects(): number {
  return intFromEnv("DOMIRA_HTTP_MAX_REDIRECTS", 5);
}

/** User-Agent every DOMIRA check sends, so operators can recognise and allow it. */
export function scannerUserAgent(): string {
  return (
    process.env.DOMIRA_SCANNER_USER_AGENT ??
    "DOMIRA-Monitor/1.0 (+https://domira.cl; passive security monitoring; contact: security@domira.cl)"
  );
}

/** How many jobs one worker process runs at the same time. */
export function workerConcurrency(): number {
  return intFromEnv("DOMIRA_WORKER_CONCURRENCY", 2);
}

/** How often an idle worker looks for work. */
export function workerPollIntervalMs(): number {
  return intFromEnv("DOMIRA_WORKER_POLL_INTERVAL_MS", 2000);
}

/** How often the scheduler looks for domains whose next scan is due. */
export function schedulerIntervalSeconds(): number {
  return intFromEnv("DOMIRA_SCHEDULER_INTERVAL_SECONDS", 60);
}

/**
 * A job whose worker stopped sending heartbeats is considered dead after this many
 * seconds and is reclaimed (see docs/scanning.md). Must be comfortably larger than
 * the slowest scan (TLS + DNS + HTTP timeouts).
 */
export function jobStaleSeconds(): number {
  return intFromEnv("DOMIRA_JOB_STALE_SECONDS", 300);
}

export function jobMaxAttempts(): number {
  return intFromEnv("DOMIRA_JOB_MAX_ATTEMPTS", 3);
}

/** Base of the exponential backoff between retries (attempt n waits base * 2^n). */
export function jobRetryBackoffSeconds(): number {
  return intFromEnv("DOMIRA_JOB_RETRY_BACKOFF_SECONDS", 30);
}

/**
 * Whether the app runs the worker loop inside its own process. Enabled by default
 * so the published site scans without a second process; real deployments should set
 * DOMIRA_INPROCESS_WORKER=false and run `bun run worker` instead
 * (docs/deployment.md).
 */
export function inProcessWorkerEnabled(): boolean {
  if (process.env.DOMIRA_DISABLE_WORKER === "1") return false;
  return envFlag("DOMIRA_INPROCESS_WORKER", true);
}

/** Domain ownership verification token lifetime. */
export function verificationTtlSeconds(): number {
  return intFromEnv("DOMIRA_VERIFICATION_TTL_SECONDS", 60 * 60 * 24 * 7);
}

/** Failed TXT verification attempts allowed before a new token must be issued. */
export function verificationMaxAttempts(): number {
  return intFromEnv("DOMIRA_VERIFICATION_MAX_ATTEMPTS", 10);
}

/** Abuse protection: scans an organisation may request per hour (all its domains). */
export function scanQuotaPerOrgPerHour(): number {
  return intFromEnv("DOMIRA_SCAN_QUOTA_PER_ORG_PER_HOUR", 60);
}

/** Abuse protection: scans one domain may receive per hour. */
export function scanQuotaPerDomainPerHour(): number {
  return intFromEnv("DOMIRA_SCAN_QUOTA_PER_DOMAIN_PER_HOUR", 12);
}

/** Abuse protection: domains one organisation may create per hour. */
export function domainCreateQuotaPerOrgPerHour(): number {
  return intFromEnv("DOMIRA_DOMAIN_CREATE_QUOTA_PER_ORG_PER_HOUR", 30);
}

/** Consecutive failed scans before a domain is moved to status 'error'. */
export function domainFailureThreshold(): number {
  return intFromEnv("DOMIRA_DOMAIN_FAILURE_THRESHOLD", 3);
}
