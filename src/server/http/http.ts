/**
 * HTTP plumbing shared by every API handler: cookies, client identity, JSON body
 * parsing with strict validation, CSRF origin checks and the security headers
 * applied to every response.
 */
import { ApiError, errors } from "./errors";
import { CSRF_HEADER_NAME, MAX_JSON_BODY_BYTES } from "../env";
import type { ZodType } from "zod";

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

export interface CookieOptions {
  maxAgeSeconds?: number;
  expires?: Date;
  httpOnly?: boolean;
  sameSite?: "Lax" | "Strict" | "None";
  path?: string;
}

export function serializeCookie(
  name: string,
  value: string,
  options: CookieOptions = {}
): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path ?? "/"}`];
  if (options.httpOnly !== false) parts.push("HttpOnly");
  parts.push(`SameSite=${options.sameSite ?? "Lax"}`);
  if (options.maxAgeSeconds !== undefined) parts.push(`Max-Age=${Math.floor(options.maxAgeSeconds)}`);
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
  return parts.join("; ");
}

/** True when this request arrived over HTTPS (through the platform's TLS proxy or directly). */
export function isSecureRequest(request: Request): boolean {
  if (request.headers.get("x-forwarded-proto") === "https") return true;
  try {
    return new URL(request.url).protocol === "https:";
  } catch {
    return false;
  }
}

/** Adds the `Secure` attribute exactly when the request itself is secure. */
export function sessionCookieHeader(
  request: Request,
  name: string,
  value: string,
  maxAgeSeconds: number
): string {
  const cookie = serializeCookie(name, value, { httpOnly: true, maxAgeSeconds });
  return isSecureRequest(request) ? `${cookie}; Secure` : cookie;
}

export function clearedCookieHeader(request: Request, name: string): string {
  const cookie = serializeCookie(name, "", { httpOnly: true, maxAgeSeconds: 0 });
  return isSecureRequest(request) ? `${cookie}; Secure` : cookie;
}

/**
 * Cookie readable by the page's own JavaScript — used only for the CSRF
 * double-submit value, which must be echoable by the client. Never put a session
 * token or any secret in a cookie like this.
 */
export function readableCookieHeader(
  request: Request,
  name: string,
  value: string,
  maxAgeSeconds: number
): string {
  const cookie = serializeCookie(name, value, { httpOnly: false, maxAgeSeconds });
  return isSecureRequest(request) ? `${cookie}; Secure` : cookie;
}

export function clientIp(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]!.trim();
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

export function userAgent(request: Request): string {
  return (request.headers.get("user-agent") ?? "unknown").slice(0, 400);
}

export function isUnsafeMethod(method: string): boolean {
  return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

/**
 * Cross-site request forgery defence, layer one: for any state-changing request
 * that carries an Origin header, the Origin must match the request host. Browsers
 * always send Origin on cross-origin writes, so a forged write from another site
 * is rejected here even before the token check.
 */
export function assertSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (!origin) return;
  let originHost: string;
  try {
    originHost = new URL(origin).host;
  } catch {
    throw errors.csrf();
  }
  const host = request.headers.get("x-forwarded-host") ?? new URL(request.url).host;
  if (originHost !== host) throw errors.csrf();
}

export async function readJsonBody<T>(request: Request, schema: ZodType<T>): Promise<T> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new ApiError(400, "VALIDATION_ERROR", "Content-Type must be application/json.", {
      details: { contentType },
    });
  }
  const raw = await request.text();
  if (raw.length > MAX_JSON_BODY_BYTES) throw errors.payloadTooLarge();
  let parsed: unknown;
  try {
    parsed = raw.length === 0 ? {} : JSON.parse(raw);
  } catch {
    throw new ApiError(400, "VALIDATION_ERROR", "The request body is not valid JSON.");
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    throw errors.validation({
      fields: result.error.issues.map((issue) => ({
        field: issue.path.join(".") || "(root)",
        message: issue.message,
      })),
    });
  }
  return result.data;
}

/** Headers applied to every dynamic response (see docs/security.md). */
export const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=(), payment=()",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  // The UI is server-rendered React with a Tailwind stylesheet; no inline scripts
  // are used by the app itself, so 'unsafe-inline' is limited to styles.
  "content-security-policy": [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data:",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self'",
  ].join("; "),
  "x-domira-csrf-header": CSRF_HEADER_NAME,
};

export function withSecurityHeaders(response: Response): Response {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    if (!response.headers.has(key)) response.headers.set(key, value);
  }
  return response;
}

export function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string | string[]> } = {}
): Response {
  const headers = new Headers();
  for (const [key, value] of Object.entries(init.headers ?? {})) {
    // Arrays become repeated headers — required for multiple Set-Cookie values.
    if (Array.isArray(value)) for (const item of value) headers.append(key, item);
    else headers.set(key, value);
  }
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return withSecurityHeaders(
    new Response(JSON.stringify(body), { status: init.status ?? 200, headers })
  );
}
