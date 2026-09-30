/**
 * Browser-side API client for the DOMIRA REST API v1.
 *
 * - Same-origin fetch, cookies included (`credentials: "same-origin"`).
 * - State-changing requests echo the CSRF token from the readable `domira_csrf`
 *   cookie into the `x-csrf-token` header (double submit; see docs/security.md).
 * - Errors are mapped to a friendly i18n key, and the raw code is kept for the UI.
 */
export interface ApiFailure {
  status: number;
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export class ApiClientError extends Error {
  readonly failure: ApiFailure;
  constructor(failure: ApiFailure) {
    super(failure.message);
    this.name = "ApiClientError";
    this.failure = failure;
  }
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]!) : null;
}

export async function apiRequest<T = unknown>(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET") {
    const csrf = readCookie("domira_csrf");
    if (csrf) headers["x-csrf-token"] = csrf;
  }
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  const parsed = text.length > 0 ? JSON.parse(text) : null;
  if (!response.ok) {
    const error = parsed?.error ?? {};
    throw new ApiClientError({
      status: response.status,
      code: error.code ?? "INTERNAL_ERROR",
      message: error.message ?? "Unexpected error.",
      ...(error.details ? { details: error.details } : {}),
    });
  }
  return parsed as T;
}
