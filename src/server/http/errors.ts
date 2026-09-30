/**
 * Consistent API error shape: every failure returns
 *   { "error": { "code": "...", "message": "...", "details": {...} } }
 * Messages are written for end users and never disclose whether an account
 * exists, whether a token was ever issued, or any internal detail.
 */
export type ApiErrorCode =
  | "VALIDATION_ERROR"
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "CSRF_FAILED"
  | "METHOD_NOT_ALLOWED"
  | "PAYLOAD_TOO_LARGE"
  | "NOT_IMPLEMENTED"
  | "DATABASE_UNAVAILABLE"
  | "INTERNAL_ERROR";

export class ApiError extends Error {
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly details?: Record<string, unknown>;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    code: ApiErrorCode,
    message: string,
    options: { details?: Record<string, unknown>; headers?: Record<string, string> } = {}
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    if (options.details) this.details = options.details;
    this.headers = options.headers ?? {};
  }
}

export const errors = {
  validation: (details: Record<string, unknown>, message = "The submitted data is not valid.") =>
    new ApiError(400, "VALIDATION_ERROR", message, { details }),
  unauthenticated: (message = "Authentication is required.") =>
    new ApiError(401, "UNAUTHENTICATED", message),
  invalidCredentials: () => new ApiError(401, "UNAUTHENTICATED", "Invalid email or password."),
  forbidden: (message = "You do not have permission to perform this action.") =>
    new ApiError(403, "FORBIDDEN", message),
  csrf: () => new ApiError(403, "CSRF_FAILED", "The request could not be verified. Reload and retry."),
  notFound: (message = "The requested resource was not found.") =>
    new ApiError(404, "NOT_FOUND", message),
  conflict: (message = "That resource already exists.") => new ApiError(409, "CONFLICT", message),
  rateLimited: (retryAfterSeconds: number) =>
    new ApiError(429, "RATE_LIMITED", "Too many attempts. Please wait and try again.", {
      headers: { "retry-after": String(Math.max(1, Math.ceil(retryAfterSeconds))) },
    }),
  payloadTooLarge: () => new ApiError(413, "PAYLOAD_TOO_LARGE", "The request body is too large."),
  methodNotAllowed: (allowed: readonly string[]) =>
    new ApiError(405, "METHOD_NOT_ALLOWED", "That method is not allowed for this endpoint.", {
      headers: { allow: allowed.join(", ") },
    }),
  notImplemented: (feature: string) =>
    new ApiError(501, "NOT_IMPLEMENTED", `${feature} is not implemented yet.`),
  databaseUnavailable: () =>
    new ApiError(503, "DATABASE_UNAVAILABLE", "The service is temporarily unavailable."),
  internal: (message = "Unexpected error.") => new ApiError(500, "INTERNAL_ERROR", message),
};

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}
