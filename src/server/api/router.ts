/**
 * The REST API v1 router (mounted under /api).
 *
 * One table describes the whole surface, so it doubles as the API index served at
 * GET /api (docs/api.md is generated from the same list). Every route goes through
 * the same wrapper, which is what makes the error shape, the security headers and
 * the request context consistent everywhere.
 *
 * Request flow:
 *   route file (src/routes/api/**) -> dispatchApi -> handler -> guard (rbac) -> SQL
 */
import { DatabaseNotConfiguredError } from "~/db";
import { ApiError, errors, isApiError } from "~/server/http/errors";
import { clientIp, jsonResponse, userAgent, withSecurityHeaders } from "~/server/http/http";
import { handleAdminAudit, handleAdminOutbox, handleAlertsNotImplemented, handleCertificatesNotImplemented, handleDomainVerificationNotImplemented, handleDomainsNotImplemented, handleFindingsNotImplemented, handleReportsNotImplemented, handleScansNotImplemented } from "./admin-handlers";
import {
  handleForgotPassword,
  handleLogin,
  handleLogout,
  handleMe,
  handleRegister,
  handleResetPassword,
  handleVerifyEmail,
} from "./auth-handlers";
import {
  handleAddMember,
  handleCreateOrganization,
  handleGetOrganization,
  handleListMembers,
  handleListOrganizations,
  handleRemoveMember,
  handleRenameOrganization,
  handleUpdateMember,
} from "./organization-handlers";
import type { ApiRoute, ApiRouteContext } from "./types";

export const API_ROUTES: ApiRoute[] = [
  {
    method: "POST",
    path: "/api/auth/register",
    summary: "Create an account (and optionally its first organisation).",
    implemented: true,
    handler: handleRegister,
  },
  {
    method: "POST",
    path: "/api/auth/login",
    summary: "Start a session; sets the session and CSRF cookies.",
    implemented: true,
    handler: handleLogin,
  },
  {
    method: "POST",
    path: "/api/auth/logout",
    summary: "Revoke the current session and clear the cookies.",
    implemented: true,
    handler: handleLogout,
  },
  {
    method: "POST",
    path: "/api/auth/verify-email",
    summary: "Consume a single-use e-mail verification token.",
    implemented: true,
    handler: handleVerifyEmail,
  },
  {
    method: "POST",
    path: "/api/auth/forgot-password",
    summary: "Generate a password reset link (no e-mail is sent; see docs/security.md).",
    implemented: true,
    handler: handleForgotPassword,
  },
  {
    method: "POST",
    path: "/api/auth/reset-password",
    summary: "Consume a reset token, set a new password and revoke all sessions.",
    implemented: true,
    handler: handleResetPassword,
  },
  {
    method: "GET",
    path: "/api/me",
    summary: "The authenticated user and their organisation memberships.",
    implemented: true,
    handler: handleMe,
  },
  {
    method: "GET",
    path: "/api/organizations",
    summary: "Organisations the caller is a member of.",
    implemented: true,
    handler: handleListOrganizations,
  },
  {
    method: "POST",
    path: "/api/organizations",
    summary: "Create an organisation; the creator becomes its ADMIN.",
    implemented: true,
    handler: handleCreateOrganization,
  },
  {
    method: "GET",
    path: "/api/organizations/:id",
    summary: "Organisation overview: name, caller role, permissions and real counts.",
    implemented: true,
    handler: handleGetOrganization,
  },
  {
    method: "PATCH",
    path: "/api/organizations/:id",
    summary: "Rename an organisation (requires org:update).",
    implemented: true,
    handler: handleRenameOrganization,
  },
  {
    method: "GET",
    path: "/api/organizations/:id/members",
    summary: "List members with their roles.",
    implemented: true,
    handler: handleListMembers,
  },
  {
    method: "POST",
    path: "/api/organizations/:id/members",
    summary: "Add an existing account to the organisation (requires org:manage_members).",
    implemented: true,
    handler: handleAddMember,
  },
  {
    method: "PATCH",
    path: "/api/organizations/:id/members/:userId",
    summary: "Change a member's role.",
    implemented: true,
    handler: handleUpdateMember,
  },
  {
    method: "DELETE",
    path: "/api/organizations/:id/members/:userId",
    summary: "Remove a member from the organisation.",
    implemented: true,
    handler: handleRemoveMember,
  },
  {
    method: "GET",
    path: "/api/admin/outbox",
    summary: "Platform admins: pending account e-mails (verification / reset links).",
    implemented: true,
    handler: handleAdminOutbox,
  },
  {
    method: "GET",
    path: "/api/admin/audit",
    summary: "Platform admins: recent audit log entries.",
    implemented: true,
    handler: handleAdminAudit,
  },
  // ---- Declared but NOT implemented (answer 501, never fake data) -------------
  {
    method: "GET",
    path: "/api/domains",
    summary: "List monitored domains — deliverable 2.",
    implemented: false,
    handler: handleDomainsNotImplemented,
  },
  {
    method: "POST",
    path: "/api/domains",
    summary: "Add a domain — deliverable 2.",
    implemented: false,
    handler: handleDomainsNotImplemented,
  },
  {
    method: "POST",
    path: "/api/domains/:id/verify",
    summary: "Verify domain ownership — deliverable 2.",
    implemented: false,
    handler: handleDomainVerificationNotImplemented,
  },
  {
    method: "GET",
    path: "/api/scans",
    summary: "List scans — deliverable 2.",
    implemented: false,
    handler: handleScansNotImplemented,
  },
  {
    method: "POST",
    path: "/api/scans",
    summary: "Queue a scan — deliverable 2.",
    implemented: false,
    handler: handleScansNotImplemented,
  },
  {
    method: "GET",
    path: "/api/findings",
    summary: "List findings — deliverable 2.",
    implemented: false,
    handler: handleFindingsNotImplemented,
  },
  {
    method: "GET",
    path: "/api/certificates",
    summary: "Certificate inventory — deliverable 2.",
    implemented: false,
    handler: handleCertificatesNotImplemented,
  },
  {
    method: "GET",
    path: "/api/alerts",
    summary: "List alerts — deliverable 4.",
    implemented: false,
    handler: handleAlertsNotImplemented,
  },
  {
    method: "GET",
    path: "/api/reports",
    summary: "Generate/read reports — deliverable 4.",
    implemented: false,
    handler: handleReportsNotImplemented,
  },
];

interface MatchedRoute {
  route: ApiRoute;
  params: Record<string, string>;
}

function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const patternParts = pattern.split("/").filter(Boolean);
  const pathParts = pathname.split("/").filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < patternParts.length; index += 1) {
    const expected = patternParts[index]!;
    const actual = pathParts[index]!;
    if (expected.startsWith(":")) {
      params[expected.slice(1)] = decodeURIComponent(actual);
      continue;
    }
    if (expected !== actual) return null;
  }
  return params;
}

function apiIndexResponse(pathname: string): Response {
  // GET /api and GET /api/ answer with the machine-readable index of the surface.
  const base = pathname.replace(/\/+$/, "");
  return jsonResponse({
    name: "DOMIRA API",
    version: "v1",
    documentation: "/docs/api.md",
    endpoints: API_ROUTES.map((route) => ({
      method: route.method,
      path: `${base}${route.path.slice(4)}`,
      summary: route.summary,
      implemented: route.implemented,
    })),
  });
}

async function dispatch(request: Request, pathname: string): Promise<Response> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  if (pathname === "/api" || pathname === "/api/") {
    if (method !== "GET") throw errors.methodNotAllowed(["GET"]);
    return apiIndexResponse(pathname);
    }

  const matches: MatchedRoute[] = [];
  for (const route of API_ROUTES) {
    const params = matchPath(route.path, pathname);
    if (params) matches.push({ route, params });
  }
  if (matches.length === 0) throw errors.notFound("Unknown API endpoint.");

  const match = matches.find((candidate) => candidate.route.method === method);
  if (!match) throw errors.methodNotAllowed(matches.map((candidate) => candidate.route.method));

  const context: ApiRouteContext = {
    request,
    url,
    params: match.params,
    ip: clientIp(request),
    userAgent: userAgent(request),
  };
  return match.route.handler(context);
}

/** Entry point used by every src/routes/api/** route file and by the test suite. */
export async function dispatchApi(request: Request): Promise<Response> {
  let pathname = "/api";
  try {
    pathname = new URL(request.url).pathname;
  } catch {
    /* keep the default */
  }
  try {
    return withSecurityHeaders(await dispatch(request, pathname));
  } catch (error) {
    if (isApiError(error)) {
      return withSecurityHeaders(
        jsonResponse(
          {
            error: {
              code: error.code,
              message: error.message,
              ...(error.details ? { details: error.details } : {}),
            },
          },
          { status: error.status, headers: error.headers }
        )
      );
    }
    if (error instanceof DatabaseNotConfiguredError) {
      // The site boots without a database; only data endpoints degrade, with a
      // message that says exactly what is missing.
      return withSecurityHeaders(
        jsonResponse(
          {
            error: {
              code: "DATABASE_UNAVAILABLE",
              message:
                "No database is connected yet. Connect the PostgreSQL database and run `bun run migrate`.",
            },
          },
          { status: 503 }
        )
      );
    }
    if (error instanceof ApiError) {
      return withSecurityHeaders(jsonResponse({ error: { code: error.code, message: error.message } }, { status: error.status }));
    }
    console.error("[domira] unhandled API error:", error);
    return withSecurityHeaders(
      jsonResponse(
        { error: { code: "INTERNAL_ERROR", message: "Unexpected error." } },
        { status: 500 }
      )
    );
  }
}
