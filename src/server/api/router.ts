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
import { handleAdminAudit, handleAdminOutbox, handleAlertsNotImplemented, handleReportsNotImplemented } from "./admin-handlers";
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
import {
  handleCreateDomain,
  handleDeleteDomain,
  handleDomainSecurity,
  handleGetDomain,
  handleListDomainScans,
  handleListDomains,
  handleRequestDomainScan,
  handleUpdateDomain,
  handleVerifyDomain,
} from "./domain-handlers";
import { handleListCertificates, handleListFindings, handleUpdateFinding } from "./finding-handlers";
import { handleCancelScan, handleGetScan, handleListScans } from "./scan-handlers";
import { ensureRuntime } from "~/server/queue/runtime";
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
  // ---- Deliverable 2a: domains, the ownership gate and scanning ---------------
  {
    method: "GET",
    path: "/api/domains",
    summary: "List the organisation's monitored domains (paginated, filter by status).",
    implemented: true,
    handler: handleListDomains,
  },
  {
    method: "POST",
    path: "/api/domains",
    summary: "Add an authorised domain and get the exact DNS TXT record to publish.",
    implemented: true,
    handler: handleCreateDomain,
  },
  {
    method: "GET",
    path: "/api/domains/:id",
    summary: "One domain: state, verification record, latest scan and score.",
    implemented: true,
    handler: handleGetDomain,
  },
  {
    method: "PATCH",
    path: "/api/domains/:id",
    summary: "Rename, change frequency, pause/resume or archive a domain.",
    implemented: true,
    handler: handleUpdateDomain,
  },
  {
    method: "DELETE",
    path: "/api/domains/:id",
    summary: "Remove a domain from monitoring (soft delete; history is kept).",
    implemented: true,
    handler: handleDeleteDomain,
  },
  {
    method: "POST",
    path: "/api/domains/:id/verify",
    summary: "Check the published DNS TXT record (real lookup) and verify ownership.",
    implemented: true,
    handler: handleVerifyDomain,
  },
  {
    method: "POST",
    path: "/api/domains/:id/scan",
    summary: "Queue a scan for a verified domain; answers 202 with the scan and job ids.",
    implemented: true,
    handler: handleRequestDomainScan,
  },
  {
    method: "GET",
    path: "/api/domains/:id/scans",
    summary: "Scan history for one domain, newest first.",
    implemented: true,
    handler: handleListDomainScans,
  },
  {
    method: "GET",
    path: "/api/domains/:id/security",
    summary: "Security Score with per-category breakdown and history (uncollected categories are explicit).",
    implemented: true,
    handler: handleDomainSecurity,
  },
  {
    method: "GET",
    path: "/api/scans",
    summary: "The organisation's scans, filterable by domain and status.",
    implemented: true,
    handler: handleListScans,
  },
  {
    method: "GET",
    path: "/api/scans/:id",
    summary: "One scan with its per-check status, errors and findings.",
    implemented: true,
    handler: handleGetScan,
  },
  {
    method: "POST",
    path: "/api/scans/:id/cancel",
    summary: "Cancel a queued or running scan.",
    implemented: true,
    handler: handleCancelScan,
  },
  {
    method: "GET",
    path: "/api/findings",
    summary: "Findings, filterable by severity, category, status and domain.",
    implemented: true,
    handler: handleListFindings,
  },
  {
    method: "PATCH",
    path: "/api/findings/:id",
    summary: "Change a finding's status (new / acknowledged / resolved / ignored).",
    implemented: true,
    handler: handleUpdateFinding,
  },
  {
    method: "GET",
    path: "/api/certificates",
    summary: "Certificate inventory: newest observation per domain, expiring first.",
    implemented: true,
    handler: handleListCertificates,
  },
  // ---- Declared but NOT implemented (answer 501, never fake data) -------------
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
  // Start the in-process scan runtime (worker + scheduler) on the first request, so
  // the published site scans without a second process. A no-op while it runs, under
  // `bun test`, or before DATABASE_URL is configured. serve.ts also starts it at boot.
  ensureRuntime();
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
