# Architecture

## What the application is

DOMIRA is a multi-tenant SaaS for **defensive** domain monitoring. This build
(deliverable 1) is the foundation: identity, tenancy, RBAC, sessions, audit, rate
limiting, the REST API and the minimal real UI. The analysis engine (passive TLS /
DNS / SPF-DMARC / HTTP-header checks), findings, scores, alerts and reports are
deliverables 2–5; their tables already exist so those deliverables are additive.

## Module layout

```
site/
  db/migrations/           plain-SQL migrations (001 core tenancy, 002 domains, 003 outbox)
  scripts/
    migrate.ts             `bun run migrate`
    promote-super-admin.ts `bun run promote-super-admin <email>`
  src/
    db.ts                  portable data-access facade (query / sql / transaction)
    server/
      db/                  driver (postgres.js), types, migration runner, PGlite driver
      env.ts               every runtime setting, read from process.env
      http/                errors (single error shape) + HTTP plumbing + security headers
      auth/                passwords (argon2id), sessions, tokens, rate limiting
      rbac/                permissions matrix + the authorisation guard
      api/                 REST v1 router, handlers, DTO helpers
      audit.ts             audit-trail writer
      validation.ts        zod schemas for every input
      (workers, queue, scanner — deliverable 2)
    routes/                pages: /, /signup, /login, /verify-email, /forgot-password,
                           /reset-password, /app, /health
    routes/api/**.ts       thin transport adapters → src/server/api/router.ts
    i18n/                   ES/EN dictionaries + t() + locale cookie
    components/ui.tsx      shared UI primitives (no hardcoded copy)
    lib/api-client.ts      browser fetch client (cookies + CSRF header)
  tests/                   bun test suite (schema, auth, rbac, tenant isolation, tokens)
```

## Request flow (REST API)

```
browser / curl
  └─ src/routes/api/<path>.ts          TanStack Start server route (thin adapter)
       └─ dispatchApi(request)          src/server/api/router.ts
            ├─ method + path matching (405/404 with the shared error shape)
            ├─ security headers on every response
            └─ handler                     src/server/api/*-handlers.ts
                 ├─ readJsonBody(schema)     zod validation, 64 KB limit, JSON only
                 ├─ requireActor()           session cookie → session row → user (401)
                 │    └─ CSRF: same-origin + session-bound double-submit token (403)
                 ├─ enforceRateLimit()       database-backed fixed window (429)
                 ├─ requireOrgRole(actor, organizationId, permission)  (404/403)
                 ├─ SQL through src/db.ts    parameterised queries only
                 └─ writeAuditLog()          append-only audit trail
```

Every handler is a plain async function of `(ctx) => Response`, so the test suite
calls the identical code path without an HTTP server (`dispatchApi`).

## Request flow (pages)

Server-rendered React pages (TanStack Start). Interactive state comes from the same
public API with `credentials: "same-origin"`: `/app` calls `GET /api/me`, then
`GET /api/organizations/:id` and `GET /api/organizations/:id/members`, so what the
dashboard shows is exactly what the API returns — no duplicated server logic, and no
data path that bypasses authorisation.

## Why this maps cleanly onto PostgreSQL + workers (deliverable 2)

* HTTP handlers never do heavy work. The `jobs` table is the queue: a handler
  inserts a row and returns; a worker claims rows with
  `SELECT ... WHERE status='queued' AND available_at <= now() ORDER BY priority FOR UPDATE SKIP LOCKED`
  and writes results into `scan_results`, `certificates`, `dns_records`,
  `email_security_results`, `http_security_results`, `findings`, `security_scores`.
* The scheduler is a small loop updating `domains.next_scan_at` /
  `monitoring_configs.next_run_at`; no external queue or cron service is required.
* Every result table carries `organization_id` NOT NULL, so the same guard
  (`requireOrgRole`) and the same composite indexes serve the scan dashboards.
* Portability: plain Postgres + plain Bun/Node + no vendor SDKs. Nothing here uses
  a serverless-only API (the previous Neon-HTTP helper was replaced by the standard
  wire protocol — see docs/database.md).

## Security posture in one line

Security first, then scalability, maintainability, portability, cost, speed: the
system refuses (404/403/401/429) rather than degrades, and every refusal is
auditable.
