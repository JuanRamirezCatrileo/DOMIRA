# Database

Standard PostgreSQL (tested on PostgreSQL 16/17 semantics; PGlite is PostgreSQL 17
compiled to WASM). No extensions, no vendor-specific types, no ORM lock-in: plain SQL
migrations plus a thin query facade.

## Running migrations

```bash
DATABASE_URL=postgres://user:pass@host:5432/domira bun run migrate
# no database yet? run the exact same SQL against PGlite:
DOMIRA_DB_DRIVER=pglite bun run migrate
```

The runner (`scripts/migrate.ts` → `src/server/db/migrate.ts`):

1. creates `schema_migrations (id, checksum, applied_at, execution_ms)`;
2. reads `db/migrations/*.sql` in filename order;
3. skips files already recorded and **aborts if an applied file's SHA-256 changed**
   (drift detection: never edit an applied migration, add a new one);
4. applies each pending file inside a transaction together with its bookkeeping row.

It is therefore idempotent and safe to run on every deploy.

## Driver and connection

`src/db.ts` exposes `query()`, `sql` (tagged template) and `transaction()`. The
driver is **postgres.js over the standard PostgreSQL wire protocol**, so Tiger
Cloud/Timescale, Neon, RDS/Aurora, Cloud SQL, Supabase and a VPS Postgres all work
unchanged — only `DATABASE_URL` differs.

Defaults chosen for portability:

* `prepare: false` (works behind transaction-mode poolers such as pgbouncer / Neon's
  pooler). Set `DOMIRA_DB_PREPARE=1` on a direct connection to enable prepared
  statements.
* `ssl: "prefer"` unless the URL already carries `sslmode` or `DOMIRA_DB_SSL=disable`
  is set.
* Pool size `DOMIRA_DB_POOL_MAX` (default 5).

`setQueryRunner()` is the test seam that wires the application to PGlite.

## Conventions

* UUID primary keys (`gen_random_uuid()`, core since PostgreSQL 13), `timestamptz`
  everywhere, FKs with explicit `ON DELETE` behaviour.
* `organization_id uuid NOT NULL` + FK on every tenant-owned table; composite indexes
  `(organization_id, …)` for every list query.
* Enumerations are `text` + `CHECK` constraints (adding a value is a plain constraint
  change inside a transaction, unlike `ALTER TYPE … ADD VALUE`).
* No triggers: `updated_at` is set by the statements that update a row (keeps the SQL
  explicit and portable).

## Table groups (23 application tables + `schema_migrations`)

**Identity & access** — `users`, `sessions`, `email_verification_tokens`,
`password_reset_tokens`, `roles` (reference data: the four roles and their
permissions, seeded by migration 001).

**Tenancy** — `organizations`, `organization_members`
(`UNIQUE (organization_id, user_id)`, `role_code` FK → `roles`).

**Domains & monitoring** — `domains` (`UNIQUE (organization_id, normalized_hostname)`),
`domain_verifications`, `monitoring_configs` (`UNIQUE (domain_id)`).

**Scans & evidence** — `scans`, `scan_results`, `certificates`, `dns_records`,
`email_security_results`, `http_security_results`.

**Outcomes** — `findings` (one open row per `(domain_id, code)` via a partial unique
index), `security_scores` (per domain and per organisation, with `CHECK` that a
domain-scoped score has a domain), `alerts`, `notifications`, `reports`.

**Platform** — `jobs` (the queue), `audit_logs`, `rate_limits`, `outbox_messages`
(messages that would be e-mailed), `subscriptions` (plan bookkeeping only — no
billing provider is connected and no prices exist).

## ER description (relationships)

```
users ──1:N── sessions
users ──1:N── email_verification_tokens / password_reset_tokens
users ──1:N── organization_members ──N:1── organizations
                                    └─N:1── roles (code)
organizations ──1:N── domains ──1:N── domain_verifications
                             ├─1:1── monitoring_configs
                             └─1:N── scans ──1:N── scan_results
                                              ├── certificates / dns_records /
                                              │   email_security_results /
                                              │   http_security_results
                                              └── findings ──1:N── alerts ──1:N── notifications
organizations ──1:N── security_scores (scope domain|organization)
organizations ──1:N── reports, jobs, audit_logs, outbox_messages, rate_limits(shared)
organizations ──1:1── subscriptions
```

`audit_logs` deliberately denormalises `actor_email` and allows a NULL
`organization_id`, so the trail survives user/organisation deletion.

## Indexing strategy

* Every list query is `(organization_id, …)`: e.g.
  `scans (organization_id, status, created_at DESC)`,
  `findings (organization_id, status, severity)`,
  `audit_logs (organization_id, created_at DESC)`,
  `dns_records (organization_id, domain_id, record_type, observed_at DESC)`.
* Partial indexes for the hot paths: `jobs (status, priority, available_at) WHERE
  status='queued'`, `sessions (user_id, last_seen_at DESC) WHERE revoked_at IS NULL`,
  `certificates (organization_id, not_after) WHERE not_after IS NOT NULL`,
  `findings (domain_id, code) WHERE status IN ('new','acknowledged')`.
* Uniqueness where it belongs: `lower(email)`, `organizations.slug`,
  `(organization_id, normalized_hostname)`, `(organization_id, user_id)`,
  `(domain_id)`, token hashes, `rate_limits.key`.

## Verification

`tests/schema.test.ts` asserts, against a real PostgreSQL engine (PGlite):

* every required table exists;
* every tenant-owned table has `organization_id uuid NOT NULL` **and** an FK;
* every tenant-owned table has a composite index starting with `organization_id`;
* running `runMigrations` twice applies nothing the second time;
* the four roles are seeded;
* the case-insensitive e-mail index and the per-organisation domain uniqueness
  actually reject duplicates;
* `security_scores` rejects a domain-scoped row with no domain.

## Deliberately not implemented at the database level

* Row-Level Security policies (isolation is enforced in the single authorisation
  layer and covered by tests — see docs/multi-tenancy.md). RLS is a Phase 2
  hardening step: it needs a request-scoped `SET LOCAL app.organization_id`, which
  belongs with the worker/queue work.
* Data retention/partitioning of scan history (Phase 3, when volume exists).
