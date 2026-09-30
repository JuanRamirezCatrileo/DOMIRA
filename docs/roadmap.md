# Roadmap

## Delivered — Phase 1, deliverable 1 ("Base sólida")

| Area | State |
| --- | --- |
| PostgreSQL schema as plain SQL migrations | ✅ 3 migrations, 23 application tables + `schema_migrations`, `bun run migrate` idempotent with checksums |
| Portable data access | ✅ postgres.js over the standard wire protocol, `query`/`sql`/`transaction`, no ORM, no vendor API |
| Authentication | ✅ register, login, logout, sessions (revocable, hashed tokens), argon2id, zod validation, verification + reset tokens (hashed, single-use, expiring), constant-time/generic credential checks, DB-backed rate limits, CSRF |
| RBAC + multi-tenancy | ✅ 4 roles, permission matrix, single `requireOrgRole()` guard, all handlers scoped, isolation tests |
| REST API v1 | ✅ 17 implemented endpoints + 9 declared 501 endpoints, one error shape, security headers |
| Audit log | ✅ register, failed/successful login, logout, e-mail verified, reset requested/completed, org created/updated, membership add/role change/remove |
| Web UI + i18n | ✅ honest landing placeholder, /signup, /login, /verify-email, /forgot-password, /reset-password, /app (real org, role, members, counts), /health; ES/EN dictionaries with `t()`, locale cookie, no hardcoded copy |
| Tests | ✅ 58 tests / ~300 assertions passing (`bun test`) |
| Docs | ✅ README + docs/{architecture,database,security,multi-tenancy,api,deployment,roadmap}.md |

## Not delivered in this build (and labelled as such everywhere)

* **Scanning engine** (deliverable 2): passive TLS/certificate, DNS, SPF/DMARC/MX,
  HTTP security headers and availability checks; job queue workers; findings; score.
  The tables exist; the endpoints answer `501`; the UI labels the sections
  "not implemented yet".
* **Monitoring scheduler, alerts, history, reports** (deliverable 4).
* **Full landing page, `/ready`, `/metrics`, structured log/metrics pipeline, CI**
  (deliverable 5). `/health` exists today.
* **E-mail delivery** — the business has no e-mail integration: verification and
  reset links go to `outbox_messages` and to the platform-admin outbox instead.
* **Billing/plans** — no Stripe, no prices. `subscriptions` holds a FREE row per
  organisation as bookkeeping only.
* **Row-Level Security** — isolation is enforced in the application layer and tested;
  RLS arrives with the worker/connection-scoping work in Phase 2.
* **`'unsafe-inline'` in the CSP** — required by the current SSR hydration script;
  Phase 2 replaces it with nonces/hashes.

## Immediately after DATABASE_URL exists (owner action or next session)

1. `cd /home/team/shared/site && bun run migrate`
2. Create the first account at `/signup`.
3. `bun run promote-super-admin <email>` for platform administration.
4. Confirm `GET /health` shows `reachable: true` and `migrationsApplied: 3`.

No republish is needed: the live site picks up `DATABASE_URL` from the environment.

## Phase 2 — deliverable 2 (analysis engine), recommended order

1. **Domain lifecycle**: `POST /api/domains` (normalise hostname, reject duplicates
   per organisation), `POST /api/domains/:id/verify` (DNS TXT/CNAME challenge stored
   in `domain_verifications`), status transitions pending → verified. All guarded by
   `requireOrgRole(…, "domain:manage")` with isolation tests before the feature ships.
2. **Queue + worker**: enqueue a `jobs` row from the API (never scan inside a request);
   a worker claims rows with `FOR UPDATE SKIP LOCKED`, writes `scans` +
   `scan_results` + the evidence tables, and records `queued/running/completed/failed`.
3. **Checks** (passive only): TLS/certificate (issuer, validity, days remaining, SAN,
   algorithm, chain), DNS (A/AAAA/CNAME/MX/NS/TXT/CAA), e-mail (SPF, DMARC, MX; DKIM
   only when publicly verifiable), HTTP security headers, availability. Every check
   gets a timeout, a hard domain allow-list (only verified, authorised domains) and a
   per-domain concurrency cap.
4. **Findings + Security Score**: mappings with technical + plain-language text and
   recommendations; `SecurityScoreEngine` as an independent service writing
   `security_scores` with category scores, factors and deltas.
5. **Dashboards**: client view (score, domains, findings, expiring certificates) and
   admin view (users, organisations, domains, scans, jobs, errors, audit).

## Phase 3

Scheduler + alerts + history charts + reports (deliverable 4); landing/i18n
completeness, `/ready`, `/metrics`, structured logging and CI pipeline (deliverable
5); then DKIM depth, PDF reports, e-mail notifications, plans/quotas, Stripe, public
API, SSO, webhooks/Slack/Teams/SIEM.
