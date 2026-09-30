# Security

Order of priorities for every decision: **security → scalability → maintainability →
portability → cost → speed**.

## Scope and threat model

DOMIRA is a **defensive** tool. It never exploits, brute-forces, evades or intrudes:
only passive checks against domains a customer has declared authorised, using
publicly available information. Nothing in this repository scans a third party, and
the analysis engine (deliverable 2) is bound to `domains` rows that belong to a
tenant and carry an explicit `authorization_note`.

Threats this deliverable addresses, and how:

| # | Threat | Control |
| --- | --- | --- |
| 1 | **Cross-tenant data access** (the defining risk of a multi-tenant SaaS) | Single server-side guard `requireOrgRole()`; `organization_id` from the client only ever selects a membership row; non-members get **404**, members without the permission get **403**. Covered by dedicated tests (docs/multi-tenancy.md). |
| 2 | Session theft / fixation | Opaque random 256-bit token, `HttpOnly` + `SameSite=Lax` + `Secure` (over HTTPS) cookie, only the SHA-256 hash in `sessions`, server-side revocation (single or all), expiry enforced in SQL, new session row on every login (no fixation), all sessions revoked on password reset. |
| 3 | Credential stuffing / brute force | argon2id hashing (Bun.password, memory-hard), DB-backed rate limits per IP and per e-mail, per-account lockout after 10 consecutive failures, audit of every failure. |
| 4 | Account enumeration | `login` returns an identical 401 body for unknown account and wrong password, and burns an equivalent argon2 verification so timing matches; `forgot-password` always answers 202 with the same text; `verify-email`/`reset-password` return one generic message for unknown/expired/used tokens. |
| 5 | CSRF on cookie-authenticated writes | Three barriers: (a) `SameSite=Lax` cookies, (b) `Origin` must equal the request host on any state-changing request that carries an `Origin` header, (c) double-submit CSRF token bound to the session row and compared in constant time (`x-csrf-token` header must equal the readable `domira_csrf` cookie **and** hash-match the session). Plus a strict CSP. |
| 6 | SQL injection | Parameterised queries only (`$1…$n`); no string interpolation of values anywhere; identifiers are never taken from user input. |
| 7 | XSS | React escapes by default; no `dangerouslySetInnerHTML`; CSP with `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`. |
| 8 | Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`. |
| 9 | Information disclosure in logs | Passwords/tokens are never logged; the only token material written to the log is the verification/reset **link** (deliberate, because there is no e-mail — see below). Audit metadata never contains secrets (asserted by a test). |
| 10 | Secret leakage | Every secret comes from `process.env` at call time. No `.env` file is committed or required. No default credentials; no seeded admin. |
| 11 | Denial of service on auth | Rate limits on register/login/forgot/reset/verify + 64 KB JSON body cap + JSON-only content type. |
| 12 | Privilege escalation inside a tenant | Permission check per handler; organisation can never be left without an administrator; role changes and removals are audited. |

Out of scope for this deliverable (stated explicitly rather than implied):
e-mail sending (no integration), billing/plans, DKIM deep testing, PDF reports,
public API keys, SSO, webhooks.

## Authentication design

* **Hashing**: argon2id, `memoryCost=19456`, `timeCost=2`, 32-byte output
  (`Bun.password`). The password never leaves `hashPassword()` unhashed; hashes are
  never returned by any endpoint.
* **Password policy** (server and UI identical): ≥ 12 characters, at least one
  letter and one non-letter, ≤ 200 characters. `passwordStrength()` exposes the same
  rules to the UI so the meter cannot disagree with the API.
* **Sessions**: `sessions(id, user_id, token_hash UNIQUE, csrf_token_hash, ip,
  user_agent, created_at, last_seen_at, expires_at, revoked_at, revoked_reason)`.
  TTL `DOMIRA_SESSION_TTL_SECONDS` (default 7 days).
* **Endpoints**: register, login, logout, verify-email, forgot-password,
  reset-password (see docs/api.md). Every one is rate limited and audited.
* **Runtime requirement**: `Bun.password` is a Bun API, so the server process must
  run on Bun (`bun run start` / `bun run publish` do). Node is not supported for the
  server runtime in this build — documented so it is not a surprise on migration.

## E-mail verification and password reset without e-mail

The business has **no e-mail integration**: DOMIRA cannot send or receive e-mail.
Rather than faking it:

* the token is generated (256-bit), stored **hashed** (SHA-256) with an expiry
  (`DOMIRA_EMAIL_TOKEN_TTL_SECONDS`, default 24 h; reset: `DOMIRA_RESET_TOKEN_TTL_SECONDS`,
  default 1 h) and is **single use** — consumption is an atomic
  `UPDATE … WHERE used_at IS NULL AND expires_at > now()`;
* the message that would have been e-mailed is stored in `outbox_messages`
  (`status='pending'`) and its link is written to the server log;
* a **platform administrator** (SUPER_ADMIN) can read pending messages through
  `GET /api/admin/outbox` and, in the UI, the "Platform administration → Outbox"
  section;
* the signup response returns the verification link **to the account owner only**,
  which keeps the flow usable without an inbox. This is a deliberate, documented
  temporary measure, not a security hole: the link authenticates that user's own
  address, and no other account's token is ever returned to a caller.

When an e-mail provider is connected, a worker consumes `outbox_messages` and marks
them `sent`; the schema does not change.

## RBAC matrix

Roles (seeded in `roles`, mirrored in `src/server/rbac/permissions.ts`):

| Permission | VIEWER | MEMBER | ADMIN | SUPER_ADMIN |
| --- | :-: | :-: | :-: | :-: |
| `org:read` | ✅ | ✅ | ✅ | ✅ |
| `domain:read` | — | ✅ | ✅ | ✅ |
| `domain:manage` | — | ✅ | ✅ | ✅ |
| `scan:run` | — | ✅ | ✅ | ✅ |
| `alert:read` | — | ✅ | ✅ | ✅ |
| `org:update` | — | — | ✅ | ✅ |
| `org:manage_members` | — | — | ✅ | ✅ |
| `audit:read` | — | — | ✅ | ✅ |
| `org:create` | — | — | — | ✅ |
| `platform:admin` | — | — | — | ✅ |

`SUPER_ADMIN` is a **platform** role: an account with `users.is_super_admin = true`
resolves as SUPER_ADMIN on any organisation (support/administration path). Ordinary
organisation membership accepts ADMIN/MEMBER/VIEWER only (`ASSIGNABLE_ORG_ROLES`).

Nothing is authorised in the UI. Hiding or disabling a control is convenience; the
backend rejects regardless (tested: a VIEWER sends a valid request with a valid CSRF
token and still gets 403).

## Rate limiting

Database-backed fixed windows (`rate_limits`), shared by every process/replica:

| Bucket | Limit |
| --- | --- |
| `register` per IP | 5 / hour |
| `login` per IP | 10 / 15 min |
| `login` per e-mail | 5 / 15 min |
| `forgot-password` per IP and per e-mail | 5 / 15 min |
| `reset-password` per IP | 10 / 15 min |
| `verify-email` per IP | 20 / 15 min |
| authenticated writes per user | 120 / min |

Exceeding a limit returns `429` with a `Retry-After` header and the standard error
shape. Counters are cleaned opportunistically when a window is opened.

## Security headers

Applied to every dynamic response (API and pages):

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self';
  frame-ancestors 'none'; object-src 'none'; img-src 'self' data:;
  script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'
```

Known deviation, stated plainly: `script-src`/`style-src` include `'unsafe-inline'`
because the SSR framework injects an inline hydration script and Tailwind ships the
stylesheet inline in the HTML. Phase 2 replaces this with a nonce/hash-based policy
(see docs/roadmap.md).

## Secrets policy

* Secrets are read from `process.env` **at call time**; nothing is hardcoded and no
  `.env` file is committed (the repository `.gitignore` excludes `.env*`).
* The only secret this deliverable requires is `DATABASE_URL`. Optional knobs are
  documented in docs/deployment.md.
* Errors and diagnostics never echo credentials: `describeTarget()` prints only
  `postgres://host:port/database`.

## Verification

`bun test` covers: argon2id hashing (not plaintext, not in the audit trail), the
register → login → session round trip, cookie attributes, logout revocation,
suspension revocation, CSRF (missing token, cross-origin), enumeration-resistant
login, rate limiting (429 + Retry-After + database counter), token single-use and
expiry, audit completeness, RBAC denials, and the full tenant-isolation suite.
