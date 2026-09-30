# REST API v1

Base URL: same origin as the site (the UI and the API share port 3000). All
responses are JSON; the machine-readable index of every endpoint is `GET /api`.

## Conventions

* **Auth**: session cookie `domira_session` (HttpOnly, SameSite=Lax, Secure over
  HTTPS). State-changing requests must additionally send the CSRF token from the
  readable `domira_csrf` cookie in the `x-csrf-token` header.
* **Errors** (single shape, always):

```json
{ "error": { "code": "VALIDATION_ERROR", "message": "…", "details": { … } } }
```

| Code | HTTP | Meaning |
| --- | --- | --- |
| `VALIDATION_ERROR` | 400 | Body/params invalid; `details.fields` lists field + message |
| `UNAUTHENTICATED` | 401 | No/invalid/expired/revoked session |
| `FORBIDDEN` | 403 | Authenticated, but the role lacks the permission (or suspended account) |
| `CSRF_FAILED` | 403 | Missing/mismatching CSRF token, or cross-origin write |
| `NOT_FOUND` | 404 | Unknown endpoint, or a resource outside your tenant (deliberate: no id probing) |
| `METHOD_NOT_ALLOWED` | 405 | Method not allowed; `Allow` header lists the accepted ones |
| `CONFLICT` | 409 | Duplicate e-mail, duplicate membership, last-admin protection, self-role change |
| `PAYLOAD_TOO_LARGE` | 413 | Body over 64 KB |
| `RATE_LIMITED` | 429 | `Retry-After` header carries the seconds to wait |
| `INTERNAL_ERROR` | 500 | Unexpected error (logged server-side, details never returned) |
| `NOT_IMPLEMENTED` | 501 | Declared endpoint whose feature ships later |
| `DATABASE_UNAVAILABLE` | 503 | No database connected / unreachable |

## Endpoints

### Authentication

| Method & path | Auth | Body | Success |
| --- | --- | --- | --- |
| `POST /api/auth/register` | none | `{ email, password, fullName?, organizationName?, locale? }` | `201 { user, organization, membership, csrfToken, emailVerification: { emailSent:false, link, token, expiresAt } }` + session cookies |
| `POST /api/auth/login` | none | `{ email, password }` | `200 { user, memberships, csrfToken }` + session cookies |
| `POST /api/auth/logout` | session | – | `200 { ok: true }` + cookies cleared; the session row is revoked |
| `POST /api/auth/verify-email` | token | `{ token }` | `200 { verified: true, email }` |
| `POST /api/auth/forgot-password` | none | `{ email }` | `202 { message, emailSent: false }` (identical for unknown accounts) |
| `POST /api/auth/reset-password` | token | `{ token, password }` | `200 { ok: true, sessionsRevoked: true }` |

No e-mail is sent anywhere: the verification and reset links are stored in
`outbox_messages` and readable by a platform administrator (see below).

Passwords: ≥ 12 characters, at least one letter and one non-letter.

### Identity and organisations

| Method & path | Permission | Notes |
| --- | --- | --- |
| `GET /api/me` | session | `{ user, memberships, sessionId }` |
| `GET /api/organizations` | session | organisations the caller belongs to |
| `POST /api/organizations` | session | `{ name }` → `201 { organization, membership }`; creator becomes ADMIN; a FREE `subscriptions` row is created (bookkeeping only — no billing exists) |
| `GET /api/organizations/:id` | `org:read` | organisation, caller role, permission list, real counts (members, domains, scans, open findings, open alerts) |
| `PATCH /api/organizations/:id` | `org:update` | `{ name }` |
| `GET /api/organizations/:id/members` | `org:read` | `{ members: [{ userId, email, role, joinedAt, emailVerified }] }` |
| `POST /api/organizations/:id/members` | `org:manage_members` | `{ email, role }`; the account must already exist (invitation e-mails are not sent) |
| `PATCH /api/organizations/:id/members/:userId` | `org:manage_members` | `{ role }`; cannot change your own role; the last ADMIN cannot be demoted |
| `DELETE /api/organizations/:id/members/:userId` | `org:manage_members` | cannot remove yourself; the last ADMIN cannot be removed |

Every `:id` is client input and grants nothing: see docs/multi-tenancy.md.

### Platform administration (SUPER_ADMIN)

| Method & path | Notes |
| --- | --- |
| `GET /api/admin/outbox?kind=&limit=` | messages that would have been e-mailed (verification / reset links), `emailIntegrationConfigured: false` |
| `GET /api/admin/audit?limit=` | recent `audit_logs` entries |

### Declared but not implemented (answer 501, never fake data)

`GET|POST /api/domains`, `POST /api/domains/:id/verify`, `GET|POST /api/scans`,
`GET /api/findings`, `GET /api/certificates`, `GET /api/alerts`, `GET /api/reports`.

Each returns:

```json
{ "error": { "code": "NOT_IMPLEMENTED", "message": "Domain management is not implemented yet.",
             "details": { "plannedIn": "deliverable 2", "endpoint": "GET /api/domains" } } }
```

## Example: register → session → organisation → members

```bash
J=/tmp/domira-cookies.txt
curl -s -c $J -X POST http://localhost:3000/api/auth/register \
  -H 'content-type: application/json' -H 'origin: http://localhost:3000' \
  -d '{"email":"a@example.com","password":"Domira-Example-2026","organizationName":"Alpha"}'
# → 201 … ; the CSRF token is in the readable domira_csrf cookie
CSRF=$(grep domira_csrf $J | awk '{print $7}')

curl -s -b $J http://localhost:3000/api/me
curl -s -b $J -H "x-csrf-token: $CSRF" -H 'origin: http://localhost:3000' \
  -X POST http://localhost:3000/api/organizations -H 'content-type: application/json' -d '{"name":"Beta"}'
```

## Audit trail actions

`user.register`, `user.register.failed`, `user.login`, `user.login.failed`,
`user.logout`, `user.email_verified`, `user.password_reset_requested`,
`user.password_reset_completed`, `organization.created`, `organization.updated`,
`membership.added`, `membership.role_changed`, `membership.removed` — each with
actor, organisation, target, outcome, ip, user-agent and timestamp.
