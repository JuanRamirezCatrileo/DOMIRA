# Multi-tenancy

## Model

* Every tenant-owned row carries `organization_id uuid NOT NULL` with an FK to
  `organizations` (asserted for all 16 tenant tables by a test).
* A user belongs to organisations through `organization_members`
  (`UNIQUE (organization_id, user_id)`) with a `role_code` referencing `roles`.
* The client may send an `organization_id` (URL path or body), but that value is
  **input, never authority**: it is only used to look up the caller's membership row.

## Enforcement point

Exactly one function guards tenant data, `requireOrgRole()` in
`src/server/rbac/guard.ts`:

```ts
requireOrgRole(actor, organizationId, permission)
  → SELECT role_code FROM organization_members
      JOIN organizations ON … WHERE organization_id = $1 AND user_id = $2
  • no row            → 404 NOT_FOUND   (the organisation is not yours; do not confirm it exists)
  • row, no permission→ 403 FORBIDDEN   (you are a member, your role is too low)
  • row + permission  → the tenant scope the handler must use
```

Rules that follow from this and are always true in the codebase:

1. **No handler builds a query from the client's `organization_id` without going
   through the guard first.** Handlers use `access.organizationId` after the guard.
2. 404 rather than 403 when there is no membership — 403 would confirm that the id
   exists (an enumeration oracle).
3. Every list query filters by `organization_id` (backed by composite indexes).
4. The only accounts that resolve outside their own memberships are platform super
   admins (`users.is_super_admin`), which is the support/administration path. It is a
   platform-level grant requiring database access
   (`bun run promote-super-admin <email>`) and is recorded in `audit_logs`.
5. Membership changes (add / role change / remove) are audited with actor, target,
   ip and user agent; an organisation can never be left without an administrator.

## Tests (tests/tenant-isolation.test.ts)

Two organisations (Alpha, Bravo) with their own administrators, plus a VIEWER
belonging to Bravo only, plus an account with no organisation. All assertions use the
**real** id of the other organisation (id guessing with a valid id):

**Read and list**

1. `GET /api/organizations lists only the caller's own organisations`
2. `GET /api/organizations/:id with another tenant's valid id returns 404`
3. `GET /api/organizations/:id/members with another tenant's valid id returns 404`
4. `GET /api/me never leaks another organisation's membership`
5. `a VIEWER of the other tenant also gets 404, not data`
6. `an account with no membership gets 404 for any organisation id`
7. `getMembership() returns null across tenants (guard-level proof)`

**Mutate and delete** (each also asserts that the victim's data is unchanged)

8. `POST /api/organizations/:id/members cannot add a user to another tenant`
9. `PATCH /api/organizations/:id/members/:userId cannot change another tenant's role`
10. `DELETE /api/organizations/:id/members/:userId cannot remove another tenant's admin`
11. `PATCH /api/organizations/:id cannot rename another tenant`
12. `guessing ids in bulk never yields another tenant's data`

**Unauthenticated / session abuse**

13. `no session gets 401 (never data) on every organisation endpoint` (9 endpoints)
14. `a suspended account cannot reuse its session`
15. `a revoked session stops working immediately`
16. `cross-origin state-changing requests are rejected (CSRF origin check)`
17. `a state-changing request without the CSRF token is rejected`
18. `login with the wrong password does not reveal that the account exists`

Run them with `bun test tests/tenant-isolation.test.ts`. They execute the real
handlers against real PostgreSQL (PGlite) — the same SQL and the same guard that run
in production, wired through the documented `setQueryRunner()` seam.

## Endpoint families covered

Implemented families (asserted above): `/api/me`, `/api/organizations`,
`/api/organizations/:id`, `/api/organizations/:id/members`,
`/api/organizations/:id/members/:userId`.

Not yet implemented (deliverable 2/4) — `/api/domains`, `/api/scans`,
`/api/findings`, `/api/certificates`, `/api/alerts`, `/api/reports` — cannot leak
anything today: they answer `501 NOT_IMPLEMENTED` for every caller (asserted in
tests/auth.test.ts, "deliverable-2 endpoints answer 501 with no fabricated data").
When they are implemented, each one must call `requireOrgRole()` and receive an
isolation test in this file before it ships; the guard-level test above
(`getMembership()` returns null across tenants) is the invariant they build on.

## Defence in depth and known gaps

* Isolation is enforced in the application layer (one guard), not by database RLS.
  RLS is planned for Phase 2 together with the workers: it requires a
  request-scoped `SET LOCAL app.organization_id` per connection, which the queue
  design must establish anyway. Until then, the guarantee is "any query that returns
  tenant rows is reached only after `requireOrgRole()`", verified by the tests above
  and by every handler being a plain function reviewed against that rule.
* Foreign keys make a cross-tenant write impossible by accident as well: a row's
  `organization_id` must reference a real organisation, and writes set it from
  `access.organizationId`, never from the request body.
