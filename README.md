# DOMIRA

Multi-tenant, **defensive** domain-monitoring SaaS. This repository is the product
surface: a TanStack Start (React 19 + Vite + Bun) application served on port 3000,
with the REST API v1 under `/api`, PostgreSQL migrations in `db/migrations`, and the
test suite in `tests/`.

> Scope of the current build (**deliverable 1 — "Base sólida"**): database schema,
> portable data access, real authentication, RBAC + multi-tenant isolation enforced
> in the backend, REST API v1, audit logging, rate limiting, CSRF protection, a real
> minimal web UI in ES/EN, and tests. **Scanning is not implemented yet** (deliverable
> 2): those endpoints answer `501 NOT_IMPLEMENTED` and the UI labels them
> "not implemented yet". Nothing in this repository simulates data or behaviour.

## Quick start

```bash
bun install

# 1. Migrations
DATABASE_URL=postgres://user:pass@host:5432/domira bun run migrate

# 2. Run the tests (they need no database: they run the real SQL against PGlite)
bun test

# 3. Development server (port 3000)
bun run dev

# 4. Production-ish: build + serve on 0.0.0.0:3000
bun run publish      # bun install && vite build && restart the port-3000 server
```

No `DATABASE_URL` yet? Run everything against PGlite (real PostgreSQL compiled to
WASM) instead:

```bash
DOMIRA_DB_DRIVER=pglite bun run migrate          # in-memory, proves the schema
PGLITE_DATA_DIR=/tmp/domira-db DOMIRA_DB_DRIVER=pglite bun run migrate   # persistent
```

## Commands

| Command | What it does |
| --- | --- |
| `bun run dev` | Vite dev server on port 3000 |
| `bun run build` | Production build into `dist/` |
| `bun run publish` | Build + (re)start the server on port 3000 |
| `bun run migrate` | Apply `db/migrations/*.sql` (idempotent, records `schema_migrations`) |
| `bun run promote-super-admin <email>` | Grant platform-administrator rights to an existing account |
| `bun test` | Test suite (schema, auth, RBAC, tenant isolation, tokens) |
| `bun run typecheck` | `tsc --noEmit` |

## First administrator

There is no seeded account and no default password. Create an account at `/signup`,
then promote it (needs database access):

```bash
bun run promote-super-admin you@example.com
```

A platform administrator can read the internal **outbox** (`GET /api/admin/outbox`,
section "Platform administration" in `/app`) to complete the verification and
password-reset flows, because DOMIRA has no e-mail integration yet.

## Documentation

- [docs/architecture.md](docs/architecture.md) — modules, request flow, PostgreSQL mapping
- [docs/database.md](docs/database.md) — schema, ER description, indexes, migrations
- [docs/security.md](docs/security.md) — threat model, sessions, RBAC, tenant isolation, rate limiting
- [docs/multi-tenancy.md](docs/multi-tenancy.md) — how isolation is enforced and tested
- [docs/api.md](docs/api.md) — REST API v1 reference
- [docs/deployment.md](docs/deployment.md) — environment variables, migrations, moving to a VPS/Render/AWS/Vercel/Cloudflare
- [docs/roadmap.md](docs/roadmap.md) — what is done, what is pending, deliverable 2 plan
