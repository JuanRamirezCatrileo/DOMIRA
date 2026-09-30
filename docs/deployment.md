# Deployment

The application is plain **TanStack Start (React 19 + Vite) on Bun + standard
PostgreSQL**. There is no vendor SDK, no serverless-only database API and no
proprietary queue: it runs on this managed environment, on a VPS with Docker or
systemd, and on Render / AWS / Vercel / Cloudflare with the same code.

## Environment variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | **yes** (except PGlite mode) | Standard PostgreSQL connection string. The app is unusable for data without it: data endpoints answer `503 DATABASE_UNAVAILABLE`, pages keep serving. |
| `NODE_ENV` | no | `production` in production builds; used for logging defaults. |
| `DOMIRA_DB_DRIVER` | no | `postgres` (default when `DATABASE_URL` is set) or `pglite` (local/test: real PostgreSQL compiled to WASM). |
| `PGLITE_DATA_DIR` | no | Directory for a persistent PGlite instance (only with `DOMIRA_DB_DRIVER=pglite`); omit for in-memory. |
| `DOMIRA_DB_POOL_MAX` | no | Connection pool size, default `5`. |
| `DOMIRA_DB_SSL` | no | `disable` to force TLS off (local Postgres). Otherwise `ssl: "prefer"`, and an `sslmode=` in the URL wins. |
| `DOMIRA_DB_PREPARE` | no | `1` enables prepared statements on a direct connection. Default is off so transaction-mode poolers work. |
| `DOMIRA_SESSION_TTL_SECONDS` | no | Session lifetime, default 604800 (7 days). |
| `DOMIRA_SESSION_COOKIE` | no | Session cookie name, default `domira_session`. |
| `DOMIRA_CSRF_COOKIE` | no | CSRF cookie name, default `domira_csrf`. |
| `DOMIRA_EMAIL_TOKEN_TTL_SECONDS` | no | E-mail verification token lifetime, default 86400 (24 h). |
| `DOMIRA_RESET_TOKEN_TTL_SECONDS` | no | Password reset token lifetime, default 3600 (1 h). |
| `DOMIRA_PUBLIC_URL` | no | Absolute base URL used to build verification/reset links (e.g. `https://domira.cl`). Defaults to the request's host/proto, honouring `x-forwarded-host`/`x-forwarded-proto`. |
| `PORT` / `HOST` | no | Ignored by `serve.ts`, which is pinned to `0.0.0.0:3000` so the published URL cannot be moved by a stray env var. On another host, run `bun run dist/server/server.js` behind your own listener instead. |

**Secrets policy:** values are read from `process.env` at call time. Never commit a
`.env` file — a value that only lives in a developer's `.env` is missing on the live
site.

## Migrations

```bash
DATABASE_URL=postgres://… bun run migrate
```

Idempotent, transactional per file, records `schema_migrations` with a checksum and
aborts if an already-applied file changed. Run it on every deploy, before the new
version receives traffic.

No database connected yet? The same migrations can be exercised locally:

```bash
DOMIRA_DB_DRIVER=pglite bun run migrate
PGLITE_DATA_DIR=/tmp/domira-domira DOMIRA_DB_DRIVER=pglite bun run migrate   # persistent
```

## Running here (the team's environment)

```bash
cd /home/team/shared/site
bun run publish     # bun install + vite build + restart the server on 0.0.0.0:3000
curl -s http://localhost:3000/health
```

Port 3000 is the team's single public surface, so the web UI and the REST API share
one origin (no second server, no CORS configuration needed).

## Docker (VPS / Render / ECS / Cloud Run)

The repository is container-ready: a single Bun process serving SSR + `/api`, plus a
PostgreSQL database.

```dockerfile
FROM oven/bun:1.4-alpine
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY . .
RUN bun run build
ENV NODE_ENV=production
EXPOSE 3000
CMD ["bun", "run", "dist/server/server.js"]
```

Notes:
* Run migrations as a separate step/job (`bun run migrate`) so two replicas never
  race on cold start.
* `serve.ts` (used by `bun run start` here) exists to free port 3000 across users;
  in a container, start the built server directly as above and let the platform
  manage the port.
* Mount nothing but the database: the app keeps no local state.

## Render / Railway / Fly.io

* Build command `bun install && bun run build`; start command
  `bun run dist/server/server.js`; health check path `/health`.
* Add `DATABASE_URL` from the managed PostgreSQL add-on (all of them speak the
  standard wire protocol).
* Run `bun run migrate` once per release (pre-deploy command or a one-off shell).

## Vercel

`build-vercel.sh` and `vercel-entry.ts` are kept from the site template and still
work: the build emits `dist/server/server.js` and the entry adapts Node's
`(req, res)` to the fetch handler, so SSR **and** `/api/*` are served by the same
function. `DATABASE_URL` must be set in the Vercel project; because Vercel runs the
handler on Node, note that Bun-only APIs are used for password hashing —
`Bun.password` — so on Vercel use the Bun runtime for the function, or swap
`src/server/auth/passwords.ts` for `node:crypto` `scrypt`/`argon2` (one file, same
interface).

## Cloudflare Workers

Workers (and Pages Functions) can serve TanStack Start through the Cloudflare adapter
and reach PostgreSQL over HTTP with a driver such as `postgres`/Hyperdrive. Two
caveats, stated honestly: Workers have no Bun runtime (`Bun.password` must be
replaced as above), and the driver must be the HTTP variant. The schema, the router,
the guard and the tests are unchanged.

## Lifting DOMIRA out of this sandbox — checklist

1. Provision PostgreSQL 16+ anywhere (Tiger Cloud, Neon, RDS, Cloud SQL, VPS).
2. Set `DATABASE_URL` (+ `DOMIRA_PUBLIC_URL`) as a secret in the target environment.
3. `bun install --frozen-lockfile && bun run build`.
4. `bun run migrate` (once per release, before switching traffic).
5. Start the server (`bun run dist/server/server.js`).
6. Create the first account through `/signup`, then
   `bun run promote-super-admin <email>` to get platform administration.
7. Verify `/health` reports `reachable: true` and the migration count.
8. Point DNS and TLS at the host; the app already emits HSTS and a CSP.

## Operations notes

* `/health` — no auth, no tenant data: process status, whether a database is
  configured, reachability and the number of applied migrations.
* Logs are structured-ish line logs on stdout (`[domira] …`); the only token material
  ever logged is the verification/reset **link**, because no e-mail provider exists.
* Backups: standard `pg_dump`. Nothing is stored outside the database.
