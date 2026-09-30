/**
 * `bun run migrate` — applies db/migrations/*.sql to the database in DATABASE_URL.
 *
 * Honours DOMIRA_DB_DRIVER=pglite for a local, dependency-free run against PGlite
 * (real PostgreSQL WASM) when no DATABASE_URL is available yet. Idempotent: safe
 * to run on every deploy (see docs/deployment.md).
 */
import { createPgliteRunner } from "../src/server/db/pglite-driver";
import { createPostgresRunner } from "../src/server/db/postgres-driver";
import { runMigrations } from "../src/server/db/migrate";
import type { QueryRunner } from "../src/server/db/types";

const driver =
  process.env.DOMIRA_DB_DRIVER ??
  (process.env.DATABASE_URL ? "postgres" : process.env.PGLITE_DATA_DIR ? "pglite" : "");

let runner: QueryRunner;
if (driver === "pglite") {
  runner = await createPgliteRunner({
    ...(process.env.PGLITE_DATA_DIR ? { dataDir: process.env.PGLITE_DATA_DIR } : {}),
  });
} else if (process.env.DATABASE_URL) {
  runner = createPostgresRunner(process.env.DATABASE_URL);
} else {
  console.error(
    "DATABASE_URL is not set.\n" +
      "  * On the managed environment, connect the PostgreSQL database (database card) and re-run.\n" +
      "  * Locally, run against PGlite instead:  DOMIRA_DB_DRIVER=pglite bun run migrate\n" +
      "  * Or use a local server:               DATABASE_URL=postgres://user:pass@localhost:5432/domira bun run migrate\n"
  );
  process.exit(1);
}

try {
  const report = await runMigrations(runner, { log: (message) => console.log(message) });
  console.log(`target: ${report.runner}`);
  console.log(`applied: ${report.applied.length ? report.applied.join(", ") : "(none — already up to date)"}`);
  console.log(`skipped: ${report.skipped.length ? report.skipped.join(", ") : "(none)"}`);
} catch (error) {
  console.error(`migration failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  await runner.close();
}
