/**
 * `bun run scheduler` — one scheduler tick, then exit.
 *
 * For platforms with native cron (Render cron jobs, Cloudflare Cron Triggers,
 * systemd timers, Kubernetes CronJobs): schedule this every few minutes instead of
 * keeping a loop alive. Idempotent — a tick that finds nothing due does nothing.
 *
 *   bun run scheduler
 *   DATABASE_URL=... bun run scheduler
 */
import { setQueryRunner } from "../src/db";
import { createPgliteRunner } from "../src/server/db/pglite-driver";
import { createPostgresRunner } from "../src/server/db/postgres-driver";
import type { QueryRunner } from "../src/server/db/types";
import { runSchedulerTick } from "../src/server/queue/scheduler";

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
  console.error("DATABASE_URL is not set — cannot run the scheduler.");
  process.exit(1);
}

setQueryRunner(runner);
try {
  const tick = await runSchedulerTick();
  console.log(JSON.stringify(tick, null, 2));
} catch (error) {
  console.error(`scheduler tick failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  await runner.close();
}
