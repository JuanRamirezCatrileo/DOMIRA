/**
 * `bun run worker` — the standalone scan worker.
 *
 * Runs the same worker loop the app can run in-process (src/server/queue/worker.ts)
 * in its own process, which is the recommended production setup: a heavy scan can
 * never compete with the web tier for CPU, memory or database connections.
 *
 *   bun run worker              # poll the queue for ever
 *   bun run worker --once       # claim and run one job, then exit (cron friendly)
 *   bun run worker --no-scheduler   # only scan jobs, never the scheduler tick
 *
 * Environment (all documented in docs/deployment.md):
 *   DATABASE_URL                     required (or DOMIRA_DB_DRIVER=pglite to try it out)
 *   DOMIRA_WORKER_CONCURRENCY        jobs run at once (default 2)
 *   DOMIRA_WORKER_POLL_INTERVAL_MS   idle poll interval (default 2000)
 *   DOMIRA_JOB_STALE_SECONDS         heartbeat timeout before a job is reclaimed (default 300)
 *   DOMIRA_JOB_MAX_ATTEMPTS          attempts before a job is failed (default 3)
 *   DOMIRA_JOB_RETRY_BACKOFF_SECONDS exponential backoff base (default 30)
 *   DOMIRA_SCHEDULER_INTERVAL_SECONDS scheduler tick interval (default 60)
 *
 * Set DOMIRA_INPROCESS_WORKER=false on the web service so the two do not compete.
 */
import { setQueryRunner } from "../src/db";
import { createPgliteRunner } from "../src/server/db/pglite-driver";
import { createPostgresRunner } from "../src/server/db/postgres-driver";
import type { QueryRunner } from "../src/server/db/types";
import { runSchedulerTick } from "../src/server/queue/scheduler";
import { runWorkerOnce, startWorkerLoop, stopWorkerLoop, workerStats } from "../src/server/queue/worker";

const args = process.argv.slice(2);
const once = args.includes("--once");
const withScheduler = !args.includes("--no-scheduler");

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
    "DATABASE_URL is not set — the worker has nothing to work on.\n" +
      "  * Connect the database (database card) and re-run.\n" +
      "  * Or try it locally: DOMIRA_DB_DRIVER=pglite bun run worker --once"
  );
  process.exit(1);
}

setQueryRunner(runner);

if (once) {
  if (withScheduler) {
    const tick = await runSchedulerTick();
    console.log(`scheduler tick: ${JSON.stringify(tick)}`);
  }
  const outcome = await runWorkerOnce(workerStats().workerId === "(not started)" ? "worker-oneshot" : workerStats().workerId);
  console.log(outcome ? `processed: ${JSON.stringify(outcome)}` : "processed: nothing to do");
  await runner.close();
  process.exit(0);
}

if (withScheduler) {
  const intervalSeconds = Number(process.env.DOMIRA_SCHEDULER_INTERVAL_SECONDS ?? 60);
  const timer = setInterval(() => {
    void runSchedulerTick()
      .then((tick) => {
        if (tick.enqueued > 0) console.log(`[domira] scheduler queued ${tick.enqueued} scan(s).`);
      })
      .catch((error) => console.error("[domira] scheduler tick failed:", error));
  }, intervalSeconds * 1000);
  if (typeof timer === "object" && "unref" in timer) timer.unref();
}

const workerId = startWorkerLoop();
console.log(`[domira] worker ${workerId} started (once=${String(once)}, scheduler=${String(withScheduler)}).`);

const shutdown = async (signal: string) => {
  console.log(`[domira] ${signal} received — finishing the current job and exiting.`);
  stopWorkerLoop();
  await runner.close().catch(() => undefined);
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
