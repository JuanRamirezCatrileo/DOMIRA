/**
 * The in-process scan runtime: worker loop + scheduler, started by the app.
 *
 * Why in-process: the published DOMIRA site must scan with no extra process and no
 * extra cost, and the deliverable-2a requirement is that the flow works end to end
 * in the deployed environment. Real deployments should instead run the worker in
 * its own process (`bun run worker`, DOMIRA_INPROCESS_WORKER=false) so a heavy scan
 * never competes with the web tier for CPU and connections — both modes share the
 * exact same code (./worker.ts, ./scheduler.ts).
 *
 * Safety rules built in:
 *   * never starts without a database (databaseConfigured()) — the app boots and
 *     serves pages before DATABASE_URL exists, and the runtime just says so once;
 *   * never starts under `bun test` (NODE_ENV=test) or when `setRuntimeEnabled(false)`
 *     was called, so the test suite is deterministic;
 *   * idempotent: repeated calls are no-ops;
 *   * every timer is unref'ed, so the runtime never keeps a process alive on its own.
 *
 * Status is exposed through `runtimeStatus()` for /health and the admin dashboard.
 */
import { databaseConfigured } from "~/db";
import { inProcessWorkerEnabled } from "~/server/env";
import { runSchedulerTick } from "./scheduler";
import { currentWorkerId, schedulerTickIntervalMs, startWorkerLoop, stopWorkerLoop, workerStats } from "./worker";

let enabled = true;
let started = false;
let schedulerTimer: ReturnType<typeof setInterval> | null = null;
let lastSchedulerTick: { at: string; result: Record<string, unknown> } | null = null;
let lastSchedulerError: string | null = null;
let lastSkipReason: string | null = null;

/** Test seam / operator switch: turn the in-process runtime off entirely. */
export function setRuntimeEnabled(value: boolean): void {
  enabled = value;
  if (!value) stopRuntime();
}

export function runtimeEnabled(): boolean {
  return enabled && inProcessWorkerEnabled() && process.env.NODE_ENV !== "test";
}

export interface RuntimeStartResult {
  started: boolean;
  reason?: string;
  workerId: string | null;
}

/**
 * Starts the runtime if it may run. Safe to call from anywhere, on every request
 * even — the guards make it a cheap no-op once running.
 */
export function ensureRuntime(): RuntimeStartResult {
  if (started) return { started: false, reason: "already_running", workerId: currentWorkerId() };
  if (!runtimeEnabled()) {
    lastSkipReason =
      process.env.NODE_ENV === "test"
        ? "test_environment"
        : !inProcessWorkerEnabled()
          ? "inprocess_worker_disabled"
          : "runtime_disabled";
    return { started: false, reason: lastSkipReason, workerId: null };
  }
  if (!databaseConfigured()) {
    lastSkipReason = "database_not_configured";
    return { started: false, reason: lastSkipReason, workerId: null };
  }

  const workerId = startWorkerLoop();
  schedulerTimer = setInterval(() => {
    void runSchedulerTick()
      .then((result) => {
        lastSchedulerTick = { at: new Date().toISOString(), result: { ...result } };
        lastSchedulerError = null;
      })
      .catch((error) => {
        lastSchedulerError = error instanceof Error ? error.message : String(error);
        console.error("[domira] scheduler tick failed:", lastSchedulerError);
      });
  }, schedulerTickIntervalMs());
  if (typeof schedulerTimer === "object" && "unref" in schedulerTimer) schedulerTimer.unref();

  started = true;
  lastSkipReason = null;
  console.log(
    `[domira] scan runtime started in-process as ${workerId} ` +
      `(poll ${String(process.env.DOMIRA_WORKER_POLL_INTERVAL_MS ?? "2000")} ms, ` +
      `scheduler every ${String(schedulerTickIntervalMs() / 1000)} s). ` +
      "Set DOMIRA_INPROCESS_WORKER=false and run `bun run worker` to split it out."
  );
  return { started: true, workerId };
}

export function stopRuntime(): void {
  if (schedulerTimer) clearInterval(schedulerTimer);
  schedulerTimer = null;
  stopWorkerLoop();
  started = false;
}

export function runtimeStatus() {
  if (!started && lastSkipReason === "database_not_configured" && runtimeEnabled() && databaseConfigured()) {
    // The database appeared after the last attempt; try once more on status reads.
    ensureRuntime();
  }
  return {
    enabled: runtimeEnabled(),
    running: started,
    mode: started ? "in_process" : "not_running",
    workerId: currentWorkerId(),
    skipReason: started ? null : lastSkipReason,
    schedulerIntervalSeconds: Math.round(schedulerTickIntervalMs() / 1000),
    lastSchedulerTick,
    lastSchedulerError,
    worker: workerStats(),
  };
}
