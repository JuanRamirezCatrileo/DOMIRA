/**
 * GET /health — liveness/readiness probe (no authentication, no tenant data).
 *
 * Reports whether the application process is up, whether migrations are applied and
 * how many are recorded. It never exposes credentials or connection details.
 * Deliverable 5 extends this with /ready and /metrics.
 */
import { createFileRoute } from "@tanstack/react-router";

import { databaseConfigured, databaseTargetDescription, query } from "~/db";
import { runtimeStatus } from "~/server/queue/runtime";

export const Route = createFileRoute("/health")({
  server: {
    handlers: {
      GET: async () => {
        const body: Record<string, unknown> = {
          status: "ok",
          service: "domira",
          database: { configured: databaseConfigured(), target: databaseTargetDescription() },
        };
        if (databaseConfigured()) {
          try {
            const result = await query<{ migrations: number; latest: string | null }>(
              "select count(*)::int as migrations, max(id) as latest from schema_migrations"
            );
            body.database = {
              ...(body.database as object),
              reachable: true,
              migrationsApplied: Number(result.rows[0]?.migrations ?? 0),
              latestMigration: result.rows[0]?.latest ?? null,
            };
            // Queue depth and the scan runtime, so an operator can see whether the
            // published site is actually processing scans (deliverable 5 adds /metrics).
            try {
              const jobs = await query<{ status: string; count: number }>(
                "select status, count(*)::int as count from jobs group by status"
              );
              body.queue = Object.fromEntries(
                jobs.rows.map((row) => [row.status, Number(row.count)])
              );
              body.scanRuntime = runtimeStatus();
            } catch (error) {
              body.queue = {
                error: error instanceof Error ? error.message.slice(0, 200) : "unknown",
              };
            }
          } catch (error) {
            body.database = {
              ...(body.database as object),
              reachable: false,
              error: error instanceof Error ? error.message.slice(0, 200) : "unknown",
            };
          }
        }
        return Response.json(body, { headers: { "cache-control": "no-store" } });
      },
    },
  },
});
