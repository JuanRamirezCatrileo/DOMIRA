/** PGlite-backed QueryRunner: real PostgreSQL compiled to WASM, used by tests and
 * by `bun run migrate` when no DATABASE_URL exists yet.
 *
 * It is imported only by scripts and tests — never by the application bundle — so
 * the production build stays free of the WASM engine. The SQL it executes is
 * byte-for-byte the same as against a real server (db/migrations/*.sql), which is
 * what makes it a meaningful verification of the schema.
 */
import { PGlite } from "@electric-sql/pglite";

import type { QueryResult, QueryRunner, Row } from "./types";

interface PgliteLike {
  query<T>(query: string, params?: unknown[]): Promise<{ rows: T[]; affectedRows?: number }>;
  exec(query: string): Promise<Array<{ rows?: unknown[]; affectedRows?: number }>>;
}

function fromPgliteLike(client: PgliteLike, label: string): QueryRunner {
  const runner: QueryRunner = {
    async query<T = Row>(text: string, params?: readonly unknown[]): Promise<QueryResult<T>> {
      if (params && params.length > 0) {
        try {
          const result = await client.query<T>(text, [...params]);
          return {
            rows: result.rows ?? [],
            rowCount: result.affectedRows || (result.rows ?? []).length,
          };
        } catch (error) {
          if (process.env.DOMIRA_SCAN_DEBUG) {
            console.error("[domira] pglite SQL failure:", text, "\nparams:", JSON.stringify(params));
          }
          throw error;
        }
      }
      // No parameters: use the simple-query protocol so a multi-statement script
      // (a whole migration file) runs as one unit, exactly like postgres.js does.
      const results = await client.exec(text);
      const last = results[results.length - 1];
      const rows = (last?.rows ?? []) as T[];
      return { rows, rowCount: last?.affectedRows || rows.length };
    },
    async transaction<T>(fn: (tx: QueryRunner) => Promise<T>): Promise<T> {
      await runner.query("begin");
      try {
        const result = await fn(runner);
        await runner.query("commit");
        return result;
      } catch (error) {
        await runner.query("rollback");
        throw error;
      }
    },
    describe: () => label,
    close: async () => {},
  };
  return runner;
}

export interface PgliteRunnerOptions {
  /** Filesystem path for a persistent instance; omit for an in-memory database. */
  dataDir?: string;
}

export async function createPgliteRunner(options: PgliteRunnerOptions = {}): Promise<QueryRunner> {
  const pg = options.dataDir ? new PGlite(options.dataDir) : new PGlite();
  await pg.waitReady;
  const runner = fromPgliteLike(pg as unknown as PgliteLike, `pglite:${options.dataDir ?? "memory"}`);
  runner.close = async () => {
    await pg.close();
  };
  return runner;
}
