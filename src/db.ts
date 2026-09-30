/**
 * DOMIRA's database facade (server-only).
 *
 *   import { query, sql, transaction } from "~/db";
 *
 * The connection string is read from `process.env.DATABASE_URL` lazily — never at
 * module load — so the app still builds and serves pages before a database is
 * connected; the error only surfaces when a query actually runs.
 *
 * Driver: standard PostgreSQL over the wire protocol (postgres.js). Swapping to a
 * different host (Tiger Cloud, Neon, RDS, VPS) means changing DATABASE_URL and
 * nothing else. `setQueryRunner()` exists so the automated tests can run the real
 * SQL against PGlite (PostgreSQL compiled to WASM) without changing application
 * code.
 */
import { createPostgresRunner, describeTarget } from "./server/db/postgres-driver";
import {
  DatabaseNotConfiguredError,
  type QueryResult,
  type QueryRunner,
  type Row,
} from "./server/db/types";

export type { QueryResult, QueryRunner, Row } from "./server/db/types";
export { DatabaseNotConfiguredError } from "./server/db/types";

let cached: QueryRunner | null = null;
let injected: QueryRunner | null = null;

export function databaseConfigured(): boolean {
  return injected !== null || Boolean(process.env.DATABASE_URL);
}

export function getQueryRunner(): QueryRunner {
  if (injected) return injected;
  if (cached) return cached;
  const url = process.env.DATABASE_URL;
  if (!url) throw new DatabaseNotConfiguredError();
  cached = createPostgresRunner(url);
  return cached;
}

/** Test seam: run the application against an in-process PGlite instance. */
export function setQueryRunner(runner: QueryRunner | null): void {
  injected = runner;
}

export async function query<T = Row>(
  text: string,
  params?: readonly unknown[]
): Promise<QueryResult<T>> {
  if (!injected && !cached && !process.env.DATABASE_URL) throw new DatabaseNotConfiguredError();
  return getQueryRunner().query<T>(text, params);
}

export function transaction<T>(fn: (tx: QueryRunner) => Promise<T>): Promise<T> {
  return getQueryRunner().transaction(fn);
}

/**
 * Tagged-template helper kept for compatibility with the site template's
 * documented usage: `sql()`select 1``. Values become $1..$n parameters — never
 * string interpolation.
 */
export function sql<T = Row>(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Promise<QueryResult<T>> {
  let text = strings[0] ?? "";
  for (let i = 0; i < values.length; i += 1) text += `$${i + 1}${strings[i + 1] ?? ""}`;
  return query<T>(text, values);
}

/** Health/diagnostics: where the app is connected, without leaking credentials. */
export function databaseTargetDescription(): string {
  if (injected) return injected.describe();
  const url = process.env.DATABASE_URL;
  return url ? describeTarget(url) : "not configured";
}
