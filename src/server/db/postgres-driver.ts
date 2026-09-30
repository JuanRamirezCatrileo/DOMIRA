/**
 * Concrete QueryRunner backed by postgres.js (standard PostgreSQL wire protocol).
 *
 * Portability notes (see docs/deployment.md):
 *  - `prepare: false` by default so the same code works behind transaction-mode
 *    poolers (pgbouncer on Tiger Cloud, Neon's pooler, Supabase). Set
 *    DOMIRA_DB_PREPARE=1 to enable prepared statements on a direct connection.
 *  - `ssl: "prefer"` unless the connection string already carries `sslmode` or
 *    DOMIRA_DB_SSL=disable is set, so managed providers (TLS) and a local
 *    Postgres (no TLS) both work with no code change.
 *  - Only DATABASE_URL is read; no credentials ever live in the repository.
 */
import postgres from "postgres";

import { DatabaseNotConfiguredError, type QueryResult, type QueryRunner, type Row } from "./types";

export type PostgresClient = postgres.Sql<Record<string, unknown>>;

function sslOption(url: string): postgres.Options<Record<string, unknown>>["ssl"] {
  if (process.env.DOMIRA_DB_SSL === "disable") return false;
  if (/[?&]sslmode=/.test(url)) return undefined;
  return "prefer";
}

export function createPostgresRunner(url: string): QueryRunner {
  if (!url) throw new DatabaseNotConfiguredError();
  const preparedStatements = process.env.DOMIRA_DB_PREPARE === "1";
  const client = postgres(url, {
    max: Number(process.env.DOMIRA_DB_POOL_MAX ?? 5),
    idle_timeout: 20,
    connect_timeout: 15,
    prepare: preparedStatements,
    ssl: sslOption(url),
    onnotice: () => {},
  });

  const wrap = (q: PostgresClient["unsafe"]): QueryRunner => ({
    async query<T = Row>(text: string, params?: readonly unknown[]): Promise<QueryResult<T>> {
      const result = (await q(text, (params ?? []) as unknown[])) as unknown as T[] & {
        count?: number;
      };
      return { rows: [...result], rowCount: result.count ?? result.length };
    },
    transaction<T>(fn: (tx: QueryRunner) => Promise<T>): Promise<T> {
      return client.begin(async (tx) => fn(wrap(tx.unsafe.bind(tx) as PostgresClient["unsafe"]))) as Promise<T>;
    },
    describe: () => describeTarget(url),
    close: () => client.end({ timeout: 5 }),
  });

  return wrap(client.unsafe.bind(client) as PostgresClient["unsafe"]);
}

/** Safe description of a connection target — never includes credentials. */
export function describeTarget(url: string): string {
  try {
    const parsed = new URL(url);
    return `postgres://${parsed.hostname}:${parsed.port || "5432"}${parsed.pathname}`;
  } catch {
    return "postgres://<unparsable DATABASE_URL>";
  }
}
