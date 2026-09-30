/**
 * Database abstractions shared by every driver.
 *
 * DOMIRA talks to a STANDARD PostgreSQL server over the standard wire protocol
 * (postgres.js). Nothing here depends on a vendor-specific API: the same code
 * runs against Tiger Cloud / Timescale, Neon (TCP), RDS, Cloud SQL, a plain VPS
 * Postgres and against PGlite (PostgreSQL compiled to WASM) in the test suite.
 */
export type Row = Record<string, unknown>;

export interface QueryResult<T = Row> {
  rows: T[];
  rowCount: number;
}

/** Minimal surface the application needs from a database. */
export interface QueryRunner {
  /** Run one SQL statement (or a multi-statement script with no parameters). */
  query<T = Row>(text: string, params?: readonly unknown[]): Promise<QueryResult<T>>;
  /** Run `fn` inside a transaction; rolls back if `fn` throws. */
  transaction<T>(fn: (tx: QueryRunner) => Promise<T>): Promise<T>;
  /** Human-readable description of where this runner points (for logs / health). */
  describe(): string;
  close(): Promise<void>;
}

/** Thrown when a query is attempted while no database is configured. */
export class DatabaseNotConfiguredError extends Error {
  constructor() {
    super(
      "DATABASE_URL is not set. Connect a PostgreSQL database (database card) or run against " +
        "PGlite locally with DOMIRA_DB_DRIVER=pglite. See docs/deployment.md."
    );
    this.name = "DatabaseNotConfiguredError";
  }
}
