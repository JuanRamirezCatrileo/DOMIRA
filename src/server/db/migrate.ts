/**
 * Migration runner. Reads `db/migrations/NNN_*.sql` in filename order and applies
 * the ones that are not yet recorded in `schema_migrations`.
 *
 * Idempotent by design:
 *  - every migration is written with IF NOT EXISTS / ON CONFLICT so re-running is
 *    harmless;
 *  - applied files are recorded with a SHA-256 checksum, and a changed file that
 *    was already applied aborts the run (drift detection) instead of silently
 *    diverging from production;
 *  - each migration runs inside a transaction together with its bookkeeping row,
 *    so a failure never leaves a half-applied migration recorded as done.
 */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { QueryRunner } from "./types";

export interface MigrationFile {
  name: string;
  sql: string;
  checksum: string;
}

export interface MigrationReport {
  applied: string[];
  skipped: string[];
  runner: string;
}

/** Default location: <repo>/db/migrations, resolved from this file, not from cwd. */
export function migrationsDirectory(custom?: string): string {
  return custom ?? join(import.meta.dir, "..", "..", "..", "db", "migrations");
}

export function loadMigrations(directory?: string): MigrationFile[] {
  const dir = migrationsDirectory(directory);
  return readdirSync(dir)
    .filter((file) => file.endsWith(".sql"))
    .sort()
    .map((file) => {
      const sql = readFileSync(join(dir, file), "utf8");
      return { name: file, sql, checksum: createHash("sha256").update(sql).digest("hex") };
    });
}

const SCHEMA_MIGRATIONS_DDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    id           text PRIMARY KEY,
    checksum     text NOT NULL,
    applied_at   timestamptz NOT NULL DEFAULT now(),
    execution_ms integer NOT NULL DEFAULT 0
)`;

export async function runMigrations(
  runner: QueryRunner,
  options: { directory?: string; log?: (message: string) => void } = {}
): Promise<MigrationReport> {
  const log = options.log ?? (() => {});
  await runner.query(SCHEMA_MIGRATIONS_DDL);

  const existing = await runner.query<{ id: string; checksum: string }>(
    "select id, checksum from schema_migrations"
  );
  const known = new Map(existing.rows.map((row) => [row.id, row.checksum]));

  const applied: string[] = [];
  const skipped: string[] = [];

  for (const migration of loadMigrations(options.directory)) {
    const previous = known.get(migration.name);
    if (previous !== undefined) {
      if (previous !== migration.checksum) {
        throw new Error(
          `Migration ${migration.name} was already applied with a different checksum. ` +
            "Add a new migration instead of editing an applied one."
        );
      }
      skipped.push(migration.name);
      continue;
    }
    const startedAt = Date.now();
    await runner.transaction(async (tx) => {
      await tx.query(migration.sql);
      await tx.query(
        "insert into schema_migrations (id, checksum, execution_ms) values ($1, $2, $3)",
        [migration.name, migration.checksum, Date.now() - startedAt]
      );
    });
    log(`applied ${migration.name} (${Date.now() - startedAt} ms)`);
    applied.push(migration.name);
  }

  return { applied, skipped, runner: runner.describe() };
}
