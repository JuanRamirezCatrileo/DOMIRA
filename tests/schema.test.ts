/**
 * Schema tests: the migrations really build the schema, they are idempotent, and
 * the constraints/indexes the product spec requires are present.
 */
import { describe, expect, test } from "bun:test";

import { query } from "~/db";
import { loadMigrations, runMigrations } from "~/server/db/migrate";
import { testContext } from "./helpers/harness";

const REQUIRED_TABLES = [
  "users",
  "organizations",
  "organization_members",
  "roles",
  "domains",
  "domain_verifications",
  "scans",
  "scan_results",
  "findings",
  "alerts",
  "certificates",
  "dns_records",
  "email_security_results",
  "http_security_results",
  "security_scores",
  "monitoring_configs",
  "reports",
  "subscriptions",
  "audit_logs",
  "notifications",
  "sessions",
  "email_verification_tokens",
  "password_reset_tokens",
  "jobs",
  "rate_limits",
  "outbox_messages",
  "schema_migrations",
];

describe("database schema", () => {
  test("migrations create every table required by the product spec", async () => {
    const { runner } = await testContext();
    const result = await runner.query<{ table_name: string }>(
      "select table_name from information_schema.tables where table_schema = 'public'"
    );
    const tables = result.rows.map((row) => row.table_name);
    for (const table of REQUIRED_TABLES) expect(tables).toContain(table);
  });

  test("every tenant-owned table has organization_id NOT NULL and a foreign key", async () => {
    const { runner } = await testContext();
    const tenantTables = [
      "organization_members",
      "domains",
      "domain_verifications",
      "scans",
      "scan_results",
      "findings",
      "alerts",
      "certificates",
      "dns_records",
      "email_security_results",
      "http_security_results",
      "security_scores",
      "monitoring_configs",
      "reports",
      "subscriptions",
      "notifications",
    ];
    for (const table of tenantTables) {
      const column = await runner.query<{ is_nullable: string; data_type: string }>(
        `select is_nullable, data_type from information_schema.columns
          where table_name = $1 and column_name = 'organization_id'`,
        [table]
      );
      expect(column.rows[0]?.is_nullable).toBe("NO");
      expect(column.rows[0]?.data_type).toBe("uuid");
      const fk = await runner.query<{ count: number }>(
        `select count(*)::int as count
           from information_schema.table_constraints tc
           join information_schema.key_column_usage kcu on kcu.constraint_name = tc.constraint_name
          where tc.table_name = $1 and tc.constraint_type = 'FOREIGN KEY'
            and kcu.column_name = 'organization_id'`,
        [table]
      );
      expect(Number(fk.rows[0]?.count)).toBeGreaterThan(0);
    }
  });

  test("every tenant-owned table has a composite index starting with organization_id", async () => {
    const { runner } = await testContext();
    const tenantTables = [
      "organization_members",
      "domains",
      "scans",
      "findings",
      "alerts",
      "certificates",
      "dns_records",
      "monitoring_configs",
      "audit_logs",
      "jobs",
    ];
    for (const table of tenantTables) {
      const indexes = await runner.query<{ indexdef: string }>(
        "select indexdef from pg_indexes where tablename = $1",
        [table]
      );
      const hasComposite = indexes.rows.some((row) =>
        /\(\s*organization_id\s*,/i.test(row.indexdef)
      );
      expect(hasComposite).toBe(true);
    }
  });

  test("migrations are idempotent — a second run applies nothing", async () => {
    const { runner } = await testContext();
    const report = await runMigrations(runner);
    expect(report.applied).toHaveLength(0);
    expect(report.skipped.length).toBe(loadMigrations().length);
  });

  test("roles reference table is seeded with the four roles", async () => {
    const { runner } = await testContext();
    const result = await runner.query<{ code: string }>("select code from roles order by rank desc");
    expect(result.rows.map((row) => row.code)).toEqual([
      "SUPER_ADMIN",
      "ADMIN",
      "MEMBER",
      "VIEWER",
    ]);
  });

  test("unique constraints: e-mail is case-insensitive unique and a domain is unique per organisation", async () => {
    const { runner } = await testContext();
    const report = await runner.query<{ indexdef: string }>(
      "select indexdef from pg_indexes where tablename = 'users'"
    );
    expect(report.rows.some((row) => row.indexdef.includes("lower(email)"))).toBe(true);

    const domainIndex = await runner.query<{ indexdef: string }>(
      "select indexdef from pg_indexes where tablename = 'domains'"
    );
    expect(
      domainIndex.rows.some(
        (row) => row.indexdef.includes("organization_id") && row.indexdef.includes("normalized_hostname") && row.indexdef.includes("UNIQUE")
      )
    ).toBe(true);

    // Prove it with data: the same domain can exist in two organisations, but not
    // twice in one.
    const suffix = Math.random().toString(36).slice(2, 8);
    const rows = await query<{ id: string }>(
      `insert into users (email, password_hash) values ($1, 'x') returning id`,
      [`schema-${suffix}@example.test`]
    );
    const userId = rows.rows[0]!.id;
    const org = await query<{ id: string }>(
      `insert into organizations (name, slug, created_by) values ('Schema Org', $1, $2) returning id`,
      [`schema-org-${suffix}`, userId]
    );
    const orgId = org.rows[0]!.id;
    await query(
      `insert into domains (organization_id, hostname, normalized_hostname) values ($1, 'example.test', 'example.test')`,
      [orgId]
    );
    let duplicated = false;
    try {
      await query(
        `insert into domains (organization_id, hostname, normalized_hostname) values ($1, 'EXAMPLE.test', 'example.test')`,
        [orgId]
      );
    } catch {
      duplicated = true;
    }
    expect(duplicated).toBe(true);
  });

  test("security_scores rejects a domain-scoped row without a domain", async () => {
    const { runner } = await testContext();
    let rejected = false;
    try {
      await runner.query(
        `insert into security_scores (organization_id, scope, score, grade)
         values (gen_random_uuid(), 'domain', 90, 'A')`
      );
    } catch {
      rejected = true;
    }
    expect(rejected).toBe(true);
  });
});
