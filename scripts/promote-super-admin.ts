/**
 * `bun run promote-super-admin <email>` — grants platform administrator rights
 * (users.is_super_admin = true) to an existing account.
 *
 * There is deliberately NO seeded admin and NO default password: the first
 * administrator is created through /signup and then promoted with this command,
 * which requires database access. Every promotion is written to audit_logs.
 */
import { createPgliteRunner } from "../src/server/db/pglite-driver";
import { createPostgresRunner } from "../src/server/db/postgres-driver";
import type { QueryRunner } from "../src/server/db/types";

const email = process.argv[2]?.trim().toLowerCase();
if (!email) {
  console.error("usage: bun run promote-super-admin <email>");
  process.exit(1);
}

const usePglite = process.env.DOMIRA_DB_DRIVER === "pglite" || !process.env.DATABASE_URL;
const runner: QueryRunner = usePglite
  ? await createPgliteRunner({
      ...(process.env.PGLITE_DATA_DIR ? { dataDir: process.env.PGLITE_DATA_DIR } : {}),
    })
  : createPostgresRunner(process.env.DATABASE_URL as string);

try {
  const result = await runner.query<{ id: string; email: string }>(
    "update users set is_super_admin = true, updated_at = now() where lower(email) = $1 returning id, email",
    [email]
  );
  if (result.rows.length === 0) {
    console.error(`no user with email ${email}`);
    process.exitCode = 1;
  } else {
    await runner.query(
      `insert into audit_logs (actor_email, action, target_type, target_id, metadata)
       values ('cli', 'platform.super_admin.granted', 'user', $1, $2::jsonb)`,
      [result.rows[0].id, JSON.stringify({ email, source: "scripts/promote-super-admin.ts" })]
    );
    console.log(`${email} is now a platform super admin`);
    if (usePglite) {
      console.log(
        "note: this ran against PGlite — set DATABASE_URL (or DOMIRA_DB_DRIVER) to target the real database"
      );
    }
  }
} finally {
  await runner.close();
}
