/**
 * Test harness.
 *
 * The whole suite runs against PGlite — real PostgreSQL compiled to WASM — with the
 * exact same SQL migrations that production runs (db/migrations/*.sql). The
 * application is wired to it through the documented test seam
 * `setQueryRunner()` in src/db.ts, so the code under test is the real code: the
 * same router, the same guards, the same queries.
 *
 * The database is created once per process (memoised) and every test uses its own
 * e-mail addresses and client IP addresses, so tests neither collide nor need
 * shared mutable state.
 */
import { setQueryRunner, query } from "~/db";
import { runMigrations } from "~/server/db/migrate";
import { createPgliteRunner } from "~/server/db/pglite-driver";
import type { QueryRunner } from "~/server/db/types";
import { dispatchApi } from "~/server/api/router";

export interface TestContext {
  runner: QueryRunner;
}

let contextPromise: Promise<TestContext> | null = null;

export function testContext(): Promise<TestContext> {
  contextPromise ??= (async () => {
    const runner = await createPgliteRunner();
    await runMigrations(runner);
    setQueryRunner(runner);
    return { runner };
  })();
  return contextPromise;
}

export interface ApiResult<T = any> {
  status: number;
  body: T;
  headers: Headers;
}

export class ApiClient {
  readonly cookies = new Map<string, string>();
  readonly ip: string;
  origin: string | null;

  constructor(options: { ip?: string; origin?: string | null } = {}) {
    this.ip = options.ip ?? randomIp();
    this.origin = options.origin === undefined ? "http://localhost" : options.origin;
  }

  get csrfToken(): string | null {
    return this.cookies.get("domira_csrf") ?? null;
  }

  get sessionToken(): string | null {
    return this.cookies.get("domira_session") ?? null;
  }

  async call<T = any>(
    method: string,
    path: string,
    options: { body?: unknown; headers?: Record<string, string>; csrf?: string | null | false } = {}
  ): Promise<ApiResult<T>> {
    await testContext();
    const headers = new Headers({ "x-forwarded-for": this.ip });
    if (this.origin) headers.set("origin", this.origin);
    if (this.cookies.size > 0) {
      headers.set(
        "cookie",
        [...this.cookies.entries()].map(([key, value]) => `${key}=${value}`).join("; ")
      );
    }
    if (options.body !== undefined) headers.set("content-type", "application/json");
    const csrf = options.csrf === undefined ? this.csrfToken : options.csrf;
    if (csrf) headers.set("x-csrf-token", csrf);
    for (const [key, value] of Object.entries(options.headers ?? {})) headers.set(key, value);

    const request = new Request(`http://localhost${path}`, {
      method,
      headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
    const response = await dispatchApi(request);
    for (const [key, value] of extractSetCookies(response.headers)) {
      if (value === "") this.cookies.delete(key);
      else this.cookies.set(key, value);
    }
    const text = await response.text();
    return {
      status: response.status,
      body: (text.length > 0 ? JSON.parse(text) : null) as T,
      headers: response.headers,
    };
  }

  get<T = any>(path: string) {
    return this.call<T>("GET", path);
  }
  post<T = any>(path: string, body?: unknown, options: { csrf?: string | null | false; headers?: Record<string, string> } = {}) {
    return this.call<T>("POST", path, { body: body ?? {}, ...options });
  }
  patch<T = any>(path: string, body?: unknown, options: { csrf?: string | null | false } = {}) {
    return this.call<T>("PATCH", path, { body: body ?? {}, ...options });
  }
  delete<T = any>(path: string, options: { csrf?: string | null | false } = {}) {
    return this.call<T>("DELETE", path, options);
  }
}

function extractSetCookies(headers: Headers): Array<[string, string]> {
  const raw = typeof (headers as any).getSetCookie === "function"
    ? ((headers as any).getSetCookie() as string[])
    : [headers.get("set-cookie") ?? ""];
  const out: Array<[string, string]> = [];
  for (const cookie of raw) {
    const first = cookie.split(";")[0] ?? "";
    const index = first.indexOf("=");
    if (index < 1) continue;
    out.push([first.slice(0, index).trim(), first.slice(index + 1).trim()]);
  }
  return out;
}

let ipCounter = 0;
export function randomIp(): string {
  ipCounter += 1;
  const a = 10 + (ipCounter % 200);
  return `10.${a}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
}

export function uniqueEmail(prefix = "user"): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}@example.test`;
}

export const STRONG_PASSWORD = "Domira-Test-Password-2026";

export interface RegisteredUser {
  client: ApiClient;
  userId: string;
  email: string;
  organizationId: string | null;
  verificationToken: string | null;
}

export async function registerUser(
  options: {
    email?: string;
    password?: string;
    organizationName?: string;
    ip?: string;
    client?: ApiClient;
  } = {}
): Promise<RegisteredUser> {
  await testContext();
  const email = options.email ?? uniqueEmail();
  const client = options.client ?? new ApiClient({ ip: options.ip });
  const response = await client.post("/api/auth/register", {
    email,
    password: options.password ?? STRONG_PASSWORD,
    fullName: "Test Person",
    ...(options.organizationName ? { organizationName: options.organizationName } : {}),
  });
  if (response.status !== 201) {
    throw new Error(`register failed: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return {
    client,
    userId: response.body.user.id,
    email,
    organizationId: response.body.organization?.id ?? null,
    verificationToken: response.body.emailVerification?.token ?? null,
  };
}

export async function promoteToSuperAdmin(userId: string): Promise<void> {
  await query("update users set is_super_admin = true where id = $1", [userId]);
}

export async function countRows(
  table: string,
  where: Record<string, unknown>
): Promise<number> {
  const keys = Object.keys(where);
  const clause = keys.map((key, index) => `${key} = $${index + 1}`).join(" and ");
  const result = await query<{ count: string | number }>(
    `select count(*)::int as count from ${table}${keys.length ? ` where ${clause}` : ""}`,
    Object.values(where)
  );
  return Number(result.rows[0]?.count ?? 0);
}

/** Reads a single scalar from the database in tests. */
export async function scalar<T = unknown>(text: string, params: unknown[] = []): Promise<T | null> {
  const result = await query<Record<string, unknown>>(text, params);
  const row = result.rows[0];
  if (!row) return null;
  return Object.values(row)[0] as T;
}
