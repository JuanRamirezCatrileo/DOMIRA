/**
 * Authentication: registration, login, session round trip, logout, hashing,
 * rate limiting, CSRF and the audit trail.
 */
import { describe, expect, test } from "bun:test";

import { query } from "~/db";
import { hashPassword, passwordStrength, verifyPassword } from "~/server/auth/passwords";
import { RATE_LIMITS } from "~/server/auth/rate-limit";
import {
  ApiClient,
  STRONG_PASSWORD,
  countRows,
  registerUser,
  scalar,
  testContext,
  uniqueEmail,
} from "./helpers/harness";

describe("passwords", () => {
  test("hashing is argon2id and never the plaintext", async () => {
    const hash = await hashPassword("Domira-Test-Password-2026");
    expect(hash.startsWith("$argon2id$")).toBe(true);
    expect(hash).not.toContain("Domira-Test-Password-2026");
    expect(await verifyPassword(hash, "Domira-Test-Password-2026")).toBe(true);
    expect(await verifyPassword(hash, "domira-test-password-2026")).toBe(false);
  });

  test("a malformed hash verifies as false instead of throwing", async () => {
    expect(await verifyPassword("not-a-hash", "whatever")).toBe(false);
  });

  test("the strength policy in the API matches the one shown in the UI", () => {
    expect(passwordStrength("short1").problems).toContain("too_short");
    expect(passwordStrength("alllettersonly").problems).toContain("needs_number_or_symbol");
    expect(passwordStrength("Domira-Test-Password-2026").problems).toEqual([]);
  });
});

describe("register -> login -> session round trip", () => {
  test("register creates a user, an organisation and a working session", async () => {
    const registered = await registerUser({ organizationName: "Round Trip Ltd" });
    expect(registered.organizationId).toBeTruthy();

    const header = registered.client.sessionToken;
    expect(header).toBeTruthy();

    // The stored hash is not the session token itself.
    const stored = await scalar<string>("select token_hash from sessions where user_id = $1", [
      registered.userId,
    ]);
    expect(stored).not.toBe(header);
    expect(stored).toHaveLength(64);

    const me = await registered.client.get("/api/me");
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(registered.email);
    expect(me.body.user.emailVerified).toBe(false);

    // The password is stored as an argon2id hash, never plaintext.
    const hash = await scalar<string>("select password_hash from users where id = $1", [
      registered.userId,
    ]);
    expect(hash!.startsWith("$argon2id$")).toBe(true);
    expect(hash).not.toContain(STRONG_PASSWORD);
  });

  test("login with correct credentials starts a new session; logout revokes exactly it", async () => {
    const registered = await registerUser({ organizationName: "Logout Ltd" });
    const second = new ApiClient();
    const login = await second.post("/api/auth/login", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    expect(login.status).toBe(200);
    expect(login.body.user.email).toBe(registered.email);
    expect(login.body.memberships).toHaveLength(1);
    expect(second.csrfToken).toBeTruthy();

    expect((await second.get("/api/me")).status).toBe(200);
    const logout = await second.post("/api/auth/logout");
    expect(logout.status).toBe(200);
    expect((await second.get("/api/me")).status).toBe(401);

    // The first session (a different session row) is still valid.
    expect((await registered.client.get("/api/me")).status).toBe(200);
    const active = await scalar<number>(
      "select count(*)::int from sessions where user_id = $1 and revoked_at is null",
      [registered.userId]
    );
    expect(active).toBe(1);
  });

  test("registering the same e-mail twice is a conflict, and never a second account", async () => {
    const registered = await registerUser();
    const duplicate = await new ApiClient().post("/api/auth/register", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    expect(duplicate.status).toBe(409);
    expect(
      await scalar<number>("select count(*)::int from users where lower(email) = $1", [
        registered.email,
      ])
    ).toBe(1);
    // The failed attempt is audited.
    expect(await countRows("audit_logs", { action: "user.register.failed" })).toBeGreaterThan(0);
  });

  test("weak passwords and malformed e-mails are rejected with field details", async () => {
    const client = new ApiClient();
    const response = await client.post("/api/auth/register", {
      email: "not-an-email",
      password: "short",
    });
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe("VALIDATION_ERROR");
    const fields = response.body.error.details.fields.map((field: any) => field.field);
    expect(fields).toContain("email");
    expect(fields).toContain("password");
  });

  test("session cookies are HttpOnly, SameSite=Lax and Secure over HTTPS", async () => {
    const client = new ApiClient();
    const response = await client.post("/api/auth/register", {
      email: uniqueEmail("cookies"),
      password: STRONG_PASSWORD,
    });
    const setCookies = (response.headers as any).getSetCookie() as string[];
    const sessionCookie = setCookies.find((cookie) => cookie.startsWith("domira_session="));
    expect(sessionCookie).toContain("HttpOnly");
    expect(sessionCookie).toContain("SameSite=Lax");
    // Plain HTTP here, so no Secure attribute; over the platform's TLS proxy the
    // same code adds it (see isSecureRequest).
    expect(sessionCookie).not.toContain("Secure");

    const secureClient = new ApiClient();
    const secureResponse = await secureClient.call("POST", "/api/auth/register", {
      body: { email: uniqueEmail("cookies-tls"), password: STRONG_PASSWORD },
      headers: { "x-forwarded-proto": "https" },
    });
    const secureCookies = (secureResponse.headers as any).getSetCookie() as string[];
    expect(secureCookies.find((cookie) => cookie.startsWith("domira_session="))).toContain("Secure");
  });
});

describe("audit trail", () => {
  test("register, login, failed login and logout all write audit rows with ip and user agent", async () => {
    const registered = await registerUser();
    await registered.client.post("/api/auth/login", {
      email: registered.email,
      password: "wrong-password-value",
    });
    const relogged = new ApiClient();
    await relogged.post("/api/auth/login", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    await relogged.post("/api/auth/logout");

    const result = await query<{
      action: string;
      ip: string | null;
      user_agent: string | null;
      outcome: string;
    }>(
      `select action, ip, user_agent, outcome from audit_logs
        where actor_email = $1 or actor_user_id = $2
        order by created_at asc`,
      [registered.email, registered.userId]
    );
    const actions = result.rows.map((row) => row.action);
    expect(actions).toContain("user.register");
    expect(actions).toContain("user.login.failed");
    expect(actions).toContain("user.login");
    expect(actions).toContain("user.logout");
    for (const row of result.rows) {
      expect(row.ip).toBeTruthy();
      expect(row.user_agent).toBeTruthy();
    }
    const failed = result.rows.find((row) => row.action === "user.login.failed");
    expect(failed?.outcome).toBe("failure");
    // No password material is ever written to the audit trail.
    const leak = await query<{ count: number }>(
      `select count(*)::int as count from audit_logs where metadata::text like $1`,
      [`%${STRONG_PASSWORD}%`]
    );
    expect(Number(leak.rows[0]!.count)).toBe(0);
  });
});

describe("rate limiting (database-backed)", () => {
  test("repeated failed logins from one IP are throttled with 429 and Retry-After", async () => {
    const attacker = new ApiClient({ ip: "203.0.113.77" });
    const statuses: number[] = [];
    // A different e-mail each time, so only the per-IP rule can trigger here.
    for (let attempt = 0; attempt < RATE_LIMITS.login.limit + 2; attempt += 1) {
      const response = await attacker.post("/api/auth/login", {
        email: uniqueEmail(`ip-limit-${attempt}`),
        password: "definitely-wrong-password",
      });
      statuses.push(response.status);
      if (response.status === 429) {
        expect(response.headers.get("retry-after")).toBeTruthy();
        expect(response.body.error.code).toBe("RATE_LIMITED");
      }
    }
    expect(statuses.slice(0, RATE_LIMITS.login.limit)).toEqual(
      Array.from({ length: RATE_LIMITS.login.limit }, () => 401)
    );
    expect(statuses.at(-1)).toBe(429);
    // The counter really lives in the database.
    const buckets = await scalar<number>(
      "select count(*)::int from rate_limits where key like $1",
      ["login|ip:203.0.113.77%"]
    );
    expect(buckets).toBeGreaterThan(0);
  });

  test("the login limit is also enforced per e-mail address across IPs", async () => {
    const registered = await registerUser();
    const statuses: number[] = [];
    for (let attempt = 0; attempt < RATE_LIMITS.loginPerEmail.limit + 1; attempt += 1) {
      const client = new ApiClient();
      const response = await client.post("/api/auth/login", {
        email: registered.email,
        password: "wrong-password-again",
      });
      statuses.push(response.status);
    }
    expect(statuses.at(-1)).toBe(429);
  });

  test("register is rate limited per IP", async () => {
    const ip = "203.0.113.99";
    const statuses: number[] = [];
    for (let attempt = 0; attempt < RATE_LIMITS.register.limit + 1; attempt += 1) {
      const client = new ApiClient({ ip });
      const response = await client.post("/api/auth/register", {
        email: uniqueEmail(`flood${attempt}`),
        password: STRONG_PASSWORD,
      });
      statuses.push(response.status);
    }
    expect(statuses.at(-1)).toBe(429);
  });
});

describe("api surface honesty", () => {
  test("GET /api lists the endpoints and marks the unimplemented ones", async () => {
    const response = await new ApiClient().get("/api");
    expect(response.status).toBe(200);
    const alerts = response.body.endpoints.find((endpoint: any) => endpoint.path === "/api/alerts");
    expect(alerts.implemented).toBe(false);
    const domains = response.body.endpoints.find((endpoint: any) => endpoint.path === "/api/domains");
    expect(domains.implemented).toBe(true);
    const me = response.body.endpoints.find((endpoint: any) => endpoint.path === "/api/me");
    expect(me.implemented).toBe(true);
  });

  test("endpoints that are still unimplemented answer 501 with no fabricated data", async () => {
    const registered = await registerUser({ organizationName: "Honest Ltd" });
    for (const path of ["/api/alerts", "/api/reports"]) {
      const response = await registered.client.get(path);
      expect({ path, status: response.status }).toEqual({ path, status: 501 });
      expect(response.body.error.code).toBe("NOT_IMPLEMENTED");
    }
  });

  test("security headers are present on API responses", async () => {
    const response = await new ApiClient().get("/api");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    expect(response.headers.get("permissions-policy")).toContain("geolocation=()");
    expect(response.headers.get("strict-transport-security")).toContain("max-age=");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  test("unknown endpoints and wrong methods answer 404/405 with the shared error shape", async () => {
    const client = new ApiClient();
    const notFound = await client.get("/api/nope");
    expect(notFound.status).toBe(404);
    expect(notFound.body.error.code).toBe("NOT_FOUND");
    const wrongMethod = await client.call("DELETE", "/api/me");
    expect(wrongMethod.status).toBe(405);
    expect(wrongMethod.headers.get("allow")).toContain("GET");
  });
});
