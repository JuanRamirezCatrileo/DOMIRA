/**
 * TENANT ISOLATION — the critical security property of a multi-tenant product.
 *
 * Two organisations exist, each with its own administrator. Every assertion below
 * tries to cross the boundary (read, list, mutate, delete) using the *real* id of
 * the other organisation, and every attempt must fail with 404 (never 403, which
 * would confirm the id exists) and leave the other tenant's data untouched.
 */
import { beforeAll, describe, expect, test } from "bun:test";

import { query } from "~/db";
import { getMembership } from "~/server/rbac/guard";
import {
  ApiClient,
  STRONG_PASSWORD,
  countRows,
  registerUser,
  scalar,
  testContext,
  uniqueEmail,
  type RegisteredUser,
} from "./helpers/harness";

let orgA: RegisteredUser;
let orgB: RegisteredUser;
let memberOfB: RegisteredUser;
let outsider: RegisteredUser;

beforeAll(async () => {
  await testContext();
  orgA = await registerUser({ organizationName: "Alpha Corp" });
  orgB = await registerUser({ organizationName: "Bravo Corp" });
  // A third account that is a VIEWER inside organisation B only.
  memberOfB = await registerUser();
  await query(
    `insert into organization_members (organization_id, user_id, role_code) values ($1, $2, 'VIEWER')`,
    [orgB.organizationId, memberOfB.userId]
  );
  // A fourth account in no organisation at all.
  outsider = await registerUser();
});

describe("tenant isolation: read and list", () => {
  test("GET /api/organizations lists only the caller's own organisations", async () => {
    const response = await orgA.client.get("/api/organizations");
    expect(response.status).toBe(200);
    const ids = response.body.organizations.map((org: any) => org.organizationId);
    expect(ids).toEqual([orgA.organizationId]);
    expect(ids).not.toContain(orgB.organizationId);
  });

  test("GET /api/organizations/:id with another tenant's valid id returns 404", async () => {
    const response = await orgA.client.get(`/api/organizations/${orgB.organizationId}`);
    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe("NOT_FOUND");
  });

  test("GET /api/organizations/:id/members with another tenant's valid id returns 404", async () => {
    const response = await orgA.client.get(
      `/api/organizations/${orgB.organizationId}/members`
    );
    expect(response.status).toBe(404);
    expect(JSON.stringify(response.body)).not.toContain(orgB.email);
  });

  test("GET /api/me never leaks another organisation's membership", async () => {
    const response = await orgA.client.get("/api/me");
    expect(response.status).toBe(200);
    const ids = response.body.memberships.map((org: any) => org.organizationId);
    expect(ids).not.toContain(orgB.organizationId);
    expect(ids).not.toContain(memberOfB.organizationId ?? "none");
  });

  test("a VIEWER of the other tenant also gets 404, not data", async () => {
    const response = await memberOfB.client.get(
      `/api/organizations/${orgA.organizationId}/members`
    );
    expect(response.status).toBe(404);
  });

  test("an account with no membership gets 404 for any organisation id", async () => {
    const response = await outsider.client.get(`/api/organizations/${orgA.organizationId}`);
    expect(response.status).toBe(404);
  });

  test("getMembership() returns null across tenants (guard-level proof)", async () => {
    expect(await getMembership(orgA.userId, orgB.organizationId!)).toBeNull();
    expect(await getMembership(orgB.userId, orgA.organizationId!)).toBeNull();
  });
});

describe("tenant isolation: mutate and delete", () => {
  test("POST /api/organizations/:id/members cannot add a user to another tenant", async () => {
    const before = await countRows("organization_members", {
      organization_id: orgB.organizationId!,
    });
    const response = await orgA.client.post(`/api/organizations/${orgB.organizationId}/members`, {
      email: outsider.email,
      role: "MEMBER",
    });
    expect(response.status).toBe(404);
    const after = await countRows("organization_members", {
      organization_id: orgB.organizationId!,
    });
    expect(after).toBe(before);
    expect(
      await countRows("organization_members", {
        organization_id: orgB.organizationId!,
        user_id: outsider.userId,
      })
    ).toBe(0);
  });

  test("PATCH /api/organizations/:id/members/:userId cannot change another tenant's role", async () => {
    const response = await orgA.client.patch(
      `/api/organizations/${orgB.organizationId}/members/${orgB.userId}`,
      { role: "VIEWER" }
    );
    expect(response.status).toBe(404);
    const role = await scalar<string>(
      "select role_code from organization_members where organization_id = $1 and user_id = $2",
      [orgB.organizationId, orgB.userId]
    );
    expect(role).toBe("ADMIN");
  });

  test("DELETE /api/organizations/:id/members/:userId cannot remove another tenant's admin", async () => {
    const response = await orgA.client.delete(
      `/api/organizations/${orgB.organizationId}/members/${orgB.userId}`
    );
    expect(response.status).toBe(404);
    expect(
      await countRows("organization_members", {
        organization_id: orgB.organizationId!,
        user_id: orgB.userId,
      })
    ).toBe(1);
  });

  test("PATCH /api/organizations/:id cannot rename another tenant", async () => {
    const response = await orgA.client.patch(`/api/organizations/${orgB.organizationId}`, {
      name: "Hijacked Corp",
    });
    expect(response.status).toBe(404);
    const name = await scalar<string>("select name from organizations where id = $1", [
      orgB.organizationId,
    ]);
    expect(name).toBe("Bravo Corp");
  });

  test("guessing ids in bulk never yields another tenant's data", async () => {
    const attempted = await Promise.all(
      [orgB.organizationId!, memberOfB.userId, "00000000-0000-4000-8000-000000000000"].map((id) =>
        orgA.client.get(`/api/organizations/${id}/members`)
      )
    );
    for (const response of attempted) {
      expect([404]).toContain(response.status);
      expect(JSON.stringify(response.body)).not.toContain("@example.test");
    }
  });
});

describe("tenant isolation: unauthenticated access", () => {
  test("no session gets 401 (never data) on every organisation endpoint", async () => {
    const client = new ApiClient();
    const paths = [
      ["GET", "/api/me"],
      ["GET", "/api/organizations"],
      ["POST", "/api/organizations"],
      ["GET", `/api/organizations/${orgA.organizationId}`],
      ["GET", `/api/organizations/${orgA.organizationId}/members`],
      ["POST", `/api/organizations/${orgA.organizationId}/members`],
      ["PATCH", `/api/organizations/${orgA.organizationId}/members/${orgA.userId}`],
      ["DELETE", `/api/organizations/${orgA.organizationId}/members/${orgA.userId}`],
      ["GET", "/api/admin/outbox"],
    ] as const;
    for (const [method, path] of paths) {
      const response = await client.call(method, path, {
        body: method === "GET" || method === "DELETE" ? undefined : { email: uniqueEmail() },
      });
      expect({ method, path, status: response.status }).toEqual({ method, path, status: 401 });
    }
  });

  test("a suspended account cannot reuse its session", async () => {
    const victim = await registerUser({ organizationName: "Gamma Corp" });
    await query("update users set status = 'suspended' where id = $1", [victim.userId]);
    const response = await victim.client.get("/api/me");
    expect(response.status).toBe(403);
  });

  test("a revoked session stops working immediately", async () => {
    const victim = await registerUser({ organizationName: "Delta Corp" });
    expect((await victim.client.get("/api/me")).status).toBe(200);
    await query("update sessions set revoked_at = now() where user_id = $1", [victim.userId]);
    expect((await victim.client.get("/api/me")).status).toBe(401);
  });

  test("cross-origin state-changing requests are rejected (CSRF origin check)", async () => {
    const attacker = new ApiClient({ origin: "https://evil.example" });
    // Copy the victim's cookies into the attacker's jar: the session cookie is what
    // a browser would send on a cross-site form post.
    for (const [key, value] of orgA.client.cookies) attacker.cookies.set(key, value);
    const response = await attacker.post("/api/organizations", { name: "Evil Corp" }, { csrf: null });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("CSRF_FAILED");
  });

  test("a state-changing request without the CSRF token is rejected", async () => {
    const response = await orgA.client.post(
      "/api/organizations",
      { name: "No Token Corp" },
      { csrf: null }
    );
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe("CSRF_FAILED");
  });

  test("login with the wrong password does not reveal that the account exists", async () => {
    const known = await registerUser();
    const wrongPassword = await known.client.post("/api/auth/login", {
      email: known.email,
      password: `${STRONG_PASSWORD}-nope`,
    });
    const unknownAccount = await known.client.post("/api/auth/login", {
      email: uniqueEmail("ghost"),
      password: STRONG_PASSWORD,
    });
    expect(wrongPassword.status).toBe(401);
    expect(unknownAccount.status).toBe(401);
    expect(wrongPassword.body).toEqual(unknownAccount.body);
  });
});
