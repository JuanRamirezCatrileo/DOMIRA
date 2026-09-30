/**
 * RBAC: role permissions are enforced in the backend, not by hiding UI.
 * A VIEWER must not be able to perform administrative actions, a MEMBER must not
 * manage members either, and the last administrator of an organisation cannot be
 * demoted or removed.
 */
import { describe, expect, test } from "bun:test";

import { query } from "~/db";
import { roleHasPermission } from "~/server/rbac/permissions";
import { countRows, registerUser, scalar, testContext } from "./helpers/harness";

describe("RBAC matrix", () => {
  test("permission matrix matches the product spec", () => {
    expect(roleHasPermission("VIEWER", "org:read")).toBe(true);
    expect(roleHasPermission("VIEWER", "org:manage_members")).toBe(false);
    expect(roleHasPermission("VIEWER", "domain:manage")).toBe(false);
    expect(roleHasPermission("MEMBER", "domain:manage")).toBe(true);
    expect(roleHasPermission("MEMBER", "org:manage_members")).toBe(false);
    expect(roleHasPermission("ADMIN", "org:manage_members")).toBe(true);
    expect(roleHasPermission("ADMIN", "platform:admin")).toBe(false);
    expect(roleHasPermission("SUPER_ADMIN", "platform:admin")).toBe(true);
  });
});

describe("RBAC enforcement in the backend", () => {
  test("a VIEWER is denied an admin action (403) even with a valid CSRF token", async () => {
    await testContext();
    const admin = await registerUser({ organizationName: "Rbac Ltd" });
    const viewer = await registerUser();
    await query(
      `insert into organization_members (organization_id, user_id, role_code) values ($1, $2, 'VIEWER')`,
      [admin.organizationId, viewer.userId]
    );

    const target = await registerUser();
    const attempt = await viewer.client.post(
      `/api/organizations/${admin.organizationId}/members`,
      { email: target.email, role: "MEMBER" },
      {}
    );
    expect(attempt.status).toBe(403);
    expect(attempt.body.error.code).toBe("FORBIDDEN");
    expect(
      await countRows("organization_members", {
        organization_id: admin.organizationId!,
        user_id: target.userId,
      })
    ).toBe(0);
  });

  test("a VIEWER can still read the organisation and its members", async () => {
    const admin = await registerUser({ organizationName: "Rbac Read Ltd" });
    const viewer = await registerUser();
    await query(
      `insert into organization_members (organization_id, user_id, role_code) values ($1, $2, 'VIEWER')`,
      [admin.organizationId, viewer.userId]
    );
    const overview = await viewer.client.get(`/api/organizations/${admin.organizationId}`);
    expect(overview.status).toBe(200);
    expect(overview.body.role).toBe("VIEWER");
    expect(overview.body.permissions).toEqual(["org:read", "domain:read"]);
    const members = await viewer.client.get(`/api/organizations/${admin.organizationId}/members`);
    expect(members.status).toBe(200);
    expect(members.body.members.length).toBe(2);
  });

  test("a MEMBER cannot change roles or remove members (403)", async () => {
    const admin = await registerUser({ organizationName: "Rbac Member Ltd" });
    const member = await registerUser();
    await query(
      `insert into organization_members (organization_id, user_id, role_code) values ($1, $2, 'MEMBER')`,
      [admin.organizationId, member.userId]
    );
    const patch = await member.client.patch(
      `/api/organizations/${admin.organizationId}/members/${admin.userId}`,
      { role: "VIEWER" }
    );
    expect(patch.status).toBe(403);
    const remove = await member.client.delete(
      `/api/organizations/${admin.organizationId}/members/${admin.userId}`
    );
    expect(remove.status).toBe(403);
    expect(
      await scalar<string>(
        "select role_code from organization_members where organization_id = $1 and user_id = $2",
        [admin.organizationId, admin.userId]
      )
    ).toBe("ADMIN");
  });

  test("an ADMIN can add a member, change a role and remove a member (audited)", async () => {
    const admin = await registerUser({ organizationName: "Rbac Admin Ltd" });
    const invitee = await registerUser({ organizationName: "Invitee Temp Org" });

    const added = await admin.client.post(`/api/organizations/${admin.organizationId}/members`, {
      email: invitee.email,
      role: "VIEWER",
    });
    expect(added.status).toBe(201);
    expect(added.body.member.role).toBe("VIEWER");

    const promoted = await admin.client.patch(
      `/api/organizations/${admin.organizationId}/members/${invitee.userId}`,
      { role: "MEMBER" }
    );
    expect(promoted.status).toBe(200);
    expect(promoted.body.member.role).toBe("MEMBER");

    const removed = await admin.client.delete(
      `/api/organizations/${admin.organizationId}/members/${invitee.userId}`
    );
    expect(removed.status).toBe(200);
    expect(
      await countRows("organization_members", {
        organization_id: admin.organizationId!,
        user_id: invitee.userId,
      })
    ).toBe(0);

    const audit = await query<{ action: string }>(
      `select action from audit_logs where organization_id = $1 order by created_at asc`,
      [admin.organizationId]
    );
    const actions = audit.rows.map((row) => row.action);
    expect(actions).toContain("membership.added");
    expect(actions).toContain("membership.role_changed");
    expect(actions).toContain("membership.removed");
  });

  test("the last administrator cannot be demoted or removed", async () => {
    const owner = await registerUser({ organizationName: "Last Admin Ltd" });
    // A platform super admin demotes the organisation's only administrator: the
    // guard must block it (otherwise the organisation is left unadministrable).
    const platform = await registerUser();
    await query("update users set is_super_admin = true where id = $1", [platform.userId]);

    const blockedDemote = await platform.client.patch(
      `/api/organizations/${owner.organizationId}/members/${owner.userId}`,
      { role: "VIEWER" }
    );
    expect(blockedDemote.status).toBe(409);
    expect(blockedDemote.body.error.message).toContain("administrator");

    const blockedRemove = await platform.client.delete(
      `/api/organizations/${owner.organizationId}/members/${owner.userId}`
    );
    expect(blockedRemove.status).toBe(409);

    expect(
      await scalar<string>(
        "select role_code from organization_members where organization_id = $1 and user_id = $2",
        [owner.organizationId, owner.userId]
      )
    ).toBe("ADMIN");
  });

  test("a user cannot change their own role", async () => {
    const admin = await registerUser({ organizationName: "Self Role Ltd" });
    const response = await admin.client.patch(
      `/api/organizations/${admin.organizationId}/members/${admin.userId}`,
      { role: "VIEWER" }
    );
    expect(response.status).toBe(409);
    expect(
      await scalar<string>(
        "select role_code from organization_members where organization_id = $1 and user_id = $2",
        [admin.organizationId, admin.userId]
      )
    ).toBe("ADMIN");
  });

  test("SUPER_ADMIN-only endpoints reject ordinary users (403)", async () => {
    const user = await registerUser({ organizationName: "Not Platform Ltd" });
    const response = await user.client.get("/api/admin/outbox");
    expect(response.status).toBe(403);
  });

  test("anonymous callers cannot reach the admin outbox (401)", async () => {
    const { ApiClient } = await import("./helpers/harness");
    const response = await new ApiClient().get("/api/admin/outbox");
    expect(response.status).toBe(401);
  });
});
