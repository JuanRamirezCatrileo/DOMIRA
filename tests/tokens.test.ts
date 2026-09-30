/**
 * Account e-mail flows: verification and password reset tokens.
 *
 * There is no e-mail integration in this business, so the contract under test is:
 * the token is generated, stored HASHED, expires, is single-use, and the link is
 * available to a platform administrator through the outbox. Nothing is "sent".
 */
import { beforeAll, describe, expect, test } from "bun:test";

import { query } from "~/db";
import { generateToken } from "~/server/auth/sessions";
import {
  STRONG_PASSWORD,
  registerUser,
  promoteToSuperAdmin,
  scalar,
  testContext,
} from "./helpers/harness";

beforeAll(async () => {
  await testContext();
});

async function superAdminClient() {
  const platform = await registerUser();
  await promoteToSuperAdmin(platform.userId);
  return platform;
}

async function latestOutboxLink(kind: string): Promise<string> {
  const platform = await superAdminClient();
  const response = await platform.client.get(`/api/admin/outbox?kind=${kind}&limit=1`);
  expect(response.status).toBe(200);
  expect(response.body.emailIntegrationConfigured).toBe(false);
  const message = response.body.messages[0];
  expect(message.status).toBe("pending");
  return message.actionUrl as string;
}

function tokenFromLink(link: string): string {
  return new URL(link).searchParams.get("token")!;
}

describe("e-mail verification tokens", () => {
  test("the raw token is never stored — only its hash", async () => {
    const registered = await registerUser();
    const raw = registered.verificationToken!;
    expect(raw.length).toBeGreaterThan(20);
    const stored = await scalar<string>(
      "select token_hash from email_verification_tokens where user_id = $1",
      [registered.userId]
    );
    expect(stored).not.toBe(raw);
    expect(stored).toHaveLength(64);
    expect(
      await scalar<number>(
        "select count(*)::int from email_verification_tokens where token_hash = $1",
        [raw]
      )
    ).toBe(0);
  });

  test("verifying marks the account verified and the token cannot be reused", async () => {
    const registered = await registerUser();
    const first = await registered.client.post("/api/auth/verify-email", {
      token: registered.verificationToken!,
    });
    expect(first.status).toBe(200);
    expect(first.body.verified).toBe(true);
    const me = await registered.client.get("/api/me");
    expect(me.body.user.emailVerified).toBe(true);

    const second = await registered.client.post("/api/auth/verify-email", {
      token: registered.verificationToken!,
    });
    expect(second.status).toBe(400);
    expect(second.body.error.message).toContain("invalid or has expired");
  });

  test("an expired verification token is rejected", async () => {
    const registered = await registerUser();
    const { token, hash } = generateToken();
    await query(
      `insert into email_verification_tokens (user_id, email, token_hash, expires_at)
       values ($1, $2, $3, now() - interval '1 minute')`,
      [registered.userId, registered.email, hash]
    );
    const response = await registered.client.post("/api/auth/verify-email", { token });
    expect(response.status).toBe(400);
    expect(
      await scalar<Date | null>("select email_verified_at from users where id = $1", [
        registered.userId,
      ])
    ).toBeNull();
  });
});

describe("password reset tokens", () => {
  test("forgot-password always answers the same way and writes a pending outbox message", async () => {
    const registered = await registerUser();
    const known = await registered.client.post("/api/auth/forgot-password", {
      email: registered.email,
    });
    const unknown = await registered.client.post("/api/auth/forgot-password", {
      email: `ghost-${registered.userId}@example.test`,
    });
    expect(known.status).toBe(202);
    expect(unknown.status).toBe(202);
    expect(known.body.message).toEqual(unknown.body.message);
    expect(known.body.emailSent).toBe(false);

    const pending = await scalar<number>(
      "select count(*)::int from outbox_messages where user_id = $1 and kind = 'password_reset' and status = 'pending'",
      [registered.userId]
    );
    expect(pending).toBe(1);
    expect(
      await scalar<number>(
        "select count(*)::int from outbox_messages where to_email = $1",
        [`ghost-${registered.userId}@example.test`]
      )
    ).toBe(0);
  });

  test("a platform admin can read the reset link from the outbox and complete the flow", async () => {
    const registered = await registerUser();
    await registered.client.post("/api/auth/forgot-password", { email: registered.email });
    const link = await latestOutboxLink("password_reset");
    expect(link).toContain("/reset-password?token=");

    const reset = await registered.client.post("/api/auth/reset-password", {
      token: tokenFromLink(link),
      password: "Brand-New-Domira-Password-2026",
    });
    expect(reset.status).toBe(200);

    // Old password no longer works, the new one does.
    const { ApiClient } = await import("./helpers/harness");
    const oldLogin = await new ApiClient().post("/api/auth/login", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    expect(oldLogin.status).toBe(401);
    const newLogin = await new ApiClient().post("/api/auth/login", {
      email: registered.email,
      password: "Brand-New-Domira-Password-2026",
    });
    expect(newLogin.status).toBe(200);
  });

  test("a reset token is single use", async () => {
    const registered = await registerUser();
    await registered.client.post("/api/auth/forgot-password", { email: registered.email });
    const link = await latestOutboxLink("password_reset");
    const token = tokenFromLink(link);

    const first = await registered.client.post("/api/auth/reset-password", {
      token,
      password: "First-Reset-Password-2026x",
    });
    expect(first.status).toBe(200);
    const second = await registered.client.post("/api/auth/reset-password", {
      token,
      password: "Second-Reset-Password-2026",
    });
    expect(second.status).toBe(400);

    const { ApiClient } = await import("./helpers/harness");
    const login = await new ApiClient().post("/api/auth/login", {
      email: registered.email,
      password: "First-Reset-Password-2026x",
    });
    expect(login.status).toBe(200);
  });

  test("an expired reset token is rejected and the password is unchanged", async () => {
    const registered = await registerUser();
    const { token, hash } = generateToken();
    await query(
      `insert into password_reset_tokens (user_id, token_hash, expires_at)
       values ($1, $2, now() - interval '1 second')`,
      [registered.userId, hash]
    );
    const response = await registered.client.post("/api/auth/reset-password", {
      token,
      password: "Expired-Token-Password-2026",
    });
    expect(response.status).toBe(400);

    const { ApiClient } = await import("./helpers/harness");
    const login = await new ApiClient().post("/api/auth/login", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    expect(login.status).toBe(200);
  });

  test("resetting a password revokes every existing session of that account", async () => {
    const registered = await registerUser();
    const secondSession = new (await import("./helpers/harness")).ApiClient();
    await secondSession.post("/api/auth/login", {
      email: registered.email,
      password: STRONG_PASSWORD,
    });
    expect((await secondSession.get("/api/me")).status).toBe(200);

    await registered.client.post("/api/auth/forgot-password", { email: registered.email });
    const link = await latestOutboxLink("password_reset");
    await registered.client.post("/api/auth/reset-password", {
      token: tokenFromLink(link),
      password: "Rotated-Password-Domira-2026",
    });

    expect((await registered.client.get("/api/me")).status).toBe(401);
    expect((await secondSession.get("/api/me")).status).toBe(401);
  });
});
