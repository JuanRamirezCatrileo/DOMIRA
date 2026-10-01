/**
 * Domain management + the ownership verification gate.
 *
 * Covers the strict hostname validation (the SSRF first filter), the lifecycle,
 * the RBAC rules, the verification flow with a real DNS TXT check behind the
 * resolver seam, and tenant isolation for every domain endpoint.
 */
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { query } from "~/db";
import {
  HostnameRejectedError,
  assertValidHostname,
  publicSuffix,
  registeredDomain,
  validateHostname,
} from "~/server/api/domain-validation";
import { ApiClient, registerUser, scalar, uniqueEmail } from "./helpers/harness";
import {
  HEALTHY_RECORDS,
  addMemberWithRole,
  installFixtureResolver,
  registerVerifiedDomain,
  resetScanningFixtures,
} from "./helpers/scanning";

let owner: Awaited<ReturnType<typeof registerUser>>;
let organizationId: string;

beforeEach(async () => {
  owner = await registerUser({ organizationName: `domains-${Math.random().toString(36).slice(2, 8)}` });
  organizationId = owner.organizationId!;
});

afterEach(() => {
  resetScanningFixtures();
  delete process.env.DOMIRA_VERIFICATION_MAX_ATTEMPTS;
});

describe("hostname validation (SSRF first filter)", () => {
  const rejected: Array<[string, string]> = [
    ["192.168.1.1", "IP literal"],
    ["93.184.216.34", "public IP literal"],
    ["2130706433", "decimal-encoded 127.0.0.1"],
    ["0x7f000001", "hex-encoded 127.0.0.1"],
    ["[::1]", "IPv6 literal"],
    ["::1", "IPv6 literal"],
    ["https://example.com", "URL with scheme"],
    ["example.com/path", "path"],
    ["example.com:8443", "port"],
    ["user@example.com", "credentials"],
    ["*.example.com", "wildcard"],
    ["example.com.", "trailing dot"],
    ["localhost", "internal hostname"],
    ["foo.internal", "reserved suffix"],
    ["metadata.google.internal", "cloud metadata endpoint"],
    ["printer.local", "mDNS namespace"],
    ["com", "public suffix only"],
    ["example.123", "numeric TLD"],
    ["notadomain", "single label"],
    ["example.zzz", "unsupported TLD"],
    ["domira.cl", "the platform's own hostname"],
  ];

  for (const [hostname, description] of rejected) {
    test(`rejects ${hostname} (${description})`, async () => {
      const response = await owner.client.post("/api/domains", { hostname, organizationId });
      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
      expect(await scalar<number>("select count(*)::int from domains where hostname = $1", [hostname])).toBe(0);
    });
  }

  test("accepts a normal registrable domain and returns the exact TXT record", async () => {
    const response = await owner.client.post("/api/domains", {
      hostname: "Example.COM",
      displayName: "Example",
      organizationId,
    });
    expect(response.status).toBe(201);
    expect(response.body.domain.hostname).toBe("example.com");
    expect(response.body.domain.status).toBe("pending_verification");
    expect(response.body.verification.recordName).toBe("_domira-verification.example.com");
    expect(response.body.verification.recordType).toBe("TXT");
    expect(response.body.verification.recordValue).toMatch(/^domira-site-verification=/);
    expect(response.body.verification.expiresAt).toBeTruthy();
  });

  /**
   * REGRESSION (deliverable 2a): the "public suffix only" check compared the
   * hostname against the REGISTERED domain instead of the public suffix, so the
   * slice after the registered domain was always empty and every bare registrable
   * domain (`example.com`) was rejected — the single most common input of the whole
   * product. Subdomains passed only by accident. These cases pin the behaviour.
   */
  test("accepts a bare registrable domain for every supported suffix shape", async () => {
    const cases: Array<[input: string, normalized: string, registered: string]> = [
      ["example.com", "example.com", "example.com"],
      ["domira-demo.cl", "domira-demo.cl", "domira-demo.cl"],
      ["something.co.uk", "something.co.uk", "something.co.uk"],
      ["algo.com.ar", "algo.com.ar", "algo.com.ar"],
    ];

    for (const [input, normalized, registered] of cases) {
      const validation = validateHostname(input);
      expect(validation).toMatchObject({ ok: true, hostname: normalized });
      // The suffix is never the hostname, and the registered domain is the hostname.
      expect(publicSuffix(normalized)).not.toBe(normalized);
      expect(registeredDomain(normalized)).toBe(registered);
    }

    // ...and the same four names are accepted by the real endpoint.
    for (const [input, normalized, registered] of cases) {
      const response = await owner.client.post("/api/domains", { hostname: input, organizationId });
      expect(response.status).toBe(201);
      expect(response.body.domain.hostname).toBe(normalized);
      expect(response.body.domain.registeredDomain).toBe(registered);
      expect(response.body.verification.recordName).toBe(`_domira-verification.${normalized}`);
    }
  });

  test("accepts a subdomain and reports the registrable name, never the public suffix", async () => {
    expect(validateHostname("sub.example.com")).toMatchObject({ ok: true, hostname: "sub.example.com" });
    expect(publicSuffix("sub.example.com")).toBe("com");
    expect(registeredDomain("sub.example.com")).toBe("example.com");

    // foo.co.uk is a registrable domain: its registered domain is itself, not co.uk.
    expect(publicSuffix("foo.co.uk")).toBe("co.uk");
    expect(registeredDomain("foo.co.uk")).toBe("foo.co.uk");
    expect(registeredDomain("a.b.co.uk")).toBe("b.co.uk");

    const response = await owner.client.post("/api/domains", { hostname: "sub.example.com", organizationId });
    expect(response.status).toBe(201);
    expect(response.body.domain.registeredDomain).toBe("example.com");
  });

  test("rejects a public suffix used as the whole domain with code public_suffix_only", async () => {
    for (const suffix of ["com", "co.uk"]) {
      const validation = validateHostname(suffix);
      expect(validation.ok).toBe(false);
      expect(validation.code).toBe("public_suffix_only");
      expect(validation.message).toContain("public suffix");
      // A public suffix has no registrable domain either.
      expect(registeredDomain(suffix)).toBeNull();

      expect(() => assertValidHostname(suffix)).toThrow(HostnameRejectedError);

      const response = await owner.client.post("/api/domains", { hostname: suffix, organizationId });
      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe("VALIDATION_ERROR");
      expect(String(response.body.error.details?.hostname)).toContain("public suffix");
      expect(await scalar<number>("select count(*)::int from domains where hostname = $1", [suffix])).toBe(0);
    }
  });

  test("rejects a duplicate domain inside the same organisation with 409", async () => {
    const first = await owner.client.post("/api/domains", { hostname: "dup.example.com", organizationId });
    expect(first.status).toBe(201);
    const second = await owner.client.post("/api/domains", { hostname: "dup.example.com", organizationId });
    expect(second.status).toBe(409);
  });
});

describe("ownership verification gate", () => {
  test("an unverified domain cannot be scanned, and no scan row is created", async () => {
    installFixtureResolver();
    const created = await owner.client.post("/api/domains", { hostname: "unverified.example.com", organizationId });
    const domainId = created.body.domain.id;

    const scan = await owner.client.post(`/api/domains/${domainId}/scan`, {});
    expect(scan.status).toBe(409);
    expect(scan.body.error.message).toContain("not verified");
    expect(await scalar<number>("select count(*)::int from scans where domain_id = $1", [domainId])).toBe(0);
    expect(await scalar<number>("select count(*)::int from jobs where domain_id = $1", [domainId])).toBe(0);
  });

  test("verify fails while the TXT record is absent and succeeds once it is published", async () => {
    const resolver = installFixtureResolver();
    const created = await owner.client.post("/api/domains", { hostname: "gate.example.com", organizationId });
    const domainId = created.body.domain.id;

    const missing = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(missing.status).toBe(409);
    expect(missing.body.verified).toBe(false);
    expect(missing.body.reason).toBe("record_not_found");
    expect(missing.body.attempts).toBe(1);

    resolver.addRecords(created.body.verification.recordName, {
      TXT: [created.body.verification.recordValue],
    });
    const verified = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(verified.status).toBe(200);
    expect(verified.body.verified).toBe(true);
    expect(verified.body.domain.status).toBe("verified");

    const scan = await owner.client.post(`/api/domains/${domainId}/scan`, {});
    expect(scan.status).toBe(202);
  });

  test("a token that does not match is refused and, after the attempt limit, a new token is issued", async () => {
    process.env.DOMIRA_VERIFICATION_MAX_ATTEMPTS = "2";
    const resolver = installFixtureResolver();
    const created = await owner.client.post("/api/domains", { hostname: "attempts.example.com", organizationId });
    const domainId = created.body.domain.id;
    resolver.addRecords(created.body.verification.recordName, { TXT: ["domira-site-verification=wrong-token"] });

    const first = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(first.status).toBe(409);
    expect(first.body.reason).toBe("record_not_found");
    expect(first.body.observedRecords).toEqual(["domira-site-verification=wrong-token"]);

    const second = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(second.status).toBe(409);
    expect(second.body.reason).toBe("attempts_exhausted");
    expect(second.body.attempts).toBe(2);

    // The exhausted token is retired and a fresh one is issued on the next attempt.
    const third = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(third.status).toBe(409);
    expect(third.body.tokenReissued).toBe(true);
    const freshRecord = third.body.verification.recordValue as string;
    expect(freshRecord).not.toBe(created.body.verification.recordValue);

    resolver.addRecords(created.body.verification.recordName, { TXT: [freshRecord] });
    const verified = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(verified.status).toBe(200);
    expect(verified.body.verified).toBe(true);
  });

  test("an expired token can never verify a domain", async () => {
    const resolver = installFixtureResolver();
    const created = await owner.client.post("/api/domains", { hostname: "expired.example.com", organizationId });
    const domainId = created.body.domain.id;
    resolver.addRecords(created.body.verification.recordName, {
      TXT: [created.body.verification.recordValue],
    });
    await query("update domain_verifications set expires_at = now() - interval '1 minute' where domain_id = $1", [
      domainId,
    ]);

    const attempt = await owner.client.post(`/api/domains/${domainId}/verify`, {});
    expect(attempt.status).toBe(409);
    expect(["token_expired", "record_not_found"]).toContain(attempt.body.reason);
    expect(await scalar<string>("select status from domains where id = $1", [domainId])).toBe("pending_verification");
  });
});

describe("domain lifecycle and roles", () => {
  test("pause, resume and archive follow the documented state machine", async () => {
    const verified = await registerVerifiedDomain(owner.client, {
      hostname: "lifecycle.example.com",
      organizationId,
    });

    const paused = await owner.client.patch(`/api/domains/${verified.domainId}`, { status: "paused" });
    expect(paused.status).toBe(200);
    expect(paused.body.domain.status).toBe("paused");
    expect(paused.body.domain.monitoringEnabled).toBe(false);

    const blocked = await owner.client.post(`/api/domains/${verified.domainId}/scan`, {});
    expect(blocked.status).toBe(409);

    const resumed = await owner.client.patch(`/api/domains/${verified.domainId}`, { status: "verified" });
    expect(resumed.status).toBe(200);
    expect(resumed.body.domain.status).toBe("verified");

    const archived = await owner.client.patch(`/api/domains/${verified.domainId}`, { status: "archived" });
    expect(archived.status).toBe(200);
    expect(archived.body.domain.status).toBe("archived");

    const resumeArchived = await owner.client.patch(`/api/domains/${verified.domainId}`, { status: "verified" });
    expect(resumeArchived.status).toBe(409);
  });

  test("a domain that was never verified cannot be resumed", async () => {
    const created = await owner.client.post("/api/domains", { hostname: "never.example.com", organizationId });
    const response = await owner.client.patch(`/api/domains/${created.body.domain.id}`, { status: "verified" });
    expect(response.status).toBe(409);
    expect(response.body.error.message).toContain("never been verified");
  });

  test("DELETE removes the domain from every listing and cancels pending work", async () => {
    const verified = await registerVerifiedDomain(owner.client, { hostname: "delete-me.example.com", organizationId });
    await owner.client.post(`/api/domains/${verified.domainId}/scan`, {});

    const deleted = await owner.client.delete(`/api/domains/${verified.domainId}`);
    expect(deleted.status).toBe(200);
    expect(deleted.body.ok).toBe(true);

    expect((await owner.client.get(`/api/domains/${verified.domainId}`)).status).toBe(404);
    const list = await owner.client.get(`/api/domains?organizationId=${organizationId}`);
    expect(list.body.domains.some((domain: { id: string }) => domain.id === verified.domainId)).toBe(false);
    expect(
      await scalar<string>("select status from scans where domain_id = $1", [verified.domainId])
    ).toBe("cancelled");
  });

  test("pagination is real: perPage is honoured and the total is reported", async () => {
    for (const hostname of ["p1.example.com", "p2.example.com", "p3.example.com"]) {
      const created = await owner.client.post("/api/domains", { hostname, organizationId });
      expect(created.status).toBe(201);
    }
    const page = await owner.client.get(`/api/domains?organizationId=${organizationId}&perPage=2&page=1`);
    expect(page.status).toBe(200);
    expect(page.body.domains).toHaveLength(2);
    expect(page.body.pagination.perPage).toBe(2);
    expect(page.body.pagination.total).toBeGreaterThanOrEqual(3);
    const second = await owner.client.get(`/api/domains?organizationId=${organizationId}&perPage=2&page=2`);
    expect(second.body.domains.length).toBeGreaterThanOrEqual(1);
    expect(second.body.domains[0].id).not.toBe(page.body.domains[0].id);
  });
});

describe("role rules (enforced in the backend, not the UI)", () => {
  test("MEMBER can create and scan, but cannot rename; VIEWER is read-only", async () => {
    const member = await addMemberWithRole(owner.client, organizationId, "MEMBER");
    const viewer = await addMemberWithRole(owner.client, organizationId, "VIEWER");

    const memberDomain = await member.client.post("/api/domains", {
      hostname: "member-domain.example.com",
      organizationId,
    });
    expect(memberDomain.status).toBe(201);

    const rename = await member.client.patch(`/api/domains/${memberDomain.body.domain.id}`, {
      displayName: "renamed",
    });
    expect(rename.status).toBe(403);

    const memberDelete = await member.client.delete(`/api/domains/${memberDomain.body.domain.id}`);
    expect(memberDelete.status).toBe(403);

    const viewerCreate = await viewer.client.post("/api/domains", {
      hostname: "viewer-domain.example.com",
      organizationId,
    });
    expect(viewerCreate.status).toBe(403);

    const viewerList = await viewer.client.get(`/api/domains?organizationId=${organizationId}`);
    expect(viewerList.status).toBe(200);

    const viewerRead = await viewer.client.get(`/api/domains/${memberDomain.body.domain.id}`);
    expect(viewerRead.status).toBe(200);

    const viewerScan = await viewer.client.post(`/api/domains/${memberDomain.body.domain.id}/scan`, {});
    expect(viewerScan.status).toBe(403);

    const adminRename = await owner.client.patch(`/api/domains/${memberDomain.body.domain.id}`, {
      displayName: "renamed by admin",
    });
    expect(adminRename.status).toBe(200);
    expect(adminRename.body.domain.displayName).toBe("renamed by admin");

    // A MEMBER of the same organisation can scan another member's verified domain.
    const verified = await registerVerifiedDomain(owner.client, {
      hostname: "member-scan.example.com",
      organizationId,
    });
    const memberScan = await member.client.post(`/api/domains/${verified.domainId}/scan`, {});
    expect(memberScan.status).toBe(202);
  });
});

describe("tenant isolation — domains", () => {
  test("another organisation's domain cannot be read, scanned, renamed, verified or deleted", async () => {
    const other = await registerUser({ organizationName: `other-${Math.random().toString(36).slice(2, 8)}` });
    const otherOrgId = other.organizationId!;
    const resolver = installFixtureResolver();
    const otherDomain = await other.client.post("/api/domains", {
      hostname: "other-tenant.example.com",
      organizationId: otherOrgId,
    });
    expect(otherDomain.status).toBe(201);
    const otherDomainId = otherDomain.body.domain.id;
    resolver.addRecords(otherDomain.body.verification.recordName, {
      TXT: [otherDomain.body.verification.recordValue],
    });

    // The intruder is a legitimate organisation of its own, with its own token.
    const intruderDomain = await owner.client.post("/api/domains", {
      hostname: "intruder.example.com",
      organizationId,
    });
    expect(intruderDomain.status).toBe(201);
    resolver.addRecords(intruderDomain.body.verification.recordName, {
      TXT: [intruderDomain.body.verification.recordValue],
    });

    expect((await owner.client.get(`/api/domains/${otherDomainId}`)).status).toBe(404);
    expect((await owner.client.patch(`/api/domains/${otherDomainId}`, { displayName: "stolen" })).status).toBe(404);
    expect((await owner.client.delete(`/api/domains/${otherDomainId}`)).status).toBe(404);
    expect((await owner.client.post(`/api/domains/${otherDomainId}/verify`, {})).status).toBe(404);
    expect((await owner.client.post(`/api/domains/${otherDomainId}/scan`, {})).status).toBe(404);
    expect((await owner.client.get(`/api/domains/${otherDomainId}/security`)).status).toBe(404);
    expect((await owner.client.get(`/api/domains/${otherDomainId}/scans`)).status).toBe(404);
    expect((await owner.client.get(`/api/domains?organizationId=${otherOrgId}`)).status).toBe(404);

    // Nothing of the other tenant changed.
    expect(await scalar<string>("select display_name from domains where id = $1", [otherDomainId])).toBeNull();
    expect(await scalar<string>("select status from domains where id = $1", [otherDomainId])).toBe(
      "pending_verification"
    );
    expect(await scalar<number>("select count(*)::int from domains where deleted_at is not null and id = $1", [otherDomainId])).toBe(0);
  });

  test("organisation A's verification token cannot verify organisation B's domain", async () => {
    const other = await registerUser({ organizationName: `other2-${Math.random().toString(36).slice(2, 8)}` });
    const otherOrgId = other.organizationId!;
    const resolver = installFixtureResolver();

    // B publishes its own token for its own domain.
    const domainB = await other.client.post("/api/domains", {
      hostname: "b-domain.example.com",
      organizationId: otherOrgId,
    });
    resolver.addRecords(domainB.body.verification.recordName, { TXT: [domainB.body.verification.recordValue] });

    // A obtains a token for the very same hostname, and publishes it too.
    const domainA = await owner.client.post("/api/domains", {
      hostname: "b-domain.example.com",
      organizationId,
    });
    expect(domainA.status).toBe(201);
    expect(domainA.body.verification.recordValue).not.toBe(domainB.body.verification.recordValue);
    resolver.addRecords(domainA.body.verification.recordName, { TXT: [domainA.body.verification.recordValue] });

    // A cannot verify B's domain even though A controls a matching TXT record for
    // that hostname: the lookup and the update are keyed by (organisation, domain).
    const crossVerify = await owner.client.post(`/api/domains/${domainB.body.domain.id}/verify`, {});
    expect(crossVerify.status).toBe(404);
    expect(await scalar<string>("select status from domains where id = $1", [domainB.body.domain.id])).toBe(
      "pending_verification"
    );
    expect(
      await scalar<string>("select status from domain_verifications where domain_id = $1", [domainB.body.domain.id])
    ).toBe("pending");

    // A's own domain verifies with A's token, which is the only value published at
    // that record name at this point.
    expect((await owner.client.post(`/api/domains/${domainA.body.domain.id}/verify`, {})).status).toBe(200);

    // Republish B's own token: B verifies its domain, proving the check follows the
    // (organisation, domain) pair and not merely "some token exists at the name".
    resolver.addRecords(domainB.body.verification.recordName, { TXT: [domainB.body.verification.recordValue] });
    expect((await other.client.post(`/api/domains/${domainB.body.domain.id}/verify`, {})).status).toBe(200);
  });

  test("an unauthenticated caller cannot touch domains at all", async () => {
    const anonymous = new ApiClient({ origin: "http://localhost" });
    expect((await anonymous.get("/api/domains")).status).toBe(401);
    expect((await anonymous.post("/api/domains", { hostname: uniqueEmail("anonymous") })).status).toBe(401);
  });
});
