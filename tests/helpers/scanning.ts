/**
 * Deterministic fixtures for the scanning tests.
 *
 * The scan pipeline is exercised end to end — API, queue, worker, engine,
 * persistence, score — with the network behind the documented seams:
 *
 *   * `setDnsResolver()` (src/server/scanning/dns.ts) — DNS answers, including the
 *     real shape of the verification TXT lookup;
 *   * `setTlsProbe()` / `setAvailabilityProbe()` (src/server/scanning/probes.ts) —
 *     the TCP/TLS handshake and the HTTPS request.
 *
 * The application code is never mocked: the real engine runs, the real SQL is
 * executed, only the network edge is supplied by the test. The real probes against a
 * real public domain are exercised by `bun run verify:real-scan`
 * (scripts/verify-real-scan.ts) — see docs/scanning.md, "Real run evidence".
 */
import { setDnsResolver, type DnsAnswer, type DnsRecordType, type DnsResolver } from "~/server/scanning/dns";
import { setAvailabilityProbe, setTlsProbe } from "~/server/scanning/probes";
import type { AvailabilityProbeResult } from "~/server/scanning/availability";
import type { CertificateObservation, TlsProbeResult } from "~/server/scanning/tls";
import { registerJobHandler, resetJobHandlers } from "~/server/queue/worker";
import { ApiClient } from "./harness";

/** A public, routable address so the scanner's SSRF guard lets the check through. */
export const FIXTURE_PUBLIC_IPV4 = "93.184.216.34";
export const VERIFICATION_PREFIX = "_domira-verification.";

export type FixtureRecords = Partial<Record<DnsRecordType, string[]>>;

export class FixtureResolver implements DnsResolver {
  readonly kind = "fixture";
  readonly queries: Array<{ name: string; type: DnsRecordType }> = [];
  private readonly byName = new Map<string, FixtureRecords>();

  constructor(private records: FixtureRecords = {}) {}

  setRecords(records: FixtureRecords): void {
    this.records = records;
  }

  /** Adds answers for one exact name (used for the verification TXT record). */
  addRecords(name: string, records: FixtureRecords): void {
    this.byName.set(name.toLowerCase(), records);
  }

  queriesFor(name: string): number {
    return this.queries.filter((entry) => entry.name === name.toLowerCase()).length;
  }

  async query(hostname: string, type: DnsRecordType): Promise<DnsAnswer[]> {
    const name = hostname.toLowerCase().replace(/\.$/, "");
    this.queries.push({ name, type });
    const table = this.byName.get(name) ?? (name.startsWith(VERIFICATION_PREFIX) ? {} : this.records);
    const values = table[type] ?? [];
    return values.map((value) => ({
      type,
      name,
      value,
      ttl: 300,
      priority: type === "MX" ? 10 : null,
    }));
  }
}

/** Records for a domain that is up, resolving, with e-mail and NS but no CAA/AAAA. */
export const HEALTHY_RECORDS: FixtureRecords = {
  A: [FIXTURE_PUBLIC_IPV4],
  NS: ["ns1.example.net", "ns2.example.net"],
  MX: ["mail.example.net"],
  TXT: ["v=spf1 -all"],
};

export function installFixtureResolver(records: FixtureRecords = HEALTHY_RECORDS): FixtureResolver {
  const resolver = new FixtureResolver(records);
  setDnsResolver(resolver);
  return resolver;
}

export function healthyCertificate(hostname: string, overrides: Partial<CertificateObservation> = {}): CertificateObservation {
  const notBefore = new Date(Date.now() - 30 * 86_400_000).toISOString();
  const notAfter = new Date(Date.now() + 200 * 86_400_000).toISOString();
  return {
    subjectCn: hostname,
    issuerCn: "DOMIRA Test Intermediate CA",
    issuerOrganization: "DOMIRA Test Issuing Authority",
    serialNumber: "0a1b2c3d4e5f",
    fingerprintSha256: "test-fingerprint-not-a-real-certificate",
    notBefore,
    notAfter,
    daysRemaining: 200,
    keyAlgorithm: "RSA",
    keySize: 2048,
    san: [hostname, `www.${hostname}`],
    hostnameMatches: true,
    isWildcard: false,
    selfSigned: false,
    chainValid: true,
    chainLength: 2,
    chainError: null,
    issues: [],
    ...overrides,
  };
}

export function healthyTls(hostname: string, overrides: Partial<TlsProbeResult> = {}): TlsProbeResult {
  return {
    ok: true,
    errorCode: null,
    error: null,
    durationMs: 42,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
    checkedHostname: hostname,
    checkedPort: 443,
    certificate: healthyCertificate(hostname),
    ...overrides,
  };
}

export function healthyAvailability(
  hostname: string,
  overrides: Partial<AvailabilityProbeResult> = {}
): AvailabilityProbeResult {
  return {
    ok: true,
    errorCode: null,
    error: null,
    durationMs: 120,
    finalUrl: `https://${hostname}/`,
    statusCode: 200,
    responseTimeMs: 120,
    hops: [{ url: `https://${hostname}/`, status: 200, location: null }],
    redirectCount: 0,
    serverHeader: "fixture",
    httpToHttpsRedirect: true,
    plainHttpStatus: 301,
    plainHttpError: null,
    plainHttpLocation: `https://${hostname}/`,
    ...overrides,
  };
}

export interface ProbeFixtureOptions {
  tls?: (hostname: string) => TlsProbeResult;
  availability?: (hostname: string) => AvailabilityProbeResult;
}

export function installHealthyProbes(options: ProbeFixtureOptions = {}): void {
  setTlsProbe(async (hostname) => (options.tls ?? healthyTls)(hostname));
  setAvailabilityProbe(async (hostname) => (options.availability ?? healthyAvailability)(hostname));
}

/** Restores every real implementation. Call from afterEach. */
export function resetScanningFixtures(): void {
  setDnsResolver(null);
  setTlsProbe(null);
  setAvailabilityProbe(null);
  resetJobHandlers();
}

export interface VerifiedDomain {
  domainId: string;
  hostname: string;
  resolver: FixtureResolver;
  verification: { recordName: string; recordValue: string; expiresAt: string };
}

/**
 * Adds a domain through the API, publishes the fixture TXT record and verifies it,
 * so the returned domain is genuinely verified — the tests then exercise the real
 * gate rather than bypassing it.
 */
export async function registerVerifiedDomain(
  client: ApiClient,
  options: { hostname: string; organizationId?: string; monitoringEnabled?: boolean; checkFrequency?: string; records?: FixtureRecords }
): Promise<VerifiedDomain> {
  const resolver = installFixtureResolver(options.records ?? HEALTHY_RECORDS);
  installHealthyProbes();
  const hostname = options.hostname;
  const created = await client.post("/api/domains", {
    hostname,
    ...(options.organizationId ? { organizationId: options.organizationId } : {}),
    ...(options.monitoringEnabled === undefined ? {} : { monitoringEnabled: options.monitoringEnabled }),
    ...(options.checkFrequency ? { checkFrequency: options.checkFrequency } : {}),
  });
  if (created.status !== 201) {
    throw new Error(`domain creation failed: ${created.status} ${JSON.stringify(created.body)}`);
  }
  const domainId: string = created.body.domain.id;
  const verification = created.body.verification as VerifiedDomain["verification"];
  resolver.addRecords(verification.recordName, { TXT: [verification.recordValue] });
  const verified = await client.post(`/api/domains/${domainId}/verify`, {});
  if (verified.status !== 200 || !verified.body.verified) {
    throw new Error(`domain verification failed: ${verified.status} ${JSON.stringify(verified.body)}`);
  }
  return { domainId, hostname, resolver, verification };
}

/** Registers a user and adds them to an existing organisation with a given role. */
export async function addMemberWithRole(
  owner: ApiClient,
  organizationId: string,
  role: "ADMIN" | "MEMBER" | "VIEWER"
): Promise<{ client: ApiClient; userId: string; email: string }> {
  const { registerUser } = await import("./harness");
  const member = await registerUser({ organizationName: `standalone-${Math.random().toString(36).slice(2, 8)}` });
  const added = await owner.post(`/api/organizations/${organizationId}/members`, {
    email: member.email,
    role,
  });
  if (added.status !== 201) {
    throw new Error(`adding member failed: ${added.status} ${JSON.stringify(added.body)}`);
  }
  return { client: member.client, userId: member.userId, email: member.email };
}

export { registerJobHandler };
