/**
 * DNS resolution for the passive scanner.
 *
 * Two interchange-compatible implementations behind one interface:
 *
 *   * `doh`  — DNS over HTTPS (RFC 8484 JSON API), queried against a public
 *              resolver (Cloudflare 1.1.1.1 by default, Quad9 and Google also
 *              work; endpoint configurable through DOMIRA_DOH_ENDPOINT). Use this
 *              when the runtime cannot open UDP/53 (many serverless and container
 *              platforms block it). Verified to work from this sandbox.
 *   * `node` — `node:dns/promises` over the host's UDP/TCP resolver. Works from
 *              this sandbox too and is the fallback.
 *
 * `auto` (the default) tries DoH first and falls back to the system resolver, so
 * the same code runs on a VPS, on Render or on Cloudflare Workers' fetch-only
 * runtime. The choice and its portability are documented in docs/scanning.md.
 *
 * Tests inject a deterministic resolver with `setDnsResolver()` — the real
 * resolvers stay behind this seam and are never mocked inside application code.
 */
import { Resolver } from "node:dns/promises";
import { isIPv4, isIPv6 } from "node:net";

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT" | "CAA";

export const DNS_RECORD_TYPES: readonly DnsRecordType[] = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "NS",
  "TXT",
  "CAA",
];

export interface DnsAnswer {
  type: DnsRecordType;
  name: string;
  value: string;
  ttl: number | null;
  priority: number | null;
}

/** A real lookup failure (distinct from "the record does not exist"). */
export class DnsLookupError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "DnsLookupError";
    this.code = code;
  }
}

export interface DnsResolver {
  readonly kind: string;
  /** Resolves one record type. Empty array = NODATA; throws DnsLookupError on failure. */
  query(hostname: string, type: DnsRecordType): Promise<DnsAnswer[]>;
}

/* -------------------------------------------------------------------------- */
/* DNS over HTTPS                                                             */
/* -------------------------------------------------------------------------- */

const DOH_TYPE_NAMES: Record<number, DnsRecordType> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  257: "CAA",
};

interface DohAnswer {
  name: string;
  type: number;
  TTL?: number;
  data: string;
}

/** DNS-name JSON responses quote TXT chunks; concatenate them like a real client. */
function normalizeTxtValue(data: string): string {
  const quoted = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((match) => match[1] ?? "");
  if (quoted.length > 0) return quoted.join("");
  return data.replace(/^"|"$/g, "");
}

function normalizeValue(type: DnsRecordType, data: string): { value: string; priority: number | null } {
  if (type === "MX") {
    const match = /^(\d+)\s+(.*)$/.exec(data.trim());
    if (match) return { value: (match[2] ?? "").replace(/\.$/, ""), priority: Number(match[1]) };
  }
  if (type === "TXT") return { value: normalizeTxtValue(data), priority: null };
  if (type === "A" || type === "AAAA") return { value: data.trim(), priority: null };
  return { value: data.trim().replace(/\.$/, ""), priority: null };
}

export class DohResolver implements DnsResolver {
  readonly kind = "doh";
  private readonly endpoint: string;
  private readonly timeoutMs: number;

  constructor(options: { endpoint?: string; timeoutMs?: number } = {}) {
    this.endpoint =
      options.endpoint ??
      process.env.DOMIRA_DOH_ENDPOINT ??
      "https://cloudflare-dns.com/dns-query";
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  async query(hostname: string, type: DnsRecordType): Promise<DnsAnswer[]> {
    const url = `${this.endpoint}${this.endpoint.includes("?") ? "&" : "?"}name=${encodeURIComponent(
      hostname
    )}&type=${type}`;
    let response: Response;
    try {
      response = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      const code =
        (error as { name?: string }).name === "TimeoutError" ? "TIMEOUT" : "DOH_UNREACHABLE";
      throw new DnsLookupError(code, `DNS over HTTPS request failed (${code}) for ${hostname} ${type}.`);
    }
    if (!response.ok) {
      throw new DnsLookupError("DOH_HTTP_ERROR", `DNS over HTTPS answered HTTP ${response.status}.`);
    }
    const payload = (await response.json()) as {
      Status?: number;
      Answer?: DohAnswer[];
      Authority?: DohAnswer[];
    };
    const status = payload.Status ?? 0;
    if (status === 3) {
      throw new DnsLookupError("NXDOMAIN", `${hostname} does not exist (NXDOMAIN).`);
    }
    if (status !== 0) {
      throw new DnsLookupError("SERVFAIL", `The resolver answered status ${status} for ${hostname} ${type}.`);
    }
    return (payload.Answer ?? [])
      .filter((answer) => DOH_TYPE_NAMES[answer.type] === type)
      .map((answer) => {
        const normalized = normalizeValue(type, answer.data);
        return {
          type,
          name: answer.name.replace(/\.$/, ""),
          value: normalized.value,
          ttl: typeof answer.TTL === "number" ? answer.TTL : null,
          priority: normalized.priority,
        };
      });
  }
}

/* -------------------------------------------------------------------------- */
/* Node's system resolver                                                     */
/* -------------------------------------------------------------------------- */

function mapNodeError(error: unknown, hostname: string, type: DnsRecordType): DnsLookupError {
  const code = (error as { code?: string }).code ?? "EUNKNOWN";
  const messages: Record<string, string> = {
    ENOTFOUND: `${hostname} does not exist (ENOTFOUND).`,
    ENODATA: `No ${type} record for ${hostname} (ENODATA).`,
    ESERVFAIL: `The resolver failed (SERVFAIL) for ${hostname}.`,
    ETIMEOUT: `The DNS lookup for ${hostname} timed out.`,
    ECONNREFUSED: `The system resolver refused the connection (no UDP/53 egress).`,
  };
  return new DnsLookupError(code, messages[code] ?? `DNS lookup failed for ${hostname} ${type} (${code}).`);
}

export class NodeResolver implements DnsResolver {
  readonly kind = "node";
  private readonly resolver: Resolver;

  constructor(options: { timeoutMs?: number } = {}) {
    this.resolver = new Resolver({ timeout: options.timeoutMs ?? 5000, tries: 1 });
  }

  async query(hostname: string, type: DnsRecordType): Promise<DnsAnswer[]> {
    const name = hostname;
    try {
      switch (type) {
        case "A":
          return (await this.resolver.resolve4(name)).map((value) => ({
            type,
            name,
            value,
            ttl: null,
            priority: null,
          }));
        case "AAAA":
          return (await this.resolver.resolve6(name)).map((value) => ({
            type,
            name,
            value,
            ttl: null,
            priority: null,
          }));
        case "CNAME":
          return (await this.resolver.resolveCname(name)).map((value) => ({
            type,
            name,
            value: value.replace(/\.$/, ""),
            ttl: null,
            priority: null,
          }));
        case "NS":
          return (await this.resolver.resolveNs(name)).map((value) => ({
            type,
            name,
            value: value.replace(/\.$/, ""),
            ttl: null,
            priority: null,
          }));
        case "MX":
          return (await this.resolver.resolveMx(name)).map((entry) => ({
            type,
            name,
            value: entry.exchange.replace(/\.$/, ""),
            ttl: null,
            priority: entry.priority,
          }));
        case "TXT":
          return (await this.resolver.resolveTxt(name)).map((chunks) => ({
            type,
            name,
            value: chunks.join(""),
            ttl: null,
            priority: null,
          }));
        case "CAA": {
          const records = await this.resolver.resolveCaa(name);
          return records.map((record) => ({
            type,
            name,
            value: [record.critical ? "critical" : "issue", record.issue ?? record.iodef ?? ""]
              .filter(Boolean)
              .join(" "),
            ttl: null,
            priority: null,
          }));
        }
        default:
          return [];
      }
    } catch (error) {
      const code = (error as { code?: string }).code;
      // ENODATA / ENOTFOUND for a single type means "NODATA", not a broken lookup:
      // only report a failure when the whole zone cannot be resolved.
      if (code === "ENODATA") return [];
      if (code === "ENOTFOUND") {
        if (type !== "A") {
          const reachable = await this.resolver.resolve4(name).catch(() => null);
          if (reachable && reachable.length > 0) return [];
        }
      }
      throw mapNodeError(error, name, type);
    }
  }
}

/** Tries each resolver in order; rethrows the first error when all of them fail. */
export class FallbackResolver implements DnsResolver {
  readonly kind: string;
  constructor(private readonly resolvers: DnsResolver[]) {
    this.kind = `fallback(${resolvers.map((resolver) => resolver.kind).join("+")})`;
  }

  async query(hostname: string, type: DnsRecordType): Promise<DnsAnswer[]> {
    let firstError: unknown = null;
    for (const resolver of this.resolvers) {
      try {
        return await resolver.query(hostname, type);
      } catch (error) {
        firstError ??= error;
      }
    }
    throw firstError ?? new DnsLookupError("EUNKNOWN", `No resolver could answer ${hostname} ${type}.`);
  }
}

let injected: DnsResolver | null = null;
let cached: DnsResolver | null = null;

/** Test seam: force a deterministic resolver. */
export function setDnsResolver(resolver: DnsResolver | null): void {
  injected = resolver;
}

export function getDnsResolver(): DnsResolver {
  if (injected) return injected;
  if (cached) return cached;
  const mode = (process.env.DOMIRA_DNS_RESOLVER ?? "auto").toLowerCase();
  const timeoutMs = 5000;
  if (mode === "node") cached = new NodeResolver({ timeoutMs });
  else if (mode === "doh") cached = new DohResolver({ timeoutMs });
  else cached = new FallbackResolver([new DohResolver({ timeoutMs }), new NodeResolver({ timeoutMs })]);
  return cached;
}

/* -------------------------------------------------------------------------- */
/* Address safety — SSRF defence for the scanner                              */
/* -------------------------------------------------------------------------- */

function ipv4IsPublic(address: string): boolean {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false;
  const [a = 0, b = 0] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // 100.64/10 CGNAT
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0) return false; // 192.0.0/24 + 192.0.2/24
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51) return false; // 198.51.100/24
  if (a === 203 && b === 0) return false; // 203.0.113/24
  return true;
}

function ipv6IsPublic(address: string): boolean {
  const value = address.toLowerCase().split("%")[0] ?? "";
  if (value === "::" || value === "::1") return false;
  if (value.startsWith("fe80") || value.startsWith("fc") || value.startsWith("fd")) return false;
  if (value.startsWith("ff")) return false; // multicast
  // IPv4-mapped (::ffff:a.b.c.d) inherits the IPv4 rules.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
  if (mapped) return ipv4IsPublic(mapped[1]!);
  if (/^2001:0?db8/.test(value)) return false; // documentation range
  return true;
}

export function isPublicAddress(address: string): boolean {
  if (isIPv4(address)) return ipv4IsPublic(address);
  if (isIPv6(address)) return ipv6IsPublic(address);
  return false;
}

/**
 * Every address a hostname resolves to must be a public, routable address.
 * Without this a customer could point a "domain" at 169.254.169.254 (cloud
 * metadata), 127.0.0.1 or a private RFC1918 host and turn DOMIRA into an SSRF
 * proxy. The check is deliberately fail-closed: DNS that cannot be resolved, or
 * resolves to anything non-public, stops the connection-based checks.
 */
export function findNonPublicAddresses(addresses: readonly string[]): string[] {
  return addresses.filter((address) => !isPublicAddress(address));
}
