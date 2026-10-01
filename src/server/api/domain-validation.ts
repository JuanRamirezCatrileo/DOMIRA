/**
 * Hostname validation for the "add a domain" endpoint.
 *
 * A scanning product is a powerful SSRF primitive: whatever hostname a tenant can
 * register, DOMIRA will later resolve and open a TCP/TLS connection to. So the
 * hostname is validated strictly, fail-closed, BEFORE it is stored:
 *
 *   * only DNS names (letters, digits, hyphen, dot) — never an IP literal, never a
 *     URL, never a port, path, credentials, wildcard or trailing dot;
 *   * at least two labels, each label 1-63 chars, whole name <= 253;
 *   * the public suffix must be a real one from a small explicit allow-list (so
 *     `localhost`, `foo.internal`, `metadata.google.internal` and friends are
 *     rejected even when they look like DNS names);
 *   * the reserved/internal namespaces (`.internal`, `.local`, `.localhost`,
 *     `.invalid`, `.test`, `.home.arpa`, `.onion`, ...) are rejected by name.
 *     `example.com` is deliberately NOT reserved: IANA operates it for
 *     documentation, it resolves publicly, and the engine's own end-to-end check
 *     (scripts/verify-example-com.ts) scans it;
 *   * the platform's own hostname(s) are rejected, so nobody can point DOMIRA at
 *     itself;
 *   * the name must not be, or end in, a numeric-looking TLD that could be used to
 *     dodge the IP checks.
 *
 * The runtime SSRF guard is the second layer: even a valid name must resolve to
 * public addresses only (see findNonPublicAddresses in src/server/scanning/dns.ts)
 * before any connection is opened. Validation in the API is a cheap first filter;
 * it is never the only defence.
 */

/** Namespaces that can never be a customer's public domain. */
const RESERVED_SUFFIXES = [
  "internal",
  "local",
  "localhost",
  "invalid",
  "test",
  "home.arpa",
  "arpa",
  "onion",
  "i2p",
  "lan",
  "intranet",
  "corp",
  "private",
  "localdomain",
  "in-addr.arpa",
  "ip6.arpa",
] as const;

/**
 * Public suffixes DOMIRA accepts today. Deliberately an allow-list: it keeps the
 * rule auditable and makes "reject public suffixes like 'com' used as the whole
 * domain" trivially true. Extend it as customers onboard, or replace it with the
 * Public Suffix List when the product needs global coverage (documented in
 * docs/security.md).
 */
const ALLOWED_SUFFIXES = [
  "cl",
  "com",
  "net",
  "org",
  "io",
  "dev",
  "app",
  "ai",
  "co",
  "es",
  "mx",
  "ar",
  "pe",
  "br",
  "uk",
  "us",
  "eu",
  "de",
  "fr",
  "it",
  "nl",
  "se",
  "info",
  "biz",
  "cloud",
  "tech",
  "online",
  "site",
  "store",
  "edu",
  "gov",
  "mil",
] as const;

/** Multi-label suffixes that must match as a whole (checked before the table above). */
const ALLOWED_MULTI_LABEL_SUFFIXES = [
  "com.cl",
  "com.ar",
  "com.br",
  "com.mx",
  "com.pe",
  "co.uk",
  "org.uk",
  "gov.uk",
  "co.nz",
  "com.au",
  "co.jp",
] as const;

const LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export interface HostnameValidationResult {
  ok: boolean;
  /** Normalised (lowercase, no trailing dot) hostname when ok. */
  hostname?: string;
  /** Machine-readable rejection code, e.g. `ip_literal`. */
  code?: string;
  message?: string;
}

export class HostnameRejectedError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "HostnameRejectedError";
    this.code = code;
  }
}

/**
 * Hostnames that belong to the platform itself. `DOMIRA_PLATFORM_HOSTS` is a
 * comma-separated list (the published hostname is added there by deployment);
 * `DOMIRA_PUBLIC_URL`'s host is always included.
 */
export function platformHostnames(): string[] {
  const hosts = new Set<string>();
  const configured = process.env.DOMIRA_PLATFORM_HOSTS;
  if (configured) {
    for (const entry of configured.split(",")) {
      const value = entry.trim().toLowerCase();
      if (value) hosts.add(value);
    }
  }
  const publicUrl = process.env.DOMIRA_PUBLIC_URL;
  if (publicUrl) {
    try {
      hosts.add(new URL(publicUrl).hostname.toLowerCase());
    } catch {
      /* an unparsable DOMIRA_PUBLIC_URL is reported by deployment checks, not here */
    }
  }
  hosts.add("domira.cl");
  hosts.add("domira.com");
  hosts.add("www.domira.cl");
  hosts.add("www.domira.com");
  return [...hosts];
}

/** True when the string is a bare IPv4/IPv6 literal (no validation of its value). */
function looksLikeIpLiteral(value: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return true;
  // Decimal/hex/octal single-integer IPv4 forms: 2130706433, 0x7f000001, 017700000001.
  if (/^(0x[0-9a-f]+|\d{8,}|0[0-7]{7,})$/.test(value)) return true;
  if (value.includes(":")) return true; // any IPv6 form (bracketed or not)
  return false;
}

/**
 * The rejection used when the input IS a public suffix (with or without further
 * labels below it): there is no registrable name and therefore nothing to monitor.
 */
function publicSuffixOnly(hostname: string): HostnameValidationResult {
  return {
    ok: false,
    code: "public_suffix_only",
    message: `"${hostname}" is a public suffix, not a registerable domain. Add the name you actually own, for example "example.${hostname}".`,
  };
}

export function validateHostname(input: string): HostnameValidationResult {
  const raw = String(input ?? "").trim();
  if (raw.length === 0) {
    return { ok: false, code: "empty", message: "Enter a domain name." };
  }
  if (raw.length > 253) {
    return { ok: false, code: "too_long", message: "A domain name is at most 253 characters." };
  }
  // A URL, port, path or credentials in the value is always a mistake or an attack.
  if (/[\s/@?#\\]/.test(raw) || raw.includes(":")) {
    return {
      ok: false,
      code: "not_a_hostname",
      message: "Enter a bare domain name — no scheme, port, path or credentials.",
    };
  }
  if (raw.includes("*")) {
    return {
      ok: false,
      code: "wildcard",
      message: "Wildcards are not accepted. Add each hostname you want monitored.",
    };
  }

  let hostname = raw.toLowerCase();
  // A single trailing dot is legal DNS but confusing in a UI and a known SSRF
  // bypass trick; reject it rather than silently normalising.
  if (hostname.endsWith(".")) {
    return { ok: false, code: "trailing_dot", message: "Remove the trailing dot." };
  }

  let ascii: string;
  try {
    // Accept IDN input but store the ASCII (punycode) form, which is what DNS and
    // TLS actually use.
    ascii = new URL(`http://${hostname}`).hostname.toLowerCase();
  } catch {
    return { ok: false, code: "invalid", message: "That does not look like a domain name." };
  }
  if (ascii !== hostname) {
    // `new URL` lowercases and punycodes; a difference means the value contained
    // something the URL parser interpreted (e.g. userinfo) rather than a plain name.
    if (ascii.includes(".") && !/[\s/@?#\\:]/.test(ascii)) hostname = ascii;
    else return { ok: false, code: "invalid", message: "That does not look like a domain name." };
  }

  if (looksLikeIpLiteral(hostname)) {
    return {
      ok: false,
      code: "ip_literal",
      message: "IP addresses cannot be registered. DOMIRA monitors domain names.",
    };
  }

  const labels = hostname.split(".");
  if (labels.length < 2) {
    // A single label is either a public suffix typed on its own (`com`, which is a
    // real suffix and therefore a public_suffix_only rejection) or not a domain name
    // at all (`notadomain`, `localhost`).
    if (hostname === publicSuffix(hostname)) {
      return publicSuffixOnly(hostname);
    }
    return {
      ok: false,
      code: "single_label",
      message: "Enter a full domain name, for example example.com.",
    };
  }
  for (const label of labels) {
    if (!LABEL_PATTERN.test(label)) {
      return {
        ok: false,
        code: "invalid_label",
        message: `"${label}" is not a valid domain label.`,
      };
    }
  }
  // A numeric TLD (example.123) is the decimal-IP encoding of an address in disguise.
  if (/^\d+$/.test(labels[labels.length - 1]!)) {
    return {
      ok: false,
      code: "numeric_tld",
      message: "That domain name ends in a number, which is not a registrable domain.",
    };
  }

  for (const reserved of RESERVED_SUFFIXES) {
    if (hostname === reserved || hostname.endsWith(`.${reserved}`)) {
      return {
        ok: false,
        code: "reserved_suffix",
        message: `".${reserved}" is a reserved, non-public namespace and cannot be monitored.`,
      };
    }
  }
  // Compare the hostname with the matched PUBLIC SUFFIX (the multi-label suffix when
  // one matches, else the last label) — never with the registered domain. `com` and
  // `co.uk` used as a whole domain are public suffixes: there is nothing to register
  // and nothing to monitor, so they are rejected. Before this, the check compared the
  // hostname against the registered domain and therefore also rejected every bare
  // registrable domain (`example.com`), which is the single most common input.
  const suffix = publicSuffix(hostname);
  if (suffix === null) {
    return {
      ok: false,
      code: "unsupported_suffix",
      message:
        "That domain's top-level suffix is not supported yet. Contact us if you need it monitored.",
    };
  }
  if (hostname === suffix) {
    return publicSuffixOnly(hostname);
  }
  const registered = registeredDomain(hostname)!;

  const platform = platformHostnames();
  if (platform.includes(hostname) || platform.includes(registered)) {
    return {
      ok: false,
      code: "platform_hostname",
      message: "That hostname belongs to the DOMIRA platform itself and cannot be monitored.",
    };
  }

  return { ok: true, hostname };
}

/**
 * The public suffix of a hostname: the matched multi-label suffix when one applies
 * (`co.uk` for `foo.co.uk`), else the single last label (`com` for `example.com`).
 * Returns null when the suffix is not in the supported table.
 *
 * This — not the registered domain — is what tells "a domain I own" apart from
 * "a public suffix typed as the whole domain".
 */
export function publicSuffix(hostname: string): string | null {
  const labels = hostname.split(".");
  for (const suffix of ALLOWED_MULTI_LABEL_SUFFIXES) {
    const suffixLength = suffix.split(".").length;
    if (labels.length >= suffixLength && labels.slice(-suffixLength).join(".") === suffix) {
      return suffix;
    }
  }
  const last = labels[labels.length - 1]!;
  return (ALLOWED_SUFFIXES as readonly string[]).includes(last) ? last : null;
}

/**
 * Returns the registered domain (e.g. `example.com`, `foo.com.ar`) for a hostname
 * whose suffix is supported, or null when the suffix is unknown OR when the hostname
 * is itself the public suffix (there is no registrable name in that case).
 */
export function registeredDomain(hostname: string): string | null {
  const labels = hostname.split(".");
  const suffix = publicSuffix(hostname);
  if (suffix === null) return null;
  const suffixLength = suffix.split(".").length;
  if (labels.length <= suffixLength) return null;
  return labels.slice(-(suffixLength + 1)).join(".");
}

/** Throws HostnameRejectedError when the hostname may not be registered. */
export function assertValidHostname(input: string): { hostname: string; registeredDomain: string } {
  const result = validateHostname(input);
  if (!result.ok) throw new HostnameRejectedError(result.code!, result.message!);
  const domain = registeredDomain(result.hostname!);
  if (!domain) {
    throw new HostnameRejectedError(
      "unsupported_suffix",
      "That domain's top-level suffix is not supported yet."
    );
  }
  return { hostname: result.hostname!, registeredDomain: domain };
}
