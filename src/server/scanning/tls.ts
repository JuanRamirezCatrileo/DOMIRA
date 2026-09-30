/**
 * Passive TLS / certificate check.
 *
 * One TCP connect + TLS handshake per assessment, against port 443 of the
 * authorised domain. Nothing is sent beyond the handshake: the check never
 * requests a path, never uses a legacy protocol to probe downgrade support and
 * never attempts exploitation. A second handshake with certificate validation
 * enabled is used to get a real verdict on chain trust from the same client.
 *
 * Values captured: negotiated protocol and cipher, certificate subject/issuer,
 * validity window and days remaining, key algorithm and size, SAN list, whether
 * the name on the certificate matches the hostname, self-signed / chain errors.
 */
import { X509Certificate, createHash } from "node:crypto";
import tls from "node:tls";

export interface CertificateObservation {
  subjectCn: string | null;
  issuerCn: string | null;
  issuerOrganization: string | null;
  serialNumber: string | null;
  fingerprintSha256: string | null;
  notBefore: string | null;
  notAfter: string | null;
  daysRemaining: number | null;
  keyAlgorithm: string | null;
  keySize: number | null;
  san: string[];
  hostnameMatches: boolean;
  isWildcard: boolean;
  selfSigned: boolean;
  chainValid: boolean | null;
  chainLength: number | null;
  chainError: string | null;
  issues: string[];
}

export interface TlsProbeResult {
  ok: boolean;
  errorCode: string | null;
  error: string | null;
  durationMs: number;
  protocol: string | null;
  cipher: string | null;
  checkedHostname: string;
  checkedPort: number;
  certificate: CertificateObservation | null;
}

export interface TlsProbeOptions {
  port?: number;
  timeoutMs?: number;
}

/** First non-empty value from a certificate NameObject-ish structure. */
function nameField(
  name: Array<{ name: string; value: string }> | Record<string, string> | undefined,
  field: string
): string | null {
  if (!name) return null;
  if (Array.isArray(name)) {
    const found = name.find((entry) => entry.name === field);
    return found ? found.value : null;
  }
  const value = (name as Record<string, string>)[field];
  return typeof value === "string" ? value : null;
}

function daysUntil(date: string | null): number | null {
  if (!date) return null;
  const timestamp = new Date(date).getTime();
  if (!Number.isFinite(timestamp)) return null;
  return Math.floor((timestamp - Date.now()) / (1000 * 60 * 60 * 24));
}

function parseSanList(subjectAltName: string | undefined): string[] {
  if (!subjectAltName) return [];
  return subjectAltName
    .split(/,\s*/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.toUpperCase().startsWith("DNS:"))
    .map((entry) => entry.slice(4).toLowerCase());
}

interface HandshakeOutcome {
  protocol: string | null;
  cipher: string | null;
  certificate: tls.PeerCertificate;
  chainLength: number;
}

function handshake(
  hostname: string,
  port: number,
  timeoutMs: number,
  rejectUnauthorized: boolean
): Promise<HandshakeOutcome> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized,
        // Capture what the server presents even when validation fails; the validity
        // verdict is then recorded explicitly instead of aborting the observation.
        minVersion: "TLSv1",
        maxVersion: "TLSv1.3",
      },
      () => {
        const certificate = socket.getPeerCertificate(true);
        let chainLength = 0;
        let current: tls.PeerCertificate | undefined = certificate;
        const seen = new Set<string>();
        while (current && current.raw) {
          const fingerprint = current.fingerprint256 ?? String(chainLength);
          if (seen.has(fingerprint)) break;
          seen.add(fingerprint);
          chainLength += 1;
          current = (current.issuerCertificate as tls.PeerCertificate | undefined) ?? undefined;
        }
        const outcome: HandshakeOutcome = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          certificate,
          chainLength,
        };
        socket.end();
        finish(() => resolve(outcome));
      }
    );
    socket.setTimeout(timeoutMs, () => {
      const error = new Error(`TLS handshake timed out after ${timeoutMs} ms.`);
      (error as { code?: string }).code = "TIMEOUT";
      socket.destroy();
      finish(() => reject(error));
    });
    socket.on("error", (error) => {
      socket.destroy();
      finish(() => reject(error));
    });
  });
}

/**
 * Runs the TLS assessment. Never throws: a failure is a real, reported check
 * error (`ok: false` plus the raw error text and code).
 */
export async function probeTls(
  hostname: string,
  options: TlsProbeOptions = {}
): Promise<TlsProbeResult> {
  const port = options.port ?? 443;
  const timeoutMs = options.timeoutMs ?? 10000;
  const started = Date.now();
  const base: TlsProbeResult = {
    ok: false,
    errorCode: null,
    error: null,
    durationMs: 0,
    protocol: null,
    cipher: null,
    checkedHostname: hostname,
    checkedPort: port,
    certificate: null,
  };

  let observed: HandshakeOutcome;
  let validationErrorCode: string | null = null;
  try {
    // Second connection first: strict, so a validation failure is a real verdict.
    try {
      await handshake(hostname, port, timeoutMs, true);
    } catch (error) {
      validationErrorCode = (error as { code?: string }).code ?? "VALIDATION_FAILED";
    }
    observed = await handshake(hostname, port, timeoutMs, false);
  } catch (error) {
    const code = (error as { code?: string }).code ?? "TLS_ERROR";
    return {
      ...base,
      errorCode: code,
      error: `${code}: ${(error as Error).message}`,
      durationMs: Date.now() - started,
    };
  }

  const { certificate: raw } = observed;
  const san = parseSanList(raw.subjectaltname);
  let keyAlgorithm: string | null = null;
  let keySize: number | null = null;
  let hostnameMatches = false;
  let fingerprintSha256 = raw.fingerprint256 ?? null;
  try {
    const x509 = new X509Certificate(raw.raw);
    fingerprintSha256 = x509.fingerprint256.replace(/:/g, "").toLowerCase();
    keyAlgorithm = x509.publicKey.asymmetricKeyType ?? null;
    const details = x509.publicKey.asymmetricKeyDetails ?? {};
    if (keyAlgorithm === "rsa" || keyAlgorithm === "rsa-pss") {
      keySize = (details as { modulusLength?: number }).modulusLength ?? null;
    } else if (keyAlgorithm === "ec") {
      const curve = (details as { namedCurve?: string }).namedCurve ?? "";
      const curveSizes: Record<string, number> = { prime256v1: 256, secp384r1: 384, secp521r1: 521 };
      keySize = curveSizes[curve] ?? null;
    }
    hostnameMatches = Boolean(x509.checkHost(hostname, { subject: "default" }));
  } catch (error) {
    // Fall back to the cleartext peer fields when the DER cannot be parsed.
    hostnameMatches = san.includes(hostname.toLowerCase());
    fingerprintSha256 = fingerprintSha256 ?? createHash("sha256").update(raw.raw).digest("hex");
    base.error = `Certificate could not be parsed: ${(error as Error).message}`;
  }

  const subjectCn = nameField(raw.subject as never, "CN");
  const issuerCn = nameField(raw.issuer as never, "CN");
  const issuerOrganization = nameField(raw.issuer as never, "O");
  const selfSigned = Boolean(subjectCn && issuerCn && subjectCn === issuerCn && observed.chainLength <= 1);
  const issues: string[] = [];
  const daysRemaining = daysUntil(raw.valid_to ?? null);

  if (validationErrorCode && validationErrorCode !== "TIMEOUT") issues.push(validationErrorCode);
  if (daysRemaining !== null && daysRemaining < 0) issues.push("EXPIRED");
  if (!hostnameMatches) issues.push("HOSTNAME_MISMATCH");
  if (selfSigned) issues.push("SELF_SIGNED");
  if (
    (keyAlgorithm === "rsa" || keyAlgorithm === "rsa-pss") &&
    typeof keySize === "number" &&
    keySize < 2048
  ) {
    issues.push("WEAK_KEY");
  }
  if (keyAlgorithm === "ec" && typeof keySize === "number" && keySize < 256) issues.push("WEAK_KEY");
  if (observed.protocol && ["TLSv1", "TLSv1.1"].includes(observed.protocol)) {
    issues.push("LEGACY_TLS");
  }

  const certificate: CertificateObservation = {
    subjectCn,
    issuerCn,
    issuerOrganization,
    serialNumber: raw.serialNumber ?? null,
    fingerprintSha256,
    notBefore: raw.valid_from ? new Date(raw.valid_from).toISOString() : null,
    notAfter: raw.valid_to ? new Date(raw.valid_to).toISOString() : null,
    daysRemaining,
    keyAlgorithm,
    keySize,
    san,
    hostnameMatches,
    isWildcard: san.some((entry) => entry.startsWith("*.")),
    selfSigned,
    chainValid: validationErrorCode === null,
    chainLength: observed.chainLength,
    chainError: validationErrorCode,
    issues,
  };

  return {
    ok: true,
    errorCode: null,
    error: validationErrorCode && !issuerCn ? "Certificate validation failed." : null,
    durationMs: Date.now() - started,
    protocol: observed.protocol,
    cipher: observed.cipher,
    checkedHostname: hostname,
    checkedPort: port,
    certificate,
  };
}
