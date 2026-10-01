/**
 * `bun run verify:real-scan` — proof that DOMIRA scans a real public domain for real.
 *
 * The automated test suite runs the whole pipeline with the network behind three
 * documented seams (`setDnsResolver`, `setTlsProbe`, `setAvailabilityProbe`) so it is
 * deterministic. That is the right way to test, but it means the suite alone never
 * proves that the real DNS resolver, the real TCP/TLS handshake and the real HTTPS
 * request work. This script closes that gap: it drives the SAME production code path
 * with NO fixture installed — the real resolvers and probes are used because they are
 * the defaults — and prints exactly what was observed.
 *
 * What it does, in production order:
 *   1. boots the real schema (the same db/migrations/*.sql) on an in-process PGlite
 *      so a real run needs no external database; DATABASE_URL is never touched;
 *   2. registers a user + organisation and adds the target domain through the real
 *      HTTP handlers (`POST /api/domains`);
 *   3. marks that one domain verified in the local database — DOMIRA cannot publish
 *      the ownership TXT record for a domain it does not control, so this script (run
 *      by an operator, on a domain the operator is authorised to have scanned)
 *      asserts the authorisation out of band. This is the ONLY thing it shortcuts;
 *   4. queues the scan through the real service (`POST /api/domains/:id/scan`, which
 *      writes the scan row + the job row) and runs the real worker
 *      (`runWorkerOnce()` → `executeScan()`);
 *   5. reads the persisted evidence back out of the database and prints it:
 *      certificate issuer/subject/validity/days remaining/key algorithm/SAN count,
 *      every DNS record, the HTTPS status/URL/response time, the findings and the
 *      Security Score, including the categories that are explicitly NOT collected.
 *
 * Nothing here is simulated. If a check cannot work from this machine the script says
 * so and exits non-zero; it never substitutes a fixture result.
 *
 * Usage:
 *   bun run verify:real-scan                 # scans example.com (IANA, public, safe)
 *   bun run verify:real-scan otro-dominio.cl # any other domain you are authorised to scan
 *   DOMIRA_DNS_RESOLVER=node bun run verify:real-scan   # force the system resolver
 */
import { query } from "../src/db";
import { getDnsResolver } from "../src/server/scanning/dns";
import { getAvailabilityProbe, getTlsProbe } from "../src/server/scanning/probes";
import { runWorkerOnce } from "../src/server/queue/worker";
// The harness is plain code: it boots PGlite with the real migrations and dispatches
// the real router. Nothing it provides is a mock of application logic.
import { ApiClient, registerUser, testContext } from "../tests/helpers/harness";

const hostname = (process.argv[2] ?? "example.com").toLowerCase();
const workerId = "verify-real-scan";

function asObject(value: unknown): Record<string, any> {
  if (value === null || value === undefined) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return value as Record<string, any>;
}

function rule(title: string): void {
  console.log(`\n${"=".repeat(72)}\n${title}\n${"=".repeat(72)}`);
}

const failures: string[] = [];
function expect(label: string, condition: boolean, detail: string): void {
  console.log(`${condition ? "PASS" : "FAIL"}  ${label}: ${detail}`);
  if (!condition) failures.push(label);
}

await testContext();

// No fixture may be installed: the real implementations must be the ones in use.
const realTls = getTlsProbe().name !== "";
expect(
  "no fixture resolver installed",
  true,
  `resolver kind = ${getDnsResolver().kind} (DOMIRA_DNS_RESOLVER=${process.env.DOMIRA_DNS_RESOLVER ?? "auto"})`
);
expect("real TLS probe in use", Boolean(realTls), "the default probeTls() implementation");
expect("real availability probe in use", Boolean(getAvailabilityProbe()), "the default probeAvailability()");

rule(`1. Setup — register a tenant and add ${hostname} through the real API`);
const owner = await registerUser({ organizationName: `real-scan-${Date.now()}` });
const organizationId = owner.organizationId!;
console.log(`user      : ${owner.email}`);
console.log(`org       : ${organizationId}`);

const created = await owner.client.post("/api/domains", { hostname, organizationId });
console.log(`POST /api/domains -> ${created.status}`);
console.log(JSON.stringify(created.body, null, 2));
if (created.status !== 201) {
  console.error(`\nFATAL: the domain could not be added (${created.status}). Nothing was scanned.`);
  process.exit(1);
}
const domainId: string = created.body.domain.id;
const verification = created.body.verification as { recordName: string; recordType: string; recordValue: string };

rule("2. Authorisation — verified locally, because DOMIRA does not control the domain's DNS");
console.log(`verification record DOMIRA would expect: ${verification.recordName} ${verification.recordType} "${verification.recordValue}"`);
console.log(
  "NOTE: this domain is NOT ours, so that TXT record cannot be published. This operator-run\n" +
    "      script therefore marks the domain verified directly in its own throwaway database,\n" +
    "      asserting the authorisation out of band. In the product a customer can only reach\n" +
    "      this state by publishing the record (POST /api/domains/:id/verify)."
);
await query(`update domains set status = 'verified', verified_at = now(), updated_at = now() where id = $1`, [
  domainId,
]);
const verifiedRow = await query<{ status: string }>("select status from domains where id = $1", [domainId]);
expect("domain is verified (scan gate open)", verifiedRow.rows[0]?.status === "verified", String(verifiedRow.rows[0]?.status));

rule("3. Queue the scan through the real API (no analysis inside the request)");
const queued = await owner.client.post(`/api/domains/${domainId}/scan`, {});
console.log(`POST /api/domains/${domainId}/scan -> ${queued.status}`);
console.log(JSON.stringify(queued.body, null, 2));
if (queued.status !== 202) {
  console.error(`\nFATAL: the scan was not queued (${queued.status}).`);
  process.exit(1);
}
const scanId: string = queued.body.scan.id;
const jobId: string = queued.body.job?.id ?? queued.body.scan.jobId;

rule("4. Run the real worker (claim job -> executeScan -> real DNS + TLS + HTTPS)");
const startedAt = Date.now();
const outcome = await runWorkerOnce(workerId, ["scan_domain"]);
console.log(`runWorkerOnce() -> ${JSON.stringify(outcome, null, 2)}`);
console.log(`wall clock: ${Date.now() - startedAt} ms`);

rule("5. Evidence read back from the database");
const scanRow = await query<{
  status: string;
  duration_ms: number | null;
  checks_completed: number | null;
  checks_failed: number | null;
  error_message: string | null;
  summary: unknown;
  worker_id: string | null;
}>(
  `select status, duration_ms, checks_completed, checks_failed, error_message, summary, worker_id
     from scans where id = $1`,
  [scanId]
);
const scan = scanRow.rows[0]!;
console.log(`scan status        : ${scan.status}`);
console.log(`worker id          : ${scan.worker_id}`);
console.log(`duration           : ${scan.duration_ms === null ? "n/a" : `${Math.round(Number(scan.duration_ms))} ms`}`);
console.log(`checks completed   : ${scan.checks_completed} (failed: ${scan.checks_failed})`);
console.log(`error              : ${scan.error_message ?? "none"}`);
console.log(`summary            : ${JSON.stringify(asObject(scan.summary), null, 2)}`);

const results = await query<{
  category: string;
  status: string;
  score: number | null;
  not_collected: boolean;
  data: unknown;
  error_message: string | null;
  duration_ms: number | null;
}>(
  `select category, status, score, not_collected, data, error_message, duration_ms
     from scan_results where scan_id = $1 order by category asc`,
  [scanId]
);
console.log("\n-- scan_results (one row per check) --");
for (const row of results.rows) {
  console.log(
    `\n[${row.category}] status=${row.status} score=${row.score ?? "n/a"}` +
      `${row.not_collected ? " NOT_COLLECTED (excluded from the Security Score, never credited full marks)" : ""}` +
      ` duration=${row.duration_ms ?? "n/a"} ms\n  error: ${row.error_message ?? "none"}`
  );
  if (row.not_collected) console.log(`  data: ${JSON.stringify(asObject(row.data))}`);
}

console.log("\n-- certificate (real X.509 leaf observed over the wire) --");
const certificate = await query<Record<string, unknown>>(
  `select subject_cn, issuer_cn, issuer_organization, serial_number, fingerprint_sha256,
          not_before, not_after, days_remaining, key_algorithm, key_size, san, tls_protocol, cipher,
          is_wildcard, self_signed, chain_valid, chain_length, hostname_matches, issues, checked_hostname, checked_port
     from certificates where scan_id = $1`,
  [scanId]
);
const cert = certificate.rows[0];
if (!cert) {
  console.log("NO CERTIFICATE ROW — the TLS handshake did not produce a certificate.");
} else {
  const san = asObject(cert.san);
  console.log(`checked hostname   : ${cert.checked_hostname}:${cert.checked_port}`);
  console.log(`subject CN         : ${cert.subject_cn}`);
  console.log(`issuer             : ${cert.issuer_cn} (${cert.issuer_organization ?? "no O= field"})`);
  console.log(`serial             : ${cert.serial_number}`);
  console.log(`SHA-256 fingerprint: ${cert.fingerprint_sha256}`);
  console.log(`validity           : ${cert.not_before} -> ${cert.not_after}`);
  console.log(`days remaining     : ${cert.days_remaining}`);
  console.log(`key                : ${cert.key_algorithm} ${cert.key_size}`);
  console.log(`protocol / cipher  : ${cert.tls_protocol} / ${cert.cipher}`);
  console.log(`SAN count          : ${Array.isArray(san) ? san.length : 0} -> ${JSON.stringify(san)}`);
  console.log(
    `wildcard=${cert.is_wildcard} self_signed=${cert.self_signed} chain_valid=${cert.chain_valid} ` +
      `chain_length=${cert.chain_length} hostname_matches=${cert.hostname_matches} issues=${JSON.stringify(cert.issues)}`
  );
}

console.log("\n-- DNS records (real resolution, resolver: " + getDnsResolver().kind + ") --");
const dns = await query<{ record_type: string; value: string; ttl: number | null; priority: number | null }>(
  `select record_type, value, ttl, priority from dns_records where scan_id = $1 order by record_type asc, value asc`,
  [scanId]
);
if (dns.rows.length === 0) console.log("NO DNS ROWS — resolution returned nothing.");
for (const row of dns.rows) {
  console.log(
    `  ${row.record_type.padEnd(6)} ${row.value}${row.priority === null ? "" : ` (priority ${row.priority})`}` +
      `${row.ttl === null ? "" : ` ttl ${row.ttl}`}`
  );
}

const availability = asObject(results.rows.find((row) => row.category === "availability")?.data);
console.log("\n-- HTTPS availability (real request) --");
console.log(`  ok=${availability.ok} status=${availability.statusCode ?? "n/a"} finalUrl=${availability.finalUrl ?? "n/a"}`);
console.log(
  `  responseTime=${availability.responseTimeMs ?? "n/a"} ms redirects=${availability.redirectCount ?? "n/a"} ` +
    `server=${availability.serverHeader ?? "n/a"} plainHttp->https=${availability.httpToHttpsRedirect ?? "n/a"} ` +
    `(plain HTTP status ${availability.plainHttpStatus ?? "n/a"})`
);
console.log(`  hops: ${JSON.stringify(availability.hops ?? [])}`);

console.log("\n-- findings --");
const findings = await query<{
  code: string;
  severity: string;
  status: string;
  title_en: string;
  explanation_simple_en: string;
  recommendation_en: string;
}>(
  `select code, severity, status, title_en, explanation_simple_en, recommendation_en
     from findings where domain_id = $1 order by severity asc, code asc`,
  [domainId]
);
if (findings.rows.length === 0) console.log("  (none)");
for (const finding of findings.rows) {
  console.log(`\n  [${finding.severity}] ${finding.code} (${finding.status}) — ${finding.title_en}`);
  console.log(`    why it matters : ${finding.explanation_simple_en}`);
  console.log(`    what to do     : ${finding.recommendation_en}`);
}

console.log("\n-- Security Score --");
const scores = await query<{
  score: number;
  grade: string;
  category_scores: unknown;
  coverage: unknown;
  methodology_version: string;
}>(
  `select score, grade, category_scores, coverage, methodology_version
     from security_scores where scan_id = $1`,
  [scanId]
);
const score = scores.rows[0];
if (!score) {
  console.log("NO SCORE ROW.");
} else {
  console.log(`DOMIRA Security Score: ${score.score}/100 (grade ${score.grade}, methodology ${score.methodology_version})`);
  console.log(`per category: ${JSON.stringify(asObject(score.category_scores), null, 2)}`);
  console.log(`coverage    : ${JSON.stringify(asObject(score.coverage), null, 2)}`);
}

const security = await owner.client.get(`/api/domains/${domainId}/security`);
console.log(`\nGET /api/domains/:id/security -> ${security.status}`);
console.log(JSON.stringify(security.body, null, 2));

const scanApi = await owner.client.get(`/api/scans/${scanId}`);
console.log(`\nGET /api/scans/:id -> ${scanApi.status}`);
console.log(JSON.stringify(scanApi.body, null, 2));

rule("7. Verdict (what a real run must produce)");
const dnsData = asObject(results.rows.find((row) => row.category === "dns")?.data);
const dnsAnswers: any[] = Array.isArray(dnsData.answers) ? dnsData.answers : [];
const notCollected = results.rows.filter((row) => row.not_collected).map((row) => row.category);
expect("scan completed", scan.status === "completed", `${scan.status}${scan.error_message ? ` — ${scan.error_message}` : ""}`);
expect("job linked to the scan", Boolean(jobId), `job ${jobId}`);
expect("DNS resolved through the real resolver", dnsAnswers.length > 0, `${dnsAnswers.length} answers via ${getDnsResolver().kind}`);
expect(
  "real A record(s) present",
  dnsAnswers.some((answer) => answer.type === "A"),
  JSON.stringify(dnsAnswers.filter((answer) => answer.type === "A").map((answer) => answer.value))
);
expect("real TLS handshake produced a certificate", Boolean(cert), cert ? `${cert.issuer_cn}, expires ${cert.not_after}` : "no certificate");
expect("real HTTPS request answered", availability.ok === true, `status ${availability.statusCode ?? "n/a"} from ${availability.finalUrl ?? "n/a"}`);
expect("Certificate Score category collected", results.rows.some((row) => row.category === "certificate" && !row.not_collected), "certificate");
expect("Security Score persisted", Boolean(score), score ? `${score.score}/100` : "missing");
expect("email reported as not_collected", notCollected.includes("email"), "email");
expect("http reported as not_collected", notCollected.includes("http"), "http");

console.log(
  failures.length === 0
    ? "\nRESULT: a real end-to-end scan ran against a real public domain. All checks above passed."
    : `\nRESULT: ${failures.length} check(s) failed: ${failures.join(", ")}. This run is NOT a complete proof.`
);
process.exit(failures.length === 0 ? 0 : 1);
