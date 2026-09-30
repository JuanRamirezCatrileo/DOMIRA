/**
 * The scan engine: one scan execution, executed by a worker — never inside an API
 * request.
 *
 * Order of work:
 *   1. load the scan and its domain (both keyed by organization_id + domain_id);
 *   2. re-check the authorisation gate: an unverified domain is never scanned, even
 *      if a job was somehow queued for it;
 *   3. resolve DNS (needed both for the results and for the SSRF guard);
 *   4. run the TLS/certificate and availability checks, each with its own timeout
 *      and each isolated — one failing check can never fail the scan;
 *   5. persist everything in one transaction: scan_results, certificates,
 *      dns_records, findings (status preserved) and the Security Score;
 *   6. finalise the scan and the domain counters.
 *
 * Every category that is NOT collected yet (e-mail, HTTP headers — deliverable 2b)
 * is written as a `scan_results` row with status 'skipped' and not_collected = true
 * so the absence of data is explicit in the database, in the API and in the UI.
 */
import { query, transaction, type QueryRunner } from "~/db";
import {
  dnsTimeoutMs,
  domainFailureThreshold,
  httpMaxRedirects,
  httpTimeoutMs,
  scannerUserAgent,
  tlsTimeoutMs,
} from "~/server/env";

import { probeAvailability } from "./availability";
import {
  DNS_RECORD_TYPES,
  findNonPublicAddresses,
  getDnsResolver,
  type DnsAnswer,
  type DnsRecordType,
} from "./dns";
import { detectFindings, recordFindings, type DnsSnapshot, type ScanInputs } from "./findings";
import { loadActiveMethodology, type MethodologyConfig } from "./methodology";
import { computeSecurityScore, type ScoreInput, type ScoreResult } from "./score";
import { probeTls, type TlsProbeResult } from "./tls";

export interface DomainRow {
  id: string;
  organization_id: string;
  hostname: string;
  normalized_hostname: string;
  status: string;
  check_frequency: string;
  monitoring_enabled: boolean;
}

export interface ScanRow {
  id: string;
  organization_id: string;
  domain_id: string;
  status: string;
  trigger_source: string;
}

export class ScanRefusedError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ScanRefusedError";
    this.code = code;
  }
}

export async function loadScanContext(
  scanId: string
): Promise<{ scan: ScanRow; domain: DomainRow } | null> {
  const result = await query<ScanRow & DomainRow & Record<string, unknown>>(
    `select s.id as scan_id, s.organization_id, s.domain_id, s.status as scan_status,
            s.trigger_source,
            d.id as domain_pk, d.hostname, d.normalized_hostname, d.status as domain_status,
            d.check_frequency, d.monitoring_enabled
       from scans s
       join domains d on d.id = s.domain_id
      where s.id = $1`,
    [scanId]
  );
  const row = result.rows[0];
  if (!row) return null;
  return {
    scan: {
      id: String(row.scan_id),
      organization_id: String(row.organization_id),
      domain_id: String(row.domain_id),
      status: String(row.scan_status),
      trigger_source: String(row.trigger_source),
    },
    domain: {
      id: String(row.domain_pk),
      organization_id: String(row.organization_id),
      hostname: String(row.hostname),
      normalized_hostname: String(row.normalized_hostname),
      status: String(row.domain_status),
      check_frequency: String(row.check_frequency),
      monitoring_enabled: Boolean(row.monitoring_enabled),
    },
  };
}

const FREQUENCY_INTERVALS: Record<string, string> = {
  hourly: "1 hour",
  "6h": "6 hours",
  daily: "1 day",
  weekly: "7 days",
};

export function nextScanExpression(frequency: string): string | null {
  const interval = FREQUENCY_INTERVALS[frequency];
  return interval ? `now() + interval '${interval}'` : null;
}

interface DnsCollection {
  snapshot: DnsSnapshot;
  byType: Record<string, { answers: DnsAnswer[]; errorCode: string | null; error: string | null }>;
}

/** Resolves every record type; a failing type records its own error and moves on. */
async function collectDns(hostname: string, timeoutMs: number): Promise<DnsCollection> {
  const resolver = getDnsResolver();
  const byType: DnsCollection["byType"] = {};
  const answers: DnsAnswer[] = [];
  let firstErrorCode: string | null = null;
  let firstError: string | null = null;

  await Promise.all(
    DNS_RECORD_TYPES.map(async (type: DnsRecordType) => {
      try {
        const result = await withTimeout(
          resolver.query(hostname, type),
          timeoutMs,
          `DNS ${type} lookup timed out after ${timeoutMs} ms.`
        );
        byType[type] = { answers: result, errorCode: null, error: null };
        answers.push(...result);
      } catch (error) {
        const code = (error as { code?: string }).code ?? "DNS_ERROR";
        const message = (error as Error).message;
        byType[type] = { answers: [], errorCode: code, error: message };
        // NXDOMAIN/ENOTFOUND on A means the name does not exist at all; that is a
        // result, not a tooling error.
        if (type === "A" && (code === "NXDOMAIN" || code === "ENOTFOUND")) {
          firstErrorCode ??= code;
          firstError ??= message;
        } else if (type === "A") {
          firstErrorCode ??= code;
          firstError ??= message;
        }
      }
    })
  );

  const hasA = (byType.A?.answers.length ?? 0) > 0;
  const resolved = hasA || (byType.AAAA?.answers.length ?? 0) > 0 || (byType.CNAME?.answers.length ?? 0) > 0;
  return {
    snapshot: {
      resolved,
      errorCode: resolved ? null : firstErrorCode,
      error: resolved ? null : firstError,
      answers,
    },
    byType,
  };
}

export function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

function checkStatusTls(tls: TlsProbeResult | null): string {
  if (!tls) return "error";
  if (!tls.ok) return "critical";
  if (tls.protocol === "TLSv1" || tls.protocol === "TLSv1.1") return "warning";
  return "ok";
}

function checkStatusCertificate(tls: TlsProbeResult | null): string {
  const certificate = tls?.certificate;
  if (!tls?.ok || !certificate) return "critical";
  if (certificate.issues.includes("EXPIRED")) return "critical";
  if (!certificate.hostnameMatches) return "critical";
  if (certificate.chainValid === false) return "warning";
  if (
    certificate.issues.includes("SELF_SIGNED") ||
    certificate.issues.includes("WEAK_KEY")
  ) {
    return "warning";
  }
  if (typeof certificate.daysRemaining === "number" && certificate.daysRemaining <= 30) return "warning";
  return "ok";
}

function checkStatusDns(snapshot: DnsSnapshot): string {
  if (!snapshot.resolved) return snapshot.errorCode ? "critical" : "warning";
  const hasA = snapshot.answers.some((answer) => answer.type === "A");
  return hasA ? "ok" : "warning";
}

function checkStatusAvailability(
  availability: Awaited<ReturnType<typeof probeAvailability>> | null
): string {
  if (!availability) return "error";
  if (!availability.ok) return "critical";
  const status = availability.statusCode ?? 0;
  if (status >= 500) return "critical";
  if (status >= 400) return "warning";
  if (
    availability.httpToHttpsRedirect === false ||
    (availability.responseTimeMs ?? 0) > 1500
  ) {
    return "warning";
  }
  return "ok";
}

function toScoreInput(inputs: ScanInputs): ScoreInput {
  const certificate = inputs.tls?.certificate ?? null;
  const answers = inputs.dns.answers;
  return {
    tls: {
      handshakeOk: Boolean(inputs.tls?.ok),
      protocol: inputs.tls?.protocol ?? null,
    },
    certificate: {
      present: Boolean(certificate),
      expired: Boolean(certificate?.issues.includes("EXPIRED")),
      daysRemaining: certificate?.daysRemaining ?? null,
      hostnameMatches: certificate ? certificate.hostnameMatches : null,
      chainValid: certificate ? certificate.chainValid : null,
      selfSigned: certificate?.selfSigned ?? false,
      keyAlgorithm: certificate?.keyAlgorithm ?? null,
      keySize: certificate?.keySize ?? null,
    },
    dns: {
      resolved: inputs.dns.resolved,
      hasA: answers.some((answer) => answer.type === "A"),
      hasAAAA: answers.some((answer) => answer.type === "AAAA"),
      hasNs: answers.some((answer) => answer.type === "NS"),
      hasMx: answers.some((answer) => answer.type === "MX"),
      hasCaa: answers.some((answer) => answer.type === "CAA"),
    },
    availability: {
      reachable: Boolean(inputs.availability?.ok),
      statusCode: inputs.availability?.statusCode ?? null,
      responseTimeMs: inputs.availability?.responseTimeMs ?? null,
      httpToHttpsRedirect: inputs.availability?.httpToHttpsRedirect ?? null,
    },
  };
}

export interface ScanExecutionResult {
  scanId: string;
  status: "completed" | "failed" | "cancelled";
  error: string | null;
  score: number | null;
  checksFailed: number;
  findings: { opened: number; updated: number };
}

/**
 * Executes one scan end to end. Called by the worker (in-process or standalone),
 * never by an HTTP handler.
 */
export async function executeScan(scanId: string, workerId: string): Promise<ScanExecutionResult> {
  const context = await loadScanContext(scanId);
  if (!context) {
    return {
      scanId,
      status: "failed",
      error: "The scan no longer exists.",
      score: null,
      checksFailed: 0,
      findings: { opened: 0, updated: 0 },
    };
  }
  const { scan, domain } = context;

  if (scan.status === "cancelled") {
    return { scanId, status: "cancelled", error: null, score: null, checksFailed: 0, findings: { opened: 0, updated: 0 } };
  }

  await query(
    `update scans set status = 'running', started_at = coalesce(started_at, now()), worker_id = $2, updated_at = now()
      where id = $1 and status in ('queued', 'running')`,
    [scanId, workerId]
  );

  // Authorisation gate, re-checked at execution time: only verified domains are
  // scanned. A paused/archived/error domain is not scanned either.
  if (domain.status !== "verified") {
    const message = `Refused: the domain is in status '${domain.status}' (only 'verified' domains are scanned).`;
    await query(
      `update scans set status = 'failed', finished_at = now(), error_message = $2, updated_at = now()
        where id = $1`,
      [scanId, message]
    );
    return { scanId, status: "failed", error: message, score: null, checksFailed: 0, findings: { opened: 0, updated: 0 } };
  }

  const methodology: MethodologyConfig = await loadActiveMethodology();
  const hostname = domain.normalized_hostname;

  try {
    const dns = await collectDns(hostname, dnsTimeoutMs());

    // SSRF guard: DOMIRA only opens connections to public addresses.
    const addresses = dns.snapshot.answers
      .filter((answer) => answer.type === "A" || answer.type === "AAAA")
      .map((answer) => answer.value);
    const nonPublic = findNonPublicAddresses(addresses);
    const refusal =
      nonPublic.length > 0
        ? {
            code: "scan.refused_private_address",
            message: `Refused: ${hostname} resolves to non-public address(es): ${nonPublic.join(", ")}.`,
            evidence: { addresses, nonPublic },
          }
        : null;

    let tls: TlsProbeResult | null = null;
    let availability: Awaited<ReturnType<typeof probeAvailability>> | null = null;
    if (!refusal) {
      const [tlsOutcome, availabilityOutcome] = await Promise.allSettled([
        probeTls(hostname, { timeoutMs: tlsTimeoutMs() }),
        probeAvailability(hostname, {
          timeoutMs: httpTimeoutMs(),
          maxRedirects: httpMaxRedirects(),
          userAgent: scannerUserAgent(),
        }),
      ]);
      tls =
        tlsOutcome.status === "fulfilled"
          ? tlsOutcome.value
          : {
              ok: false,
              errorCode: (tlsOutcome.reason as { code?: string })?.code ?? "TLS_CHECK_ERROR",
              error: String((tlsOutcome.reason as Error)?.message ?? tlsOutcome.reason),
              durationMs: 0,
              protocol: null,
              cipher: null,
              checkedHostname: hostname,
              checkedPort: 443,
              certificate: null,
            };
      availability =
        availabilityOutcome.status === "fulfilled"
          ? availabilityOutcome.value
          : null;
    }

    const inputs: ScanInputs = { hostname, tls, dns: dns.snapshot, availability, refusal };
    const inputsForScore = refusal
      ? {
          ...inputs,
          tls: {
            ok: false,
            errorCode: "REFUSED_PRIVATE_ADDRESS",
            error: refusal.message,
            durationMs: 0,
            protocol: null,
            cipher: null,
            checkedHostname: hostname,
            checkedPort: 443,
            certificate: null,
          } satisfies TlsProbeResult,
          availability: {
            ok: false,
            errorCode: "REFUSED_PRIVATE_ADDRESS",
            error: refusal.message,
            durationMs: 0,
            finalUrl: null,
            statusCode: null,
            responseTimeMs: null,
            hops: [],
            redirectCount: 0,
            serverHeader: null,
            httpToHttpsRedirect: null,
            plainHttpStatus: null,
            plainHttpError: null,
            plainHttpLocation: null,
          },
        }
      : inputs;

    const detected = detectFindings(inputs, methodology);
    const scoreResult = computeSecurityScore(toScoreInput(inputsForScore), methodology);

    const persisted = await transaction(async (tx) => {
      // A cancelled scan must not write results, even if the worker finished first.
      const stillActive = await tx.query<{ status: string }>(
        "select status from scans where id = $1",
        [scanId]
      );
      if (stillActive.rows[0]?.status === "cancelled") return null;

      const categoryScores = new Map(
        scoreResult.categories.map((entry) => [entry.category, entry.score])
      );
      const checkRows: Array<{
        category: string;
        status: string;
        data: unknown;
        errorMessage: string | null;
        durationMs: number | null;
      }> = [
        {
          category: "dns",
          status: checkStatusDns(dns.snapshot),
          data: { answers: dns.snapshot.answers, perType: dns.byType, resolver: getDnsResolver().kind },
          errorMessage: dns.snapshot.error,
          durationMs: null,
        },
        {
          category: "tls",
          status: checkStatusTls(tls),
          data: {
            ok: tls?.ok ?? false,
            protocol: tls?.protocol ?? null,
            cipher: tls?.cipher ?? null,
            chainValid: tls?.certificate?.chainValid ?? null,
            chainLength: tls?.certificate?.chainLength ?? null,
            chainError: tls?.certificate?.chainError ?? null,
            issues: tls?.certificate?.issues ?? [],
            refused: refusal ? refusal.message : null,
          },
          errorMessage: tls?.ok ? null : (tls?.error ?? refusal?.message ?? null),
          durationMs: tls?.durationMs ?? null,
        },
        {
          category: "certificate",
          status: checkStatusCertificate(tls),
          data: tls?.certificate ?? { refused: refusal?.message ?? null },
          errorMessage: tls?.certificate ? null : (refusal?.message ?? tls?.error ?? null),
          durationMs: null,
        },
        {
          category: "availability",
          status: checkStatusAvailability(availability),
          data: availability ?? { refused: refusal?.message ?? null },
          errorMessage: availability?.ok
            ? null
            : (availability?.error ?? refusal?.message ?? "The availability check could not run."),
          durationMs: availability?.durationMs ?? null,
        },
      ];

      for (const row of checkRows) {
        await tx.query(
          `insert into scan_results
             (organization_id, scan_id, domain_id, category, status, score, data, error_message, duration_ms, check_duration_ms)
           values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $9)`,
          [
            scan.organization_id,
            scanId,
            scan.domain_id,
            row.category,
            row.status,
            categoryScores.get(row.category as never) ?? null,
            JSON.stringify(row.data ?? {}),
            row.errorMessage,
            row.durationMs,
          ]
        );
      }

      // Categories that are not collected yet: recorded explicitly, never faked.
      for (const category of scoreResult.notCollectedCategories) {
        await tx.query(
          `insert into scan_results
             (organization_id, scan_id, domain_id, category, status, score, data, error_message, not_collected)
           values ($1, $2, $3, $4, 'skipped', null, $5::jsonb, null, true)`,
          [
            scan.organization_id,
            scanId,
            scan.domain_id,
            category,
            JSON.stringify({
              reason: "not_collected",
              plannedIn: "deliverable 2b",
              message:
                "This category is not collected yet. It is excluded from the Security Score and is never counted as full marks.",
            }),
          ]
        );
      }

      if (tls?.ok && tls.certificate) {
        const certificate = tls.certificate;
        await tx.query(
          `insert into certificates
             (organization_id, domain_id, scan_id, subject_cn, issuer_cn, issuer_organization,
              serial_number, fingerprint_sha256, not_before, not_after, days_remaining,
              key_algorithm, key_size, san, tls_versions, is_wildcard, chain_valid, hostname_matches,
              issues, chain_length, chain_error, checked_hostname, checked_port, tls_protocol, cipher,
              self_signed)
           values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16,$17,$18,
                   $19::jsonb,$20,$21,$22,$23,$24,$25,$26)`,
          [
            scan.organization_id,
            scan.domain_id,
            scanId,
            certificate.subjectCn ?? hostname,
            certificate.issuerCn,
            certificate.issuerOrganization,
            certificate.serialNumber,
            certificate.fingerprintSha256,
            certificate.notBefore,
            certificate.notAfter,
            certificate.daysRemaining,
            certificate.keyAlgorithm,
            certificate.keySize,
            JSON.stringify(certificate.san),
            JSON.stringify(tls.protocol ? [tls.protocol] : []),
            certificate.isWildcard,
            certificate.chainValid,
            certificate.hostnameMatches,
            JSON.stringify(certificate.issues),
            certificate.chainLength,
            certificate.chainError,
            tls.checkedHostname,
            tls.checkedPort,
            tls.protocol,
            tls.cipher,
            certificate.selfSigned,
          ]
        );
      }

      if (dns.snapshot.resolved) {
        const previous = await tx.query<{ record_type: string; value: string }>(
          `select record_type, value from dns_records
            where domain_id = $1
              and scan_id = (select id from scans
                              where domain_id = $1 and id <> $2 and status = 'completed'
                              order by created_at desc limit 1)`,
          [scan.domain_id, scanId]
        );
        const previousSet = new Set(
          previous.rows.map((row) => `${row.record_type}|${row.value}`)
        );
        const hasPrevious = previous.rows.length > 0;
        for (const answer of dns.snapshot.answers) {
          const changed = hasPrevious && !previousSet.has(`${answer.type}|${answer.value}`);
          await tx.query(
            `insert into dns_records
               (organization_id, domain_id, scan_id, record_type, name, value, ttl, priority, is_change, previous_value)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [
              scan.organization_id,
              scan.domain_id,
              scanId,
              answer.type,
              hostname,
              answer.value,
              answer.ttl,
              answer.priority,
              changed,
              null,
            ]
          );
        }
      }

      const findingsResult = await recordFindings(
        tx,
        {
          organizationId: scan.organization_id,
          domainId: scan.domain_id,
          scanId,
        },
        detected
      );

      const previousScore = await tx.query<{ score: number }>(
        "select score from security_scores where domain_id = $1 order by computed_at desc limit 1",
        [scan.domain_id]
      );
      const previousValue = previousScore.rows[0]?.score ?? null;
      await tx.query(
        `insert into security_scores
           (organization_id, domain_id, scan_id, scope, score, grade, previous_score, delta,
            category_scores, factors, changes, methodology_version, coverage, trigger_source)
         values ($1,$2,$3,'domain',$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12::jsonb,$13)`,
        [
          scan.organization_id,
          scan.domain_id,
          scanId,
          scoreResult.score,
          scoreResult.grade,
          previousValue,
          previousValue === null ? null : scoreResult.score - previousValue,
          JSON.stringify(
            Object.fromEntries(
              scoreResult.categories.map((entry) => [
                entry.category,
                {
                  score: entry.score,
                  collected: entry.collected,
                  weight: entry.weight,
                },
              ])
            )
          ),
          JSON.stringify(scoreResult.factors),
          JSON.stringify([]),
          scoreResult.methodologyVersion,
          JSON.stringify({
            collected: scoreResult.collectedCategories,
            notCollected: scoreResult.notCollectedCategories,
            policy: methodology.uncollectedPolicy,
          }),
          scan.trigger_source,
        ]
      );

      const checksFailed = checkRows.filter((row) => row.status === "error").length;
      const summary = {
        hostname,
        checks: Object.fromEntries(checkRows.map((row) => [row.category, row.status])),
        notCollected: scoreResult.notCollectedCategories,
        score: scoreResult.score,
        grade: scoreResult.grade,
        methodologyVersion: scoreResult.methodologyVersion,
        findings: findingsResult,
        partial: refusal !== null,
        refused: refusal?.message ?? null,
      };

      await tx.query(
        `update scans
            set status = 'completed', finished_at = now(), error_message = null,
                duration_ms = extract(epoch from (now() - coalesce(started_at, created_at))) * 1000,
                checks_completed = $2, checks_failed = $3, summary = $4::jsonb, updated_at = now()
          where id = $1`,
        [scanId, checkRows.length, checksFailed, JSON.stringify(summary)]
      );

      const nextScan = nextScanExpression(domain.check_frequency);
      await tx.query(
        `update domains
            set last_scan_at = now(),
                next_scan_at = case when monitoring_enabled and $3::text is not null
                                    then now() + ($3::text)::interval else next_scan_at end,
                consecutive_failures = 0,
                status = case when status = 'error' then 'verified' else status end,
                updated_at = now()
          where id = $1`,
        [scan.domain_id, scan.organization_id, nextScan]
      );

      return {
        score: scoreResult.score,
        findings: { opened: findingsResult.opened, updated: findingsResult.updated },
        checksFailed,
      };
    });

    if (persisted === null) {
      return {
        scanId,
        status: "cancelled",
        error: null,
        score: null,
        checksFailed: 0,
        findings: { opened: 0, updated: 0 },
      };
    }

    return {
      scanId,
      status: "completed",
      error: null,
      score: persisted.score,
      checksFailed: persisted.checksFailed,
      findings: persisted.findings,
    };
  } catch (error) {
    const message = `${(error as { code?: string }).code ?? "SCAN_ERROR"}: ${(error as Error).message}`;
    await failScan(scanId, scan.domain_id, message);
    return { scanId, status: "failed", error: message, score: null, checksFailed: 0, findings: { opened: 0, updated: 0 } };
  }
}

/** Marks a scan failed and advances the domain's failure counter. */
async function failScan(scanId: string, domainId: string, message: string): Promise<void> {
  await query(
    `update scans set status = 'failed', finished_at = now(), error_message = $2, updated_at = now()
      where id = $1 and status <> 'cancelled'`,
    [scanId, message]
  );
  const threshold = domainFailureThreshold();
  await query(
    `update domains
        set consecutive_failures = consecutive_failures + 1,
            status = case when consecutive_failures + 1 >= $2 and status = 'verified' then 'error' else status end,
            updated_at = now()
      where id = $1`,
    [domainId, threshold]
  );
}

/** Helper used by tests and the worker to persist a scan result outside a scan. */
export async function countOpenFindings(organizationId: string, runner?: QueryRunner): Promise<number> {
  const run = <T>(text: string, params?: readonly unknown[]) =>
    runner ? runner.query<T>(text, params) : query<T>(text, params);
  const result = await run<{ count: number }>(
    "select count(*)::int as count from findings where organization_id = $1 and status in ('new','acknowledged')",
    [organizationId]
  );
  return Number(result.rows[0]?.count ?? 0);
}
