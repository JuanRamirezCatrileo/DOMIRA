/**
 * Shared serialisers for the scanning surface.
 *
 * Keeping them in one module avoids a cycle between the domain, scan and finding
 * handlers, and guarantees that a domain/scan/finding looks identical wherever it
 * is returned. Nothing here ever adds data that is not in the row: an absent value
 * is `null`, never a placeholder.
 */
import { toIso, toNumber } from "./types";

export interface ScanRow {
  id: string;
  organization_id: string;
  domain_id: string;
  job_id?: string | null;
  status: string;
  trigger_source: string;
  requested_by?: string | null;
  started_at?: Date | string | null;
  finished_at?: Date | string | null;
  duration_ms?: number | null;
  error_message?: string | null;
  summary?: Record<string, unknown>;
  checks_completed?: number;
  checks_failed?: number;
  cancelled_at?: Date | string | null;
  worker_id?: string | null;
  created_at: Date | string;
  updated_at?: Date | string;
}

/** Default number of score points returned by GET /api/domains/:id/security. */
export const SCAN_HISTORY_DEFAULT_LIMIT = 30;

export function scanToJson(scan: ScanRow) {
  return {
    id: scan.id,
    domainId: scan.domain_id,
    status: scan.status,
    triggerSource: scan.trigger_source,
    jobId: scan.job_id ?? null,
    requestedBy: scan.requested_by ?? null,
    startedAt: toIso(scan.started_at ?? null),
    finishedAt: toIso(scan.finished_at ?? null),
    durationMs: scan.duration_ms === null || scan.duration_ms === undefined
      ? null
      : toNumber(scan.duration_ms),
    checksCompleted: toNumber(scan.checks_completed ?? 0),
    checksFailed: toNumber(scan.checks_failed ?? 0),
    workerId: scan.worker_id ?? null,
    cancelledAt: toIso(scan.cancelled_at ?? null),
    error: scan.error_message ?? null,
    summary: scan.summary ?? {},
    createdAt: toIso(scan.created_at),
    updatedAt: toIso(scan.updated_at ?? scan.created_at),
  };
}

export interface FindingRow {
  id: string;
  organization_id: string;
  domain_id: string;
  scan_id: string | null;
  last_scan_id: string | null;
  category: string;
  code: string;
  severity: string;
  status: string;
  title_es: string;
  title_en: string;
  explanation_simple_es: string;
  explanation_simple_en: string;
  explanation_tech: string;
  impact_es: string;
  impact_en: string;
  recommendation_es: string;
  recommendation_en: string;
  evidence: Record<string, unknown>;
  occurrences: number;
  first_seen_at: Date | string;
  last_seen_at: Date | string;
  acknowledged_at: Date | string | null;
  acknowledged_by: string | null;
  resolved_at: Date | string | null;
  status_changed_at: Date | string | null;
  status_changed_by: string | null;
  created_at: Date | string;
  updated_at?: Date | string;
}

export function findingToJson(finding: FindingRow, extras: Record<string, unknown> = {}) {
  return {
    id: finding.id,
    domainId: finding.domain_id,
    scanId: finding.scan_id,
    lastScanId: finding.last_scan_id,
    category: finding.category,
    code: finding.code,
    severity: finding.severity,
    status: finding.status,
    title: { es: finding.title_es, en: finding.title_en },
    explanation: {
      simple: { es: finding.explanation_simple_es, en: finding.explanation_simple_en },
      technical: finding.explanation_tech,
    },
    impact: { es: finding.impact_es, en: finding.impact_en },
    recommendation: { es: finding.recommendation_es, en: finding.recommendation_en },
    evidence: finding.evidence,
    occurrences: toNumber(finding.occurrences),
    firstSeenAt: toIso(finding.first_seen_at),
    lastSeenAt: toIso(finding.last_seen_at),
    acknowledgedAt: toIso(finding.acknowledged_at),
    resolvedAt: toIso(finding.resolved_at),
    statusChangedAt: toIso(finding.status_changed_at),
    createdAt: toIso(finding.created_at),
    ...extras,
  };
}

export interface CertificateRow {
  id: string;
  organization_id: string;
  domain_id: string;
  scan_id: string | null;
  subject_cn: string;
  issuer_cn: string | null;
  issuer_organization: string | null;
  serial_number: string | null;
  fingerprint_sha256: string | null;
  not_before: Date | string | null;
  not_after: Date | string | null;
  days_remaining: number | null;
  key_algorithm: string | null;
  key_size: number | null;
  signature_algorithm: string | null;
  san: unknown;
  tls_versions: unknown;
  is_wildcard: boolean;
  chain_valid: boolean | null;
  hostname_matches: boolean | null;
  issues: unknown;
  self_signed: boolean;
  observed_at: Date | string;
}

export function certificateToJson(certificate: CertificateRow, extras: Record<string, unknown> = {}) {
  return {
    id: certificate.id,
    domainId: certificate.domain_id,
    scanId: certificate.scan_id,
    subjectCommonName: certificate.subject_cn,
    issuerCommonName: certificate.issuer_cn,
    issuerOrganization: certificate.issuer_organization,
    serialNumber: certificate.serial_number,
    fingerprintSha256: certificate.fingerprint_sha256,
    notBefore: toIso(certificate.not_before),
    notAfter: toIso(certificate.not_after),
    daysRemaining: certificate.days_remaining === null ? null : toNumber(certificate.days_remaining),
    keyAlgorithm: certificate.key_algorithm,
    keySize: certificate.key_size === null ? null : toNumber(certificate.key_size),
    signatureAlgorithm: certificate.signature_algorithm,
    san: certificate.san,
    tlsVersions: certificate.tls_versions,
    isWildcard: Boolean(certificate.is_wildcard),
    selfSigned: Boolean(certificate.self_signed),
    chainValid: certificate.chain_valid,
    hostnameMatches: certificate.hostname_matches,
    issues: certificate.issues,
    observedAt: toIso(certificate.observed_at),
    ...extras,
  };
}
