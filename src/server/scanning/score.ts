/**
 * The DOMIRA Security Score engine — a pure, deterministic module.
 *
 * Input: the structured result of the passive checks of one scan plus the active
 * methodology. Output: a 0–100 score, per-category scores, the grade and every
 * penalty that was applied (the "factors"), so a score can always be explained.
 *
 * Properties the tests rely on:
 *   * deterministic — same input, same output; no clock, no randomness, no I/O;
 *   * the overall score renormalises over the COLLECTED categories only, so the
 *     categories that are not collected yet (e-mail, HTTP until 2b) neither help
 *     nor hurt, and are reported separately as `notCollectedCategories`;
 *   * every weight, penalty and threshold comes from the methodology document,
 *     never from a literal in the UI.
 */
import type { Category, MethodologyConfig } from "./methodology";
import { CATEGORIES } from "./methodology";

export interface ScoreInput {
  tls: {
    handshakeOk: boolean;
    protocol: string | null;
  };
  certificate: {
    present: boolean;
    expired: boolean;
    daysRemaining: number | null;
    hostnameMatches: boolean | null;
    chainValid: boolean | null;
    selfSigned: boolean;
    keyAlgorithm: string | null;
    keySize: number | null;
  };
  dns: {
    resolved: boolean;
    hasA: boolean;
    hasAAAA: boolean;
    hasNs: boolean;
    hasMx: boolean;
    hasCaa: boolean;
  };
  availability: {
    reachable: boolean;
    statusCode: number | null;
    responseTimeMs: number | null;
    httpToHttpsRedirect: boolean | null;
  };
}

export interface ScoreFactor {
  code: string;
  category: Category;
  points: number;
  detail: string;
}

export interface CategoryScore {
  category: Category;
  collected: boolean;
  weight: number;
  /** null for categories that are not collected yet. */
  score: number | null;
  factors: ScoreFactor[];
}

export interface ScoreResult {
  score: number;
  grade: string;
  methodologyVersion: string;
  collectedCategories: Category[];
  notCollectedCategories: Category[];
  categories: CategoryScore[];
  /** Flat list of every penalty applied, for the "why is my score this" view. */
  factors: ScoreFactor[];
}

interface Penalty {
  code: string;
  points: number;
  detail: string;
}

function penalty(
  methodology: MethodologyConfig,
  category: Category,
  key: string,
  detail: string
): Penalty {
  const points = methodology.categories[category].penalties[key] ?? 0;
  return { code: `${category}.${key}`, points, detail };
}

function tlsPenalties(input: ScoreInput, methodology: MethodologyConfig): Penalty[] {
  if (!input.tls.handshakeOk) {
    return [penalty(methodology, "tls", "handshake_failed", "No TLS handshake on port 443.")];
  }
  const protocol = input.tls.protocol ?? "";
  if (protocol === "TLSv1" || protocol === "TLSv1.1") {
    return [penalty(methodology, "tls", "legacy_protocol", `Negotiated ${protocol}.`)];
  }
  if (protocol === "TLSv1.2") {
    return [penalty(methodology, "tls", "outdated_protocol", "Negotiated TLSv1.2 (not the newest).")];
  }
  return [];
}

function certificatePenalties(input: ScoreInput, methodology: MethodologyConfig): Penalty[] {
  const certificate = input.certificate;
  const out: Penalty[] = [];
  if (!certificate.present) {
    return [penalty(methodology, "certificate", "missing", "No certificate could be observed.")];
  }
  if (certificate.expired || (certificate.daysRemaining !== null && certificate.daysRemaining < 0)) {
    out.push(penalty(methodology, "certificate", "expired", "The certificate is expired."));
  } else if (
    certificate.daysRemaining !== null &&
    certificate.daysRemaining <= methodology.thresholds.expiringSoonDays
  ) {
    out.push(
      penalty(
        methodology,
        "certificate",
        "expiring_soon",
        `The certificate expires in ${certificate.daysRemaining} days.`
      )
    );
  } else if (
    certificate.daysRemaining !== null &&
    certificate.daysRemaining <= methodology.thresholds.expiringWarningDays
  ) {
    out.push(
      penalty(
        methodology,
        "certificate",
        "expiring_warning",
        `The certificate expires in ${certificate.daysRemaining} days.`
      )
    );
  }
  if (certificate.hostnameMatches === false) {
    out.push(
      penalty(methodology, "certificate", "hostname_mismatch", "The hostname is not in the certificate.")
    );
  }
  if (certificate.chainValid === false) {
    out.push(penalty(methodology, "certificate", "chain_invalid", "The chain did not validate."));
  }
  if (certificate.selfSigned) {
    out.push(penalty(methodology, "certificate", "self_signed", "The certificate is self-signed."));
  }
  const weakRsa =
    (certificate.keyAlgorithm === "rsa" || certificate.keyAlgorithm === "rsa-pss") &&
    typeof certificate.keySize === "number" &&
    certificate.keySize < methodology.thresholds.weakRsaBits;
  const weakEc = certificate.keyAlgorithm === "ec" && typeof certificate.keySize === "number" && certificate.keySize < 256;
  if (weakRsa || weakEc) {
    out.push(
      penalty(
        methodology,
        "certificate",
        "weak_key",
        `Key is ${certificate.keyAlgorithm ?? "unknown"} ${certificate.keySize ?? "?"} bit.`
      )
    );
  }
  return out;
}

function dnsPenalties(input: ScoreInput, methodology: MethodologyConfig): Penalty[] {
  const dns = input.dns;
  if (!dns.resolved) {
    return [penalty(methodology, "dns", "not_resolving", "The domain did not resolve.")];
  }
  const out: Penalty[] = [];
  if (!dns.hasA) out.push(penalty(methodology, "dns", "no_a_record", "No A record."));
  if (!dns.hasNs) out.push(penalty(methodology, "dns", "no_ns_record", "No NS record."));
  if (!dns.hasMx) out.push(penalty(methodology, "dns", "no_mx_record", "No MX record."));
  if (!dns.hasCaa) out.push(penalty(methodology, "dns", "no_caa_record", "No CAA record."));
  if (!dns.hasAAAA) out.push(penalty(methodology, "dns", "no_aaaa_record", "No AAAA record."));
  return out;
}

function availabilityPenalties(input: ScoreInput, methodology: MethodologyConfig): Penalty[] {
  const availability = input.availability;
  const out: Penalty[] = [];
  if (!availability.reachable) {
    return [penalty(methodology, "availability", "unreachable", "HTTPS did not answer.")];
  }
  const status = availability.statusCode ?? 0;
  if (status >= 500) {
    out.push(penalty(methodology, "availability", "server_error", `The site answered HTTP ${status}.`));
  } else if (status >= 400) {
    out.push(penalty(methodology, "availability", "client_error", `The site answered HTTP ${status}.`));
  }
  if (availability.httpToHttpsRedirect === false) {
    out.push(
      penalty(methodology, "availability", "no_https_redirect", "HTTP does not redirect to HTTPS.")
    );
  }
  const responseTime = availability.responseTimeMs;
  if (responseTime !== null && responseTime > methodology.thresholds.slowResponseMs) {
    if (responseTime > methodology.thresholds.verySlowResponseMs) {
      out.push(
        penalty(methodology, "availability", "very_slow_response", `Answered in ${responseTime} ms.`)
      );
    } else {
      out.push(penalty(methodology, "availability", "slow_response", `Answered in ${responseTime} ms.`));
    }
  }
  return out;
}

/** Pure scoring function: no I/O, no clock, stable across runs. */
export function computeSecurityScore(
  input: ScoreInput,
  methodology: MethodologyConfig
): ScoreResult {
  const appliedByCategory: Record<Category, Penalty[]> = {
    tls: tlsPenalties(input, methodology),
    certificate: certificatePenalties(input, methodology),
    dns: dnsPenalties(input, methodology),
    email: [],
    http: [],
    availability: availabilityPenalties(input, methodology),
  };

  const categories: CategoryScore[] = [];
  const collectedCategories: Category[] = [];
  const notCollectedCategories: Category[] = [];

  for (const category of CATEGORIES) {
    const config = methodology.categories[category];
    const applied = appliedByCategory[category];
    const score = config.collected
      ? Math.max(0, 100 - applied.reduce((total, item) => total + item.points, 0))
      : null;
    if (config.collected) collectedCategories.push(category);
    else notCollectedCategories.push(category);
    categories.push({
      category,
      collected: config.collected,
      weight: config.weight,
      score,
      factors: applied.map((item) => ({
        code: item.code,
        category,
        points: item.points,
        detail: item.detail,
      })),
    });
  }

  const totalWeight = collectedCategories.reduce(
    (total, category) => total + methodology.categories[category].weight,
    0
  );
  const weighted = collectedCategories.reduce((total, category) => {
    const entry = categories.find((item) => item.category === category)!;
    return total + (entry.score ?? 0) * methodology.categories[category].weight;
  }, 0);
  const score = totalWeight > 0 ? Math.round(weighted / totalWeight) : 0;

  return {
    score,
    grade: gradeFor(score, methodology),
    methodologyVersion: methodology.version,
    collectedCategories,
    notCollectedCategories,
    categories,
    factors: categories.flatMap((entry) => entry.factors),
  };
}

export function gradeFor(score: number, methodology: MethodologyConfig): string {
  const { grades } = methodology;
  if (score >= grades.A) return "A";
  if (score >= grades.B) return "B";
  if (score >= grades.C) return "C";
  if (score >= grades.D) return "D";
  if (score >= grades.E) return "E";
  return "F";
}
