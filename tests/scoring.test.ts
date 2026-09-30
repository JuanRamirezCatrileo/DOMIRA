/**
 * Engine unit tests: the scoring methodology is a pure function of the observed
 * inputs, so deterministic inputs must produce exact per-category and overall
 * scores — and the same result every time (a score that drifts between runs would
 * make the product's history meaningless).
 *
 * These tests touch no database and no network: `computeSecurityScore()` is pure.
 */
import { describe, expect, test } from "bun:test";
import { DEFAULT_METHODOLOGY, notCollectedCategories } from "~/server/scanning/methodology";
import { computeSecurityScore, gradeFor, type ScoreInput } from "~/server/scanning/score";

function input(overrides: {
  tls?: Partial<ScoreInput["tls"]>;
  certificate?: Partial<ScoreInput["certificate"]>;
  dns?: Partial<ScoreInput["dns"]>;
  availability?: Partial<ScoreInput["availability"]>;
} = {}): ScoreInput {
  return {
    tls: { handshakeOk: true, protocol: "TLSv1.3", ...overrides.tls },
    certificate: {
      present: true,
      expired: false,
      daysRemaining: 200,
      hostnameMatches: true,
      chainValid: true,
      selfSigned: false,
      keyAlgorithm: "RSA",
      keySize: 2048,
      ...overrides.certificate,
    },
    dns: {
      resolved: true,
      hasA: true,
      hasAAAA: false,
      hasNs: true,
      hasMx: true,
      hasCaa: false,
      ...overrides.dns,
    },
    availability: {
      reachable: true,
      statusCode: 200,
      responseTimeMs: 120,
      httpToHttpsRedirect: true,
      ...overrides.availability,
    },
  };
}

function categoryScore(result: ReturnType<typeof computeSecurityScore>, category: string) {
  return result.categories.find((entry) => entry.category === category)?.score ?? null;
}

describe("computeSecurityScore", () => {
  test("a healthy domain scores exactly 96 (TLS 100, cert 100, DNS 85, availability 100)", () => {
    const result = computeSecurityScore(input(), DEFAULT_METHODOLOGY);
    expect(categoryScore(result, "tls")).toBe(100);
    expect(categoryScore(result, "certificate")).toBe(100);
    // No CAA record (10) and no AAAA record (5) — real observations, real penalty.
    expect(categoryScore(result, "dns")).toBe(85);
    expect(categoryScore(result, "availability")).toBe(100);
    expect(result.score).toBe(96);
    expect(result.grade).toBe("A");
    expect(result.methodologyVersion).toBe("1.0.0");
    expect(result.factors.map((factor) => factor.code).sort()).toEqual([
      "dns.no_aaaa_record",
      "dns.no_caa_record",
    ]);
  });

  test("a failed TLS handshake costs the TLS category entirely (20 of 100 weight)", () => {
    const result = computeSecurityScore(input({ tls: { handshakeOk: false, protocol: null } }), DEFAULT_METHODOLOGY);
    expect(categoryScore(result, "tls")).toBe(0);
    expect(categoryScore(result, "certificate")).toBe(100);
    expect(result.score).toBe(76);
    expect(result.grade).toBe("C");
  });

  test("an expired certificate zeroes the certificate category", () => {
    const result = computeSecurityScore(input({ certificate: { expired: true, daysRemaining: -1 } }), DEFAULT_METHODOLOGY);
    expect(categoryScore(result, "certificate")).toBe(0);
    expect(result.score).toBe(66);
    expect(result.grade).toBe("D");
  });

  test("a certificate expiring within the warning window is penalised but not zeroed", () => {
    const result = computeSecurityScore(input({ certificate: { daysRemaining: 20 } }), DEFAULT_METHODOLOGY);
    expect(categoryScore(result, "certificate")).toBe(60);
    expect(result.score).toBe(84);
    expect(result.grade).toBe("B");
  });

  test("e-mail and HTTP are reported as not collected, never as full marks", () => {
    const result = computeSecurityScore(input(), DEFAULT_METHODOLOGY);
    expect(result.notCollectedCategories).toEqual(["email", "http"]);
    expect(categoryScore(result, "email")).toBeNull();
    expect(categoryScore(result, "http")).toBeNull();
    // The weighted average renormalises over the collected categories only, whose
    // weights add up to 100 in methodology 1.0.0 — so an uncollected category can
    // never contribute points.
    const collectedWeight = result.categories
      .filter((entry) => entry.collected)
      .reduce((total, entry) => total + entry.weight, 0);
    expect(collectedWeight).toBe(100);
    expect(notCollectedCategories(DEFAULT_METHODOLOGY)).toEqual(["email", "http"]);
  });

  test("re-scoring identical observations is byte-for-byte stable", () => {
    const observations = input({ certificate: { daysRemaining: 44 } });
    const first = computeSecurityScore(observations, DEFAULT_METHODOLOGY);
    const second = computeSecurityScore(observations, DEFAULT_METHODOLOGY);
    expect(second).toEqual(first);
    expect(second.score).toBe(first.score);
  });

  test("an unreachable, unresolvable host scores 0 and grade F", () => {
    const result = computeSecurityScore(
      input({
        tls: { handshakeOk: false, protocol: null },
        certificate: { present: false, expired: false, daysRemaining: null, hostnameMatches: null, chainValid: null },
        dns: { resolved: false, hasA: false, hasAAAA: false, hasNs: false, hasMx: false, hasCaa: false },
        availability: { reachable: false, statusCode: null, responseTimeMs: null, httpToHttpsRedirect: null },
      }),
      DEFAULT_METHODOLOGY
    );
    expect(result.score).toBe(0);
    expect(result.grade).toBe("F");
    expect(categoryScore(result, "tls")).toBe(0);
    expect(categoryScore(result, "certificate")).toBe(0);
    expect(categoryScore(result, "dns")).toBe(0);
    expect(categoryScore(result, "availability")).toBe(0);
  });

  test("grade thresholds are the methodology's, not hardcoded in a component", () => {
    expect(gradeFor(90, DEFAULT_METHODOLOGY)).toBe("A");
    expect(gradeFor(89, DEFAULT_METHODOLOGY)).toBe("B");
    expect(gradeFor(70, DEFAULT_METHODOLOGY)).toBe("C");
    expect(gradeFor(60, DEFAULT_METHODOLOGY)).toBe("D");
    expect(gradeFor(40, DEFAULT_METHODOLOGY)).toBe("E");
    expect(gradeFor(39, DEFAULT_METHODOLOGY)).toBe("F");
  });
});
