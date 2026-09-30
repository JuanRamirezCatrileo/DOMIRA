/**
 * The DOMIRA Scoring Methodology.
 *
 * The methodology is DATA, not code: weights, penalties, thresholds and the
 * coverage policy live in the `score_methodologies` table (migration 004) as a
 * versioned JSON document, so an operator can change how domains are scored
 * without touching — or rebuilding — the UI. Every score row records the version
 * that produced it.
 *
 * The 1.0.0 default below is the seed: it is inserted idempotently the first time
 * the engine needs an active methodology, then read back from the database on
 * every scan (`loadActiveMethodology`). Changing a weight means inserting a new
 * version row and activating it — documented in docs/scanning.md.
 *
 * Coverage is explicit and honest: version 1.0.0 collects TLS, Certificate, DNS
 * and Availability. E-mail (SPF/DMARC/DKIM) and HTTP security headers are NOT
 * collected yet (deliverable 2b); they are stored with `collected: false` and
 * weight 0, and the overall score renormalises over the collected categories
 * only — an uncollected category is never silently credited with full marks.
 */
import { z } from "zod";

import { query, type QueryRunner } from "~/db";

export const CATEGORIES = ["tls", "certificate", "dns", "email", "http", "availability"] as const;
export type Category = (typeof CATEGORIES)[number];

const categoryMethodologySchema = z.object({
  collected: z.boolean(),
  weight: z.number().min(0).max(100),
  penalties: z.record(z.string(), z.number().min(0).max(100)),
});

export const methodologySchema = z.object({
  version: z.string().min(1).max(40),
  description: z.string().max(400),
  uncollectedPolicy: z.literal("exclude_and_renormalise"),
  categories: z.object({
    tls: categoryMethodologySchema,
    certificate: categoryMethodologySchema,
    dns: categoryMethodologySchema,
    email: categoryMethodologySchema,
    http: categoryMethodologySchema,
    availability: categoryMethodologySchema,
  }),
  thresholds: z.object({
    expiringSoonDays: z.number(),
    expiringWarningDays: z.number(),
    slowResponseMs: z.number(),
    verySlowResponseMs: z.number(),
    weakRsaBits: z.number(),
  }),
  grades: z.object({
    A: z.number(),
    B: z.number(),
    C: z.number(),
    D: z.number(),
    E: z.number(),
  }),
});

export type MethodologyConfig = z.infer<typeof methodologySchema>;
export type CategoryMethodology = z.infer<typeof categoryMethodologySchema>;

/** Methodology version 1.0.0 — the seed row written on first use. */
export const DEFAULT_METHODOLOGY: MethodologyConfig = {
  version: "1.0.0",
  description:
    "Deliverable 2a coverage: TLS, Certificate, DNS and Availability are collected. " +
    "E-mail (SPF/DMARC/DKIM) and HTTP security headers are not collected yet " +
    "(deliverable 2b) and are excluded from the weighted average.",
  uncollectedPolicy: "exclude_and_renormalise",
  categories: {
    tls: {
      collected: true,
      weight: 20,
      penalties: {
        handshake_failed: 100,
        legacy_protocol: 40,
        outdated_protocol: 10,
      },
    },
    certificate: {
      collected: true,
      weight: 30,
      penalties: {
        missing: 100,
        expired: 100,
        expiring_soon: 40,
        expiring_warning: 15,
        hostname_mismatch: 35,
        chain_invalid: 25,
        self_signed: 20,
        weak_key: 20,
      },
    },
    dns: {
      collected: true,
      weight: 25,
      penalties: {
        not_resolving: 100,
        no_a_record: 60,
        no_ns_record: 20,
        no_mx_record: 10,
        no_caa_record: 10,
        no_aaaa_record: 5,
      },
    },
    email: {
      collected: false,
      weight: 0,
      penalties: {},
    },
    http: {
      collected: false,
      weight: 0,
      penalties: {},
    },
    availability: {
      collected: true,
      weight: 25,
      penalties: {
        unreachable: 100,
        server_error: 45,
        client_error: 25,
        no_https_redirect: 15,
        very_slow_response: 15,
        slow_response: 8,
      },
    },
  },
  thresholds: {
    expiringSoonDays: 30,
    expiringWarningDays: 60,
    slowResponseMs: 1500,
    verySlowResponseMs: 3000,
    weakRsaBits: 2048,
  },
  grades: { A: 90, B: 80, C: 70, D: 60, E: 40 },
};

/** Categories that version 1.0.0 does not collect yet (reported as not_collected). */
export function notCollectedCategories(methodology: MethodologyConfig): Category[] {
  return CATEGORIES.filter((category) => !methodology.categories[category].collected);
}

/**
 * Reads the active methodology from the database, seeding the 1.0.0 default when
 * the table is empty. A row whose JSON does not match the schema is ignored (and
 * reported), so a bad edit can never silently produce a wrong score.
 */
export async function loadActiveMethodology(runner?: QueryRunner): Promise<MethodologyConfig> {
  const run = <T>(text: string, params?: readonly unknown[]) =>
    runner ? runner.query<T>(text, params) : query<T>(text, params);

  const existing = await run<{ version: string; config: unknown }>(
    "select version, config from score_methodologies where is_active order by created_at desc limit 1"
  );
  const row = existing.rows[0];
  if (row) {
    const parsed = methodologySchema.safeParse(row.config);
    if (parsed.success) return parsed.data;
    console.error(
      `[domira] active score methodology ${row.version} is invalid; falling back to the built-in default.`
    );
    return DEFAULT_METHODOLOGY;
  }

  await run(
    `insert into score_methodologies (version, description, is_active, config, activated_at)
     values ($1, $2, true, $3::jsonb, now())
     on conflict (version) do nothing`,
    [DEFAULT_METHODOLOGY.version, DEFAULT_METHODOLOGY.description, JSON.stringify(DEFAULT_METHODOLOGY)]
  );
  const reselected = await run<{ config: unknown }>(
    "select config from score_methodologies where is_active limit 1"
  );
  const seeded = reselected.rows[0];
  if (seeded) {
    const parsed = methodologySchema.safeParse(seeded.config);
    if (parsed.success) return parsed.data;
  }
  return DEFAULT_METHODOLOGY;
}
