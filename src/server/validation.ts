/**
 * Strict input validation with zod. Every request body and every path/query
 * parameter is parsed here before it reaches a query — handlers never read raw
 * client values.
 */
import { z } from "zod";

import { ASSIGNABLE_ORG_ROLES, isRoleCode } from "~/server/rbac/permissions";

export const emailSchema = z
  .string()
  .trim()
  .min(3)
  .max(254)
  .refine((value) => /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(value), {
    message: "Enter a valid e-mail address.",
  })
  .transform((value) => value.toLowerCase());

/** Policy mirrors passwordStrength() in src/server/auth/passwords.ts. */
export const passwordSchema = z
  .string()
  .min(12, "Use at least 12 characters.")
  .max(200, "Use at most 200 characters.")
  .refine((value) => /[A-Za-z]/.test(value), { message: "Include at least one letter." })
  .refine((value) => /[^A-Za-z]/.test(value), {
    message: "Include at least one number or symbol.",
  });

export const fullNameSchema = z.string().trim().min(2).max(120);
export const uuidSchema = z
  .string()
  .trim()
  .regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, {
    message: "Invalid identifier.",
  });

export const localeSchema = z.enum(["es", "en"]);
export const orgRoleSchema = z
  .string()
  .trim()
  .refine((value) => isRoleCode(value) && ASSIGNABLE_ORG_ROLES.includes(value), {
    message: "That role cannot be assigned inside an organisation.",
  });

export const organizationNameSchema = z.string().trim().min(2).max(120);

export const tokenSchema = z.string().trim().min(20).max(200);

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  fullName: fullNameSchema.optional(),
  organizationName: organizationNameSchema.optional(),
  locale: localeSchema.optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(200),
});

export const verifyEmailSchema = z.object({ token: tokenSchema });

export const forgotPasswordSchema = z.object({ email: emailSchema });

export const resetPasswordSchema = z.object({ token: tokenSchema, password: passwordSchema });

export const createOrganizationSchema = z.object({
  name: organizationNameSchema,
  locale: localeSchema.optional(),
});

export const addMemberSchema = z.object({
  email: emailSchema,
  role: orgRoleSchema.default("MEMBER"),
});

export const updateMemberSchema = z.object({ role: orgRoleSchema });

/* -------------------------------------------------------------------------- */
/* Deliverable 2a — domains, scans and findings                               */
/* -------------------------------------------------------------------------- */

export const domainFrequencySchema = z.enum(["manual", "hourly", "6h", "daily", "weekly"]);
export type DomainFrequency = z.infer<typeof domainFrequencySchema>;

export const findFindingStatusSchema = z.enum(["new", "acknowledged", "resolved", "ignored"]);
export const findingSeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export const findingCategorySchema = z.enum([
  "tls",
  "certificate",
  "dns",
  "email",
  "http",
  "availability",
]);

/** Pagination shared by every list endpoint: 1-based page, bounded page size. */
export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).max(100000).default(1),
  perPage: z.coerce.number().int().min(1).max(100).default(20),
});

export const createDomainSchema = z.object({
  hostname: z.string().trim().min(1).max(253),
  displayName: z.string().trim().min(1).max(120).optional(),
  authorizationNote: z.string().trim().max(500).optional(),
  monitoringEnabled: z.boolean().optional(),
  checkFrequency: domainFrequencySchema.optional(),
  organizationId: uuidSchema.optional(),
});

export const updateDomainSchema = z
  .object({
    displayName: z.string().trim().min(1).max(120).nullable().optional(),
    authorizationNote: z.string().trim().max(500).nullable().optional(),
    monitoringEnabled: z.boolean().optional(),
    checkFrequency: domainFrequencySchema.optional(),
    /** pause | resume | archive — the documented lifecycle transitions. */
    status: z.enum(["paused", "verified", "archived"]).optional(),
    organizationId: uuidSchema.optional(),
  })
  .refine(
    (value) =>
      value.displayName !== undefined ||
      value.authorizationNote !== undefined ||
      value.monitoringEnabled !== undefined ||
      value.checkFrequency !== undefined ||
      value.status !== undefined,
    { message: "Send at least one field to update." }
  );

export const updateFindingSchema = z.object({
  status: findFindingStatusSchema,
  organizationId: uuidSchema.optional(),
});

