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
