import type { Actor } from "~/server/rbac/guard";

/** Context handed to every API handler. */
export interface ApiRouteContext {
  request: Request;
  url: URL;
  params: Record<string, string>;
  ip: string;
  userAgent: string;
}

export interface ApiRoute {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  /** Path pattern; `:name` segments are captured into ctx.params. */
  path: string;
  summary: string;
  /** False for endpoints that exist only to answer 501 until deliverable 2. */
  implemented: boolean;
  handler: (ctx: ApiRouteContext) => Promise<Response>;
}

export type AuthenticatedHandler = (
  ctx: ApiRouteContext,
  actor: Actor
) => Promise<Response>;

/** Serialises a user row for API responses — never includes the password hash. */
export function publicUser(user: {
  id: string;
  email: string;
  full_name?: string | null;
  fullName?: string | null;
  locale?: string;
  is_super_admin?: boolean;
  isSuperAdmin?: boolean;
  email_verified_at?: Date | string | null;
  emailVerifiedAt?: Date | string | null;
  created_at?: Date | string | null;
  createdAt?: Date | string | null;
}) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName ?? user.full_name ?? null,
    locale: user.locale ?? "es",
    isSuperAdmin: user.isSuperAdmin ?? user.is_super_admin ?? false,
    emailVerified: Boolean(user.emailVerifiedAt ?? user.email_verified_at ?? null),
    createdAt: toIso(user.createdAt ?? user.created_at ?? null),
  };
}

export function toIso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

export function toNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}
