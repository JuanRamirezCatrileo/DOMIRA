/**
 * The RBAC matrix — the single source of truth in code, mirrored by the `roles`
 * reference rows seeded in db/migrations/001_core_tenancy.sql.
 *
 * Adding a permission means: add it here, add it to the seeded arrays in a new
 * migration, then use `requireOrgRole(...)` in the handler. Nothing is decided in
 * the UI: hiding a button is never authorisation.
 */
export const ROLE_CODES = ["SUPER_ADMIN", "ADMIN", "MEMBER", "VIEWER"] as const;
export type RoleCode = (typeof ROLE_CODES)[number];

export const PERMISSIONS = [
  "platform:admin",
  "org:read",
  "org:create",
  "org:update",
  "org:manage_members",
  "domain:read",
  "domain:manage",
  "domain:delete",
  "scan:run",
  "finding:manage",
  "alert:read",
  "audit:read",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLE_PERMISSIONS: Record<RoleCode, readonly Permission[]> = {
  SUPER_ADMIN: [
    "platform:admin",
    "org:read",
    "org:create",
    "org:update",
    "org:manage_members",
    "domain:read",
    "domain:manage",
    "domain:delete",
    "scan:run",
    "finding:manage",
    "alert:read",
    "audit:read",
  ],
  ADMIN: [
    "org:read",
    "org:update",
    "org:manage_members",
    "domain:read",
    "domain:manage",
    "domain:delete",
    "scan:run",
    "finding:manage",
    "alert:read",
    "audit:read",
  ],
  MEMBER: [
    "org:read",
    "domain:read",
    "domain:manage",
    "scan:run",
    "finding:manage",
    "alert:read",
  ],
  VIEWER: ["org:read", "domain:read"],
};

export const ROLE_RANK: Record<RoleCode, number> = {
  SUPER_ADMIN: 100,
  ADMIN: 40,
  MEMBER: 20,
  VIEWER: 10,
};

/** Roles a customer may assign inside their own organisation. */
export const ASSIGNABLE_ORG_ROLES: readonly RoleCode[] = ["ADMIN", "MEMBER", "VIEWER"];

export function isRoleCode(value: unknown): value is RoleCode {
  return typeof value === "string" && (ROLE_CODES as readonly string[]).includes(value);
}

export function roleHasPermission(role: RoleCode, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}

export function roleRank(role: RoleCode): number {
  return ROLE_RANK[role];
}
