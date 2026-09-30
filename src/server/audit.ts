/**
 * Audit trail writer.
 *
 * Called for register, login (success and failure), logout, organisation creation
 * and membership changes. An audit write must never break the request it
 * describes — failures are logged and swallowed.
 *
 * Never write secrets here: no passwords, no session tokens, no CSRF tokens.
 */
import { query, type QueryRunner } from "~/db";

export type AuditAction =
  | "user.register"
  | "user.register.failed"
  | "user.login"
  | "user.login.failed"
  | "user.logout"
  | "user.email_verified"
  | "user.password_reset_requested"
  | "user.password_reset_completed"
  | "organization.created"
  | "organization.updated"
  | "membership.added"
  | "membership.role_changed"
  | "membership.removed"
  // Deliverable 2a — domain management, verification gate, scans and findings.
  | "domain.created"
  | "domain.updated"
  | "domain.deleted"
  | "domain.verification_started"
  | "domain.verified"
  | "domain.verification_failed"
  | "scan.requested"
  | "scan.cancelled"
  | "finding.status_changed";

export interface AuditEntry {
  action: AuditAction;
  organizationId?: string | null;
  actorUserId?: string | null;
  actorEmail?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  outcome?: "success" | "failure";
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

export async function writeAuditLog(entry: AuditEntry, runner?: QueryRunner): Promise<void> {
  const text = `insert into audit_logs
      (organization_id, actor_user_id, actor_email, action, target_type, target_id, outcome, ip, user_agent, metadata)
      values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`;
  const params = [
    entry.organizationId ?? null,
    entry.actorUserId ?? null,
    entry.actorEmail ?? null,
    entry.action,
    entry.targetType ?? null,
    entry.targetId ?? null,
    entry.outcome ?? "success",
    entry.ip ?? null,
    entry.userAgent ?? null,
    JSON.stringify(entry.metadata ?? {}),
  ];
  try {
    if (runner) await runner.query(text, params);
    else await query(text, params);
  } catch (error) {
    console.error(
      `[domira] audit log write failed for ${entry.action}:`,
      error instanceof Error ? error.message : error
    );
  }
}
