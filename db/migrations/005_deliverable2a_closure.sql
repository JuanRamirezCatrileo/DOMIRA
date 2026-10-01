-- DOMIRA — migration 005: deliverable 2a closure (queue throughput, quotas and the
-- single-pending-token guarantee for domain verification).
--
-- Additive only. Nothing already applied (001-004) is edited; this file is the
-- schema change that ships with the API + worker + scheduler closure. Every
-- statement is idempotent so `bun run migrate` can be re-run on every deploy.

-- ---------------------------------------------------------------------------
-- domain_verifications — at most ONE pending token per domain.
-- `ensureVerification()` retires the previous pending row before issuing a new one,
-- so the customer can never be shown two valid challenges, and a retry cannot
-- accidentally verify with a stale token. A partial unique index enforces it at the
-- database level rather than trusting the code path.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS domain_verifications_pending_key
    ON domain_verifications (domain_id) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- scans — the hourly scan quotas (per organisation and per domain) are counted from
-- the real rows, so the lookups need an index on created_at.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS scans_org_created_quota_idx
    ON scans (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_domain_created_quota_idx
    ON scans (domain_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- jobs — claiming orders by (priority, available_at, created_at) among due jobs;
-- the worker also lists the queued jobs of one organisation for the admin view.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS jobs_due_claim_idx
    ON jobs (priority, available_at, created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS jobs_org_status_created_idx
    ON jobs (organization_id, status, created_at DESC);
