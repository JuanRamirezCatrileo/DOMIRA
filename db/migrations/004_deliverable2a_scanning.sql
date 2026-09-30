-- DOMIRA — migration 004: deliverable 2a (domain management, verification gate,
-- Postgres-backed job queue and the passive scanning pipeline).
--
-- Everything here is additive and portable: plain standard PostgreSQL (>= 14), no
-- extensions, no vendor types. Existing rows keep working (new columns have
-- defaults); the only destructive-looking statements are DROP CONSTRAINT +
-- ADD CONSTRAINT on text CHECK enumerations, which is the documented convention in
-- migration 001 (adding a value to a CHECK runs inside a transaction, unlike
-- ALTER TYPE ... ADD VALUE).

-- ---------------------------------------------------------------------------
-- domains — the lifecycle gains 'paused' and 'error' (docs/scanning.md documents
-- the full state machine) and the frequency gains '6h'.
-- ---------------------------------------------------------------------------
ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_status_check;
ALTER TABLE domains ADD CONSTRAINT domains_status_check
    CHECK (status IN ('pending_verification', 'verified', 'paused', 'error', 'suspended', 'archived'));

ALTER TABLE domains DROP CONSTRAINT IF EXISTS domains_check_frequency_check;
ALTER TABLE domains ADD CONSTRAINT domains_check_frequency_check
    CHECK (check_frequency IN ('manual', 'hourly', '6h', 'daily', 'weekly'));

-- Consecutive failed scans. When a scheduled scan fails the counter grows; at the
-- documented threshold the domain moves to status='error' and monitoring pauses
-- until the customer acts (see docs/scanning.md). A successful scan clears it.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS consecutive_failures integer NOT NULL DEFAULT 0;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS paused_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS updated_by uuid REFERENCES users (id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- domain_verifications — the ownership gate. New columns record what the real DNS
-- lookup saw, so the customer can be shown the observed TXT values, and the
-- attempt/exhaustion state is auditable.
-- ---------------------------------------------------------------------------
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS record_name text;
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS record_value text;
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS evidence jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE domain_verifications ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS domain_verifications_pending_idx
    ON domain_verifications (domain_id) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- jobs — the queue. A job that produces tenant data always carries organization_id
-- AND domain_id (deliverable 2 requirement), plus a heartbeat so a worker that dies
-- mid-job can be detected and its job reclaimed.
-- ---------------------------------------------------------------------------
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS domain_id uuid REFERENCES domains (id) ON DELETE CASCADE;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scan_id uuid REFERENCES scans (id) ON DELETE SET NULL;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at timestamptz;
CREATE INDEX IF NOT EXISTS jobs_stale_idx
    ON jobs (heartbeat_at) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS jobs_org_domain_idx ON jobs (organization_id, domain_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- scans — a domain may have at most one active (queued or running) scan. This is
-- the database-level idempotency guarantee behind "clicking scan twice must not
-- corrupt state": the second request re-uses the active scan instead of inserting.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS scans_domain_active_key
    ON scans (domain_id) WHERE status IN ('queued', 'running');
ALTER TABLE scans ADD COLUMN IF NOT EXISTS checks_completed integer NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS checks_failed integer NOT NULL DEFAULT 0;
-- A cancelled scan whose worker is still running must not write results: the worker
-- re-reads the status before persisting (documented in docs/scanning.md).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS worker_id text;

-- ---------------------------------------------------------------------------
-- certificates — the TLS snapshot. Extra columns cover chain length/error and the
-- hostname that was actually checked (the certificate is fetched for the domain,
-- but recording the checked host keeps the row self-describing).
-- ---------------------------------------------------------------------------
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS chain_length integer;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS chain_error text;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS checked_hostname text;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS checked_port integer NOT NULL DEFAULT 443;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS tls_protocol text;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS cipher text;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS self_signed boolean NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- scan_results — one row per check category per scan. `data` holds the raw
-- observation and `error_message` the real error text when the check failed, so a
-- failed check can never be mistaken for a clean one.
-- ---------------------------------------------------------------------------
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS check_duration_ms integer;
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS not_collected boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS scan_results_org_scan_cat_idx
    ON scan_results (organization_id, scan_id, category);

-- ---------------------------------------------------------------------------
-- score_methodologies — the scoring methodology lives in the database, versioned,
-- so changing weights or thresholds never requires rebuilding the UI and every
-- stored score records which version produced it. Only one row may be active
-- (partial unique index). The 1.0.0 default is defined in
-- src/server/scanning/methodology.ts and inserted idempotently on first use.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS score_methodologies (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version         text NOT NULL UNIQUE,
    description     text NOT NULL DEFAULT '',
    is_active       boolean NOT NULL DEFAULT false,
    config          jsonb NOT NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    activated_at    timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS score_methodologies_active_key
    ON score_methodologies (is_active) WHERE is_active;

-- ---------------------------------------------------------------------------
-- security_scores — record the methodology version and the coverage of each score
-- so a score can always be explained, including which categories were NOT
-- collected (email and HTTP until deliverable 2b).
-- ---------------------------------------------------------------------------
ALTER TABLE security_scores ADD COLUMN IF NOT EXISTS methodology_version text NOT NULL DEFAULT '1.0.0';
ALTER TABLE security_scores ADD COLUMN IF NOT EXISTS coverage jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE security_scores ADD COLUMN IF NOT EXISTS trigger_source text;

-- ---------------------------------------------------------------------------
-- findings — the resolution trail is useful for the dashboard and for deliverable
-- 4 alerts; `last_scan_id` shows which scan confirmed the finding most recently.
-- ---------------------------------------------------------------------------
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_scan_id uuid REFERENCES scans (id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_changed_at timestamptz;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_changed_by uuid REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS occurrences integer NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS findings_org_category_idx
    ON findings (organization_id, category, last_seen_at DESC);

-- ---------------------------------------------------------------------------
-- RBAC reference data. The authoritative matrix lives in
-- src/server/rbac/permissions.ts (ROLE_PERMISSIONS) — the same convention as
-- migration 001. Deliverable 2a adds two permissions:
--   * domain:delete  — deleting/archiving a domain (ADMIN and above).
--   * finding:manage — acknowledging/resolving/ignoring a finding (MEMBER and above).
-- ---------------------------------------------------------------------------
UPDATE roles SET permissions = (
    SELECT array_agg(DISTINCT p) FROM unnest(permissions || ARRAY['domain:delete']) AS p
) WHERE code IN ('SUPER_ADMIN', 'ADMIN');
UPDATE roles SET permissions = (
    SELECT array_agg(DISTINCT p) FROM unnest(permissions || ARRAY['finding:manage']) AS p
) WHERE code IN ('SUPER_ADMIN', 'ADMIN', 'MEMBER');
