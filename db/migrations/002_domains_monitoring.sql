-- DOMIRA — migration 002: domains, passive monitoring results and findings.
--
-- Every table here is tenant-owned: organization_id is NOT NULL with an FK to
-- organizations. Rows written by the scanning engine (deliverable 2) always carry
-- both organization_id and domain_id so tenant isolation can be enforced at the
-- SQL level for every read. No table stores third-party data: DOMIRA only stores
-- results of passive checks against domains a customer has declared authorised.

-- ---------------------------------------------------------------------------
-- domains — the customer's authorised domains.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domains (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    hostname             text NOT NULL CHECK (hostname ~ '^[a-zA-Z0-9.-]{1,253}$'),
    normalized_hostname  text NOT NULL,
    display_name         text,
    status               text NOT NULL DEFAULT 'pending_verification'
                         CHECK (status IN ('pending_verification', 'verified', 'suspended', 'archived')),
    authorization_note   text,
    monitoring_enabled   boolean NOT NULL DEFAULT false,
    check_frequency      text NOT NULL DEFAULT 'daily'
                         CHECK (check_frequency IN ('manual', 'hourly', 'daily', 'weekly')),
    added_by             uuid REFERENCES users (id) ON DELETE SET NULL,
    verified_at          timestamptz,
    last_scan_at         timestamptz,
    next_scan_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    deleted_at           timestamptz,
    CONSTRAINT domains_org_hostname_unique UNIQUE (organization_id, normalized_hostname)
);
CREATE INDEX IF NOT EXISTS domains_org_status_idx ON domains (organization_id, status);
CREATE INDEX IF NOT EXISTS domains_org_created_idx ON domains (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS domains_due_idx ON domains (next_scan_at) WHERE monitoring_enabled;

-- ---------------------------------------------------------------------------
-- domain_verifications — proof that the customer controls the domain.
-- challenge_token is intentionally stored in clear text: the customer has to
-- publish it as a DNS TXT record, so it is a public challenge, not a secret.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domain_verifications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    method          text NOT NULL
                    CHECK (method IN ('dns_txt', 'dns_cname', 'http_file', 'meta_tag')),
    challenge_token text NOT NULL,
    record_name     text,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
    attempts        integer NOT NULL DEFAULT 0,
    last_checked_at timestamptz,
    verified_at     timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS domain_verifications_org_domain_idx
    ON domain_verifications (organization_id, domain_id, status);
CREATE INDEX IF NOT EXISTS domain_verifications_token_idx
    ON domain_verifications (challenge_token);

-- ---------------------------------------------------------------------------
-- jobs — the queue. API requests only enqueue; workers pick work up.
-- organization_id may be NULL for platform-wide jobs, but any job that produces
-- tenant data carries it, so a worker can never be tricked into writing across
-- tenants.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    type            text NOT NULL,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    priority        integer NOT NULL DEFAULT 100,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    result          jsonb,
    attempts        integer NOT NULL DEFAULT 0,
    max_attempts    integer NOT NULL DEFAULT 3,
    available_at    timestamptz NOT NULL DEFAULT now(),
    locked_at       timestamptz,
    locked_by       text,
    last_error      text,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);
CREATE INDEX IF NOT EXISTS jobs_claim_idx
    ON jobs (status, priority, available_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS jobs_org_created_idx ON jobs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS jobs_type_status_idx ON jobs (type, status);

-- ---------------------------------------------------------------------------
-- scans — one execution of the analysis pipeline for one domain.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    job_id          uuid REFERENCES jobs (id) ON DELETE SET NULL,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    trigger_source  text NOT NULL DEFAULT 'manual'
                    CHECK (trigger_source IN ('manual', 'scheduled', 'api')),
    requested_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    started_at      timestamptz,
    finished_at     timestamptz,
    duration_ms     integer,
    error_message   text,
    summary         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scans_org_status_idx ON scans (organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS scans_org_domain_idx ON scans (organization_id, domain_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- scan_results — one row per check category inside a scan.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    scan_id         uuid NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    category        text NOT NULL
                    CHECK (category IN ('tls', 'certificate', 'dns', 'email', 'http', 'availability')),
    status          text NOT NULL CHECK (status IN ('ok', 'warning', 'critical', 'error', 'skipped')),
    score           integer CHECK (score BETWEEN 0 AND 100),
    data            jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_message   text,
    duration_ms     integer,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scan_results_org_scan_idx ON scan_results (organization_id, scan_id);
CREATE INDEX IF NOT EXISTS scan_results_org_domain_cat_idx
    ON scan_results (organization_id, domain_id, category, created_at DESC);

-- ---------------------------------------------------------------------------
-- certificates — TLS certificate snapshots observed per domain.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS certificates (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id            uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    scan_id              uuid REFERENCES scans (id) ON DELETE SET NULL,
    subject_cn           text NOT NULL,
    issuer_cn            text,
    issuer_organization  text,
    serial_number        text,
    fingerprint_sha256   text,
    not_before           timestamptz,
    not_after            timestamptz,
    days_remaining       integer,
    key_algorithm        text,
    key_size             integer,
    signature_algorithm  text,
    san                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    tls_versions         jsonb NOT NULL DEFAULT '[]'::jsonb,
    is_wildcard          boolean NOT NULL DEFAULT false,
    chain_valid          boolean,
    hostname_matches     boolean,
    issues               jsonb NOT NULL DEFAULT '[]'::jsonb,
    observed_at          timestamptz NOT NULL DEFAULT now(),
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS certificates_org_domain_expiry_idx
    ON certificates (organization_id, domain_id, not_after DESC);
CREATE INDEX IF NOT EXISTS certificates_expiring_idx
    ON certificates (organization_id, not_after) WHERE not_after IS NOT NULL;

-- ---------------------------------------------------------------------------
-- dns_records — observed DNS answers (passive lookups only).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_records (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    scan_id         uuid REFERENCES scans (id) ON DELETE SET NULL,
    record_type     text NOT NULL
                    CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA')),
    name            text NOT NULL,
    value           text NOT NULL,
    ttl             integer,
    priority        integer,
    is_change       boolean NOT NULL DEFAULT false,
    previous_value  text,
    observed_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dns_records_org_domain_type_idx
    ON dns_records (organization_id, domain_id, record_type, observed_at DESC);
CREATE INDEX IF NOT EXISTS dns_records_org_changes_idx
    ON dns_records (organization_id, observed_at DESC) WHERE is_change;

-- ---------------------------------------------------------------------------
-- email_security_results — SPF / DMARC / MX and DKIM when publicly verifiable.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_security_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    scan_id         uuid REFERENCES scans (id) ON DELETE SET NULL,
    spf_present     boolean,
    spf_record      text,
    spf_policy      text,
    spf_all         text,
    dmarc_present   boolean,
    dmarc_record    text,
    dmarc_policy    text,
    dmarc_rua       text,
    dkim_present    boolean,
    dkim_selector   text,
    dkim_record     text,
    mx_present      boolean,
    mx_hosts        jsonb NOT NULL DEFAULT '[]'::jsonb,
    issues          jsonb NOT NULL DEFAULT '[]'::jsonb,
    observed_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_security_results_org_domain_idx
    ON email_security_results (organization_id, domain_id, observed_at DESC);

-- ---------------------------------------------------------------------------
-- http_security_results — HTTP security headers and availability observations.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS http_security_results (
    id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id               uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    scan_id                 uuid REFERENCES scans (id) ON DELETE SET NULL,
    final_url               text,
    status_code             integer,
    response_time_ms        integer,
    redirects_to_https      boolean,
    hsts                    boolean,
    hsts_max_age            integer,
    hsts_include_subdomains boolean,
    csp                     boolean,
    csp_value               text,
    x_content_type_options  boolean,
    referrer_policy         text,
    permissions_policy      text,
    x_frame_options         text,
    server_header           text,
    issues                  jsonb NOT NULL DEFAULT '[]'::jsonb,
    observed_at             timestamptz NOT NULL DEFAULT now(),
    created_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS http_security_results_org_domain_idx
    ON http_security_results (organization_id, domain_id, observed_at DESC);

-- ---------------------------------------------------------------------------
-- findings — human-readable problems, with technical AND plain-language text.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id             uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    scan_id               uuid REFERENCES scans (id) ON DELETE SET NULL,
    scan_result_id        uuid REFERENCES scan_results (id) ON DELETE SET NULL,
    category              text NOT NULL
                          CHECK (category IN ('tls', 'certificate', 'dns', 'email', 'http', 'availability')),
    code                  text NOT NULL,
    severity              text NOT NULL
                          CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status                text NOT NULL DEFAULT 'new'
                          CHECK (status IN ('new', 'acknowledged', 'resolved', 'ignored')),
    title_es              text NOT NULL,
    title_en              text NOT NULL,
    explanation_simple_es text NOT NULL DEFAULT '',
    explanation_simple_en text NOT NULL DEFAULT '',
    explanation_tech      text NOT NULL DEFAULT '',
    impact_es             text NOT NULL DEFAULT '',
    impact_en             text NOT NULL DEFAULT '',
    recommendation_es     text NOT NULL DEFAULT '',
    recommendation_en     text NOT NULL DEFAULT '',
    evidence              jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),
    acknowledged_at       timestamptz,
    acknowledged_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    resolved_at           timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_domain_code_open_key
    ON findings (domain_id, code) WHERE status IN ('new', 'acknowledged');
CREATE INDEX IF NOT EXISTS findings_org_status_sev_idx
    ON findings (organization_id, status, severity);
CREATE INDEX IF NOT EXISTS findings_org_domain_idx
    ON findings (organization_id, domain_id, last_seen_at DESC);

-- ---------------------------------------------------------------------------
-- security_scores — DOMIRA Security Score history, per domain and aggregate.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_scores (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid REFERENCES domains (id) ON DELETE CASCADE,
    scan_id         uuid REFERENCES scans (id) ON DELETE SET NULL,
    scope           text NOT NULL CHECK (scope IN ('domain', 'organization')),
    score           integer NOT NULL CHECK (score BETWEEN 0 AND 100),
    grade           text NOT NULL CHECK (grade IN ('A', 'B', 'C', 'D', 'E', 'F')),
    previous_score  integer,
    delta           integer,
    category_scores jsonb NOT NULL DEFAULT '{}'::jsonb,
    factors         jsonb NOT NULL DEFAULT '[]'::jsonb,
    changes         jsonb NOT NULL DEFAULT '[]'::jsonb,
    computed_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_scores_scope_domain_chk
        CHECK ((scope = 'domain' AND domain_id IS NOT NULL) OR (scope = 'organization'))
);
CREATE INDEX IF NOT EXISTS security_scores_org_computed_idx
    ON security_scores (organization_id, computed_at DESC);
CREATE INDEX IF NOT EXISTS security_scores_domain_computed_idx
    ON security_scores (domain_id, computed_at DESC);

-- ---------------------------------------------------------------------------
-- monitoring_configs — how often DOMIRA re-checks a domain and what it alerts on.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS monitoring_configs (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id          uuid NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    is_enabled         boolean NOT NULL DEFAULT false,
    frequency          text NOT NULL DEFAULT 'daily'
                       CHECK (frequency IN ('hourly', 'daily', 'weekly')),
    notify_on          text[] NOT NULL DEFAULT ARRAY['certificate_expiring','dns_change','dmarc_change','config_change','availability']::text[],
    certificate_expiry_days integer NOT NULL DEFAULT 30,
    score_alert_threshold   integer NOT NULL DEFAULT 60,
    last_run_at        timestamptz,
    next_run_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT monitoring_configs_domain_unique UNIQUE (domain_id)
);
CREATE INDEX IF NOT EXISTS monitoring_configs_org_enabled_idx
    ON monitoring_configs (organization_id, is_enabled);
CREATE INDEX IF NOT EXISTS monitoring_configs_next_run_idx
    ON monitoring_configs (next_run_at) WHERE is_enabled;

-- ---------------------------------------------------------------------------
-- alerts — what the customer is told about, with plain-language context.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid REFERENCES domains (id) ON DELETE CASCADE,
    finding_id      uuid REFERENCES findings (id) ON DELETE SET NULL,
    type            text NOT NULL
                    CHECK (type IN ('certificate_expiring', 'certificate_expired', 'dns_change',
                                    'dmarc_change', 'config_change', 'availability', 'score_drop')),
    severity        text NOT NULL
                    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status          text NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged', 'resolved', 'ignored')),
    title_es        text NOT NULL,
    title_en        text NOT NULL,
    message_es      text NOT NULL DEFAULT '',
    message_en      text NOT NULL DEFAULT '',
    impact_es       text NOT NULL DEFAULT '',
    impact_en       text NOT NULL DEFAULT '',
    recommendation_es text NOT NULL DEFAULT '',
    recommendation_en text NOT NULL DEFAULT '',
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    triggered_at    timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    acknowledged_by uuid REFERENCES users (id) ON DELETE SET NULL,
    resolved_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_org_status_idx
    ON alerts (organization_id, status, triggered_at DESC);
CREATE INDEX IF NOT EXISTS alerts_org_domain_idx
    ON alerts (organization_id, domain_id, triggered_at DESC);

-- ---------------------------------------------------------------------------
-- notifications — outbound delivery records (no e-mail provider is connected
-- yet: rows here are only 'in_app' until an e-mail integration exists).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid REFERENCES users (id) ON DELETE CASCADE,
    alert_id        uuid REFERENCES alerts (id) ON DELETE CASCADE,
    channel         text NOT NULL CHECK (channel IN ('in_app', 'email', 'webhook')),
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sent', 'failed', 'suppressed')),
    subject         text,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_message   text,
    sent_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_org_created_idx
    ON notifications (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS notifications_user_unread_idx
    ON notifications (user_id, status, created_at DESC);

-- ---------------------------------------------------------------------------
-- reports — generated security reports (web view now; PDF is Phase 2).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    domain_id       uuid REFERENCES domains (id) ON DELETE CASCADE,
    type            text NOT NULL CHECK (type IN ('security_summary', 'score_history', 'findings')),
    format          text NOT NULL DEFAULT 'html' CHECK (format IN ('html', 'json', 'pdf')),
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    period_start    timestamptz,
    period_end      timestamptz,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_message   text,
    generated_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz
);
CREATE INDEX IF NOT EXISTS reports_org_created_idx
    ON reports (organization_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- subscriptions — plan bookkeeping only. No billing provider is connected and
-- no price, trial or payment feature exists yet; every organisation sits on the
-- FREE plan until Phase 2 wires a payment provider.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscriptions (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id          uuid NOT NULL UNIQUE REFERENCES organizations (id) ON DELETE CASCADE,
    plan_code                text NOT NULL DEFAULT 'FREE'
                             CHECK (plan_code IN ('FREE', 'PRO', 'BUSINESS', 'ENTERPRISE')),
    status                   text NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'trialing', 'past_due', 'cancelled')),
    seats                    integer NOT NULL DEFAULT 1 CHECK (seats > 0),
    provider                 text,
    provider_customer_id     text,
    provider_subscription_id text,
    current_period_start     timestamptz,
    current_period_end       timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscriptions_plan_idx ON subscriptions (plan_code, status);
