-- DOMIRA — migration 001: core identity, tenancy, sessions, audit and rate limiting.
--
-- Portable standard PostgreSQL (>= 14). No extensions, no vendor-specific types:
-- every statement below runs unchanged on Tiger Cloud / Timescale, Neon,
-- RDS/Aurora, Cloud SQL, a plain VPS Postgres and on PGlite (PostgreSQL compiled
-- to WASM) used by the test suite.
--
-- Conventions used across every migration:
--   * uuid primary keys, default gen_random_uuid() (core since PostgreSQL 13).
--   * timestamptz everywhere.
--   * every tenant-owned row carries organization_id NOT NULL + FK.
--   * enumerations are `text` + CHECK constraints instead of native enum types
--     (adding a value later is a plain ALTER ... DROP/ADD CONSTRAINT, which runs
--     inside a transaction; ALTER TYPE ... ADD VALUE would not).
--   * list queries are backed by composite indexes on (organization_id, ...).

-- ---------------------------------------------------------------------------
-- roles — reference table, the single source of truth for the RBAC matrix.
-- Rows are seeded at the bottom of this migration (reference data, not demo data).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    code            text PRIMARY KEY
                    CHECK (code IN ('SUPER_ADMIN', 'ADMIN', 'MEMBER', 'VIEWER')),
    name_es         text NOT NULL,
    name_en         text NOT NULL,
    description_es  text NOT NULL,
    description_en  text NOT NULL,
    permissions     text[] NOT NULL DEFAULT '{}',
    rank            integer NOT NULL,
    is_platform     boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- users — platform accounts. Email uniqueness is enforced case-insensitively
-- through a unique index on lower(email) (no citext dependency).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email               text NOT NULL CHECK (position('@' IN email) > 1),
    password_hash       text NOT NULL,
    full_name           text,
    locale              text NOT NULL DEFAULT 'es' CHECK (locale IN ('es', 'en')),
    is_super_admin      boolean NOT NULL DEFAULT false,
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'suspended')),
    email_verified_at   timestamptz,
    failed_login_count  integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (lower(email));
CREATE INDEX IF NOT EXISTS users_status_idx ON users (status);

-- ---------------------------------------------------------------------------
-- sessions — server-side, revocable sessions. Only the SHA-256 hash of the
-- session token is stored, so a database leak does not hand over live sessions.
-- csrf_token_hash binds the CSRF token to this session (double-submit + Origin).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash      text NOT NULL UNIQUE,
    csrf_token_hash text NOT NULL,
    ip              text,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_reason  text
);
CREATE INDEX IF NOT EXISTS sessions_user_active_idx
    ON sessions (user_id, last_seen_at DESC) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- email_verification_tokens / password_reset_tokens — single-use, hashed,
-- expiring tokens. DOMIRA has no e-mail integration yet: tokens are generated
-- and returned to the caller (logged server-side) instead of being e-mailed.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email       text NOT NULL,
    token_hash  text NOT NULL UNIQUE,
    attempts    integer NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email_verification_tokens_user_idx
    ON email_verification_tokens (user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  text NOT NULL UNIQUE,
    attempts    integer NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
    ON password_reset_tokens (user_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- organizations + membership. Slug is globally unique and is the only
-- human-facing identifier; every tenant resource points at organizations.id.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 2 AND 120),
    slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    status      text NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'archived')),
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);
CREATE INDEX IF NOT EXISTS organizations_status_idx ON organizations (status, created_at DESC);

CREATE TABLE IF NOT EXISTS organization_members (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_code       text NOT NULL REFERENCES roles (code) ON UPDATE CASCADE,
    invited_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    joined_at       timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organization_members_unique UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS organization_members_org_role_idx
    ON organization_members (organization_id, role_code);
CREATE INDEX IF NOT EXISTS organization_members_user_idx
    ON organization_members (user_id, organization_id);

-- ---------------------------------------------------------------------------
-- audit_logs — append-only trail of security-relevant actions. Never contains
-- secrets or password material; target/actor are denormalised so the trail
-- survives user deletion.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE SET NULL,
    actor_user_id   uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_email     text,
    action          text NOT NULL,
    target_type     text,
    target_id       text,
    outcome         text NOT NULL DEFAULT 'success'
                    CHECK (outcome IN ('success', 'failure')),
    ip              text,
    user_agent      text,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_org_created_idx
    ON audit_logs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_actor_created_idx
    ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_action_created_idx
    ON audit_logs (action, created_at DESC);

-- ---------------------------------------------------------------------------
-- rate_limits — database-backed fixed-window counters (per IP and per identity).
-- Stored in Postgres so the limit is shared by every process/replica.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
    key               text PRIMARY KEY,
    window_started_at timestamptz NOT NULL DEFAULT now(),
    count             integer NOT NULL DEFAULT 0,
    expires_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rate_limits_expires_idx ON rate_limits (expires_at);

-- Reference data: the RBAC matrix, mirrored in src/server/rbac/permissions.ts.
INSERT INTO roles (code, name_es, name_en, description_es, description_en, permissions, rank, is_platform)
VALUES
    ('SUPER_ADMIN', 'Superadministrador', 'Super admin',
     'Administra la plataforma DOMIRA completa.', 'Administers the whole DOMIRA platform.',
     ARRAY['platform:admin','org:read','org:create','org:update','org:manage_members','domain:read','domain:manage','scan:run','alert:read','audit:read'],
     100, true),
    ('ADMIN', 'Administrador', 'Admin',
     'Administra su organización, sus miembros y sus dominios.',
     'Manages their organisation, its members and its domains.',
     ARRAY['org:read','org:update','org:manage_members','domain:read','domain:manage','scan:run','alert:read','audit:read'],
     40, false),
    ('MEMBER', 'Miembro', 'Member',
     'Trabaja con los dominios y análisis de su organización.',
     'Works with their organisation domains and scans.',
     ARRAY['org:read','domain:read','domain:manage','scan:run','alert:read'],
     20, false),
    ('VIEWER', 'Lector', 'Viewer',
     'Solo lectura de los datos de su organización.',
     'Read-only access to their organisation data.',
     ARRAY['org:read'],
     10, false)
ON CONFLICT (code) DO UPDATE
    SET name_es = EXCLUDED.name_es,
        name_en = EXCLUDED.name_en,
        description_es = EXCLUDED.description_es,
        description_en = EXCLUDED.description_en,
        permissions = EXCLUDED.permissions,
        rank = EXCLUDED.rank,
        is_platform = EXCLUDED.is_platform;
