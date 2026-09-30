-- DOMIRA — migration 003: transactional outbox for account e-mails.
--
-- DOMIRA has NO e-mail integration today: the business cannot send or receive
-- e-mail. Instead of pretending, every message that would be e-mailed (address
-- verification, password reset) is written here with status 'pending' and the
-- single-use token is stored hashed in the corresponding token table. Platform
-- administrators can read the pending messages through
-- GET /api/admin/outbox (SUPER_ADMIN only) to complete the flow manually.
--
-- When a real e-mail provider is connected, a worker picks up 'pending' rows,
-- sends them and marks them 'sent' — the schema does not change.
CREATE TABLE IF NOT EXISTS outbox_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         uuid REFERENCES users (id) ON DELETE CASCADE,
    kind            text NOT NULL
                    CHECK (kind IN ('email_verification', 'password_reset', 'alert', 'report')),
    to_email        text NOT NULL,
    subject         text NOT NULL,
    body            text NOT NULL,
    action_url      text,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sent', 'failed', 'discarded')),
    error_message   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX IF NOT EXISTS outbox_messages_status_created_idx
    ON outbox_messages (status, created_at DESC);
CREATE INDEX IF NOT EXISTS outbox_messages_user_idx
    ON outbox_messages (user_id, created_at DESC);
