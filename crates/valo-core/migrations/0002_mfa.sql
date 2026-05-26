ALTER TABLE users ADD COLUMN mfa_secret BYTEA;          -- AES-GCM (nonce||ciphertext); NULL = not enrolled
ALTER TABLE users ADD COLUMN mfa_enabled_at TIMESTAMPTZ; -- NULL until enrollment is confirmed

CREATE TABLE mfa_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BYTEA NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_mfa_recovery_user ON mfa_recovery_codes (user_id);
