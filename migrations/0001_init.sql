-- Jnex cloud: first set of tables (M1: shops, owners, logins, POS machines).
-- Run with:  npm run migrate     (safe to run again: finished files are skipped)

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- bcrypt password hashing (crypt / gen_salt)
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive email

CREATE TABLE tenants (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code               text NOT NULL UNIQUE,                -- shop code given to the customer, e.g. JX-4F7K2M9P
  name               text NOT NULL,
  plan               text NOT NULL DEFAULT 'standard',
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  license_expires_at timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE owners (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  email                citext NOT NULL UNIQUE,
  name                 text NOT NULL,
  password_hash        text NOT NULL,                     -- bcrypt, made inside Postgres
  must_change_password boolean NOT NULL DEFAULT true,
  mfa_secret_enc       text,                              -- authenticator secret, AES-GCM encrypted by the server
  mfa_enabled          boolean NOT NULL DEFAULT false,
  mfa_last_step        bigint,                            -- last 30-second code step used (a code works once)
  status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at           timestamptz NOT NULL DEFAULT now(),
  last_login_at        timestamptz
);
CREATE INDEX owners_tenant_idx ON owners (tenant_id);

-- between "password ok" and "authenticator code ok"
CREATE TABLE auth_challenges (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id   uuid NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
  kind       text NOT NULL CHECK (kind IN ('mfa', 'mfa_setup')),
  token_hash text NOT NULL UNIQUE,                        -- only the hash is stored
  attempts   int NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id     uuid NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
  token_hash   text NOT NULL UNIQUE,                      -- only the hash is stored
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  ip           text,
  user_agent   text,
  revoked_at   timestamptz
);
CREATE INDEX sessions_owner_idx ON sessions (owner_id);

CREATE TABLE devices (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
  name          text NOT NULL,
  hw_hash       text NOT NULL,
  public_key    text NOT NULL,                            -- Ed25519, base64url
  status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
  device_code   text,                                     -- A, B, C ... (bill number prefix)
  app_version   text,
  revoke_reason text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  approved_at   timestamptz,
  revoked_at    timestamptz,
  last_seen_at  timestamptz,
  UNIQUE (tenant_id, public_key),
  UNIQUE (tenant_id, device_code)
);
CREATE INDEX devices_status_idx ON devices (status);

CREATE TABLE rate_limits (
  key          text NOT NULL,
  window_start timestamptz NOT NULL,
  count        int NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window_start)
);

CREATE TABLE audit_events (
  id        bigserial PRIMARY KEY,
  at        timestamptz NOT NULL DEFAULT now(),
  tenant_id uuid,
  actor     text NOT NULL,
  action    text NOT NULL,
  details   jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, at DESC);

-- the audit trail can be added to, never edited or deleted
CREATE FUNCTION audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
