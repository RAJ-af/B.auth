-- Initial schema for the sovereign_app database (spec §5).
CREATE TABLE IF NOT EXISTS accounts (
  email TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  phone_e164 TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK (account_type IN ('independent','guardian_managed')),
  guardian_phone TEXT,
  tier TEXT NOT NULL CHECK (tier IN ('tier1_phone','tier2_identity')),
  verification TEXT NOT NULL,
  id_source TEXT CHECK (id_source IN ('auto','manual')),
  govt_id_ref TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id BIGSERIAL PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('signup','recovery')),
  phone_e164 TEXT NOT NULL,
  code_sha256 TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('sms','voice')),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts_left INT NOT NULL DEFAULT 5,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_otp_phone_created ON otp_challenges (phone_e164, created_at);

CREATE TABLE IF NOT EXISTS devices (
  device_hash TEXT PRIMARY KEY,              -- SHA-256 hex of raw device_id; raw NEVER stored
  email TEXT NOT NULL REFERENCES accounts(email),
  label TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_links (
  link_id BIGSERIAL PRIMARY KEY,
  requester_email TEXT NOT NULL REFERENCES accounts(email),
  target_email TEXT NOT NULL REFERENCES accounts(email),
  status TEXT NOT NULL CHECK (status IN ('requested','approved','revoked','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,           -- requested-state TTL (10 min)
  approved_at TIMESTAMPTZ,
  usable_at TIMESTAMPTZ,                     -- approved_at + FAMILY_LINK_COOLDOWN_HOURS
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_fl_target ON family_links (target_email, status);
CREATE INDEX IF NOT EXISTS idx_fl_requester ON family_links (requester_email, status);

CREATE TABLE IF NOT EXISTS recovery_requests (
  req_id TEXT PRIMARY KEY,
  email TEXT NOT NULL REFERENCES accounts(email),
  status TEXT NOT NULL CHECK (status IN ('awaiting_phone','pending_family',
      'pending_dwell','pending_admin','authorized','completed','expired',
      'denied','cancelled')),
  recognizing_device_hash TEXT,
  recognized_device BOOLEAN NOT NULL DEFAULT false,
  authorized_at TIMESTAMPTZ,
  decided_by_member TEXT,
  cancel_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rr_email ON recovery_requests (email, status);

CREATE TABLE IF NOT EXISTS verification_reviews (
  review_id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  reason TEXT NOT NULL CHECK (reason IN ('policy_manual','auto_script_error')),
  error_detail TEXT,
  reviewed_by TEXT,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  notif_id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  type TEXT NOT NULL,
  body TEXT NOT NULL,
  link_ref TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notif_email ON notifications (email, created_at);

CREATE TABLE IF NOT EXISTS signup_sessions (
  token TEXT PRIMARY KEY,
  payload_json JSONB NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN ('awaiting_otp','awaiting_identity_choice')),
  expires_at TIMESTAMPTZ NOT NULL
);