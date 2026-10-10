-- FootprintX initial schema.
-- All user-owned tables reference users(id) ON DELETE CASCADE so that account
-- deletion removes every row belonging to the user in one transaction.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email                  text NOT NULL,
  password_hash          text NOT NULL,
  display_name           text,
  plan                   text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'premium')),
  plan_source            text NOT NULL DEFAULT 'default' CHECK (plan_source IN ('default', 'development', 'billing')),
  plan_updated_at        timestamptz NOT NULL DEFAULT now(),
  privacy_policy_version text NOT NULL,
  privacy_consent_at     timestamptz NOT NULL,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_lowercase CHECK (email = lower(email))
);
CREATE UNIQUE INDEX users_email_key ON users (email);

CREATE TABLE sessions (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   bytea NOT NULL UNIQUE,
  csrf_token   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE password_reset_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Email connections used for account discovery. Tokens are AES-256-GCM encrypted.
CREATE TABLE email_connections (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider          text NOT NULL CHECK (provider IN ('google', 'microsoft', 'devfixture')),
  email_address     text NOT NULL,
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'error', 'reauth_required')),
  scopes            text[] NOT NULL DEFAULT '{}',
  access_token_enc  text,
  refresh_token_enc text,
  token_expires_at  timestamptz,
  consent_version   text NOT NULL,
  consent_at        timestamptz NOT NULL,
  last_scan_at      timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, provider, email_address)
);

CREATE TABLE oauth_states (
  state_hash        bytea PRIMARY KEY,
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider          text NOT NULL,
  code_verifier_enc text NOT NULL,
  expires_at        timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scans (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  connection_id      uuid REFERENCES email_connections(id) ON DELETE SET NULL,
  provider           text NOT NULL,
  is_fixture         boolean NOT NULL DEFAULT false,
  status             text NOT NULL CHECK (status IN ('running', 'completed', 'partial', 'failed')),
  messages_examined  integer NOT NULL DEFAULT 0,
  messages_limit     integer,
  evidence_found     integer NOT NULL DEFAULT 0,
  accounts_new       integer NOT NULL DEFAULT 0,
  error_code         text,
  error_message      text,
  started_at         timestamptz NOT NULL DEFAULT now(),
  finished_at        timestamptz
);
CREATE INDEX scans_user_idx ON scans (user_id, started_at DESC);

CREATE TABLE accounts (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_domain    text NOT NULL,
  service_name      text NOT NULL,
  category          text NOT NULL DEFAULT 'other',
  ownership         text NOT NULL DEFAULT 'discovered'
                    CHECK (ownership IN ('discovered', 'user_confirmed', 'user_added', 'false_positive')),
  confidence        numeric(4,3) NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
  mfa_status        text NOT NULL DEFAULT 'unknown'
                    CHECK (mfa_status IN ('unknown', 'user_reported_enabled', 'user_reported_disabled', 'evidence_enabled')),
  is_fixture        boolean NOT NULL DEFAULT false,
  first_seen_at     timestamptz,
  last_seen_at      timestamptz,
  risk_score        integer,
  risk_level        text,
  risk_components   jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_updated_at   timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, service_domain)
);

CREATE TABLE account_identities (
  account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  email_address text NOT NULL,
  PRIMARY KEY (account_id, email_address)
);

-- Evidence keeps the minimum necessary: classification, date, sender domain and a
-- hash of the provider message id (for deduplication). No subjects or bodies.
CREATE TABLE evidence (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  connection_id     uuid REFERENCES email_connections(id) ON DELETE SET NULL,
  scan_id           uuid REFERENCES scans(id) ON DELETE SET NULL,
  source            text NOT NULL CHECK (source IN ('google', 'microsoft', 'devfixture', 'user', 'hibp')),
  evidence_type     text NOT NULL CHECK (evidence_type IN
                      ('account_creation', 'security_notification', 'password_reset', 'transactional', 'marketing',
                       'user_reported', 'breach_record')),
  signal            text NOT NULL,
  confidence        numeric(4,3) NOT NULL,
  sender_domain     text,
  identity_email    text,
  message_ref_hash  text,
  observed_at       timestamptz NOT NULL,
  is_fixture        boolean NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX evidence_dedupe ON evidence (account_id, message_ref_hash) WHERE message_ref_hash IS NOT NULL;
CREATE INDEX evidence_account_idx ON evidence (account_id);

-- Suppression list: user corrections that future scans must respect.
CREATE TABLE discovery_suppressions (
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  service_domain text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, service_domain)
);

CREATE TABLE breach_catalog (
  id             text PRIMARY KEY,
  title          text NOT NULL,
  domain         text,
  breach_date    date,
  added_date     timestamptz,
  pwn_count      bigint,
  data_classes   text[] NOT NULL DEFAULT '{}',
  is_verified    boolean NOT NULL DEFAULT false,
  is_sensitive   boolean NOT NULL DEFAULT false,
  is_fabricated  boolean NOT NULL DEFAULT false,
  is_spam_list   boolean NOT NULL DEFAULT false,
  source         text NOT NULL CHECK (source IN ('hibp', 'fixture')),
  fetched_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX breach_catalog_domain_idx ON breach_catalog (domain);

CREATE TABLE source_status (
  source       text PRIMARY KEY,
  last_attempt timestamptz,
  last_success timestamptz,
  last_status  text,
  last_error   text,
  item_count   integer
);

CREATE TABLE findings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  finding_type  text NOT NULL CHECK (finding_type IN
                  ('service_breach', 'email_breach', 'security_alert', 'posture_unknown', 'dormant_account')),
  fingerprint   text NOT NULL,
  breach_id     text,
  severity      text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title         text NOT NULL,
  explanation   text NOT NULL,
  contribution  numeric(6,2) NOT NULL DEFAULT 0,
  details       jsonb NOT NULL DEFAULT '{}'::jsonb,
  state         text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'mitigated_user_reported', 'mitigated_verified', 'inactive')),
  first_detected_at timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, fingerprint)
);
CREATE INDEX findings_account_idx ON findings (account_id);

CREATE TABLE remediation_items (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id       uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  finding_id       uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action_type      text NOT NULL CHECK (action_type IN
                     ('change_password', 'enable_mfa', 'review_activity', 'delete_account', 'review_account')),
  title            text NOT NULL,
  description      text NOT NULL,
  priority         integer NOT NULL,
  official_url     text,
  url_kind         text CHECK (url_kind IN ('curated_official', 'well_known_standard')),
  status           text NOT NULL DEFAULT 'recommended' CHECK (status IN
                     ('recommended', 'in_progress', 'user_reported_complete', 'verification_pending',
                      'verified_complete', 'unable_to_verify', 'dismissed')),
  status_note      text,
  user_reported_at timestamptz,
  verified_at      timestamptz,
  last_reminded_at timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (finding_id, action_type)
);
CREATE INDEX remediation_user_idx ON remediation_items (user_id, status);

CREATE TABLE remediation_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  item_id     uuid NOT NULL REFERENCES remediation_items(id) ON DELETE CASCADE,
  from_status text,
  to_status   text NOT NULL,
  note        text,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE dasi_snapshots (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  score          integer CHECK (score IS NULL OR (score >= 0 AND score <= 100)),
  level          text NOT NULL,
  coverage       text NOT NULL CHECK (coverage IN ('none', 'partial', 'complete')),
  model_version  text NOT NULL,
  components     jsonb NOT NULL,
  changes        jsonb NOT NULL DEFAULT '[]'::jsonb,
  reason         text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dasi_user_idx ON dasi_snapshots (user_id, created_at DESC);

CREATE TABLE alerts (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        text NOT NULL,
  severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title       text NOT NULL,
  body        text NOT NULL,
  fingerprint text NOT NULL,
  account_id  uuid REFERENCES accounts(id) ON DELETE SET NULL,
  read_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, fingerprint)
);

CREATE TABLE notification_preferences (
  user_id                        uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_security_alerts          boolean NOT NULL DEFAULT false,
  email_remediation_reminders    boolean NOT NULL DEFAULT false,
  email_periodic_summary         boolean NOT NULL DEFAULT false,
  email_consent_at               timestamptz,
  security_event_sync            boolean NOT NULL DEFAULT false,
  security_event_sync_consent_at timestamptz,
  last_summary_sent_at           timestamptz,
  last_summary_fingerprint       text,
  updated_at                     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_deliveries (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        text NOT NULL,
  fingerprint text NOT NULL,
  status      text NOT NULL CHECK (status IN ('sent', 'failed', 'not_configured', 'dev_logged')),
  error       text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX notification_dedupe ON notification_deliveries (user_id, kind, fingerprint)
  WHERE status IN ('sent', 'dev_logged');

CREATE TABLE contact_messages (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         uuid REFERENCES users(id) ON DELETE SET NULL,
  name            text NOT NULL,
  email           text NOT NULL,
  subject         text NOT NULL,
  message         text NOT NULL,
  delivery_status text NOT NULL CHECK (delivery_status IN ('sent', 'failed', 'not_configured', 'dev_logged')),
  delivery_error  text,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- DEVELOPMENT ONLY outbox used by EMAIL_PROVIDER=devlog. Never used in production.
CREATE TABLE dev_outbox (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  to_address  text NOT NULL,
  subject     text NOT NULL,
  body        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE extension_link_codes (
  code_hash  bytea PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE extension_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   bytea NOT NULL UNIQUE,
  label        text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);

-- Global domain-reputation cache. Not linked to any user, so it cannot be used to
-- reconstruct an individual's browsing history.
CREATE TABLE domain_reputation_cache (
  domain     text PRIMARY KEY,
  status     text NOT NULL CHECK (status IN ('green', 'red', 'amber', 'grey')),
  result     jsonb NOT NULL,
  checked_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE TABLE threat_feed_entries (
  feed_id    text NOT NULL,
  domain     text NOT NULL,
  synced_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain, feed_id)
);

CREATE TABLE threat_feeds (
  feed_id        text PRIMARY KEY,
  url            text NOT NULL,
  last_attempt   timestamptz,
  last_success   timestamptz,
  last_status    text,
  last_error     text,
  entry_count    integer NOT NULL DEFAULT 0
);

-- Premium: security events. Only warnings (red/amber), only with explicit opt-in.
CREATE TABLE security_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  source      text NOT NULL CHECK (source IN ('extension')),
  domain      text NOT NULL,
  status      text NOT NULL CHECK (status IN ('red', 'amber')),
  reasons     jsonb NOT NULL DEFAULT '[]'::jsonb,
  action      text CHECK (action IN ('warned', 'blocked', 'proceeded', 'went_back')),
  client_event_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, client_event_id)
);
CREATE INDEX security_events_user_idx ON security_events (user_id, occurred_at DESC);
