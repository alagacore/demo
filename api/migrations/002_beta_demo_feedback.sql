-- Private beta: sign-up codes for daycares, private demo links, and feedback.
-- Only the API's own 'system' steps (and verified Alaga team requests, which
-- run as 'system') can read or change these; anyone may add feedback.

CREATE TABLE beta_codes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash   text NOT NULL UNIQUE,        -- only a hash of the code is kept
  label       text NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
  max_uses    int NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 1000),
  uses        int NOT NULL DEFAULT 0,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE beta_code_uses (
  id           bigserial PRIMARY KEY,
  beta_code_id uuid NOT NULL REFERENCES beta_codes(id) ON DELETE CASCADE,
  provider_id  uuid REFERENCES providers(id) ON DELETE SET NULL,
  user_uid     text NOT NULL,
  used_at      timestamptz NOT NULL DEFAULT now()
);

-- Demo links open sample data only, so the token itself is kept (the team
-- needs to copy the link again later).
CREATE TABLE demo_links (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token       text NOT NULL UNIQUE,
  label       text NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
  active      boolean NOT NULL DEFAULT true,
  views       int NOT NULL DEFAULT 0,
  expires_at  timestamptz,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feedback (
  id           bigserial PRIMARY KEY,
  kind         text NOT NULL CHECK (kind IN ('feedback', 'demo_survey')),
  rating       int CHECK (rating BETWEEN 1 AND 5),
  message      text CHECK (length(message) <= 4000),
  answers      jsonb NOT NULL DEFAULT '{}'::jsonb,
  contact      text CHECK (length(contact) <= 200),
  screen       text,
  role         text,
  user_uid     text,
  user_email   text,
  provider_id  uuid REFERENCES providers(id) ON DELETE SET NULL,
  demo_link_id uuid REFERENCES demo_links(id) ON DELETE SET NULL,
  language     text,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX feedback_created ON feedback (created_at DESC);

ALTER TABLE beta_codes     ENABLE ROW LEVEL SECURITY; ALTER TABLE beta_codes     FORCE ROW LEVEL SECURITY;
ALTER TABLE beta_code_uses ENABLE ROW LEVEL SECURITY; ALTER TABLE beta_code_uses FORCE ROW LEVEL SECURITY;
ALTER TABLE demo_links     ENABLE ROW LEVEL SECURITY; ALTER TABLE demo_links     FORCE ROW LEVEL SECURITY;
ALTER TABLE feedback       ENABLE ROW LEVEL SECURITY; ALTER TABLE feedback       FORCE ROW LEVEL SECURITY;

CREATE POLICY beta_codes_system ON beta_codes USING (app_role() = 'system') WITH CHECK (app_role() = 'system');
CREATE POLICY beta_code_uses_system ON beta_code_uses USING (app_role() = 'system') WITH CHECK (app_role() = 'system');
CREATE POLICY demo_links_system ON demo_links USING (app_role() = 'system') WITH CHECK (app_role() = 'system');
CREATE POLICY feedback_read ON feedback FOR SELECT USING (app_role() = 'system');
CREATE POLICY feedback_add ON feedback FOR INSERT WITH CHECK (true);
