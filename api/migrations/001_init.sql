-- Alaga core schema: daycares, their families, and parent invites.
--
-- Every row carries its daycare's id. Row-level security (forced, so it also
-- applies to the table owner) means a query only ever sees rows for the
-- daycare — or the one family — set for the current request by the API:
--   app.role         'owner' | 'staff' | 'parent' | 'system'
--   app.user_id      the signed-in Firebase user
--   app.provider_id  the daycare the request is for
--   app.household_id the family (parents only)
-- 'system' is used only by the API's own sign-up and invite steps.

CREATE OR REPLACE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE AS $$ SELECT coalesce(current_setting('app.role', true), '') $$;
CREATE OR REPLACE FUNCTION app_uid() RETURNS text LANGUAGE sql STABLE AS $$ SELECT coalesce(current_setting('app.user_id', true), '') $$;
CREATE OR REPLACE FUNCTION app_provider() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.provider_id', true), '')::uuid $$;
CREATE OR REPLACE FUNCTION app_household() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.household_id', true), '')::uuid $$;
CREATE OR REPLACE FUNCTION app_is_staff() RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT app_role() IN ('owner', 'staff') $$;

CREATE TABLE providers (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  city          text,
  license       text,
  provider_type text,
  capacity      int CHECK (capacity BETWEEN 0 AND 500),
  settings      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
  provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  user_uid    text NOT NULL,
  email       text NOT NULL,
  role        text NOT NULL CHECK (role IN ('owner', 'staff')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider_id, user_uid)
);
CREATE INDEX memberships_user ON memberships (user_uid);

CREATE TABLE households (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX households_provider ON households (provider_id);

CREATE TABLE guardians (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id  uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  household_id uuid NOT NULL REFERENCES households(id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  relationship text,
  email        text,
  phone        text,
  user_uid     text,           -- set when the parent accepts an invite
  linked_at    timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX guardians_household ON guardians (household_id);
CREATE INDEX guardians_user ON guardians (user_uid);

CREATE TABLE children (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id  uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  household_id uuid NOT NULL REFERENCES households(id) ON DELETE CASCADE,
  first_name   text NOT NULL CHECK (length(first_name) BETWEEN 1 AND 100),
  last_name    text,
  birth_date   date,
  classroom    text,
  enroll_date  date,
  status       text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'withdrawn')),
  details      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX children_household ON children (household_id);
CREATE INDEX children_provider ON children (provider_id);

-- Only a hash of each invite code is stored; the code itself is shown once.
CREATE TABLE invites (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id    uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  household_id   uuid NOT NULL REFERENCES households(id) ON DELETE CASCADE,
  guardian_id    uuid NOT NULL REFERENCES guardians(id) ON DELETE CASCADE,
  email          text NOT NULL,
  code_hash      text NOT NULL UNIQUE,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  used_by_uid    text,
  revoked_at     timestamptz,
  created_by_uid text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invites_guardian ON invites (guardian_id);

-- Who looked at or changed what. Rows can be added, never edited or removed.
CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  provider_id uuid,
  actor_uid   text,
  action      text NOT NULL,
  target      text,
  meta        jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip          text,
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_provider_at ON audit_log (provider_id, at DESC);

CREATE OR REPLACE FUNCTION audit_log_no_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit_log rows cannot be changed or deleted'; END $$;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_no_change();

-- Row-level security -------------------------------------------------------
ALTER TABLE providers   ENABLE ROW LEVEL SECURITY; ALTER TABLE providers   FORCE ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY; ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE households  ENABLE ROW LEVEL SECURITY; ALTER TABLE households  FORCE ROW LEVEL SECURITY;
ALTER TABLE guardians   ENABLE ROW LEVEL SECURITY; ALTER TABLE guardians   FORCE ROW LEVEL SECURITY;
ALTER TABLE children    ENABLE ROW LEVEL SECURITY; ALTER TABLE children    FORCE ROW LEVEL SECURITY;
ALTER TABLE invites     ENABLE ROW LEVEL SECURITY; ALTER TABLE invites     FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log   ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_log   FORCE ROW LEVEL SECURITY;

CREATE POLICY providers_access ON providers USING (
  app_role() = 'system' OR id = app_provider()
) WITH CHECK (app_role() = 'system' OR (app_role() = 'owner' AND id = app_provider()));

-- A user can always see their own memberships (to find their daycare).
CREATE POLICY memberships_access ON memberships USING (
  app_role() = 'system' OR user_uid = app_uid() OR (app_is_staff() AND provider_id = app_provider())
) WITH CHECK (app_role() = 'system' OR (app_role() = 'owner' AND provider_id = app_provider()));

CREATE POLICY households_access ON households USING (
  app_role() = 'system'
  OR (app_is_staff() AND provider_id = app_provider())
  OR (app_role() = 'parent' AND id = app_household() AND provider_id = app_provider())
) WITH CHECK (app_role() = 'system' OR (app_is_staff() AND provider_id = app_provider()));

-- A parent can find their own guardian row (to find their family), and see
-- the other guardians in that family.
CREATE POLICY guardians_access ON guardians USING (
  app_role() = 'system'
  OR (app_is_staff() AND provider_id = app_provider())
  OR (user_uid IS NOT NULL AND user_uid = app_uid())
  OR (app_role() = 'parent' AND household_id = app_household() AND provider_id = app_provider())
) WITH CHECK (app_role() = 'system' OR (app_is_staff() AND provider_id = app_provider()));

CREATE POLICY children_access ON children USING (
  app_role() = 'system'
  OR (app_is_staff() AND provider_id = app_provider())
  OR (app_role() = 'parent' AND household_id = app_household() AND provider_id = app_provider())
) WITH CHECK (app_role() = 'system' OR (app_is_staff() AND provider_id = app_provider()));

CREATE POLICY invites_access ON invites USING (
  app_role() = 'system' OR (app_is_staff() AND provider_id = app_provider())
) WITH CHECK (app_role() = 'system' OR (app_is_staff() AND provider_id = app_provider()));

CREATE POLICY audit_read ON audit_log FOR SELECT USING (
  app_role() = 'system' OR (app_role() = 'owner' AND provider_id = app_provider())
);
CREATE POLICY audit_write ON audit_log FOR INSERT WITH CHECK (true);
