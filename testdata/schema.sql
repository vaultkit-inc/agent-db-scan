-- Seed fixture for integration tests.
--
-- Deliberately includes a few "tricky" grant patterns so the role graph
-- builder and privilege resolver have something real to be tested against:
--   * app_service   -- a LOGIN role that INHERITs from app_writer, which in
--                       turn inherits from app_reader (transitive grants)
--   * app_noinherit -- a LOGIN role granted app_admin but with NOINHERIT,
--                       so that membership must NOT translate into access
--   * a PUBLIC grant on app.widgets (loose access this tool should flag)
--   * a default privilege (ALTER DEFAULT PRIVILEGES) covering tables
--     app_admin has not created yet
--   * row-level security enabled on app.secrets

-- Roles ----------------------------------------------------------------

CREATE ROLE app_reader NOLOGIN;
CREATE ROLE app_writer NOLOGIN;
CREATE ROLE app_admin NOLOGIN;

-- Inherits app_writer -> app_reader transitively (rolinherit defaults true).
CREATE ROLE app_service LOGIN PASSWORD 'app_service' INHERIT;
GRANT app_writer TO app_service;

-- Granted app_admin, but NOINHERIT means the grant is dormant unless the
-- role explicitly does SET ROLE app_admin.
CREATE ROLE app_noinherit LOGIN PASSWORD 'app_noinherit' NOINHERIT;
GRANT app_admin TO app_noinherit;

-- Schema & objects -------------------------------------------------------

CREATE SCHEMA app;

CREATE TABLE app.widgets (
    id   serial PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE app.secrets (
    id    serial PRIMARY KEY,
    value text NOT NULL
);

GRANT USAGE ON SCHEMA app TO app_reader, app_writer, app_admin;

-- app_reader: read-only on widgets.
GRANT SELECT ON app.widgets TO app_reader;

-- app_writer: inherits app_reader's SELECT, plus its own DML.
GRANT app_reader TO app_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.widgets TO app_writer;

-- app_admin: owns secrets outright.
ALTER TABLE app.secrets OWNER TO app_admin;

-- Deliberately loose: anyone (PUBLIC) can read widgets.
GRANT SELECT ON app.widgets TO PUBLIC;

-- Default privilege: any future table app_admin creates in `app` is
-- automatically readable by app_reader, even though no such table exists
-- yet at scan time.
ALTER DEFAULT PRIVILEGES FOR ROLE app_admin IN SCHEMA app
    GRANT SELECT ON TABLES TO app_reader;

-- Database-wide default privilege: applies to any schema app_admin creates
-- future tables in, not just `app`. Exercises the defaclnamespace IS NULL
-- case.
ALTER DEFAULT PRIVILEGES FOR ROLE app_admin
    GRANT SELECT ON TABLES TO app_reader;

-- Row-level security -----------------------------------------------------

ALTER TABLE app.secrets ENABLE ROW LEVEL SECURITY;

CREATE POLICY secrets_owner_only ON app.secrets
    USING (current_user = 'app_admin');

-- A second RLS table, this one FORCEd — exercises the
-- relforcerowsecurity=true path, which app.secrets alone doesn't cover
-- (FORCE also means even the table owner is subject to the policy).

CREATE TABLE app.audit_log (
    id     serial PRIMARY KEY,
    action text NOT NULL
);

ALTER TABLE app.audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_log_admin_only ON app.audit_log
    USING (current_user = 'app_admin');