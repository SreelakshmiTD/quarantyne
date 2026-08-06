-- production_role_setup.sql
-- Least-privilege role setup for a production Quarantyne CDC connector.
--
-- In this project's local dev environment, the Debezium connector runs as
-- the "privacypulse" user, which is also the database owner. That is
-- intentional for local convenience but wrong for production: a database
-- owner has unrestricted DDL and DML rights, far beyond what a CDC
-- connector needs.
--
-- A production connector needs exactly three things:
--   1. REPLICATION privilege    — to open a logical replication slot and
--                                 stream WAL changes via pgoutput.
--   2. LOGIN privilege          — to authenticate to the database.
--   3. SELECT on captured tables — Debezium reads initial snapshots of
--                                  each table before streaming live changes;
--                                  SELECT is required for that snapshot phase.
--
-- Nothing else. No INSERT, UPDATE, DELETE, CREATE, DROP, or superuser rights.
-- Granting SELECT only on the specific tables being captured (not the whole
-- schema) limits blast radius if the connector credential is ever compromised.

-- ── Create the role ───────────────────────────────────────────────────────────

CREATE ROLE quarantyne_cdc
    WITH LOGIN
         REPLICATION
         PASSWORD 'replace_with_secrets_manager_value';

-- REPLICATION: required for logical replication slot creation (pgoutput plugin).
-- LOGIN: required to authenticate; REPLICATION alone does not imply LOGIN.
-- PASSWORD: shown as a placeholder — in production, inject via AWS Secrets
--           Manager, HashiCorp Vault, or a similar secrets manager rather than
--           hardcoding in SQL or config files.

-- ── Grant database access ────────────────────────────────────────────────────

-- Allow the role to connect to the database at all.
GRANT CONNECT ON DATABASE privacypulse_db TO quarantyne_cdc;

-- ── Grant schema usage ────────────────────────────────────────────────────────

-- USAGE on the schema is required to resolve table names; it does not
-- grant SELECT on any tables by itself.
GRANT USAGE ON SCHEMA public TO quarantyne_cdc;

-- ── Grant SELECT on captured tables only ─────────────────────────────────────

-- Explicitly enumerate only the tables the connector is configured to capture
-- (matching table.include.list in debezium-connector-config.json).
-- Do NOT use "GRANT SELECT ON ALL TABLES IN SCHEMA public" — that grants
-- access to every current and future table, which violates least-privilege.

GRANT SELECT ON public.customers TO quarantyne_cdc;
GRANT SELECT ON public.orders    TO quarantyne_cdc;

-- To add a new captured table in future, add a matching GRANT here and
-- update table.include.list in the connector config. The role never
-- automatically gains access to tables added after this script runs.

-- ── Replication slot note ─────────────────────────────────────────────────────

-- Debezium creates a replication slot on first connect. The REPLICATION
-- privilege above is sufficient for slot creation. No superuser rights are
-- needed when using pgoutput (the native Postgres logical decoding plugin),
-- which is why this project uses plugin.name=pgoutput rather than wal2json
-- or decoderbufs, which have historically required superuser in some versions.
