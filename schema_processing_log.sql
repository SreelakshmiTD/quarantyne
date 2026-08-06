CREATE TABLE processing_log (
    id                  SERIAL PRIMARY KEY,
    event_timestamp     TIMESTAMPTZ NOT NULL,
    table_name          TEXT        NOT NULL,
    decision            TEXT        NOT NULL,
    raw_before_payload  JSONB   -- populated for DELETE events; null for INSERT/UPDATE/COMPLIANT/VIOLATION
);
