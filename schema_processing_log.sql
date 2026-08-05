CREATE TABLE processing_log (
    id               SERIAL PRIMARY KEY,
    event_timestamp  TIMESTAMPTZ,
    table_name       TEXT,
    decision         TEXT
);
