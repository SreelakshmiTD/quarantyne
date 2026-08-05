CREATE TABLE violation_audit_log (
    id                       SERIAL PRIMARY KEY,
    event_timestamp          TIMESTAMPTZ,
    table_name               TEXT,
    operation                TEXT,
    unauthorized_fields      JSONB,
    detected_fields          JSONB,
    detection_reasons        JSONB,
    raw_after_payload        JSONB,
    raw_before_payload       JSONB,
    newly_introduced_fields  JSONB,
    logged_at                TIMESTAMPTZ DEFAULT NOW()
);
