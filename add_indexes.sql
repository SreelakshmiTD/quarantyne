CREATE INDEX idx_violation_audit_log_timestamp ON violation_audit_log(event_timestamp);
CREATE INDEX idx_violation_audit_log_table     ON violation_audit_log(table_name);
CREATE INDEX idx_processing_log_timestamp      ON processing_log(event_timestamp);
CREATE INDEX idx_processing_log_table          ON processing_log(table_name);
CREATE INDEX idx_processing_log_decision       ON processing_log(decision);
