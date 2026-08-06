import yaml


def load_policy_config(path: str) -> dict:
    """
    Load and parse a YAML policy configuration file.

    Returns the parsed contents as a dict.
    """
    with open(path, "r") as f:
        return yaml.safe_load(f)


def evaluate_policy(table: str, detection_result: dict, policy_config: dict) -> dict:
    """
    Evaluate a detection result against the policy for a given table.

    Looks up the table's allowed_pii_fields in policy_config. Any detected
    PII field not in that allowlist is considered unauthorized and causes a
    VIOLATION. If no detected fields are unauthorized (or no PII was detected),
    the record is COMPLIANT.

    Fail-closed for unrecognized tables: if the table is not present in
    policy_config["tables"], any detected PII is treated as a VIOLATION.
    An unrecognized table with no PII is COMPLIANT (nothing to block).
    This prevents a missing policy entry from silently allowing sensitive data
    through — the safe default is to quarantine, not to pass.

    Args:
        table:            The fully-qualified table name (e.g. "public.customers").
        detection_result: Output of detect_pii_in_payload().
        policy_config:    Parsed policy YAML as returned by load_policy_config().

    Returns a dict with:
      - decision: "COMPLIANT" or "VIOLATION"
      - unauthorized_fields: list of detected fields not permitted by policy
    """
    detected = detection_result.get("detected_fields", [])

    # Fail-closed: unrecognized table with PII → VIOLATION on all detected fields.
    if table not in policy_config.get("tables", {}):
        return {
            "decision": "VIOLATION" if detected else "COMPLIANT",
            "unauthorized_fields": list(detected),
        }

    allowed = set(policy_config["tables"][table].get("allowed_pii_fields", []))
    # Compare the leaf key (last dotted component) against allowed_pii_fields,
    # so "contact.email" matches an allow-list entry of "email". The full path
    # is retained in unauthorized_fields for audit precision.
    unauthorized = [field for field in detected if field.split(".")[-1] not in allowed]

    return {
        "decision": "VIOLATION" if unauthorized else "COMPLIANT",
        "unauthorized_fields": unauthorized,
    }
