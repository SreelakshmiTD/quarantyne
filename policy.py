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

    Args:
        table:            The fully-qualified table name (e.g. "public.customers").
        detection_result: Output of detect_pii_in_payload().
        policy_config:    Parsed policy YAML as returned by load_policy_config().

    Returns a dict with:
      - decision: "COMPLIANT" or "VIOLATION"
      - unauthorized_fields: list of detected fields not permitted by policy
    """
    table_policy = policy_config.get("tables", {}).get(table, {})
    allowed = set(table_policy.get("allowed_pii_fields", []))

    unauthorized = [
        field for field in detection_result.get("detected_fields", [])
        if field not in allowed
    ]

    return {
        "decision": "VIOLATION" if unauthorized else "COMPLIANT",
        "unauthorized_fields": unauthorized,
    }
