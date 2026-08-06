import re

SENSITIVE_FIELD_NAMES = {"email", "phone", "ssn", "credit_card", "address", "dob", "phone_number"}

PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\b\d{10}\b"),
    "credit_card": re.compile(r"\b\d{13,16}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}

# Substrings that make a field name "plausible" for a given pattern type.
# Email has no requirement — the regex is specific enough to avoid false positives.
PATTERN_FIELD_HINTS: dict[str, set[str]] = {
    "email": set(),  # no field-name requirement
    "phone": {"phone", "mobile", "contact", "cell"},
    "credit_card": {"card", "payment", "credit"},
    "ssn": {"ssn", "social", "tax_id"},
}


def _scan_field(path: str, value, detected_fields: list, detection_reasons: dict) -> None:
    """
    Scan a single field for PII, recursing into dict values (one level at a time).

    - path: dotted key path, e.g. "contact.email" for a nested field
    - Leaf-key name is used for field-name and pattern-hint matching throughout.
    - Lists of dicts are not recursed into (out of scope for v1).
    """
    if isinstance(value, dict):
        for nested_key, nested_val in value.items():
            _scan_field(f"{path}.{nested_key}", nested_val, detected_fields, detection_reasons)
        return

    leaf = path.split(".")[-1]

    if leaf.lower() in SENSITIVE_FIELD_NAMES and value is not None and value != "":
        detected_fields.append(path)
        detection_reasons[path] = "field_name_match"
        return

    if value is not None:
        str_value = str(value)
        leaf_lower = leaf.lower()
        for pii_type, pattern in PATTERNS.items():
            if not pattern.search(str_value):
                continue
            hints = PATTERN_FIELD_HINTS[pii_type]
            if hints and not any(h in leaf_lower for h in hints):
                continue
            detected_fields.append(path)
            detection_reasons[path] = "pattern_match"
            break


def detect_pii_in_payload(payload: dict) -> dict:
    """
    Scan a Debezium 'after' object for PII.

    Two independent detection signals are used:

    1. field_name_match: the leaf field name exactly matches a known sensitive name
       (email, phone, ssn, credit_card, address, dob, phone_number) AND the
       value is non-null and non-empty.

    2. pattern_match: the field value matches a regex for a PII type AND the
       leaf field name contains a plausible substring for that type, reducing
       false positives from coincidental numeric matches in unrelated fields:
         - phone pattern    → field name must contain: phone, mobile, contact, cell
         - credit_card      → field name must contain: card, payment, credit
         - ssn              → field name must contain: ssn, social, tax_id
         - email pattern    → no field-name requirement (the regex is specific enough)

    Nested dict values are recursed into; detected field paths use dot notation
    (e.g. "contact.email"). Lists of dicts are not recursed into.

    Returns a dict with:
      - has_pii: True if any field was flagged
      - detected_fields: list of field paths that were flagged
      - detection_reasons: mapping of field path to "field_name_match" or "pattern_match"
    """
    detected_fields = []
    detection_reasons = {}

    for field, value in payload.items():
        _scan_field(field, value, detected_fields, detection_reasons)

    return {
        "has_pii": len(detected_fields) > 0,
        "detected_fields": detected_fields,
        "detection_reasons": detection_reasons,
    }


def diff_before_after(before: dict | None, after: dict) -> dict:
    """
    Identify fields in 'after' that are newly introduced compared to 'before'.

    A field is considered newly introduced if:
      - It did not exist in 'before', or
      - It existed in 'before' as None or an empty string, and now has a value.

    If 'before' is None (i.e. this is an INSERT event), returns an empty list
    since there is no prior state to compare against.

    Returns a dict with:
      - newly_introduced_fields: list of field names meeting the above criteria
    """
    if before is None:
        return {"newly_introduced_fields": []}

    newly_introduced = []
    for field, value in after.items():
        prior = before.get(field)
        if (field not in before and (value is not None and value != "")) or (
            field in before and (prior is None or prior == "") and (value is not None and value != "")
        ):
            newly_introduced.append(field)

    return {"newly_introduced_fields": newly_introduced}
