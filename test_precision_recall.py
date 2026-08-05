from detector import detect_pii_in_payload

# Each entry: (label, payload, expected_has_pii)
# label describes the intent of the test case
TEST_CASES = [
    # --- True Positives: should be flagged ---
    (
        "TP: email field with real email value",
        {"customer_id": 1, "segment": "premium", "email": "alice.smith@example.com"},
        True,
    ),
    (
        "TP: phone field with 10-digit number",
        {"customer_id": 2, "country": "US", "phone": "4155551234"},
        True,
    ),
    (
        "TP: ssn field with SSN-shaped value",
        {"user_id": 3, "ssn": "123-45-6789"},
        True,
    ),
    (
        "TP: credit_card field with card-shaped number",
        {"user_id": 4, "credit_card": "4111111111111111"},
        True,
    ),
    (
        "TP: dob field with non-null value",
        {"user_id": 5, "segment": "trial", "dob": "1990-06-15"},
        True,
    ),
    (
        "TP: address field with non-null value",
        {"user_id": 6, "address": "123 Main St, Springfield"},
        True,
    ),
    (
        "TP: phone_number field (alternate name)",
        {"user_id": 7, "phone_number": "9876543210"},
        True,
    ),
    (
        "TP: non-sensitive field name containing a real email (pattern match)",
        {"user_id": 8, "contact_info": "reach me at bob.jones@mail.com"},
        True,
    ),
    (
        "TP: non-sensitive field name containing SSN pattern (pattern match)",
        {"user_id": 9, "notes": "SSN on file: 987-65-4321"},
        True,
    ),
    (
        "TP: multiple PII fields in one payload",
        {"user_id": 10, "email": "carol@testcorp.io", "phone": "8005551234"},
        True,
    ),

    # --- False Negative edge cases: may be missed by field-name matching alone ---
    (
        "FN-RISK: 'customer_email' field (not in sensitive list, needs pattern match)",
        {"user_id": 11, "customer_email": "dave.nguyen@fakeco.net"},
        True,  # should still be caught by email pattern on value
    ),
    (
        "FN-RISK: 'contact_phone' field containing 10-digit number",
        {"user_id": 12, "contact_phone": "3105559876"},
        True,  # should be caught by phone pattern on value
    ),
    (
        "FN-RISK: email field with value None (should NOT flag)",
        {"user_id": 13, "email": None},
        False,
    ),
    (
        "FN-RISK: email field with empty string (should NOT flag)",
        {"user_id": 14, "email": ""},
        False,
    ),

    # --- True Negatives: should NOT be flagged ---
    (
        "TN: clean payload, no PII fields or values",
        {"customer_id": 15, "segment": "standard", "country": "IN"},
        False,
    ),
    (
        "TN: all fields clean, numeric IDs only",
        {"order_id": 100200300, "product_id": 42, "quantity": 3},
        False,
    ),
    (
        "TN: text fields with no PII content",
        {"status": "active", "tier": "gold", "region": "APAC"},
        False,
    ),

    # --- False Positive edge cases: should NOT be flagged but are at risk ---
    (
        "FP-RISK: 'order_id' containing a 10-digit number (looks like phone, not a sensitive field)",
        {"order_id": "4085551234", "product": "widget"},
        False,  # not real PII — detector incorrectly flags via phone pattern
    ),
    (
        "FP-RISK: 'transaction_amount' with 13-digit number (looks like credit card)",
        {"transaction_id": 99, "transaction_amount": "1234567890123"},
        False,  # not real PII — detector incorrectly flags via credit card pattern
    ),
    (
        "FP-RISK: 'description' field with innocuous 10-digit product code",
        {"item_id": 7, "description": "SKU: 8005554321", "price": 9.99},
        False,  # not real PII — detector incorrectly flags via phone pattern
    ),
]


def run() -> None:
    tp = tn = fp = fn = 0
    false_positives = []
    false_negatives = []

    print(f"{'#':<4} {'Result':<6} {'Expected':<10} {'Got':<10} Label")
    print("-" * 80)

    for i, (label, payload, expected) in enumerate(TEST_CASES, 1):
        result = detect_pii_in_payload(payload)
        got = result["has_pii"]

        if expected and got:
            outcome = "TP"
            tp += 1
        elif not expected and not got:
            outcome = "TN"
            tn += 1
        elif not expected and got:
            outcome = "FP"
            fp += 1
            false_positives.append((i, label, result["detected_fields"]))
        else:
            outcome = "FN"
            fn += 1
            false_negatives.append((i, label))

        marker = "" if outcome in ("TP", "TN") else " <--"
        print(f"{i:<4} {outcome:<6} {str(expected):<10} {str(got):<10} {label}{marker}")

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0

    print()
    print("=" * 80)
    print(f"Total test cases : {total}")
    print(f"True Positives   : {tp}")
    print(f"True Negatives   : {tn}")
    print(f"False Positives  : {fp}")
    print(f"False Negatives  : {fn}")
    print(f"Precision        : {precision:.2%}")
    print(f"Recall           : {recall:.2%}")
    print(f"Accuracy         : {accuracy:.2%}")

    if false_positives:
        print("\nFalse Positives (flagged but should be clean):")
        for idx, label, fields in false_positives:
            print(f"  [{idx}] {label}")
            print(f"       detected: {fields}")

    if false_negatives:
        print("\nFalse Negatives (missed PII):")
        for idx, label in false_negatives:
            print(f"  [{idx}] {label}")


if __name__ == "__main__":
    run()
