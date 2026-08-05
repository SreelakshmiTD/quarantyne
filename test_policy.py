from policy import load_policy_config, evaluate_policy

policy_config = load_policy_config("policy.yaml")
print(f"Loaded policy: {policy_config}\n")

# --- Test 1: PII detected — should be VIOLATION ---
detection_with_pii = {
    "has_pii": True,
    "detected_fields": ["email", "phone"],
    "detection_reasons": {"email": "field_name_match", "phone": "field_name_match"},
}
result1 = evaluate_policy("public.customers", detection_with_pii, policy_config)
print("Test 1: PII detected (email, phone) against customers policy")
print(f"  detected_fields:    {detection_with_pii['detected_fields']}")
print(f"  decision:           {result1['decision']}")
print(f"  unauthorized_fields:{result1['unauthorized_fields']}")
assert result1["decision"] == "VIOLATION", "FAIL: expected VIOLATION"
assert set(result1["unauthorized_fields"]) == {"email", "phone"}, "FAIL: expected both fields unauthorized"
print("  PASS\n")

# --- Test 2: No PII detected — should be COMPLIANT ---
detection_no_pii = {
    "has_pii": False,
    "detected_fields": [],
    "detection_reasons": {},
}
result2 = evaluate_policy("public.customers", detection_no_pii, policy_config)
print("Test 2: No PII detected against customers policy")
print(f"  detected_fields:    {detection_no_pii['detected_fields']}")
print(f"  decision:           {result2['decision']}")
print(f"  unauthorized_fields:{result2['unauthorized_fields']}")
assert result2["decision"] == "COMPLIANT", "FAIL: expected COMPLIANT"
assert result2["unauthorized_fields"] == [], "FAIL: expected no unauthorized fields"
print("  PASS\n")

# --- Test 3: email allowed, phone not — should be VIOLATION with only phone unauthorized ---
detection_partial = {
    "has_pii": True,
    "detected_fields": ["email", "phone"],
    "detection_reasons": {},
}
result3 = evaluate_policy("public.customers_partial_test", detection_partial, policy_config)
print("Test 3: email + phone detected against customers_partial_test policy (email is allowed)")
print(f"  detected_fields:    {detection_partial['detected_fields']}  (2 fields)")
print(f"  decision:           {result3['decision']}")
print(f"  unauthorized_fields:{result3['unauthorized_fields']}  (should be only phone)")
assert result3["decision"] == "VIOLATION", "FAIL: expected VIOLATION"
assert result3["unauthorized_fields"] == ["phone"], "FAIL: expected only ['phone'] unauthorized"
print("  PASS\n")

print("All tests passed.")
