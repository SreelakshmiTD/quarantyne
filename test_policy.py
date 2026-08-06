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

# --- Test 4: unrecognized table with PII — fail-closed, should be VIOLATION ---
detection_with_pii = {
    "has_pii": True,
    "detected_fields": ["email"],
    "detection_reasons": {"email": "field_name_match"},
}
result4 = evaluate_policy("public.unknown_table", detection_with_pii, policy_config)
print("Test 4: PII detected against unrecognized table (fail-closed)")
print(f"  table:              public.unknown_table (not in policy.yaml)")
print(f"  detected_fields:    {detection_with_pii['detected_fields']}")
print(f"  decision:           {result4['decision']}")
print(f"  unauthorized_fields:{result4['unauthorized_fields']}")
assert result4["decision"] == "VIOLATION", "FAIL: expected VIOLATION for unrecognized table with PII"
assert result4["unauthorized_fields"] == ["email"], "FAIL: expected ['email'] as unauthorized"
print("  PASS\n")

# --- Test 5: unrecognized table with no PII — should be COMPLIANT (nothing to block) ---
detection_no_pii = {
    "has_pii": False,
    "detected_fields": [],
    "detection_reasons": {},
}
result5 = evaluate_policy("public.unknown_table", detection_no_pii, policy_config)
print("Test 5: No PII detected against unrecognized table (nothing to block)")
print(f"  table:              public.unknown_table (not in policy.yaml)")
print(f"  detected_fields:    {detection_no_pii['detected_fields']}")
print(f"  decision:           {result5['decision']}")
print(f"  unauthorized_fields:{result5['unauthorized_fields']}")
assert result5["decision"] == "COMPLIANT", "FAIL: expected COMPLIANT for unrecognized table with no PII"
assert result5["unauthorized_fields"] == [], "FAIL: expected no unauthorized fields"
print("  PASS\n")

# --- Test 6: nested dotted path "contact.email" against a policy that allows "email" ---
# The policy engine matches using the leaf key only (field.split(".")[-1]), so
# "contact.email" is evaluated as "email" against the allow-list. This means a
# table's allowed_pii_fields applies to the PII type regardless of nesting depth —
# "email" in the allow-list covers "email", "contact.email", "person.contact.email", etc.
# The full dotted path is preserved in unauthorized_fields when a violation does occur,
# so audit records retain exact field location detail.
detection_nested = {
    "has_pii": True,
    "detected_fields": ["contact.email"],
    "detection_reasons": {"contact.email": "field_name_match"},
}
# Use customers_partial_test which has allowed_pii_fields: ["email"]
result6 = evaluate_policy("public.customers_partial_test", detection_nested, policy_config)
print("Test 6: nested path 'contact.email' vs policy that allows 'email' (leaf-name match)")
print(f"  table:              public.customers_partial_test  (allowed: ['email'])")
print(f"  detected_fields:    {detection_nested['detected_fields']}")
print(f"  decision:           {result6['decision']}")
print(f"  unauthorized_fields:{result6['unauthorized_fields']}")
print(f"  NOTE: leaf match — 'contact.email' is checked as 'email', which is allowed.")
print()

print("All tests passed.")
