from detector import detect_pii_in_payload, diff_before_after

# --- Test 1: Clean payload ---
clean_payload = {"customer_id": 1, "segment": "premium", "country": "IN"}
result1 = detect_pii_in_payload(clean_payload)
print("Test 1: Clean payload")
print(f"  Input:            {clean_payload}")
print(f"  has_pii:          {result1['has_pii']}")
print(f"  detected_fields:  {result1['detected_fields']}")
print(f"  detection_reasons:{result1['detection_reasons']}")
assert result1["has_pii"] is False, "FAIL: expected has_pii=False"
print("  PASS\n")

# --- Test 2: Payload with PII (email field) ---
pii_payload = {"customer_id": 1, "segment": "premium", "country": "IN", "email": "user@example.com"}
result2 = detect_pii_in_payload(pii_payload)
print("Test 2: Payload with PII (email field name)")
print(f"  Input:            {pii_payload}")
print(f"  has_pii:          {result2['has_pii']}")
print(f"  detected_fields:  {result2['detected_fields']}")
print(f"  detection_reasons:{result2['detection_reasons']}")
assert result2["has_pii"] is True, "FAIL: expected has_pii=True"
assert "email" in result2["detected_fields"], "FAIL: expected 'email' in detected_fields"
assert result2["detection_reasons"]["email"] == "field_name_match", "FAIL: expected field_name_match for email"
print("  PASS\n")

# --- Test 3: diff_before_after with before (no email) -> after (with email) ---
before = {"customer_id": 1, "segment": "premium", "country": "IN"}
after  = {"customer_id": 1, "segment": "premium", "country": "IN", "email": "user@example.com"}
result3 = diff_before_after(before, after)
print("Test 3: diff_before_after (email newly introduced)")
print(f"  Before:                  {before}")
print(f"  After:                   {after}")
print(f"  newly_introduced_fields: {result3['newly_introduced_fields']}")
assert result3["newly_introduced_fields"] == ["email"], "FAIL: expected ['email']"
print("  PASS\n")

# --- Test 4: email field present but value is None ---
null_email_payload = {"customer_id": 1, "segment": "premium", "country": "IN", "email": None}
result4 = detect_pii_in_payload(null_email_payload)
print("Test 4: email field present but value is None")
print(f"  Input:            {null_email_payload}")
print(f"  has_pii:          {result4['has_pii']}")
print(f"  detected_fields:  {result4['detected_fields']}")
print(f"  detection_reasons:{result4['detection_reasons']}")
assert result4["has_pii"] is False, "FAIL: expected has_pii=False"
assert result4["detected_fields"] == [], "FAIL: expected no detected fields"
print("  PASS\n")

# --- Test 5: diff_before_after where new field is absent in before but null in after ---
before5 = {"customer_id": 1, "segment": "premium"}
after5  = {"customer_id": 1, "segment": "premium", "email": None}
result5 = diff_before_after(before5, after5)
print("Test 5: diff_before_after (email absent in before, null in after)")
print(f"  Before:                  {before5}")
print(f"  After:                   {after5}")
print(f"  newly_introduced_fields: {result5['newly_introduced_fields']}")
assert result5["newly_introduced_fields"] == [], "FAIL: expected []"
print("  PASS\n")

print("All tests passed.")
