"""
seed_demo.py  —  Demo Data Seeder
===================================
Clears and re-seeds processing_log and violation_audit_log with
realistic synthetic data covering every enforcement scenario:

  Tables   : public.customers, public.employees, public.orders, public.payments
  Ops      : INSERT, UPDATE, DELETE
  Decisions: COMPLIANT, VIOLATION, DELETED
  PII types: email, phone_number, ssn, date_of_birth, salary, home_address,
             credit_card_number, billing_address, card_holder_name,
             bank_account_iban, shipping_address, full_name
  Chart    : spike pattern (incident on day 3-4, remediation day 5-7)
  Volume   : ~2100 events, ~550 violations, 4 tables

Run:
    source .venv/bin/activate
    python3 seed_demo.py
"""

import math
import os
import random
from datetime import datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

random.seed(42)

DB = {
    "host":     os.getenv("POSTGRES_HOST", "localhost"),
    "port":     int(os.getenv("POSTGRES_PORT", 5433)),
    "user":     os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "dbname":   os.getenv("POSTGRES_DB"),
}

# ── Fake data helpers ──────────────────────────────────────────────────────────

FIRST = ["Alice", "Bob", "Carol", "David", "Emma", "Frank", "Grace", "Henry",
         "Isabella", "James", "Karen", "Liam", "Mia", "Noah", "Olivia",
         "Peter", "Quinn", "Rachel", "Samuel", "Tina", "Uma", "Victor",
         "Wendy", "Xander", "Yara", "Zoe"]
LAST  = ["Johnson", "Smith", "Davis", "Wilson", "Martinez", "Anderson",
         "Taylor", "Thomas", "Jackson", "White", "Harris", "Martin",
         "Garcia", "Clark", "Lewis", "Robinson", "Walker", "Hall", "Young", "King"]
DOMAINS  = ["gmail.com", "yahoo.com", "outlook.com", "icloud.com", "proton.me", "company.io"]
SEGMENTS = ["premium", "standard", "basic", "enterprise", "trial"]
COUNTRIES= ["US", "UK", "CA", "AU", "DE", "FR", "SG", "NL"]
STREETS  = ["Main St", "Oak Ave", "Elm Blvd", "Park Rd", "Cedar Lane", "Broadway", "5th Ave"]
CITIES   = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Seattle", "Austin"]
DEPTS    = ["Engineering", "Sales", "HR", "Finance", "Marketing", "Operations", "Legal"]
TITLES   = ["Engineer", "Senior Engineer", "Manager", "Analyst", "Director", "VP", "Coordinator"]
PRODUCTS = ["Pro Plan", "Basic Plan", "Enterprise License", "Add-on Pack", "Support Contract"]
GATEWAYS = ["stripe", "paypal", "braintree", "adyen", "square"]
STATUSES = {"order": ["pending", "completed", "completed", "shipped", "refunded", "failed"],
            "pay":   ["captured", "captured", "authorized", "refunded", "failed"]}


def rname():
    return f"{random.choice(FIRST)} {random.choice(LAST)}"

def remail(name=None):
    n = name or rname()
    f, l = n.lower().split()[:2]
    sep = random.choice([".", "_", ""])
    return f"{f}{sep}{l}@{random.choice(DOMAINS)}"

def rphone():
    return f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}"

def rssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def rcard():
    return f"4{random.randint(100,999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def raddress():
    return f"{random.randint(10,9999)} {random.choice(STREETS)}, {random.choice(CITIES)}, {random.choice(COUNTRIES)}"

def rdob():
    return f"{random.randint(1955,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"

def rsalary():
    return random.choice([45000,62000,75000,89000,95000,115000,140000,180000,220000,310000])

def riban():
    return f"GB{random.randint(10,99)} MOCK {random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(10,99)}"


# ── Timestamp distribution: spike at day 3-4 of 7-day window ──────────────────

NOW   = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
START = NOW - timedelta(days=7)
HOURS = 7 * 24

def _spike(h):
    return 0.12 + math.exp(-((h - 80) ** 2) / (2 * 28 ** 2))

_WEIGHTS = [_spike(h) for h in range(HOURS)]

def rts():
    h = random.choices(range(HOURS), weights=_WEIGHTS)[0]
    return START + timedelta(hours=h, minutes=random.randint(0,59), seconds=random.randint(0,59))


# ── Table configurations ───────────────────────────────────────────────────────

TABLES = {
    "public.customers": {
        "allowed_pii":    {"email"},
        "n_events":       900,
        "violation_rate": 0.30,
        "delete_rate":    0.05,
        "update_rate":    0.25,
        "pii_pool":       ["phone_number", "ssn", "date_of_birth", "full_name", "home_address"],
        "pii_count":      (1, 3),
    },
    "public.employees": {
        "allowed_pii":    set(),
        "n_events":       400,
        "violation_rate": 0.62,
        "delete_rate":    0.04,
        "update_rate":    0.30,
        "pii_pool":       ["ssn", "date_of_birth", "salary", "bank_account_iban",
                           "home_address", "email", "phone_number"],
        "pii_count":      (2, 5),
    },
    "public.orders": {
        "allowed_pii":    set(),
        "n_events":       500,
        "violation_rate": 0.18,
        "delete_rate":    0.08,
        "update_rate":    0.20,
        "pii_pool":       ["shipping_address", "contact_email", "phone_number"],
        "pii_count":      (1, 2),
    },
    "public.payments": {
        "allowed_pii":    set(),
        "n_events":       300,
        "violation_rate": 0.72,
        "delete_rate":    0.02,
        "update_rate":    0.15,
        "pii_pool":       ["credit_card_number", "billing_address",
                           "card_holder_name", "bank_account_iban"],
        "pii_count":      (1, 3),
    },
}


# ── Payload builders ───────────────────────────────────────────────────────────

def _customer(cid, pii=()):
    name = rname()
    row = {"id": cid, "email": remail(name), "segment": random.choice(SEGMENTS),
           "country": random.choice(COUNTRIES), "created_at": rts().isoformat()}
    for f in pii:
        if f == "phone_number":    row["phone_number"]  = rphone()
        elif f == "ssn":           row["ssn"]           = rssn()
        elif f == "date_of_birth": row["date_of_birth"] = rdob()
        elif f == "home_address":  row["home_address"]  = raddress()
        elif f == "full_name":     row["full_name"]     = name
    return row

def _employee(eid, pii=()):
    row = {"id": eid, "employee_id": f"EMP{eid:04d}",
           "department": random.choice(DEPTS), "job_title": random.choice(TITLES),
           "hire_date": rdob(), "status": random.choice(["active","active","active","on_leave"])}
    for f in pii:
        if f == "ssn":                 row["ssn"]               = rssn()
        elif f == "date_of_birth":     row["date_of_birth"]     = rdob()
        elif f == "salary":            row["salary"]            = rsalary()
        elif f == "bank_account_iban": row["bank_account_iban"] = riban()
        elif f == "home_address":      row["home_address"]      = raddress()
        elif f == "email":             row["email"]             = remail()
        elif f == "phone_number":      row["phone_number"]      = rphone()
    return row

def _order(oid, pii=()):
    row = {"id": oid, "order_number": f"ORD-{oid:06d}",
           "product": random.choice(PRODUCTS),
           "amount": round(random.uniform(9.99, 2999.99), 2), "currency": "USD",
           "status": random.choice(STATUSES["order"])}
    for f in pii:
        if f == "shipping_address": row["shipping_address"] = raddress()
        elif f == "contact_email":  row["contact_email"]    = remail()
        elif f == "phone_number":   row["phone_number"]     = rphone()
    return row

def _payment(pid, pii=()):
    row = {"id": pid, "transaction_id": f"TXN-{random.randint(100000,999999)}",
           "amount": round(random.uniform(4.99, 9999.99), 2),
           "currency": random.choice(["USD","EUR","GBP"]),
           "status": random.choice(STATUSES["pay"]),
           "gateway": random.choice(GATEWAYS)}
    for f in pii:
        if f == "credit_card_number":  row["credit_card_number"]  = rcard()
        elif f == "billing_address":   row["billing_address"]     = raddress()
        elif f == "card_holder_name":  row["card_holder_name"]    = rname()
        elif f == "bank_account_iban": row["bank_account_iban"]   = riban()
    return row

BUILDERS = {
    "public.customers": _customer,
    "public.employees": _employee,
    "public.orders":    _order,
    "public.payments":  _payment,
}

OP_LABELS = {"c": "INSERT", "u": "UPDATE", "d": "DELETE"}


def _detection_reasons(fields):
    reasons = {}
    for f in fields:
        if any(k in f for k in ["email", "mail"]):
            reasons[f] = ["field name matches known PII identifier", "value matches email address pattern"]
        elif any(k in f for k in ["phone", "mobile"]):
            reasons[f] = ["field name matches known PII identifier", "value matches phone number pattern"]
        elif "ssn" in f or "social" in f:
            reasons[f] = ["field name matches known PII identifier", "value matches SSN pattern (xxx-xx-xxxx)"]
        elif "card" in f or "credit" in f:
            reasons[f] = ["field name matches known PII identifier", "value matches credit card pattern"]
        elif "iban" in f or "bank_account" in f:
            reasons[f] = ["field name matches known PII identifier (financial)", "value matches IBAN format"]
        elif "salary" in f or "wage" in f:
            reasons[f] = ["field name matches known PII identifier (financial)"]
        elif "dob" in f or "birth" in f or "date_of" in f:
            reasons[f] = ["field name matches known PII identifier"]
        elif "address" in f or "addr" in f:
            reasons[f] = ["field name matches known PII identifier"]
        elif "name" in f:
            reasons[f] = ["field name contains personal name indicator"]
        else:
            reasons[f] = ["field name matches known PII identifier"]
    return reasons


# ── Main seeder ────────────────────────────────────────────────────────────────

def seed():
    conn = psycopg2.connect(**DB)

    print("This will CLEAR all existing data in processing_log and violation_audit_log.")
    confirm = input("Type 'yes' to continue: ").strip().lower()
    if confirm != "yes":
        print("Aborted.")
        conn.close()
        return

    with conn.cursor() as cur:
        cur.execute("TRUNCATE violation_audit_log, processing_log RESTART IDENTITY CASCADE")
    conn.commit()
    print("Tables cleared.\n")

    proc_rows = []   # (ts, table, decision, raw_before)
    viol_rows = []   # (ts, table, op_label, unauth, detected, reasons, after, before, new_fields)

    ids = {t: 1 for t in TABLES}

    for table, cfg in TABLES.items():
        build   = BUILDERS[table]
        allowed = cfg["allowed_pii"]
        pool    = cfg["pii_pool"]
        vrate   = cfg["violation_rate"]
        drate   = cfg["delete_rate"]
        urate   = cfg["update_rate"]
        pmin, pmax = cfg["pii_count"]

        for _ in range(cfg["n_events"]):
            rid = ids[table]
            ids[table] += 1
            ts  = rts()

            r = random.random()
            if r < drate:
                op = "d"
            elif r < drate + urate:
                op = "u"
            else:
                op = "c"

            # DELETE — log and move on
            if op == "d":
                before = build(rid)
                proc_rows.append((ts, table, "DELETED", psycopg2.extras.Json(before)))
                continue

            is_violation = random.random() < vrate

            if not is_violation:
                proc_rows.append((ts, table, "COMPLIANT", None))
                continue

            # Pick PII fields for this violation
            n_pii   = random.randint(pmin, min(pmax, len(pool)))
            pii_flds = random.sample(pool, n_pii)

            after = build(rid, pii_flds)

            # For customers, email is always in the payload — include it as detected
            detected = list(pii_flds)
            if table == "public.customers" and "email" not in detected:
                detected = ["email"] + detected

            unauthorized = [f for f in detected if f not in allowed]

            # UPDATE: simulate a before-state (may be missing some of the new PII)
            if op == "u":
                n_new = random.randint(1, len(pii_flds))
                newly_introduced = random.sample(pii_flds, n_new)
                before_pii = [f for f in pii_flds if f not in newly_introduced]
                before = build(rid, before_pii)
            else:
                before = None
                newly_introduced = []

            proc_rows.append((ts, table, "VIOLATION", None))
            viol_rows.append((
                ts,
                table,
                OP_LABELS[op],
                psycopg2.extras.Json(unauthorized),
                psycopg2.extras.Json(detected),
                psycopg2.extras.Json(_detection_reasons(detected)),
                psycopg2.extras.Json(after),
                psycopg2.extras.Json(before),
                psycopg2.extras.Json(newly_introduced),
            ))

    proc_rows.sort(key=lambda x: x[0])
    viol_rows.sort(key=lambda x: x[0])

    print(f"Inserting {len(proc_rows):,} processing_log rows...")
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            "INSERT INTO processing_log (event_timestamp, table_name, decision, raw_before_payload) VALUES (%s,%s,%s,%s)",
            proc_rows, page_size=500,
        )
    conn.commit()

    print(f"Inserting {len(viol_rows):,} violation_audit_log rows...")
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            """
            INSERT INTO violation_audit_log (
                event_timestamp, table_name, operation,
                unauthorized_fields, detected_fields, detection_reasons,
                raw_after_payload, raw_before_payload, newly_introduced_fields
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            viol_rows, page_size=500,
        )
    conn.commit()
    conn.close()

    decisions = {}
    for row in proc_rows:
        decisions[row[2]] = decisions.get(row[2], 0) + 1

    vrate_actual = decisions.get("VIOLATION", 0) / max(decisions.get("COMPLIANT", 0) + decisions.get("VIOLATION", 0), 1) * 100

    print("\n── Seed Summary ─────────────────────────────────────────────────")
    print(f"  Total events       : {len(proc_rows):,}")
    print(f"  COMPLIANT          : {decisions.get('COMPLIANT', 0):,}")
    print(f"  VIOLATION          : {decisions.get('VIOLATION', 0):,}  ({vrate_actual:.1f}%)")
    print(f"  DELETED            : {decisions.get('DELETED', 0):,}")
    print(f"  Violation records  : {len(viol_rows):,}")
    print(f"  Tables seeded      : {', '.join(TABLES)}")
    print(f"  Time range         : {START.strftime('%Y-%m-%d')} → {NOW.strftime('%Y-%m-%d')} (7 days)")
    print(f"  PII types exposed  : email, phone_number, ssn, date_of_birth, salary,")
    print(f"                       home_address, credit_card_number, billing_address,")
    print(f"                       card_holder_name, bank_account_iban, shipping_address, full_name")
    print("─────────────────────────────────────────────────────────────────")
    print("\nDone. Refresh the dashboard to see the new data.")


if __name__ == "__main__":
    seed()
