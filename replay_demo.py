"""
replay_demo.py — Policy Replay Demo
=====================================
Replays the quarantyne.public.customers topic from the beginning using a
fresh consumer group ("quarantyne-replay-demo"), evaluating every historical
event against the current policy.yaml.

Purpose: demonstrate that changing policy.yaml and reprocessing the Kafka
topic from offset 0 produces different COMPLIANT/VIOLATION outcomes than the
original run — without touching the source database.

This script exits automatically after IDLE_TIMEOUT_S seconds of no new
messages (i.e. once it has caught up to the end of the topic).

Run:
    source .venv/bin/activate
    python3 replay_demo.py
"""

import json
import os
import time
from confluent_kafka import Consumer, KafkaError, KafkaException
from dotenv import load_dotenv

from detector import detect_pii_in_payload
from policy import load_policy_config, evaluate_policy

load_dotenv()

KAFKA_BROKER   = os.getenv("KAFKA_BROKER", "localhost:9092")
TOPIC_PATTERN  = r"^quarantyne\.public\..+"
GROUP_ID       = os.getenv("KAFKA_REPLAY_GROUP_ID", "quarantyne-replay-demo")   # distinct var from KAFKA_GROUP_ID — can never collide with the production consumer by construction
IDLE_TIMEOUT_S = 5                          # exit after this many seconds with no new messages

OP_LABELS = {
    "c": "INSERT",
    "u": "UPDATE",
    "d": "DELETE",
    "r": "READ (snapshot)",
}


def run() -> None:
    try:
        policy_config = load_policy_config(os.path.join(os.path.dirname(__file__), "policy.yaml"))
        if not isinstance(policy_config, dict) or "tables" not in policy_config:
            raise ValueError("policy config must be a dict with a 'tables' key")
    except Exception as e:
        print(f"[FATAL] Could not load policy config: {e}")
        return
    print("Policy loaded:")
    for table, cfg in policy_config.get("tables", {}).items():
        print(f"  {table}: allowed_pii_fields = {(cfg or {}).get('allowed_pii_fields', [])}")
    print()

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKER,
        "group.id": GROUP_ID,
        "auto.offset.reset": "earliest",   # replay from the beginning
        "enable.auto.commit": False,        # read-only replay; no offset commits
    })
    consumer.subscribe([TOPIC_PATTERN])
    print(f"Consumer group : {GROUP_ID}")
    print(f"Topic pattern  : {TOPIC_PATTERN}")
    print(f"Offset reset   : earliest  (full replay from offset 0)")
    print(f"Auto-exit after: {IDLE_TIMEOUT_S}s idle\n")
    print("=" * 60)

    total = 0
    compliant = 0
    violations = 0
    changed_outcome = 0   # COMPLIANT events that have detected PII (would have been VIOLATION under a stricter policy)
    last_msg_time = time.time()

    try:
        while True:
            if time.time() - last_msg_time > IDLE_TIMEOUT_S:
                print("=" * 60)
                print(f"No messages for {IDLE_TIMEOUT_S}s — caught up to end of topic. Exiting.\n")
                break

            msg = consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(msg.error())

            last_msg_time = time.time()

            raw = msg.value()
            if raw is None:
                continue

            try:
                envelope = json.loads(raw)
                payload  = envelope.get("payload", envelope)
                op       = payload.get("op")
                before   = payload.get("before")
                after    = payload.get("after")
                source   = payload.get("source", {})
                table_name = f"{source.get('schema', 'unknown')}.{source.get('table', 'unknown')}"
            except (json.JSONDecodeError, AttributeError, TypeError) as e:
                print(f"  [SKIP] Unparseable message at offset {msg.offset()}: {e}\n")
                continue

            total += 1
            print(f"[offset={msg.offset()}] table={table_name} op={OP_LABELS.get(op, op)}")

            if after is None:
                print("  → DELETE — skipping PII detection\n")
                continue

            pii_result    = detect_pii_in_payload(after)
            policy_result = evaluate_policy(table_name, pii_result, policy_config)
            decision      = policy_result["decision"]

            if decision == "COMPLIANT":
                compliant += 1
            else:
                violations += 1

            # Flag COMPLIANT events that still contain detected PII — these are
            # fields explicitly allowed by the current policy. Under a stricter
            # (empty) allowlist they would have been VIOLATION.
            allowed_pii = [f for f in pii_result["detected_fields"] if f not in policy_result["unauthorized_fields"]]
            if decision == "COMPLIANT" and allowed_pii:
                changed_outcome += 1
                print(f"  → COMPLIANT  *** outcome changed: PII allowed by current policy (was VIOLATION) ***")
                print(f"     allowed fields: {allowed_pii}")
            else:
                print(f"  → {decision}")
                if pii_result["detected_fields"]:
                    print(f"     detected: {pii_result['detected_fields']}")
                if policy_result["unauthorized_fields"]:
                    print(f"     unauthorized: {policy_result['unauthorized_fields']}")
            print()

    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        consumer.close()

    print("── Replay Summary ──────────────────────────────────")
    print(f"  Total events processed : {total}")
    print(f"  COMPLIANT              : {compliant}")
    print(f"  VIOLATION              : {violations}")
    print(f"  Outcome changed        : {changed_outcome}  (PII present but allowed by current policy)")
    print(f"  Consumer group         : {GROUP_ID}")
    print(f"  Policy evaluated       : policy.yaml (current state)")
    print("────────────────────────────────────────────────────")


if __name__ == "__main__":
    run()
