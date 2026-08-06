import json
import os
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
from dotenv import load_dotenv

from detector import detect_pii_in_payload, diff_before_after
from policy import load_policy_config, evaluate_policy

load_dotenv()

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
POLICY_FILE   = os.path.join(os.path.dirname(__file__), "policy.yaml")
# Pattern matches quarantyne.public.* (CDC intake topics) only.
# Does NOT match quarantyne.approved or quarantyne.quarantine — those lack ".public." in their name.
TOPIC_PATTERN = r"^quarantyne\.public\..+"
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "quarantyne-consumer")
TOPIC_APPROVED = "quarantyne.approved"
TOPIC_QUARANTINE = "quarantyne.quarantine"

OP_LABELS = {
    "c": "INSERT",
    "u": "UPDATE",
    "d": "DELETE",
    "r": "READ (snapshot)",
}


def print_summary(op: str, pii_result: dict, diff_result: dict, policy_result: dict) -> None:
    op_label = OP_LABELS.get(op, op)
    pii_flag = "YES" if pii_result["has_pii"] else "NO"
    print(f"  op:                      {op_label}")
    print(f"  PII detected:            {pii_flag}")
    if pii_result["detected_fields"]:
        print(f"  detected_fields:         {pii_result['detected_fields']}")
        print(f"  detection_reasons:       {pii_result['detection_reasons']}")
    if diff_result["newly_introduced_fields"]:
        print(f"  newly_introduced_fields: {diff_result['newly_introduced_fields']}")
    else:
        print(f"  newly_introduced_fields: (none)")
    print(f"  policy decision:         {policy_result['decision']}")
    if policy_result["unauthorized_fields"]:
        print(f"  unauthorized_fields:     {policy_result['unauthorized_fields']}")


PRODUCER_FLUSH_EVERY = 100   # flush producer and commit offsets every N messages
VIOLATION_COMMIT_EVERY = 50  # also flush if this many violations are pending


def flush_batch(
    producer: Producer,
    db,
    consumer: Consumer,
    last_msg,
    pending_violations: int,
    label: str = "batch",
) -> None:
    """Flush producer, commit any pending Postgres audit inserts, commit Kafka offset."""
    producer.flush()
    db.commit()
    consumer.commit(message=last_msg)
    print(f"  [BATCH FLUSH ({label})] producer flushed | {pending_violations} audit insert(s) committed | offset committed")


def run() -> None:
    try:
        policy_config = load_policy_config(POLICY_FILE)
    except Exception as e:
        print(f"[FATAL] Could not load policy config from {POLICY_FILE}: {e}")
        return
    policy_mtime  = os.path.getmtime(POLICY_FILE)
    print("Policy config loaded.\n")

    producer = Producer({"bootstrap.servers": KAFKA_BROKER})

    db = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", 5433)),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        dbname=os.getenv("POSTGRES_DB"),
    )
    print("Postgres connection established.\n")

    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": GROUP_ID,
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([TOPIC_PATTERN])
    print(f"Subscribed via pattern: {TOPIC_PATTERN}\n")

    # Batch state
    msgs_since_batch = 0      # messages processed since last flush (including deletes)
    pending_violations = 0    # staged audit inserts not yet committed to Postgres
    last_processed_msg = None # last message successfully processed; used for offset commit
    last_flush_time = time.time()  # time of last batch flush; used for time-based flush trigger

    # Throughput and latency instrumentation — intentional, permanent observability.
    # These counters produced the performance numbers documented in the README.
    total_msg_count = 0
    first_msg_time = None
    batch_start_time = None
    batch_latencies = []  # per-message processing times within the current batch

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

            # Policy hot-reload: runs on every poll tick, including idle (msg is None)
            current_mtime = os.path.getmtime(POLICY_FILE)
            if current_mtime != policy_mtime:
                try:
                    policy_config = load_policy_config(POLICY_FILE)
                    policy_mtime  = current_mtime
                    print(f"Policy config reloaded from {POLICY_FILE}")
                except Exception as e:
                    print(f"  [WARN] Policy reload failed — keeping previous config: {e}")

            # Time-based flush: runs on every poll tick, including idle (msg is None)
            if last_processed_msg is not None and msgs_since_batch > 0:
                if time.time() - last_flush_time > 5:
                    flush_batch(producer, db, consumer, last_processed_msg, pending_violations, label="timeout")
                    msgs_since_batch = 0
                    pending_violations = 0
                    last_flush_time = time.time()

            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                raise KafkaException(msg.error())

            raw = msg.value()
            if raw is None:
                print("[SKIP] Tombstone message (null value)\n")
                continue

            try:
                envelope = json.loads(raw)
                payload = envelope.get("payload", envelope)
                op = payload.get("op")
                before = payload.get("before")
                after = payload.get("after")
                source = payload.get("source", {})
                table_name = f"{source.get('schema', 'unknown')}.{source.get('table', 'unknown')}"
            except (json.JSONDecodeError, AttributeError, TypeError) as e:
                print(f"  [SKIP] Unparseable message at offset {msg.offset()}: {e}\n")
                last_processed_msg = msg
                msgs_since_batch += 1
                continue

            print(f"--- Message (partition={msg.partition()}, offset={msg.offset()}) ---")

            if after is None:
                print(f"  op: {OP_LABELS.get(op, op)}")
                print("  after is None — skipping PII detection (delete event)")
                try:
                    with db.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO processing_log (event_timestamp, table_name, decision, raw_before_payload)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (datetime.now(timezone.utc), table_name, "DELETED", psycopg2.extras.Json(before)),
                        )
                    print(f"  processing_log:          DELETED staged (pending flush)")
                    last_processed_msg = msg
                    msgs_since_batch += 1
                    if msgs_since_batch >= PRODUCER_FLUSH_EVERY:
                        flush_batch(producer, db, consumer, last_processed_msg, pending_violations)
                        msgs_since_batch = 0
                        pending_violations = 0
                        last_flush_time = time.time()
                except Exception as e:
                    db.rollback()
                    print(f"  [ERROR] Failed to stage delete log at offset {msg.offset()}: {e}")
                    print(f"  [ERROR] Staged insert rolled back. Offset NOT committed.\n")
                print()
                continue

            try:
                _msg_start = time.time()  # per-message latency start

                pii_result = detect_pii_in_payload(after)
                diff_result = diff_before_after(before, after)
                policy_result = evaluate_policy(table_name, pii_result, policy_config)
                print_summary(op, pii_result, diff_result, policy_result)

                dest_topic = TOPIC_APPROVED if policy_result["decision"] == "COMPLIANT" else TOPIC_QUARANTINE
                producer.produce(dest_topic, key=msg.key(), value=raw)
                producer.poll(0)  # serve delivery callbacks non-blocking
                print(f"  routed to:               {dest_topic} (pending flush)")

                with db.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO processing_log (event_timestamp, table_name, decision)
                        VALUES (%s, %s, %s)
                        """,
                        (datetime.now(timezone.utc), table_name, policy_result["decision"]),
                    )

                if policy_result["decision"] == "VIOLATION":
                    with db.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO violation_audit_log (
                                event_timestamp, table_name, operation,
                                unauthorized_fields, detected_fields, detection_reasons,
                                raw_after_payload, raw_before_payload, newly_introduced_fields
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                datetime.now(timezone.utc),
                                table_name,
                                OP_LABELS.get(op, op),
                                psycopg2.extras.Json(policy_result["unauthorized_fields"]),
                                psycopg2.extras.Json(pii_result["detected_fields"]),
                                psycopg2.extras.Json(pii_result["detection_reasons"]),
                                psycopg2.extras.Json(after),
                                psycopg2.extras.Json(before),
                                psycopg2.extras.Json(diff_result["newly_introduced_fields"]),
                            ),
                        )
                    pending_violations += 1
                    print(f"  audit log:               staged ({pending_violations} pending)")

                last_processed_msg = msg
                msgs_since_batch += 1

                # Per-message latency tracking for batch throughput summary.
                _msg_latency = time.time() - _msg_start
                batch_latencies.append(_msg_latency)
                total_msg_count += 1
                if first_msg_time is None:
                    first_msg_time = time.time()
                    batch_start_time = first_msg_time

                # Flush if batch thresholds are met
                should_flush = (
                    msgs_since_batch >= PRODUCER_FLUSH_EVERY
                    or pending_violations >= VIOLATION_COMMIT_EVERY
                )
                if should_flush:
                    flush_batch(producer, db, consumer, last_processed_msg, pending_violations)
                    msgs_since_batch = 0
                    pending_violations = 0
                    last_flush_time = time.time()

                    # Batch throughput summary — printed on every flush.
                    batch_elapsed = time.time() - batch_start_time
                    total_elapsed = time.time() - first_msg_time
                    batch_mps = len(batch_latencies) / batch_elapsed if batch_elapsed > 0 else float("inf")
                    overall_mps = total_msg_count / total_elapsed if total_elapsed > 0 else float("inf")
                    avg_ms = (sum(batch_latencies) / len(batch_latencies)) * 1000
                    min_ms = min(batch_latencies) * 1000
                    max_ms = max(batch_latencies) * 1000
                    print(
                        f"  [THROUGHPUT] total={total_msg_count} | overall={overall_mps:.1f} msg/s"
                        f" | batch={batch_mps:.1f} msg/s ({len(batch_latencies)} msgs in {batch_elapsed:.1f}s)"
                        f" | latency min={min_ms:.1f}ms avg={avg_ms:.1f}ms max={max_ms:.1f}ms"
                    )
                    batch_latencies = []
                    batch_start_time = time.time()

                print()

            except Exception as e:
                db.rollback()
                pending_violations = 0
                print(f"  [ERROR] Failed to process message at offset {msg.offset()}: {e}")
                print(f"  [ERROR] All pending audit inserts for this batch rolled back — offsets for earlier messages in this batch may still advance on next flush.\n")

    except KeyboardInterrupt:
        print("\nStopped by user.")
        if last_processed_msg is not None and msgs_since_batch > 0:
            print(f"Flushing {msgs_since_batch} pending message(s) before exit...")
            flush_batch(producer, db, consumer, last_processed_msg, pending_violations, label="shutdown")
    finally:
        consumer.close()
        db.close()


if __name__ == "__main__":
    run()
