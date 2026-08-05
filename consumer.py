import json
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from confluent_kafka import Consumer, Producer, KafkaError, KafkaException

from detector import detect_pii_in_payload, diff_before_after
from policy import load_policy_config, evaluate_policy

KAFKA_BROKER = "localhost:9092"
TOPIC = "quarantyne.public.customers"
GROUP_ID = "quarantyne-consumer"
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
    if pending_violations > 0:
        db.commit()
    consumer.commit(message=last_msg)
    print(f"  [BATCH FLUSH ({label})] producer flushed | {pending_violations} audit insert(s) committed | offset committed")


def run() -> None:
    policy_config = load_policy_config("policy.yaml")
    print("Policy config loaded.\n")

    producer = Producer({"bootstrap.servers": KAFKA_BROKER})

    db = psycopg2.connect(
        host="localhost",
        port=5433,
        user="privacypulse",
        password="privacypulse",
        dbname="privacypulse_db",
    )
    print("Postgres connection established.\n")

    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BROKER,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([TOPIC])
    print(f"Subscribed to {TOPIC}. Waiting for messages...\n")

    # Batch state
    msgs_since_batch = 0      # messages processed since last flush (including deletes)
    pending_violations = 0    # staged audit inserts not yet committed to Postgres
    last_processed_msg = None # last message successfully processed; used for offset commit
    last_flush_time = time.time()  # time of last batch flush; used for time-based flush trigger

    # TEMPORARY: throughput instrumentation for load testing
    total_msg_count = 0
    first_msg_time = None
    batch_start_time = None
    batch_latencies = []  # per-message processing times within the current batch

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

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

            envelope = json.loads(raw)
            payload = envelope.get("payload", envelope)

            op = payload.get("op")
            before = payload.get("before")
            after = payload.get("after")
            source = payload.get("source", {})
            table_name = f"{source.get('schema', 'unknown')}.{source.get('table', 'unknown')}"

            print(f"--- Message (partition={msg.partition()}, offset={msg.offset()}) ---")

            if after is None:
                print(f"  op: {OP_LABELS.get(op, op)}")
                print("  after is None — skipping PII detection (delete event)")
                last_processed_msg = msg
                msgs_since_batch += 1
                if msgs_since_batch >= PRODUCER_FLUSH_EVERY:
                    flush_batch(producer, db, consumer, last_processed_msg, pending_violations)
                    msgs_since_batch = 0
                    pending_violations = 0
                    last_flush_time = time.time()
                print()
                continue

            try:
                _msg_start = time.time()  # TEMPORARY: per-message timing

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

                # TEMPORARY: throughput instrumentation for load testing
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

                    # TEMPORARY: batch throughput summary
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
                print(f"  [ERROR] Pending audit inserts rolled back. Offset NOT committed.\n")

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
