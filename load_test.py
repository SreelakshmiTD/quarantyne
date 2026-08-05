import random
import time

import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "user": "privacypulse",
    "password": "privacypulse",
    "dbname": "privacypulse_db",
}

SEGMENTS = ["premium", "standard", "trial", "enterprise"]
COUNTRIES = ["IN", "US", "GB", "DE", "SG", "AU", "CA", "FR"]

FIRST_NAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry"]
LAST_NAMES = ["smith", "jones", "patel", "kim", "nguyen", "garcia", "müller", "chen"]
DOMAINS = ["example.com", "mail.com", "testcorp.io", "fakeco.net"]

TOTAL_ROWS = 10_000
STARTING_ID = 60000
VIOLATING_PROBABILITY = 0.30  # 30% chance of a violating row
BATCH_SIZE = 200
BATCH_PAUSE = 0.05  # seconds between batches
PROGRESS_EVERY = 2_000


def fake_email(customer_id: int) -> str:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    domain = random.choice(DOMAINS)
    return f"{first}.{last}{customer_id}@{domain}"


def fake_phone() -> str:
    return f"{random.randint(200, 999)}{random.randint(1000000, 9999999)}"


def main() -> None:
    db = psycopg2.connect(**DB_CONFIG)
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            customer_id  INTEGER PRIMARY KEY,
            segment      TEXT,
            country      TEXT,
            email        TEXT,
            phone        TEXT
        )
    """)
    db.commit()

    clean_count = 0
    violating_count = 0
    start = time.time()

    for batch_start in range(0, TOTAL_ROWS, BATCH_SIZE):
        batch_end = min(batch_start + BATCH_SIZE, TOTAL_ROWS)

        for i in range(batch_start, batch_end):
            customer_id = STARTING_ID + i
            segment = random.choice(SEGMENTS)
            country = random.choice(COUNTRIES)

            if random.random() < VIOLATING_PROBABILITY:
                include_email = random.random() < 0.7
                include_phone = random.random() < 0.5
                email = fake_email(customer_id) if include_email else None
                phone = fake_phone() if include_phone else None
                violating_count += 1
            else:
                email = None
                phone = None
                clean_count += 1

            cur.execute(
                """
                INSERT INTO customers (customer_id, segment, country, email, phone)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (customer_id) DO NOTHING
                """,
                (customer_id, segment, country, email, phone),
            )

        db.commit()

        rows_done = batch_end
        if rows_done % PROGRESS_EVERY == 0 or rows_done == TOTAL_ROWS:
            elapsed = time.time() - start
            print(f"  Progress: {rows_done}/{TOTAL_ROWS} rows inserted ({elapsed:.1f}s elapsed)")

        time.sleep(BATCH_PAUSE)

    elapsed = time.time() - start

    cur.close()
    db.close()

    print(f"Inserted {TOTAL_ROWS} rows in {elapsed:.2f}s")
    print(f"  Clean rows:     {clean_count}")
    print(f"  Violating rows: {violating_count}")


if __name__ == "__main__":
    main()
