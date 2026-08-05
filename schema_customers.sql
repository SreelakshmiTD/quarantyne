CREATE TABLE customers (
    customer_id  INTEGER PRIMARY KEY,
    segment      TEXT,
    country      TEXT,
    email        TEXT,
    phone        TEXT
);

ALTER TABLE customers REPLICA IDENTITY FULL;
