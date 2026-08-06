CREATE TABLE orders (
    order_id      INTEGER PRIMARY KEY,
    customer_id   INTEGER,
    order_amount  NUMERIC(10, 2),
    notes         TEXT
);

ALTER TABLE orders REPLICA IDENTITY FULL;
