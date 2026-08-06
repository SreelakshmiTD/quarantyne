import html
import os
from datetime import date, timedelta

import altair as alt
import psycopg2
import psycopg2.extras
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", 5433)),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
    "dbname": os.getenv("POSTGRES_DB"),
}


# ── Data fetchers ─────────────────────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def fetch_summary(conn, table_filter=None, date_from=None, date_to=None):
    conditions, params = [], []
    if table_filter:
        conditions.append("table_name = %s")
        params.append(table_filter)
    if date_from:
        conditions.append("event_timestamp >= %s")
        params.append(date_from)
    if date_to:
        conditions.append("event_timestamp < %s")
        params.append(date_to + timedelta(days=1))
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT
                COUNT(*) FILTER (WHERE decision != 'DELETED') AS total,
                COUNT(*) FILTER (WHERE decision = 'COMPLIANT') AS compliant,
                COUNT(*) FILTER (WHERE decision = 'VIOLATION') AS violations,
                COUNT(*) FILTER (WHERE decision = 'DELETED')  AS deletes
            FROM processing_log
            {where}
        """, params)
        row = cur.fetchone()
    total, compliant, violations, deletes = row
    rate = (violations / total * 100) if total else 0.0
    return {"total": total, "compliant": compliant, "violations": violations, "deletes": deletes, "rate": rate}


def fetch_table_names(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT table_name FROM violation_audit_log ORDER BY table_name"
        )
        return ["All tables"] + [r[0] for r in cur.fetchall()]


PAGE_SIZE = 50


def _violation_where(table_filter, field_search, date_from=None, date_to=None, operation=None):
    """Build shared WHERE clause and params for violation queries."""
    conditions, params = [], []
    if table_filter:
        conditions.append("table_name = %s")
        params.append(table_filter)
    if field_search:
        conditions.append("unauthorized_fields ? %s")
        params.append(field_search.strip().lower())
    if date_from:
        conditions.append("event_timestamp >= %s")
        params.append(date_from)
    if date_to:
        conditions.append("event_timestamp < %s")
        params.append(date_to + timedelta(days=1))
    if operation:
        conditions.append("operation = %s")
        params.append(operation)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def fetch_violation_count(conn, table_filter=None, field_search=None, date_from=None, date_to=None, operation=None):
    where, params = _violation_where(table_filter, field_search, date_from, date_to, operation)
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM violation_audit_log {where}", params if params else [])
        return cur.fetchone()[0]


def fetch_violations(conn, table_filter=None, field_search=None, date_from=None, date_to=None, operation=None, page=1):
    where, params = _violation_where(table_filter, field_search, date_from, date_to, operation)
    offset = (page - 1) * PAGE_SIZE
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT
                id, event_timestamp, table_name, operation,
                unauthorized_fields, detected_fields, detection_reasons,
                raw_after_payload, raw_before_payload, newly_introduced_fields
            FROM violation_audit_log
            {where}
            ORDER BY event_timestamp DESC
            LIMIT %s OFFSET %s
            """,
            (params + [PAGE_SIZE, offset]) if params else [PAGE_SIZE, offset],
        )
        return cur.fetchall()


def fetch_violations_over_time(conn, table_filter=None, date_from=None, date_to=None, operation=None):
    where, params = _violation_where(table_filter, None, date_from, date_to, operation)
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT date_trunc('day', event_timestamp AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS violations
            FROM violation_audit_log
            {where}
            GROUP BY 1
            ORDER BY 1
        """, params if params else [])
        rows = cur.fetchall()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows, columns=["day", "violations"])
    df["day"] = pd.to_datetime(df["day"])
    return df.set_index("day")


def fetch_pii_breakdown(conn, table_filter=None, date_from=None, date_to=None, operation=None):
    where, params = _violation_where(table_filter, None, date_from, date_to, operation)
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT field, COUNT(*) AS count
            FROM violation_audit_log,
                 jsonb_array_elements_text(unauthorized_fields) AS field
            {where}
            GROUP BY field
            ORDER BY count DESC
        """, params if params else [])
        rows = cur.fetchall()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows, columns=["field", "count"])
    return df.set_index("field")


def fetch_last_updated(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT MAX(event_timestamp) FROM processing_log")
        row = cur.fetchone()
    return row[0] if row and row[0] else None


# ── PII masking ──────────────────────────────────────────────────────────────

_EMAIL_FIELDS = {"email", "e_mail", "email_address"}
_PHONE_FIELDS = {"phone", "phone_number", "mobile", "mobile_number", "cell"}
_UNMASKED_FIELDS = {"customer_id", "segment", "country", "id"}


def mask_pii_value(field_name: str, value) -> str | None:
    if value is None:
        return None
    s = str(value)
    name = field_name.lower()
    if name in _EMAIL_FIELDS or "@" in s:
        at = s.find("@")
        if at >= 0:
            return s[:2] + "***" + s[at:]
        return s[:2] + "***"
    if name in _PHONE_FIELDS:
        digits = "".join(c for c in s if c.isdigit())
        return "***-***-" + digits[-4:] if len(digits) >= 4 else "***"
    return s[:2] + "***"


def _mask_dict(obj: dict, sensitive: set, prefix: str = "") -> dict:
    result = {}
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result[k] = _mask_dict(v, sensitive, path)
        elif path.lower() in sensitive and k.lower() not in _UNMASKED_FIELDS:
            result[k] = mask_pii_value(k, v)
        else:
            result[k] = v
    return result


def mask_payload(payload: dict, detected_fields: list) -> dict:
    if not payload:
        return payload
    sensitive = {f.lower() for f in (detected_fields or [])}
    return _mask_dict(payload, sensitive)


# ── UI helpers ────────────────────────────────────────────────────────────────

def metric_card(label: str, value: str, color: str) -> None:
    st.markdown(
        f'<div class="q-card {color}">'
        f'<div class="q-label">{label}</div>'
        f'<div class="q-value">{value}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def _paginator_items(current: int, total: int) -> list:
    """Return page numbers and None (ellipsis) for the paginator strip."""
    pages = sorted(
        set(range(1, min(3, total + 1)))
        | set(range(max(1, total - 1), total + 1))
        | set(range(max(1, current - 2), min(total + 1, current + 3)))
    )
    result, prev = [], None
    for p in pages:
        if prev is not None and p - prev > 1:
            result.append(None)  # ellipsis slot
        result.append(p)
        prev = p
    return ["←"] + result + ["→"]


def field_badges(fields: list, border: str = "#dc2626", fg: str = "#dc2626", bg: str = "#fff1f2") -> None:
    if not fields:
        st.markdown('<span style="color:#9ca3af;font-style:italic;">none</span>', unsafe_allow_html=True)
        return
    badges = " ".join(
        f'<span style="background:{bg};color:{fg};border:1px solid {border};'
        f'padding:3px 11px;border-radius:12px;font-size:0.78rem;margin-right:4px;">{html.escape(str(f))}</span>'
        for f in fields
    )
    st.markdown(badges, unsafe_allow_html=True)


@st.dialog("Violation Detail", width="large")
def show_violation_detail(row: dict) -> None:
    ts = row["event_timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(
        f'<p style="color:#6b7280;font-size:0.85rem;margin-top:-8px;">'
        f'ID&nbsp;{row["id"]} &nbsp;·&nbsp; {ts} &nbsp;·&nbsp;'
        f' {html.escape(row["table_name"])} &nbsp;·&nbsp; {html.escape(row["operation"])}</p>',
        unsafe_allow_html=True,
    )

    # Newly introduced fields
    nif = row.get("newly_introduced_fields") or []
    if nif:
        st.markdown("**Newly Introduced Fields**")
        field_badges(nif, border="#2563eb", fg="#1d4ed8", bg="#eff6ff")
        st.markdown("")

    # Unauthorized fields
    st.markdown("**Unauthorized Fields**")
    field_badges(row.get("unauthorized_fields") or [])

    st.markdown("---")

    # Before / After (PII values masked for display)
    detected = row.get("detected_fields") or []
    col_before, col_after = st.columns(2)
    with col_before:
        st.markdown("**Before**")
        if row.get("raw_before_payload"):
            st.json(mask_payload(dict(row["raw_before_payload"]), detected))
        else:
            st.markdown(
                '<p style="color:#9ca3af;font-style:italic;font-size:0.9rem;">'
                "No prior state (INSERT)</p>",
                unsafe_allow_html=True,
            )
    with col_after:
        st.markdown("**After**")
        if row.get("raw_after_payload"):
            st.json(mask_payload(dict(row["raw_after_payload"]), detected))
        else:
            st.markdown(
                '<p style="color:#9ca3af;font-style:italic;font-size:0.9rem;">'
                "No after state</p>",
                unsafe_allow_html=True,
            )

    st.caption(
        "PII values are masked for display. "
        "Full values are available in the audit log with appropriate access controls."
    )

    st.markdown("---")
    st.markdown("**Detection Reasons**")
    st.json(row["detection_reasons"])


# ── Page setup ────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Quarantyne",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
/* sidebar — follows theme */
[data-testid="stSidebar"] {
    background-color: var(--secondary-background-color);
    border-right: 1px solid rgba(128,128,128,0.2);
}

/* sidebar top accent bar */
[data-testid="stSidebar"] > div:first-child {
    border-top: 4px solid #2563eb;
    padding-top: 1.2rem;
}

/* metric cards — follow theme for bg/text, hardcoded semantic accents */
.q-card {
    border-left: 4px solid;
    border-radius: 6px;
    background: var(--secondary-background-color);
    padding: 1.1rem 1.3rem;
    margin-bottom: 0.25rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
.q-label {
    color: var(--text-color);
    opacity: 0.6;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-bottom: 0.3rem;
}
.q-value {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.1;
    color: var(--text-color);
}

/* semantic accent colors — hardcoded, must be legible on both light and dark bg */
.q-card.neutral { border-color: rgba(128,128,128,0.5); }
.q-card.green   { border-color: #059669; }
.q-card.green   .q-value { color: #059669; }
.q-card.red     { border-color: #dc2626; }
.q-card.red     .q-value { color: #dc2626; }
.q-card.amber   { border-color: #d97706; }
.q-card.amber   .q-value { color: #d97706; }

/* section labels — follow theme */
.q-section {
    color: var(--text-color);
    opacity: 0.75;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.75rem;
}

/* All primary buttons — brand blue (Refresh, View Details, etc.) */
button[kind="primary"],
[data-testid="stBaseButton-primary"] {
    background-color: #2563eb;
    border-color: #2563eb;
    color: #ffffff;
}
button[kind="primary"]:hover,
[data-testid="stBaseButton-primary"]:hover {
    background-color: #1d4ed8;
    border-color: #1d4ed8;
    color: #ffffff;
}
</style>
""", unsafe_allow_html=True)

# ── Connect (needed before sidebar to populate filter options) ────────────────

try:
    conn = get_connection()
except Exception as e:
    st.error(f"Could not connect to Postgres: {e}")
    st.stop()

try:
    table_names = fetch_table_names(conn)
except Exception as e:
    table_names = ["(all)"]

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        '<div style="font-size:0.7rem;font-weight:600;text-transform:uppercase;'
        'letter-spacing:0.1em;color:#9ca3af;margin-bottom:1rem;">'
        "Privacy Enforcement Dashboard</div>",
        unsafe_allow_html=True,
    )
    if st.button("Refresh", type="primary", use_container_width=True):
        st.rerun()

    st.markdown("---")
    st.markdown("**Filters**")
    selected_table = st.selectbox("Table", options=table_names)
    field_search = st.text_input("Field", placeholder="e.g. email", key="field_search_input")
    selected_operation = st.selectbox(
        "Operation",
        options=["All operations", "INSERT", "UPDATE", "DELETE"],
        key="operation_filter",
    )

    st.markdown("**Date Range**")
    date_from = st.date_input("From", value=None, key="date_from_input")
    date_to   = st.date_input("To",   value=None, key="date_to_input")
    if st.button("Clear dates", use_container_width=True):
        st.session_state["date_from_input"] = None
        st.session_state["date_to_input"]   = None
        st.rerun()

    # Reset page to 1 whenever filters change
    _filter_sig = (selected_table, field_search, selected_operation, date_from, date_to)
    if _filter_sig != st.session_state.get("_prev_filter_sig"):
        st.session_state["page_input"] = 1
    st.session_state["_prev_filter_sig"] = _filter_sig

table_filter = None if selected_table == "All tables" else selected_table
op_filter    = None if selected_operation == "All operations" else selected_operation
filter_date_from = date_from
filter_date_to   = date_to
page = st.session_state.get("page_input", 1)

# ── Header ────────────────────────────────────────────────────────────────────

try:
    last_updated = fetch_last_updated(conn)
except Exception:
    last_updated = None
ts_str = last_updated.strftime("%Y-%m-%d %H:%M:%S UTC") if last_updated else "—"

st.markdown(
    '<h1 style="font-size:2.4rem;font-weight:800;letter-spacing:-0.03em;'
    'color:#2563eb;margin:0 0 4px 0;line-height:1.1;">Quarantyne</h1>'
    '<p style="color:#4b5563;font-size:0.95rem;font-weight:500;margin:0 0 2px 0;">'
    "Real-Time Privacy Enforcement for CDC Streams</p>"
    f'<p style="color:#9ca3af;font-size:0.78rem;margin:0 0 2.5rem 0;">Last event: {ts_str}</p>',
    unsafe_allow_html=True,
)

# ── Processing Health ─────────────────────────────────────────────────────────

st.markdown('<div class="q-section">Processing Health</div>', unsafe_allow_html=True)

try:
    summary = fetch_summary(conn, table_filter, filter_date_from, filter_date_to)
except Exception as e:
    st.error(f"Failed to load summary: {e}")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
with c1:
    metric_card("Total Processed", f"{summary['total']:,}", "neutral")
with c2:
    metric_card("Compliant", f"{summary['compliant']:,}", "green")
with c3:
    metric_card("Violations", f"{summary['violations']:,}", "red")
with c4:
    metric_card("Violation Rate", f"{summary['rate']:.1f}%", "amber")
active_filters = []
if table_filter:
    active_filters.append(f"table: `{table_filter}`")
if filter_date_from:
    active_filters.append(f"from: {filter_date_from}")
if filter_date_to:
    active_filters.append(f"to: {filter_date_to}")
if active_filters:
    st.caption(f"{summary['deletes']:,} delete event(s) excluded from counts · Filtered by {' · '.join(active_filters)}")
else:
    st.caption(f"{summary['deletes']:,} delete event(s) excluded from counts · Showing all tables")

# ── Charts ────────────────────────────────────────────────────────────────────

st.markdown("---")

try:
    df_time = fetch_violations_over_time(conn, table_filter, filter_date_from, filter_date_to, op_filter)
    df_pii  = fetch_pii_breakdown(conn, table_filter, filter_date_from, filter_date_to, op_filter)
except Exception as e:
    st.warning(f"Could not load chart data: {e}")
    df_time = df_pii = pd.DataFrame()

st.markdown('<div class="q-section">Violations Over Time</div>', unsafe_allow_html=True)
if not df_time.empty:
    base = alt.Chart(df_time.reset_index()).encode(
        x=alt.X("day:T", title=None, axis=alt.Axis(format="%b %d", tickCount="day")),
        y=alt.Y("violations:Q", title=None, scale=alt.Scale(domainMin=0)),
        tooltip=[
            alt.Tooltip("day:T", title="Date", format="%b %d", timeUnit="yearmonthdate"),
            alt.Tooltip("violations:Q", title="Violations"),
        ],
    )
    chart = (
        base.mark_area(color="#ef4444", opacity=0.15)
        + base.mark_line(color="#ef4444", strokeWidth=2.5, point=alt.OverlayMarkDef(color="#ef4444", size=70, filled=True))
    ).properties(height=220)
    st.altair_chart(chart, use_container_width=True)
else:
    st.caption("No data yet.")

st.markdown("---")
st.markdown('<div class="q-section">PII Type Breakdown</div>', unsafe_allow_html=True)
if not df_pii.empty:
    chart = (
        alt.Chart(df_pii.reset_index())
        .mark_bar(color="#f59e0b", cornerRadiusTopRight=3, cornerRadiusBottomRight=3)
        .encode(
            y=alt.Y("field:N", sort="-x", title=None, axis=alt.Axis(labelLimit=200)),
            x=alt.X("count:Q", title=None, scale=alt.Scale(domainMin=0)),
            tooltip=[
                alt.Tooltip("field:N", title="Field"),
                alt.Tooltip("count:Q", title="Violations"),
            ],
        )
        .properties(height=max(220, len(df_pii) * 36))
    )
    st.altair_chart(chart, use_container_width=True)
else:
    st.caption("No data yet.")

# ── Policy Violations ─────────────────────────────────────────────────────────

st.markdown("---")
st.markdown('<div class="q-section">Policy Violations</div>', unsafe_allow_html=True)
st.markdown("<div style='margin-bottom:0.4rem'></div>", unsafe_allow_html=True)

try:
    total_violations = fetch_violation_count(conn, table_filter, field_search or None, filter_date_from, filter_date_to, op_filter)
    total_pages = max(1, -(-total_violations // PAGE_SIZE))  # ceiling division
    current_page = min(int(page), total_pages)
    violations = fetch_violations(conn, table_filter, field_search or None, filter_date_from, filter_date_to, op_filter, page=current_page)
except Exception as e:
    st.error(f"Failed to load violations: {e}")
    st.stop()
finally:
    conn.close()

if not violations:
    st.info("No violations match the current filters.")
    st.stop()

st.caption(f"Page {current_page} of {total_pages} · {total_violations:,} total violations · select a row then click View Details")

display_rows = [
    {
        "id": row["id"],
        "timestamp": row["event_timestamp"],
        "table": row["table_name"],
        "operation": row["operation"],
        "unauthorized_fields": ", ".join(row["unauthorized_fields"] or []),
        "detected_fields": ", ".join(row["detected_fields"] or []),
    }
    for row in violations
]

selected = st.dataframe(
    display_rows,
    use_container_width=True,
    hide_index=True,
    on_select="rerun",
    selection_mode="single-row",
    column_config={
        "id": st.column_config.NumberColumn("ID", width="small"),
        "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        "table": "Table",
        "operation": st.column_config.TextColumn("Operation", width="small"),
        "unauthorized_fields": st.column_config.TextColumn("Unauthorized Fields"),
        "detected_fields": st.column_config.TextColumn("Detected Fields"),
    },
)

selected_rows = selected.selection.rows if selected.selection else []

# ── Paginator (below table, right-aligned) ────────────────────────────────────
_, pager_col = st.columns([2, 3])
with pager_col:
    pager = _paginator_items(current_page, total_pages)
    for col, item in zip(st.columns(len(pager)), pager):
        with col:
            if item == "←":
                if st.button("←", disabled=current_page <= 1, use_container_width=True):
                    st.session_state["page_input"] = current_page - 1
                    st.rerun()
            elif item == "→":
                if st.button("→", disabled=current_page >= total_pages, use_container_width=True):
                    st.session_state["page_input"] = current_page + 1
                    st.rerun()
            elif item is None:
                st.markdown(
                    '<p style="text-align:center;margin-top:6px;color:#9ca3af;">…</p>',
                    unsafe_allow_html=True,
                )
            elif item == current_page:
                st.markdown(
                    f'<div style="text-align:center;margin-top:4px;">'
                    f'<span style="background:#2563eb;color:#fff;border-radius:4px;'
                    f'padding:5px 10px;font-size:0.875rem;font-weight:600;">{item}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
            else:
                if st.button(str(item), use_container_width=True):
                    st.session_state["page_input"] = item
                    st.rerun()

if selected_rows:
    row = violations[selected_rows[0]]
    st.markdown("<div style='margin-top:0.5rem'></div>", unsafe_allow_html=True)
    if st.button(f"View Details — Violation #{row['id']}", type="primary"):
        show_violation_detail(row)
