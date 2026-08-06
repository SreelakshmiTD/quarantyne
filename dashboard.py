import html
import os

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


def fetch_summary(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE decision != 'DELETED') AS total,
                COUNT(*) FILTER (WHERE decision = 'COMPLIANT') AS compliant,
                COUNT(*) FILTER (WHERE decision = 'VIOLATION') AS violations,
                COUNT(*) FILTER (WHERE decision = 'DELETED')  AS deletes
            FROM processing_log
        """)
        row = cur.fetchone()
    total, compliant, violations, deletes = row
    rate = (violations / total * 100) if total else 0.0
    return {"total": total, "compliant": compliant, "violations": violations, "deletes": deletes, "rate": rate}


def fetch_table_names(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT table_name FROM violation_audit_log ORDER BY table_name"
        )
        return ["(all)"] + [r[0] for r in cur.fetchall()]


PAGE_SIZE = 50


def _violation_where(table_filter, field_search):
    """Build shared WHERE clause and params for violation queries."""
    conditions, params = [], []
    if table_filter:
        conditions.append("table_name = %s")
        params.append(table_filter)
    if field_search:
        conditions.append("unauthorized_fields ? %s")
        params.append(field_search.strip().lower())
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return where, params


def fetch_violation_count(conn, table_filter=None, field_search=None):
    where, params = _violation_where(table_filter, field_search)
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM violation_audit_log {where}", params if params else [])
        return cur.fetchone()[0]


def fetch_violations(conn, table_filter=None, field_search=None, page=1):
    where, params = _violation_where(table_filter, field_search)
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


def fetch_violations_over_time(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT date_trunc('hour', event_timestamp) AS hour, COUNT(*) AS violations
            FROM violation_audit_log
            GROUP BY 1
            ORDER BY 1
        """)
        rows = cur.fetchall()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows, columns=["hour", "violations"])
    df["hour"] = pd.to_datetime(df["hour"])
    return df.set_index("hour")


def fetch_pii_breakdown(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT field, COUNT(*) AS count
            FROM violation_audit_log,
                 jsonb_array_elements_text(unauthorized_fields) AS field
            GROUP BY field
            ORDER BY count DESC
        """)
        rows = cur.fetchall()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows, columns=["field", "count"])
    return df.set_index("field")


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
    st.markdown("## QUARANTYNE")
    st.markdown(
        '<p style="color:#9ca3af;font-size:0.78rem;margin-top:-10px;margin-bottom:1rem;">'
        "Privacy Enforcement Dashboard</p>",
        unsafe_allow_html=True,
    )
    if st.button("Refresh", type="primary", use_container_width=True):
        st.rerun()

    st.markdown("---")
    st.markdown("**Filters**")
    selected_table = st.selectbox("Table", options=table_names)
    field_search = st.text_input("Unauthorized Field", placeholder="e.g. email", key="field_search_input")

    # Reset page to 1 whenever filters change
    if (selected_table != st.session_state.get("_prev_table")
            or field_search != st.session_state.get("_prev_field")):
        st.session_state["page_input"] = 1
    st.session_state["_prev_table"] = selected_table
    st.session_state["_prev_field"] = field_search

    st.markdown("**Page**")
    page = st.number_input("Page", min_value=1, value=1, step=1, label_visibility="collapsed", key="page_input")

table_filter = None if selected_table == "(all)" else selected_table

# ── Header ────────────────────────────────────────────────────────────────────

st.markdown("# QUARANTYNE")
st.markdown(
    '<p style="color:#9ca3af;margin-top:-14px;margin-bottom:4px;">'
    "Real-Time Privacy Enforcement for CDC Streams</p>",
    unsafe_allow_html=True,
)

# ── Processing Health ─────────────────────────────────────────────────────────

st.markdown("---")
st.markdown('<div class="q-section">Processing Health</div>', unsafe_allow_html=True)

try:
    summary = fetch_summary(conn)
except Exception as e:
    conn.close()
    st.error(f"Failed to load summary: {e}")
    st.stop()

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    metric_card("Total Processed", f"{summary['total']:,}", "neutral")
with c2:
    metric_card("Compliant", f"{summary['compliant']:,}", "green")
with c3:
    metric_card("Violations", f"{summary['violations']:,}", "red")
with c4:
    metric_card("Violation Rate", f"{summary['rate']:.1f}%", "amber")
with c5:
    metric_card("Deletes", f"{summary['deletes']:,}", "neutral")

# ── Charts ────────────────────────────────────────────────────────────────────

st.markdown("---")

try:
    df_time = fetch_violations_over_time(conn)
    df_pii  = fetch_pii_breakdown(conn)
except Exception as e:
    st.warning(f"Could not load chart data: {e}")
    df_time = df_pii = pd.DataFrame()

chart_l, chart_r = st.columns(2)

with chart_l:
    st.markdown('<div class="q-section">Violations Over Time</div>', unsafe_allow_html=True)
    if not df_time.empty:
        chart = (
            alt.Chart(df_time.reset_index())
            .mark_line(color="#ef4444")
            .encode(
                x=alt.X("hour:T", title=None),
                y=alt.Y("violations:Q", title="violations", scale=alt.Scale(domainMin=0)),
            )
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        st.caption("No data yet.")

with chart_r:
    st.markdown('<div class="q-section">PII Type Breakdown</div>', unsafe_allow_html=True)
    if not df_pii.empty:
        st.bar_chart(df_pii, color="#f59e0b", use_container_width=True)
    else:
        st.caption("No data yet.")

# ── Policy Violations ─────────────────────────────────────────────────────────

st.markdown("---")
st.markdown('<div class="q-section">Policy Violations</div>', unsafe_allow_html=True)
st.markdown("<div style='margin-bottom:0.4rem'></div>", unsafe_allow_html=True)

try:
    total_violations = fetch_violation_count(conn, table_filter, field_search or None)
    total_pages = max(1, -(-total_violations // PAGE_SIZE))  # ceiling division
    current_page = min(int(page), total_pages)
    violations = fetch_violations(conn, table_filter, field_search or None, page=current_page)
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
        "unauthorized_fields": row["unauthorized_fields"],
        "detected_fields": row["detected_fields"],
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
        "unauthorized_fields": "Unauthorized Fields",
        "detected_fields": "Detected Fields",
    },
)

selected_rows = selected.selection.rows if selected and selected.selection else []

if selected_rows:
    row = violations[selected_rows[0]]
    st.markdown("<div style='margin-top:0.5rem'></div>", unsafe_allow_html=True)
    if st.button(f"View Details — Violation #{row['id']}", type="primary"):
        show_violation_detail(row)
