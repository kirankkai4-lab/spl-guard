"""
telemetry/dashboard.py
──────────────────────
Layer 5 — SPL Guard FinOps Dashboard

Single data source: proxy /stats endpoint.
/stats merges local SQLite + live Splunk _internal via MCP channel.

Run with:
  Windows: streamlit run telemetry/dashboard.py --server.port 8502
"""

import os
import sqlite3
import time
from datetime import datetime, timezone

import httpx
import pandas as pd
import streamlit as st

PROXY_BASE        = os.getenv("PROXY_BASE_URL", "http://127.0.0.1:8080")
MEMORY_DB_PATH    = os.getenv("MEMORY_DB_PATH", "./memory/query_cache.db")
REFRESH_SECS      = 10
SVC_PER_HIGH_RISK = 2.5
SVC_ANNUAL_COST   = 65000
SVC_HOURLY_COST   = round(SVC_ANNUAL_COST / 365 / 24, 2)
DOLLAR_PER_HIGH_RISK = round(SVC_HOURLY_COST * SVC_PER_HIGH_RISK, 2)

st.set_page_config(
    page_title = "SPL Guard — FinOps",
    page_icon  = "⚡",
    layout     = "wide",
)

st.title("⚡ SPL Guard — Splunk MCP FinOps Dashboard")
st.caption(
    f"Source: Splunk MCP Server via proxy `/stats`  ·  "
    f"Proxy: {PROXY_BASE}  ·  Refreshes every {REFRESH_SECS}s"
)


# ── Fetch stats ────────────────────────────────────────────────────────────────
@st.cache_data(ttl=REFRESH_SECS)
def fetch_stats() -> dict:
    try:
        r = httpx.get(f"{PROXY_BASE}/stats", timeout=10)
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


data = fetch_stats()

if "error" in data:
    st.error(f"Proxy unreachable: {data['error']}")
    st.info("Start the proxy:  `uvicorn proxy.main:app --host 127.0.0.1 --port 8080 --reload`")
    st.stop()


# ── Mode indicator ─────────────────────────────────────────────────────────────
mode = data.get("mode", "active")
if mode == "active":
    st.success("🟢 Active mode — SPL Guard is intercepting and rewriting queries")
elif mode == "passive":
    st.warning("🟡 Passive mode — SPL Guard is monitoring only, not rewriting or blocking")
elif mode == "bypass":
    st.error("🔴 Bypass mode — SPL Guard is transparent, no governance active")

st.divider()


# ── Extract fields ─────────────────────────────────────────────────────────────
total      = data.get("total", 0)
safe       = data.get("safe", 0)
rewritten  = data.get("rewritten", 0)
blocked    = data.get("blocked", 0)
cache_hits = data.get("cache_hits", 0)
high_risk  = data.get("high_risk_prevented", 0)
svc_saved       = round(high_risk * SVC_PER_HIGH_RISK, 1)
dollars_saved   = round(high_risk * DOLLAR_PER_HIGH_RISK, 2)

splunk_mcp_rows  = data.get("splunk_mcp_activity", [])
rate_limit_rows  = data.get("splunk_rate_limiting", [])
audit_rows       = data.get("splguard_audit_from_splunk", [])
splunk_live      = bool(splunk_mcp_rows or rate_limit_rows)


# ── KPI row ────────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
c1.metric("Queries intercepted", total)
c2.metric("Safe — forwarded",    safe)
c3.metric("Rewritten",           rewritten,
          delta=f"saved {rewritten}" if rewritten else None)
c4.metric("Blocked",             blocked,
          delta=f"prevented {blocked}" if blocked else None,
          delta_color="inverse")
c5.metric("SVC units saved",     svc_saved,
          delta="↓ compute cost" if svc_saved > 0 else None)
c6.metric("Est. $ saved (session)", f"${dollars_saved:,.2f}",
          delta="↓ SVC spend" if dollars_saved > 0 else None)
c7.metric("Cache hits",          cache_hits,
          delta=f"{round(cache_hits/total*100)}% rate" if total else None)

if dollars_saved > 0:
    st.success(
        f"🛡️ SPL Guard intercepted {high_risk} high-risk queries this session — "
        f"estimated **${dollars_saved:,.2f}** in SVC compute costs avoided. "
        f"Based on Splunk workload pricing of ~$65K/SVC/year."
    )

if splunk_live:
    st.success("🟢 Splunk _internal telemetry live — data sourced via MCP channel")
else:
    st.warning(
        "🟡 Splunk _internal telemetry not yet available. "
        "Stats are from local SQLite. "
        "Ensure the MCP token role has `splunk_run_query` access."
    )

st.divider()


# ── Main panels ────────────────────────────────────────────────────────────────
left, right = st.columns(2)

with left:
    st.subheader("Query disposition")
    if total > 0:
        chart_df = pd.DataFrame({
            "Verdict": ["Safe", "Rewritten", "Blocked"],
            "Count":   [safe, rewritten, blocked],
        })
        st.bar_chart(chart_df.set_index("Verdict"))
    else:
        st.info("No queries yet. Send a query through the proxy to populate this chart.")

    st.subheader("Cache efficiency")
    cache_pct = round(cache_hits / total * 100, 1) if total else 0
    st.metric("Hit rate", f"{cache_pct}%",
              help="Queries served from memory — skipped full inspection")
    st.progress(min(cache_pct / 100, 1.0))

with right:
    st.subheader("Splunk MCP Server — live _internal activity")
    st.caption("Source: index=_internal via run_splunk_query on MCP channel")
    if splunk_mcp_rows:
        st.dataframe(pd.DataFrame(splunk_mcp_rows), use_container_width=True)
    else:
        st.info("Waiting for Splunk _internal data via MCP channel.")

    st.subheader("Rate limit telemetry (v1.2)")
    if rate_limit_rows:
        st.dataframe(pd.DataFrame(rate_limit_rows), use_container_width=True)
    else:
        st.info("No rate-limit events yet.")

st.divider()


# ── Recent rewrites — intent preserved ────────────────────────────────────────
st.subheader("🔄 Recent rewrites — intent preserved")
st.caption(
    "Shows original vs rewritten SPL side by side. "
    "The search intent is preserved — only unsafe bounds are added."
)
try:
    import os as _os
    db_path = MEMORY_DB_PATH.replace('/', '\\') if '/' in MEMORY_DB_PATH else MEMORY_DB_PATH
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT raw_spl, final_spl, reasons, svc_risk, last_seen "
        "FROM query_cache ORDER BY last_seen DESC LIMIT 5"
    ).fetchall()
    conn.close()
    if rows:
        for row in rows:
            with st.expander(f"Rewrite — {row['last_seen'][:19]}  |  risk: {row['svc_risk'].upper()}"):
                col1, col2 = st.columns(2)
                col1.markdown("**Original (unsafe)**")
                col1.code(row["raw_spl"], language="text")
                col2.markdown("**Rewritten (safe)**")
                col2.code(row["final_spl"], language="text")
                import json as _json
                reasons = _json.loads(row["reasons"]) if row["reasons"] else []
                st.caption(f"Reasons: {', '.join(reasons)}")
    else:
        st.info("No rewrites recorded yet.")
except Exception as e:
    st.error(f"Error reading cache: {e}")

st.divider()


# ── Blocked queries — admin review ────────────────────────────────────────────
st.subheader("🚫 Blocked queries — admin review")
st.caption(
    "Queries stopped before reaching Splunk. "
    "Full details available in index=splguard_audit in Splunk."
)
try:
    conn = sqlite3.connect(MEMORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    blocked_rows = conn.execute(
        "SELECT hash, ts, verdict, svc_risk FROM intercept_log "
        "WHERE verdict='blocked' ORDER BY ts DESC LIMIT 10"
    ).fetchall()
    conn.close()
    if blocked_rows:
        df = pd.DataFrame([dict(r) for r in blocked_rows])
        st.dataframe(df, use_container_width=True)
        st.caption(
            "To alert on blocked queries in Splunk: "
            "`index=splguard_audit sourcetype=splguard_intercept verdict=blocked`"
        )
    else:
        st.info("No blocked queries yet.")
except Exception:
    st.info("Intercept log not yet initialised.")

st.divider()


# ── SPL Guard audit log from Splunk ───────────────────────────────────────────
st.subheader("SPL Guard audit log — read back from Splunk")
st.caption(
    "Every proxy decision written to index=splguard_audit via MCP, "
    "then read back here. Native Splunk audit trail — no side channel."
)
if audit_rows:
    st.dataframe(pd.DataFrame(audit_rows), use_container_width=True)
else:
    st.info(
        "No audit events yet, or splguard_audit index not yet created. "
        "First intercept will trigger the write."
    )

st.divider()


# ── Governance mode control ────────────────────────────────────────────────────
st.subheader("⚙️ Governance mode")
col1, col2 = st.columns(2)
col1.metric("Current mode", mode.upper())
col2.info(
    "To change mode: update `SPLGUARD_MODE` in `.env` and restart the proxy.\n\n"
    "**active** — intercept, rewrite, block (default)\n\n"
    "**passive** — observe and log only, forward unchanged\n\n"
    "**bypass** — completely transparent, no governance"
)

st.divider()


# ── HITL toggle ───────────────────────────────────────────────────────────────
st.subheader("🔀 Human-in-the-loop intercept")
hitl = st.toggle(
    "Manual intercept mode",
    value=False,
    help="When ON — high-risk queries pause for admin approval before forwarding",
)
if hitl:
    st.warning(
        "Manual mode active. High-risk queries pause at the proxy and wait for "
        "admin approval. Full wiring: LangGraph interrupt() → approve/deny here "
        "→ proxy resumes forward. (v1.1 roadmap)"
    )
else:
    st.success("Automated mode — proxy rewrites and forwards without interruption.")


# ── Footer ─────────────────────────────────────────────────────────────────────
st.divider()
st.caption(
    f"SPL Guard · Splunk MCP Server v1.2 · "
    f"All telemetry via MCP encrypted token · "
    f"Last refresh {datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC"
)

time.sleep(REFRESH_SECS)
st.rerun()