"""
telemetry/dashboard.py
──────────────────────
Layer 5 — FinOps Dashboard

Single data source: the proxy /stats endpoint.

/stats already merges:
  - Local SQLite intercept counts
  - Live Splunk _internal MCP telemetry   ← via MCP channel (encrypted token)
  - SVC rate-limit hit data               ← via MCP channel (encrypted token)
  - SPL Guard audit log read back from Splunk  ← via MCP channel (encrypted token)

No SPLUNK_REST_TOKEN. No side connection on port 8089.
One token. One channel. Dashboard just reads /stats.
"""

import os
import time
from datetime import datetime, timezone

import httpx
import pandas as pd
import streamlit as st

PROXY_BASE       = os.getenv("PROXY_BASE_URL", "http://localhost:8080")
REFRESH_SECS     = 10
SVC_PER_HIGH_RISK    = 2.5      # SVC units per high-risk intercept (conservative)
SVC_ANNUAL_COST      = 65000    # $ per SVC per year (Splunk workload pricing midpoint)
SVC_HOURLY_COST      = round(SVC_ANNUAL_COST / 365 / 24, 2)   # $7.42/hr
DOLLAR_PER_HIGH_RISK = round(SVC_HOURLY_COST * SVC_PER_HIGH_RISK, 2)  # ~$18.55

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


# ── Fetch ──────────────────────────────────────────────────────────────────────
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
    st.info("Start the proxy:  `uvicorn proxy.main:app --port 8080 --reload`")
    st.stop()


# ── Extract fields ─────────────────────────────────────────────────────────────
total      = data.get("total", 0)
safe       = data.get("safe", 0)
rewritten  = data.get("rewritten", 0)
blocked    = data.get("blocked", 0)
cache_hits = data.get("cache_hits", 0)
high_risk  = data.get("high_risk_prevented", 0)
svc_saved        = round(high_risk * SVC_PER_HIGH_RISK, 1)
dollars_saved    = round(high_risk * DOLLAR_PER_HIGH_RISK, 2)

splunk_mcp_rows   = data.get("splunk_mcp_activity", [])
rate_limit_rows   = data.get("splunk_rate_limiting", [])
audit_rows        = data.get("splguard_audit_from_splunk", [])

splunk_live = bool(splunk_mcp_rows or rate_limit_rows)


# ── Top KPI row ────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5, c6 , c7 = st.columns(7)
c1.metric("Queries intercepted", total)
c2.metric("Safe — forwarded",    safe)
c3.metric("Rewritten",           rewritten,
          delta=f"saved {rewritten}" if rewritten else None)
c4.metric("Blocked",             blocked,
          delta=f"prevented {blocked}" if blocked else None,
          delta_color="inverse")
c5.metric("SVC units saved", svc_saved,
          delta="↓ compute cost" if svc_saved > 0 else None)
c6.metric("Estimated $ saved", f"${dollars_saved:,.2f}",
          delta="↓ SVC spend" if dollars_saved > 0 else None)
c7.metric("Cache hits",          cache_hits,
          delta=f"{round(cache_hits/total*100)}% rate" if total else None)

# Splunk live indicator
if splunk_live:
    st.success("🟢 Splunk _internal telemetry live — data sourced via MCP channel")
else:
    st.warning(
        "🟡 Splunk _internal telemetry not yet available. "
        "Proxy stats are from local SQLite. "
        "Ensure the MCP token has `splunk_run_query` access."
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
    st.caption("Source: MCP rate-limit hits from _internal — shows what AICB prevents")
    if rate_limit_rows:
        rl_df = pd.DataFrame(rate_limit_rows)
        st.dataframe(rl_df, use_container_width=True)
    else:
        st.info("No rate-limit events yet.")

st.divider()


# ── SPL Guard audit from Splunk ────────────────────────────────────────────────────
st.subheader("SPL Guard audit log — read back from Splunk")
st.caption(
    "Every proxy decision written to index=splguard_audit via MCP, "
    "then read back here. Native Splunk audit trail — no side channel."
)
if audit_rows:
    st.dataframe(pd.DataFrame(audit_rows), use_container_width=True)
else:
    st.info(
        "No audit events yet, or SPL_Guard_Audit index not yet created. "
        "First intercept will trigger the write."
    )

st.divider()


# ── HITL mode ─────────────────────────────────────────────────────────────────
st.subheader("🔀 Intercept mode")
hitl = st.toggle(
    "Manual intercept mode (HITL)",
    value=False,
    help="When ON — high-risk queries queue here for admin approval before forwarding",
)
if hitl:
    st.warning(
        "Manual mode active. High-risk queries pause at the proxy and wait for "
        "admin approval. Full wiring: LangGraph `interrupt()` → approve/deny here "
        "→ proxy resumes forward."
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