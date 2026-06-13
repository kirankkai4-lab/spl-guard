"""
proxy/main.py
─────────────
Layer 1 — MCP-to-MCP Reverse Proxy

Flow:
  LangGraph  ──►  POST /mcp  (this proxy)
                     │
                     ├─ tools/call with search tool name?
                     │     extract search_query
                     │     check SQLite memory cache
                     │     run SPL inspector (regex)
                     │     if rewritten → store in cache
                     │     log intercept to SQLite + Splunk (via MCP)
                     │     forward safe/rewritten query to Splunk MCP Server
                     │
                     └─ anything else → transparent passthrough to Splunk MCP Server

One token. One channel. All Splunk calls go through SplunkMCPClient.
"""

import copy
import hashlib
import json
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic_settings import BaseSettings

from spl.inspector import inspect, Verdict
from memory.query_cache import init_db, lookup, store, log_intercept, get_stats
from proxy.splunk_mcp_client import SplunkMCPClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("splguard.proxy")


# ── Settings ───────────────────────────────────────────────────────────────────
class Settings(BaseSettings):
    splunk_mcp_endpoint:        str
    splunk_mcp_encrypted_token: str
    proxy_host:                 str = "0.0.0.0"
    proxy_port:                 int = 8080
    splunk_mcp_ssl_verify:      bool = False   

    class Config:
        env_file = ".env"
        extra    = "ignore"


settings = Settings()

# Shared client — one instance, one token, one channel
splunk = SplunkMCPClient(
    endpoint        = settings.splunk_mcp_endpoint,
    encrypted_token = settings.splunk_mcp_encrypted_token,
    ssl_verify      = settings.splunk_mcp_ssl_verify,
)

# ── MCP tool names that carry a search_query argument ─────────────────────────
# Splunk MCP Server v1.2 prefixes tools with "splunk_"
# Community / older servers use unprefixed names
SEARCH_TOOL_NAMES = {
    "splunk_run_query",   # official Splunk MCP Server v1.x
    "run_splunk_query",   # alternative naming
    "search_splunk",      # community implementations
    "saia_run_query",     # AI Assistant variant
}

SEARCH_ARG_KEYS = ["query", "search_query", "search", "spl"]


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("SPL Guard proxy started — forwarding to %s", settings.splunk_mcp_endpoint)
    yield
    logger.info("SPL Guard proxy shutting down")


app = FastAPI(
    title    = "SPL Guard — Splunk MCP Proxy",
    version  = "1.0.0",
    lifespan = lifespan,
)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _is_search_tool_call(body: dict) -> bool:
    if body.get("method") != "tools/call":
        return False
    return body.get("params", {}).get("name", "") in SEARCH_TOOL_NAMES


def _extract_search_query(body: dict) -> tuple[str | None, str | None]:
    params    = body.get("params", {})
    arguments = params.get("arguments", params.get("input", {}))
    for key in SEARCH_ARG_KEYS:
        if key in arguments:
            return key, str(arguments[key])
    return None, None


def _inject_rewrite(body: dict, arg_key: str, new_spl: str) -> dict:
    modified  = copy.deepcopy(body)
    params    = modified.setdefault("params", {})
    arguments = params.get("arguments", params.get("input", {}))
    arguments[arg_key] = new_spl
    if "arguments" in params:
        params["arguments"] = arguments
    else:
        params["input"] = arguments
    return modified


def _blocked_mcp_error(request_id, reasons: list[str]) -> dict:
    return {
        "jsonrpc": "2.0",
        "id":      request_id,
        "error": {
            "code":    -32600,
            "message": "Query blocked by SPL Guard",
            "data":    {"reasons": reasons},
        },
    }


def _splunk_response_to_fastapi(resp) -> Response:
    """Convert an httpx.Response from Splunk into a FastAPI Response."""
    return Response(
        content    = resp.content,
        status_code= resp.status_code,
        media_type = resp.headers.get("content-type", "application/json"),
    )


# ── Main proxy endpoint ────────────────────────────────────────────────────────
@app.post("/mcp")
async def mcp_proxy(request: Request) -> Response:
    raw_bytes = await request.body()

    try:
        body = json.loads(raw_bytes)
    except json.JSONDecodeError:
        # Malformed — let Splunk return the error
        resp = await splunk.forward_raw(raw_bytes)
        return _splunk_response_to_fastapi(resp)

    # ── Passthrough: anything that is not a search tool call ──────────────────
    if not _is_search_tool_call(body):
        resp = await splunk.forward_raw(raw_bytes)
        return _splunk_response_to_fastapi(resp)

    # ── Intercept: search tool call ───────────────────────────────────────────
    arg_key, raw_spl = _extract_search_query(body)

    if not raw_spl:
        logger.warning("Search tool call with no query arg — passing through")
        resp = await splunk.forward_raw(raw_bytes)
        return _splunk_response_to_fastapi(resp)

    request_id = body.get("id")
    t_start    = time.perf_counter()
    query_hash = hashlib.sha256(raw_spl.encode()).hexdigest()

    # ── Check memory cache first ──────────────────────────────────────────────
    cached = lookup(query_hash)
    if cached:
        final_spl = cached["final_spl"]
        verdict   = "rewritten" if final_spl != raw_spl else "safe"
        logger.info("CACHE HIT | hash=%s", query_hash[:8])
        log_intercept(query_hash, verdict, cached["svc_risk"], from_cache=True)
        # Fire-and-forget audit write to Splunk (non-blocking)
        import asyncio
        asyncio.create_task(splunk.log_intercept_to_splunk(
            verdict=verdict, svc_risk=cached["svc_risk"],
            raw_spl=raw_spl, final_spl=final_spl,
            reasons=json.loads(cached["reasons"]), from_cache=True,
        ))
        modified = _inject_rewrite(body, arg_key, final_spl)
        resp = await splunk.forward_body(modified)
        return _splunk_response_to_fastapi(resp)

    # ── SPL inspection ────────────────────────────────────────────────────────
    result     = inspect(raw_spl)
    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)

    # Write to local SQLite (always)
    log_intercept(query_hash, result.verdict.value, result.svc_risk, from_cache=False)

    # Write audit event to Splunk via MCP (fire-and-forget — never blocks proxy)
    import asyncio
    asyncio.create_task(splunk.log_intercept_to_splunk(
        verdict    = result.verdict.value,
        svc_risk   = result.svc_risk,
        raw_spl    = result.original_spl,
        final_spl  = result.final_spl,
        reasons    = result.reasons,
        from_cache = False,
    ))

    # ── BLOCKED ───────────────────────────────────────────────────────────────
    if result.verdict == Verdict.BLOCKED:
        logger.warning("BLOCKED | reasons=%s | %sms", result.reasons, elapsed_ms)
        return JSONResponse(
            status_code = 200,   # MCP errors ride in 200 OK
            content     = _blocked_mcp_error(request_id, result.reasons),
        )

    # ── REWRITTEN ─────────────────────────────────────────────────────────────
    if result.verdict == Verdict.REWRITTEN:
        logger.info(
            "REWRITTEN | reasons=%s | risk=%s | %sms",
            result.reasons, result.svc_risk, elapsed_ms,
        )
        store(
            hash_     = result.query_hash,
            raw_spl   = result.original_spl,
            final_spl = result.final_spl,
            reasons   = result.reasons,
            svc_risk  = result.svc_risk,
        )
        modified = _inject_rewrite(body, arg_key, result.final_spl)
        resp = await splunk.forward_body(modified)
        return _splunk_response_to_fastapi(resp)

    # ── SAFE ──────────────────────────────────────────────────────────────────
    logger.debug("SAFE | %sms", elapsed_ms)
    resp = await splunk.forward_raw(raw_bytes)
    return _splunk_response_to_fastapi(resp)


# ── Stats endpoint — merges SQLite + live Splunk telemetry ────────────────────
@app.get("/stats")
async def stats():
    """
    Merged view: local SQLite intercept counts + live Splunk _internal telemetry.
    Both pulled through the same MCP channel.
    """
    local = get_stats()

    # Pull live MCP activity from Splunk _internal via MCP channel
    splunk_mcp_activity  = await splunk.query_internal_mcp_telemetry()
    splunk_rate_limiting = await splunk.query_svc_rate_limit_telemetry()
    splguard_audit       = await splunk.query_splguard_audit_log()

    return {
    **local,
    "splunk_mcp_activity":        splunk_mcp_activity,
    "splunk_rate_limiting":       splunk_rate_limiting,
    "splguard_audit_from_splunk": splguard_audit,
}


@app.get("/health")
async def health():
    return {"status": "ok", "target": settings.splunk_mcp_endpoint}