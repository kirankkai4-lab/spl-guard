"""
proxy/splunk_mcp_client.py
──────────────────────────
Single place where all Splunk communication happens.

Everything goes through the Splunk MCP Server using the encrypted token.
No side REST connections. No second auth session. One channel, one token.

Three responsibilities:
  1. _internal telemetry queries  — routed as run_splunk_query MCP calls
  2. SPL Guard audit log writes   — routed as run_splunk_query on a writable index
  3. Forward agent queries        — the main proxy passthrough

This is what makes Splunk genuinely central rather than a destination label.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("splguard.splunk_client")


class SplunkMCPClient:
    """
    Wraps all Splunk MCP Server communication.
    Constructed once at proxy startup and shared across requests.
    """

    def __init__(self, endpoint: str, encrypted_token: str, ssl_verify: bool = False):
        self.endpoint        = endpoint.rstrip("/")
        self.encrypted_token = encrypted_token
        self.ssl_verify      = ssl_verify
        self._headers = {
            "Authorization": f"Bearer {encrypted_token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    # ── Low-level MCP call ────────────────────────────────────────────────────
    async def _mcp_tools_call(
        self,
        tool_name: str,
        arguments:  dict,
        request_id: str | None = None,
    ) -> dict:
        """
        Send one MCP tools/call to the Splunk MCP Server.
        Returns the parsed JSON response body.
        """
        rid = request_id or str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id":      rid,
            "method":  "tools/call",
            "params": {
                "name":      tool_name,
                "arguments": arguments,
            },
        }
        async with httpx.AsyncClient(verify=self.ssl_verify, timeout=70.0) as client:
            try:
                resp = await client.post(
                    self.endpoint,
                    content=json.dumps(payload).encode(),
                    headers=self._headers,
                )
                return resp.json()
            except httpx.TimeoutException:
                logger.error("Splunk MCP timeout | tool=%s", tool_name)
                return {"error": "timeout"}
            except httpx.RequestError as exc:
                logger.error("Splunk MCP connection error: %s", exc)
                return {"error": str(exc)}

    # ── Forward raw bytes (agent passthrough) ─────────────────────────────────
    async def forward_raw(self, raw_bytes: bytes) -> httpx.Response:
        """
        Forward an unchanged MCP request from the agent to Splunk.
        Used for safe queries and all non-search MCP methods.
        """
        async with httpx.AsyncClient(verify=self.ssl_verify, timeout=70.0) as client:
            return await client.post(
                self.endpoint,
                content=raw_bytes,
                headers=self._headers,
            )

    async def forward_body(self, body: dict) -> httpx.Response:
        """Forward a (possibly rewritten) dict as an MCP request."""
        return await self.forward_raw(json.dumps(body).encode())

    # ── _internal telemetry query ─────────────────────────────────────────────
    async def query_internal_mcp_telemetry(self) -> list[dict]:
        """
        Pull MCP tool call activity from _internal via the MCP channel.

        SPL reads the Splunk MCP Server app logs natively.
        sourcetype=splunk_web_access filtered on MCP URI paths gives us:
          - which MCP tools were called
          - how many calls per tool
          - how many unique agents hit the server

        This is Layer 5 — no external API, no second token.
        Same encrypted token, same MCP channel.
        """
        spl = (
            "search index=_internal sourcetype=splunk_web_access "
            "(uri_path=\"*/mcp/*\" OR uri_path=\"*/services/mcp/*\") "
            "earliest=-15m latest=now "
            "| rex field=uri_path \"/mcp/(?<tool>[^/]+)\" "
            "| stats count as calls, dc(clientip) as unique_agents by tool "
            "| sort -calls"
        )
        result = await self._mcp_tools_call(
            tool_name="splunk_run_query",
            arguments={"search_query": spl},
        )
        return self._parse_mcp_results(result)

    async def query_svc_rate_limit_telemetry(self) -> list[dict]:
        """
        Pull SVC consumption and rate limit hits from _internal.
        This is the data that feeds the 'SVC units saved' metric.

        Reads the MCP Server rate limiting telemetry introduced in v1.2.
        """
        spl = (
            "search index=_internal sourcetype=splunk_web_access "
            "(uri_path=\"*/mcp/*\") "
            "earliest=-15m latest=now "
            "| stats count as total_calls, "
            "sum(eval(if(status=429,1,0))) as rate_limited_calls "
            "by date_minute "
            "| eval pct_limited=round(rate_limited_calls/total_calls*100,1) "
            "| sort date_minute"
        )
        result = await self._mcp_tools_call(
            tool_name="splunk_run_query",
            arguments={"search_query": spl},
        )
        return self._parse_mcp_results(result)

    async def query_splguard_audit_log(self) -> list[dict]:
        """
        Pull AICB intercept events that were written back to Splunk.
        Reads from the splguard_audit index we write to in log_intercept_to_splunk().
        """
        spl = (
            "search index=splguard_audit sourcetype=splguard_intercept "
            "earliest=-15m latest=now "
            "| stats count by verdict, svc_risk "
            "| sort -count"
        )
        result = await self._mcp_tools_call(
            tool_name="splunk_run_query",
            arguments={"search_query": spl},
        )
        return self._parse_mcp_results(result)

    # ── Write AICB audit events back to Splunk ────────────────────────────────
    async def log_intercept_to_splunk(
        self,
        verdict:    str,
        svc_risk:   str,
        raw_spl:    str,
        final_spl:  str,
        reasons:    list[str],
        from_cache: bool,
    ) -> None:
        """
        Write one AICB intercept event back into Splunk via HEC-style SPL.

        We use the collect command to write a structured event into the
        splguard_audit  index. This gives Splunk admins a native audit trail
        of every decision the proxy made — queryable with SPL like any
        other Splunk data.

        If the write fails (Splunk down, permissions), we log locally and
        continue — never block the main proxy flow for telemetry.
        """
        now = datetime.now(timezone.utc).isoformat()
        event = {
            "ts":         now,
            "verdict":    verdict,
            "svc_risk":   svc_risk,
            "reasons":    reasons,
            "from_cache": from_cache,
            "raw_spl":    raw_spl[:500],    # truncate to avoid huge events
            "final_spl":  final_spl[:500],
            "source":     "splguard_proxy1",
        }
        # SPL collect writes an event into a Splunk index
        # Requires the MCP token's role to have write access to aicb_audit index
        spl = (
            f"| makeresults "
            f"| eval _raw=\"{json.dumps(event).replace(chr(34), chr(39))}\" "
            f"| eval index=\"aicb_audit\", sourcetype=\"aicb_intercept\" "
            f"| collect index=splguard_audit sourcetype=splguard_intercept"
        )
        try:
            await self._mcp_tools_call(
                tool_name="splunk_run_query",
                arguments={"search_query": spl},
            )
            logger.debug("Audit event written to Splunk | verdict=%s", verdict)
        except Exception as exc:
            # Non-fatal — local SQLite still has the record
            logger.warning("Splunk audit write failed (non-fatal): %s", exc)

    # ── Parse MCP response into usable rows ───────────────────────────────────
    @staticmethod
    def _parse_mcp_results(mcp_response: dict) -> list[dict]:
        """
        Extract result rows from an MCP tools/call response.

        MCP responses nest results inside content[].text as JSON.
        Handle both the official Splunk MCP Server format and
        community server variants.
        """
        if "error" in mcp_response:
            logger.warning("MCP query returned error: %s", mcp_response["error"])
            return []

        result = mcp_response.get("result", {})

        # Official Splunk MCP Server: structuredContent.results
        structured = result.get("structuredContent", {})
        if "results" in structured:
            return structured["results"]

        # Fallback: content[0].text contains JSON string
        content = result.get("content", [])
        for block in content:
            if block.get("type") == "text":
                try:
                    parsed = json.loads(block["text"])
                    if isinstance(parsed, list):
                        return parsed
                    if isinstance(parsed, dict) and "results" in parsed:
                        return parsed["results"]
                except (json.JSONDecodeError, KeyError):
                    pass

        return []