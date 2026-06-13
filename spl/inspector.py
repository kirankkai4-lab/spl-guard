"""
spl/inspector.py
────────────────
Layer 2 — SPL Intelligence

Inspects the raw search_query string extracted from an MCP tools/call payload.
Returns either:
  - the original query (safe)
  - a rewritten query (unsafe → fixed)
  - a rejection reason (unfixable)

No splunk-sdk. No second auth session. Pure regex + string rewriting.
"""

import re
import hashlib
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("aicb.spl")


class Verdict(str, Enum):
    SAFE      = "safe"       # forward as-is
    REWRITTEN = "rewritten"  # proxy rewrote it — forward the new version
    BLOCKED   = "blocked"    # cannot fix — return error to agent


@dataclass
class InspectionResult:
    verdict:       Verdict
    original_spl:  str
    final_spl:     str          # same as original if SAFE, rewritten if REWRITTEN
    reasons:       list[str]    # human-readable list of what was wrong
    svc_risk:      str          # "low" | "medium" | "high" — feeds FinOps dashboard
    query_hash:    str          # sha256 of original — used by memory layer


# ── Defaults injected when bounds are missing ──────────────────────────────────
SAFE_INDEX    = "main"
SAFE_EARLIEST = "-15m"
SAFE_LATEST   = "now"

# ── Patterns that flag a query as dangerous ────────────────────────────────────
DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, human reason, risk level)
    (r"\bindex\s*=\s*\*",                   "Wildcard index (index=*)",              "high"),
    (r"\bearliesttime?\s*=\s*-[1-9]\d*[yd]", "Time range exceeds 1 day",             "high"),
    (r"\bearliesttime?\s*=\s*0",              "earliest=0 scans all time",            "high"),
    (r"\balltime\b",                          "alltime keyword — unbounded scan",     "high"),
    (r"\bearliest\s*=\s*-([6-9]\d|\d{3,})[m]", "Time range wider than 60 minutes",  "medium"),
    (r"\bearliest\s*=\s*-[2-9][h]",            "Time range wider than 1 hour",       "medium"),
    (r"\bindex\s*=\s*_\*",                   "Wildcard internal index (index=_*)",   "medium"),
    (r"\|\s*map\b",                           "map command can spawn sub-searches",  "medium"),
    (r"\|\s*join\b",                          "join command — high memory use",       "medium"),
    # ── Splunk 10.4 Federated Search patterns (GA May 2026) ───────────────────
    # Unbounded federated queries fan out across S3, Snowflake, Azure Data Lake
    # simultaneously — compute cost amplification is significantly higher than
    # a local index scan. Intercept before the fan-out begins.
    (r"\bindex\s*=\s*fed:\s*\*",
     "Federated wildcard — fans out across all remote environments",         "high"),
    (r"\bindex\s*=\s*fed:[^\s]+.*earliest\s*=\s*-[1-9]\d*[yd]",
     "Federated index with wide time range — cross-environment scan",        "high"),
    (r"\bfrom\s+index:[^\s]+.*earliest\s*=\s*-[1-9]\d*[yd]",
     "SPL2 federated query with wide time range",                            "high"),
    (r"\bdataset\s*=\s*\S+.*earliest\s*=\s*-[1-9]\d*[yd]",
     "Federated dataset with wide time range",                               "high"),
]

# ── Unfixable patterns — block outright ───────────────────────────────────────
BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"\|\s*delete\b",   "delete command — destructive"),
    (r"\|\s*rest\b",     "rest command — bypasses MCP guardrails"),
    (r"\[\s*search\b",   "subsearch injection — CVE-2025-20381 pattern"),
    (r"\bindex\s*=\s*fed:.*\|\s*delete\b",
     "delete on federated index — cross-environment destructive"),
]



def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _missing_index(spl: str) -> bool:
    """True if no explicit index= directive found."""
    return not re.search(r"\bindex\s*=\s*\S+", spl, re.IGNORECASE)


def _missing_time_bound(spl: str) -> bool:
    """True if no earliest= or latest= directive found."""
    has_earliest = bool(re.search(r"\bearliest\s*=", spl, re.IGNORECASE))
    has_latest   = bool(re.search(r"\blatest\s*=",   spl, re.IGNORECASE))
    return not (has_earliest and has_latest)


def _inject_index(spl: str, index: str = SAFE_INDEX) -> str:
    """Prepend index=<safe> if not already present."""
    if _missing_index(spl):
        # Insert right after the leading 'search' keyword if present
        if re.match(r"^\s*search\b", spl, re.IGNORECASE):
            return re.sub(
                r"^(\s*search\s+)",
                rf"\1index={index} ",
                spl,
                count=1,
                flags=re.IGNORECASE,
            )
        return f"search index={index} {spl}"
    return spl


def _inject_time_bounds(spl: str, earliest: str = SAFE_EARLIEST, latest: str = SAFE_LATEST) -> str:
    """Append earliest/latest if not already present."""
    if _missing_time_bound(spl):
        return f"{spl} earliest={earliest} latest={latest}"
    return spl


def _replace_wildcard_index(spl: str) -> str:
    """Replace index=* or index=_* with index=main."""
    spl = re.sub(r"\bindex\s*=\s*\*",  f"index={SAFE_INDEX}", spl, flags=re.IGNORECASE)
    spl = re.sub(r"\bindex\s*=\s*_\*", f"index={SAFE_INDEX}", spl, flags=re.IGNORECASE)
    return spl


def _cap_time_range(spl: str) -> str:
    """Replace dangerous time range values with safe bound."""
    # Replace earliest=-Nd, -Nh (large) with safe earliest
    spl = re.sub(
        r"\bearliest\s*=\s*-[1-9]\d*[ydhm]",
        f"earliest={SAFE_EARLIEST}",
        spl,
        flags=re.IGNORECASE,
    )
    spl = re.sub(r"\balltime\b", f"earliest={SAFE_EARLIEST} latest={SAFE_LATEST}", spl, flags=re.IGNORECASE)
    spl = re.sub(r"\bearliest\s*=\s*0", f"earliest={SAFE_EARLIEST}", spl, flags=re.IGNORECASE)
    return spl


def inspect(raw_spl: str) -> InspectionResult:
    """
    Main entry point.
    Takes raw SPL string from MCP tools/call payload.
    Returns InspectionResult with verdict + final (possibly rewritten) SPL.
    """
    reasons:   list[str] = []
    svc_risk:  str = "low"
    query_hash = _sha256(raw_spl)

    # ── Step 1: Check for unfixable / blocked patterns ─────────────────────────
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, raw_spl, re.IGNORECASE):
            logger.warning("BLOCKED query | reason=%s | hash=%s", reason, query_hash[:8])
            return InspectionResult(
                verdict=Verdict.BLOCKED,
                original_spl=raw_spl,
                final_spl=raw_spl,
                reasons=[reason],
                svc_risk="high",
                query_hash=query_hash,
            )

    # ── Step 2: Scan for dangerous (but fixable) patterns ─────────────────────
    for pattern, reason, risk in DANGEROUS_PATTERNS:
        if re.search(pattern, raw_spl, re.IGNORECASE):
            reasons.append(reason)
            if risk == "high":
                svc_risk = "high"
            elif risk == "medium" and svc_risk != "high":
                svc_risk = "medium"

    # ── Step 3: Check structural gaps even if no explicit bad pattern ──────────
    if _missing_index(raw_spl):
        reasons.append("No explicit index specified")
        if svc_risk == "low":
            svc_risk = "medium"

    if _missing_time_bound(raw_spl):
        reasons.append("No time bounds specified")
        if svc_risk == "low":
            svc_risk = "medium"

    # ── Step 4: If clean, return safe ─────────────────────────────────────────
    if not reasons:
        logger.debug("SAFE query | hash=%s", query_hash[:8])
        return InspectionResult(
            verdict=Verdict.SAFE,
            original_spl=raw_spl,
            final_spl=raw_spl,
            reasons=[],
            svc_risk="low",
            query_hash=query_hash,
        )

    # ── Step 5: Rewrite ───────────────────────────────────────────────────────
    rewritten = raw_spl
    rewritten = _replace_wildcard_index(rewritten)
    rewritten = _cap_time_range(rewritten)
    rewritten = _inject_index(rewritten)
    rewritten = _inject_time_bounds(rewritten)

    logger.info(
        "REWRITTEN query | reasons=%s | risk=%s | hash=%s",
        reasons, svc_risk, query_hash[:8],
    )

    return InspectionResult(
        verdict=Verdict.REWRITTEN,
        original_spl=raw_spl,
        final_spl=rewritten,
        reasons=reasons,
        svc_risk=svc_risk,
        query_hash=query_hash,
    )