"""
memory/query_cache.py
─────────────────────
SQLite-backed cache of approved SPL rewrites.

Key:   sha256(raw_spl)
Value: approved final_spl + metadata

When the proxy sees a query hash it has approved before,
it skips the regex inspection and forwards the cached version directly.
This is the learning layer — gets smarter every session.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("splguard.memory")

DB_PATH = os.getenv("MEMORY_DB_PATH", "./memory/query_cache.db")


def _get_conn() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create table if not exists. Called at proxy startup."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS query_cache (
                hash        TEXT PRIMARY KEY,
                raw_spl     TEXT NOT NULL,
                final_spl   TEXT NOT NULL,
                reasons     TEXT NOT NULL,   -- JSON list
                svc_risk    TEXT NOT NULL,
                hit_count   INTEGER DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS intercept_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT NOT NULL,
                hash        TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                svc_risk    TEXT NOT NULL,
                from_cache  INTEGER NOT NULL DEFAULT 0
            )
        """)
    logger.info("Query memory DB initialised at %s", DB_PATH)


def lookup(query_hash: str) -> dict | None:
    """Return cached approved rewrite or None."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM query_cache WHERE hash = ?", (query_hash,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE query_cache SET hit_count = hit_count + 1, last_seen = ? WHERE hash = ?",
                (datetime.now(timezone.utc).isoformat(), query_hash),
            )
            return dict(row)
    return None


def store(hash_: str, raw_spl: str, final_spl: str, reasons: list[str], svc_risk: str) -> None:
    """Persist an approved rewrite."""
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO query_cache (hash, raw_spl, final_spl, reasons, svc_risk, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hash) DO UPDATE SET
                hit_count  = hit_count + 1,
                last_seen  = excluded.last_seen
            """,
            (hash_, raw_spl, final_spl, json.dumps(reasons), svc_risk, now, now),
        )
    logger.debug("Stored rewrite in memory | hash=%s", hash_[:8])


def log_intercept(hash_: str, verdict: str, svc_risk: str, from_cache: bool = False) -> None:
    """Append one row to the intercept log — feeds the Streamlit dashboard."""
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO intercept_log (ts, hash, verdict, svc_risk, from_cache) VALUES (?,?,?,?,?)",
            (now, hash_, verdict, svc_risk, int(from_cache)),
        )


def get_stats() -> dict:
    """Summary stats for the FinOps dashboard."""
    with _get_conn() as conn:
        total       = conn.execute("SELECT COUNT(*) FROM intercept_log").fetchone()[0]
        rewritten   = conn.execute("SELECT COUNT(*) FROM intercept_log WHERE verdict='rewritten'").fetchone()[0]
        blocked     = conn.execute("SELECT COUNT(*) FROM intercept_log WHERE verdict='blocked'").fetchone()[0]
        safe        = conn.execute("SELECT COUNT(*) FROM intercept_log WHERE verdict='safe'").fetchone()[0]
        cache_hits  = conn.execute("SELECT COUNT(*) FROM intercept_log WHERE from_cache=1").fetchone()[0]
        high_risk   = conn.execute("SELECT COUNT(*) FROM intercept_log WHERE svc_risk='high'").fetchone()[0]

    return {
        "total":      total,
        "safe":       safe,
        "rewritten":  rewritten,
        "blocked":    blocked,
        "cache_hits": cache_hits,
        "high_risk_prevented": high_risk,
    }
