"""
tests/test_spl_inspector.py
───────────────────────────
Run with:  python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from spl.inspector import inspect, Verdict


# ── Should be SAFE ────────────────────────────────────────────────────────────
class TestSafe:
    def test_clean_query(self):
        r = inspect("search index=main error earliest=-10m latest=now")
        assert r.verdict == Verdict.SAFE

    def test_specific_index_and_time(self):
        r = inspect("index=web_logs status=500 earliest=-5m latest=now | stats count by host")
        assert r.verdict == Verdict.SAFE


# ── Should be REWRITTEN ───────────────────────────────────────────────────────
class TestRewritten:
    def test_wildcard_index(self):
        r = inspect("search index=* error")
        assert r.verdict == Verdict.REWRITTEN
        assert "index=*" not in r.final_spl
        assert "index=main" in r.final_spl

    def test_missing_index(self):
        r = inspect("search error earliest=-5m latest=now")
        assert r.verdict == Verdict.REWRITTEN
        assert "index=" in r.final_spl

    def test_missing_time_bounds(self):
        r = inspect("search index=main error")
        assert r.verdict == Verdict.REWRITTEN
        assert "earliest=" in r.final_spl
        assert "latest=" in r.final_spl

    def test_alltime_keyword(self):
        r = inspect("search index=main error alltime")
        assert r.verdict == Verdict.REWRITTEN
        assert "alltime" not in r.final_spl

    def test_30_day_range(self):
        r = inspect("search index=main error earliest=-30d")
        assert r.verdict == Verdict.REWRITTEN
        assert "-30d" not in r.final_spl

    def test_1_year_range(self):
        r = inspect("search index=security earliest=-1y")
        assert r.verdict == Verdict.REWRITTEN

    def test_missing_everything(self):
        """The absolute worst agent query."""
        r = inspect("search index=* earliest=-30d error")
        assert r.verdict == Verdict.REWRITTEN
        assert r.svc_risk == "high"
        assert "index=*" not in r.final_spl


# ── Should be BLOCKED ─────────────────────────────────────────────────────────
class TestBlocked:
    def test_delete_command(self):
        r = inspect("search index=main | delete")
        assert r.verdict == Verdict.BLOCKED

    def test_rest_command(self):
        r = inspect("search index=main | rest /services/admin/users")
        assert r.verdict == Verdict.BLOCKED

    def test_subsearch_injection(self):
        """CVE-2025-20381 pattern."""
        r = inspect("search index=main [ search index=_internal admin ]")
        assert r.verdict == Verdict.BLOCKED

    def test_blocked_takes_priority_over_rewrite(self):
        """Even if query also has bad time range, blocked wins."""
        r = inspect("search index=* earliest=-30d | delete")
        assert r.verdict == Verdict.BLOCKED


# ── SVC risk levels ───────────────────────────────────────────────────────────
class TestRiskLevel:
    def test_high_risk_wildcard(self):
        r = inspect("search index=* error")
        assert r.svc_risk == "high"

    def test_medium_risk_missing_index(self):
        r = inspect("search error earliest=-5m latest=now")
        assert r.svc_risk in ("medium", "high")

    def test_low_risk_clean(self):
        r = inspect("search index=main error earliest=-5m latest=now")
        assert r.svc_risk == "low"


# ── Hash stability ────────────────────────────────────────────────────────────
class TestHashing:
    def test_same_query_same_hash(self):
        r1 = inspect("search index=main error earliest=-5m latest=now")
        r2 = inspect("search index=main error earliest=-5m latest=now")
        assert r1.query_hash == r2.query_hash

    def test_different_queries_different_hash(self):
        r1 = inspect("search index=main error")
        r2 = inspect("search index=main warning")
        assert r1.query_hash != r2.query_hash


# ── Federated Search patterns (Splunk 10.4) ───────────────────────────────────
class TestFederatedSearch:
    def test_federated_wildcard_blocked(self):
        r = inspect("search index=fed:* earliest=-7d error")
        assert r.verdict == Verdict.REWRITTEN
        assert r.svc_risk == "high"
        assert any("federated" in reason.lower() or "Federated" in reason for reason in r.reasons)

    def test_federated_wide_time_range(self):
        r = inspect("search index=fed:s3_logs earliest=-30d error")
        assert r.verdict == Verdict.REWRITTEN
        assert r.svc_risk == "high"

    def test_federated_dataset_wide_range(self):
        r = inspect("search dataset=snowflake_prod earliest=-1y status=500")
        assert r.verdict == Verdict.REWRITTEN
        assert r.svc_risk == "high"

    def test_federated_delete_blocked(self):
        r = inspect("search index=fed:s3_archive | delete")
        assert r.verdict == Verdict.BLOCKED

    def test_spl2_federated_wide_range(self):
        r = inspect("from index:fed_logs where earliest=-30d AND status=404")
        assert r.verdict == Verdict.REWRITTEN
        assert r.svc_risk == "high"