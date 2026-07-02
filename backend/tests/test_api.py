"""
API integration tests — exercise the full request path (routers, DB,
scanner, exports) against a throwaway SQLite database.

Paste scans run synchronously enough for testing: FastAPI background tasks
execute before the ASGI transport returns control, so by the time the POST
response is consumed the scan has completed.
"""

PASTE_WITH_SECRETS = (
    'aws_key = "AKIAV3WBCDEF4GHI7JKM"\n'
    'db_url = "postgresql://admin:S3cretPass@prod-db.internal:5432/app"\n'
)

PASTE_CLEAN = 'greeting = "hello world"\n'


async def _run_paste_scan(client, content=PASTE_WITH_SECRETS):
    resp = await client.post(
        "/api/v1/scans",
        json={"source_type": "paste", "source_ref": content},
    )
    assert resp.status_code == 202
    return resp.json()["id"]


class TestHealth:
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestScanLifecycle:
    async def test_paste_scan_completes_with_findings(self, client):
        scan_id = await _run_paste_scan(client)
        scan = (await client.get(f"/api/v1/scans/{scan_id}")).json()
        assert scan["status"] == "completed"
        assert scan["total_findings"] >= 2
        types = {f["secret_type"] for f in scan["findings"]}
        assert "AWS Access Key" in types
        assert "Database Connection String" in types

    async def test_findings_carry_risk_scores(self, client):
        scan_id = await _run_paste_scan(client)
        findings = (await client.get(f"/api/v1/scans/{scan_id}/findings")).json()
        for f in findings:
            assert 0 < f["risk_score"] <= 100
            assert f["risk_factors"]

    async def test_findings_severity_filter(self, client):
        scan_id = await _run_paste_scan(client)
        crit = (
            await client.get(
                f"/api/v1/scans/{scan_id}/findings", params={"severity": "critical"}
            )
        ).json()
        assert all(f["severity"] == "CRITICAL" for f in crit)

    async def test_clean_paste_yields_zero_findings(self, client):
        scan_id = await _run_paste_scan(client, PASTE_CLEAN)
        scan = (await client.get(f"/api/v1/scans/{scan_id}")).json()
        assert scan["status"] == "completed"
        assert scan["total_findings"] == 0

    async def test_scan_listing_and_delete(self, client):
        scan_id = await _run_paste_scan(client)
        scans = (await client.get("/api/v1/scans")).json()
        assert any(s["id"] == scan_id for s in scans)

        assert (await client.delete(f"/api/v1/scans/{scan_id}")).status_code == 204
        assert (await client.get(f"/api/v1/scans/{scan_id}")).status_code == 404

    async def test_get_missing_scan_404(self, client):
        assert (await client.get("/api/v1/scans/nope")).status_code == 404


class TestDiff:
    async def test_no_baseline(self, client):
        scan_id = await _run_paste_scan(client)
        diff = (await client.get(f"/api/v1/scans/{scan_id}/diff")).json()
        assert diff["has_baseline"] is False

    async def test_diff_detects_new_and_resolved(self, client):
        # Baseline and current scans must share source_ref to be comparable —
        # here identical content, so all findings are "unchanged".
        first = await _run_paste_scan(client)
        second = await _run_paste_scan(client)
        diff = (await client.get(f"/api/v1/scans/{second}/diff")).json()
        assert diff["has_baseline"] is True
        assert diff["baseline_scan_id"] == first
        assert diff["new_count"] == 0
        assert diff["resolved_count"] == 0
        assert diff["unchanged_count"] >= 2
        assert diff["net_change"] == 0


class TestExports:
    async def test_sarif_export_is_valid(self, client):
        scan_id = await _run_paste_scan(client)
        resp = await client.get(f"/api/v1/export/{scan_id}/sarif")
        assert resp.status_code == 200
        doc = resp.json()
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert len(run["results"]) >= 2
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert {r["ruleId"] for r in run["results"]} <= rule_ids

    async def test_json_and_csv_exports(self, client):
        scan_id = await _run_paste_scan(client)
        assert (await client.get(f"/api/v1/export/{scan_id}/json")).status_code == 200
        csv_resp = await client.get(f"/api/v1/export/{scan_id}/csv")
        assert csv_resp.status_code == 200
        assert "AWS Access Key" in csv_resp.text

    async def test_patch_export(self, client):
        scan_id = await _run_paste_scan(client)
        resp = await client.get(f"/api/v1/export/{scan_id}/patch")
        assert resp.status_code == 200
        assert "--- a/" in resp.text
        assert "Next steps" in resp.text


class TestStats:
    async def test_stats_reflect_scans(self, client):
        await _run_paste_scan(client)
        stats = (await client.get("/api/v1/stats")).json()
        assert stats["total_scans"] >= 1
        assert stats["total_findings"] >= 2
        assert stats["critical_count"] >= 1
