"""Input-validation guardrails for the public API."""

from app.schemas import MAX_PASTE_BYTES


class TestScanInputValidation:
    async def test_rejects_invalid_source_type(self, client):
        resp = await client.post(
            "/api/v1/scans", json={"source_type": "ftp", "source_ref": "x"}
        )
        assert resp.status_code == 422

    async def test_rejects_empty_source_ref(self, client):
        resp = await client.post(
            "/api/v1/scans", json={"source_type": "paste", "source_ref": "   "}
        )
        assert resp.status_code == 422

    async def test_rejects_non_github_url(self, client):
        for bad in [
            "https://gitlab.com/owner/repo",
            "http://github.com/owner/repo",  # http not allowed
            "https://github.com/owner",  # missing repo
            "not a url",
        ]:
            resp = await client.post(
                "/api/v1/scans", json={"source_type": "github", "source_ref": bad}
            )
            assert resp.status_code == 422, bad

    async def test_accepts_valid_github_url_variants(self, client):
        # Trailing slash and .git suffix should be normalised, not rejected.
        for ok in [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo/",
            "https://github.com/owner/repo.git",
        ]:
            resp = await client.post(
                "/api/v1/scans", json={"source_type": "github", "source_ref": ok}
            )
            assert resp.status_code == 202, ok
            assert resp.json()["source_ref"] == "https://github.com/owner/repo"

    async def test_rejects_oversized_paste(self, client):
        resp = await client.post(
            "/api/v1/scans",
            json={"source_type": "paste", "source_ref": "a" * (MAX_PASTE_BYTES + 1)},
        )
        assert resp.status_code == 422

    async def test_rejects_out_of_range_scan_params(self, client):
        resp = await client.post(
            "/api/v1/scans",
            json={"source_type": "paste", "source_ref": "x = 1", "max_commits": 99999},
        )
        assert resp.status_code == 422

    async def test_pagination_limits_clamped(self, client):
        assert (await client.get("/api/v1/scans", params={"limit": 9999})).status_code == 422
        assert (await client.get("/api/v1/scans", params={"offset": -1})).status_code == 422


class TestScheduleValidation:
    async def test_rejects_malformed_cron(self, client):
        resp = await client.post(
            "/api/v1/schedules",
            json={
                "name": "nightly",
                "source_type": "github",
                "source_ref": "https://github.com/owner/repo",
                "cron_expression": "not-a-cron",
            },
        )
        assert resp.status_code == 422

    async def test_accepts_valid_schedule(self, client):
        resp = await client.post(
            "/api/v1/schedules",
            json={
                "name": "nightly",
                "source_type": "github",
                "source_ref": "https://github.com/owner/repo",
                "cron_expression": "0 3 * * *",
            },
        )
        assert resp.status_code in (200, 201)
