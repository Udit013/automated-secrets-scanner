"""
Regression tests for the hardening pass: secret retention, startup
reconciliation, schedule validation, archive limits, and alert escaping.
"""

import io
import zipfile

import pytest

from app.database import AsyncSessionLocal
from app.models import Scan
from app.routers import scans as scans_router
from app.scanner import github_scanner
from app.scanner.core import scan_text
from app.scanner.patterns import is_placeholder
from app.workers import scheduler

# Fake credentials, assembled at runtime so this file never contains a
# literal in a real provider's format (repository push protection, and
# this scanner itself, would rightly flag one).
AWS = "AKIAV3WBCDEF4GHI7JKM"
STRIPE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0kLmN"
GITHUB_TOKEN = "ghp" + "_16C7e42F292c6912E7710c838347Ae178B4b"
STRIPE_TEST = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
PASTE = f'aws_key = "{AWS}"; stripe = "{STRIPE}"\n'


async def _paste_scan(client, content=PASTE) -> dict:
    resp = await client.post("/api/v1/scans", json={"source_type": "paste", "source_ref": content})
    assert resp.status_code == 202
    return resp.json()


class TestNoRawSecretRetention:
    def test_context_masks_every_secret_on_the_line(self):
        findings = scan_text(PASTE, "config.py")
        assert {f.secret_type for f in findings} >= {"AWS Access Key", "Stripe Live Secret Key"}
        for f in findings:
            assert AWS not in f.context and STRIPE not in f.context
            assert "aws_key" in f.context  # still useful for locating the line

    async def test_raw_secrets_absent_from_every_output(self, client):
        scan = await _paste_scan(client)
        sid = scan["id"]
        outputs = [
            (await client.get("/api/v1/scans")).text,
            (await client.get(f"/api/v1/scans/{sid}")).text,
            (await client.get(f"/api/v1/scans/{sid}/findings")).text,
        ] + [
            (await client.get(f"/api/v1/export/{sid}/{fmt}")).text
            for fmt in ("json", "csv", "sarif", "remediation", "patch")
        ]
        for body in outputs:
            assert AWS not in body and STRIPE not in body

    async def test_paste_content_is_replaced_by_a_stable_digest(self, client):
        first = await _paste_scan(client)
        second = await _paste_scan(client)
        other = await _paste_scan(client, f'token = "{GITHUB_TOKEN}"\n')
        assert first["source_ref"].startswith("paste:")
        assert first["source_ref"] == second["source_ref"]  # same content → diffable
        assert first["source_ref"] != other["source_ref"]
        scan = (await client.get(f"/api/v1/scans/{first['id']}")).json()
        assert scan["status"] == "completed" and scan["total_findings"] >= 2


class TestStartupReconciliation:
    async def test_interrupted_scans_are_failed(self, client):
        async with AsyncSessionLocal() as db:
            for status in ("queued", "running", "completed"):
                db.add(Scan(source_type="github", source_ref="https://github.com/a/b", status=status))
            await db.commit()

        assert await scans_router.mark_interrupted_scans() == 2
        statuses = sorted(s["status"] for s in (await client.get("/api/v1/scans")).json())
        assert statuses == ["completed", "failed", "failed"]

    async def test_schedules_survive_restart(self, client):
        body = {
            "source_type": "github",
            "source_ref": "https://github.com/owner/repo",
            "cron_expression": "0 3 * * *",
        }
        active = (await client.post("/api/v1/schedules", json={**body, "name": "a"})).json()
        paused = (await client.post("/api/v1/schedules", json={**body, "name": "p"})).json()
        await client.patch(f"/api/v1/schedules/{paused['id']}/toggle")

        scheduler.start_scheduler()
        try:
            scheduler._scheduler.remove_all_jobs()  # simulate the restart
            assert await scheduler.restore_schedules() == 2
            assert scheduler._scheduler.get_job(active["id"]).next_run_time is not None
            assert scheduler._scheduler.get_job(paused["id"]).next_run_time is None
        finally:
            scheduler._scheduler.remove_all_jobs()
            scheduler.stop_scheduler()


class TestScheduleValidation:
    @pytest.mark.parametrize("cron", ["99 * * * *", "* 25 * * *", "0 0 * * banana"])
    async def test_invalid_cron_values_are_422_not_500(self, client, cron):
        resp = await client.post("/api/v1/schedules", json={
            "name": "x", "source_type": "github",
            "source_ref": "https://github.com/owner/repo", "cron_expression": cron,
        })
        assert resp.status_code == 422

    @pytest.mark.parametrize("cron,ok", [
        ("* * * * *", False), ("*/5 * * * *", False),
        ("*/15 * * * *", True), ("0 * * * *", True), ("0 */6 * * *", True),
    ])
    async def test_minimum_interval(self, client, cron, ok):
        resp = await client.post("/api/v1/schedules", json={
            "name": "x", "source_type": "github",
            "source_ref": "https://github.com/owner/repo", "cron_expression": cron,
        })
        assert (resp.status_code == 201) is ok

    async def test_paste_schedules_rejected(self, client):
        resp = await client.post("/api/v1/schedules", json={
            "name": "x", "source_type": "paste",
            "source_ref": "x = 1", "cron_expression": "0 3 * * *",
        })
        assert resp.status_code == 422


class TestArchiveLimits:
    @staticmethod
    def _zip(files: dict[str, bytes]) -> zipfile.ZipFile:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in files.items():
                zf.writestr(name, data)
        buf.seek(0)
        return zipfile.ZipFile(buf)

    def test_rejects_oversized_uncompressed_content(self, tmp_path, monkeypatch):
        monkeypatch.setattr(github_scanner, "MAX_EXTRACTED_BYTES", 1000)
        zf = self._zip({"repo/a.txt": b"0" * 2000})  # compresses tiny, inflates past the cap
        with pytest.raises(ValueError, match="uncompressed"):
            github_scanner._safe_extract(zf, str(tmp_path))
        assert not any(tmp_path.iterdir())  # nothing partially extracted

    def test_rejects_too_many_members(self, tmp_path, monkeypatch):
        monkeypatch.setattr(github_scanner, "MAX_ARCHIVE_MEMBERS", 3)
        zf = self._zip({f"repo/{i}.txt": b"x" for i in range(4)})
        with pytest.raises(ValueError, match="more than"):
            github_scanner._safe_extract(zf, str(tmp_path))

    def test_normal_archive_extracts(self, tmp_path):
        zf = self._zip({"repo/src/app.py": b"print(1)"})
        github_scanner._safe_extract(zf, str(tmp_path))
        assert (tmp_path / "repo" / "src" / "app.py").read_text() == "print(1)"


class TestPlaceholderBoundaries:
    def test_vendor_doc_example_key_is_suppressed(self):
        assert is_placeholder("AKIAIOSFODNN7EXAMPLE")
        assert scan_text('key = "AKIAIOSFODNN7EXAMPLE"', "config.py") == []

    def test_real_keys_are_not_suppressed(self):
        assert not is_placeholder(AWS)
        assert not is_placeholder(STRIPE_TEST)


class TestAlertEmail:
    async def test_source_is_escaped(self, monkeypatch):
        from app import notifications

        for field, value in {"SMTP_USER": "u", "SMTP_PASSWORD": "p", "ALERT_EMAIL": "a@b.c"}.items():
            monkeypatch.setattr(notifications.settings, field, value)
        sent = []

        async def fake_send(msg, **_):
            sent.append(msg.get_payload()[0].get_payload(decode=True).decode())

        monkeypatch.setattr(notifications.aiosmtplib, "send", fake_send)
        await notifications.send_critical_alert("id1", 1, '<a href="https://evil.test">click</a>')

        assert '<a href="https://evil.test">' not in sent[0]
        assert "&lt;a href=&quot;https://evil.test&quot;&gt;" in sent[0]
