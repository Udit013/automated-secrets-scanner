"""
Credential ledger: fingerprints, grouping, triage, trend, diff, and alerting.

Scans are written straight to the database from real engine output (no
network), so every fingerprint here is produced by the production code path.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models import CredentialState, Finding as FindingRow, Scan
from app.scanner import core
from app.scanner.core import scan_text
from app.services import inventory

REPO = "https://github.com/acme/api"
# Fake credentials, assembled at runtime so this file never contains a
# literal in a real provider's format.
AWS = "AKIA" + "V3WBCDEF4GHI7JKM"
AWS_2 = "AKIA" + "Q7RTZXWV2MNB8KLP"
STRIPE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0kLmN"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def make_scan(files: dict[str, str], *, history: dict[str, str] | None = None,
                    ref: str = REPO, age_days: float = 0) -> str:
    """Persist a completed scan whose findings come from the real engine."""
    created = _now() - timedelta(days=age_days)
    async with AsyncSessionLocal() as db:
        scan = Scan(source_type="github", source_ref=ref, status="completed",
                    progress=100, created_at=created, completed_at=created)
        db.add(scan)
        await db.flush()
        for paths, in_history in ((files, False), (history or {}, True)):
            for path, content in paths.items():
                for f in scan_text(content, path, is_history=in_history):
                    db.add(FindingRow(
                        scan_id=scan.id, file_path=f.file_path, line_number=f.line_number,
                        secret_type=f.secret_type, matched_string=f.matched_string,
                        entropy=f.entropy, severity=f.severity, confidence=f.confidence,
                        context=f.context, remediation=f.remediation,
                        is_in_history=f.is_in_history, risk_score=f.risk_score,
                        risk_factors=f.risk_factors, fingerprint=f.fingerprint,
                    ))
        await db.commit()
        return scan.id


async def credentials(client, **params) -> list[dict]:
    resp = await client.get("/api/v1/projects/acme/api/credentials", params=params)
    assert resp.status_code == 200
    return resp.json()["credentials"]


class TestFingerprint:
    def test_same_value_in_two_files_is_one_credential(self):
        a = scan_text(f'k = "{AWS}"', "a.py")[0]
        b = scan_text(f'aws: "{AWS}"', "deploy/b.yml")[0]
        assert a.fingerprint == b.fingerprint
        assert a.fingerprint != scan_text(f'k = "{AWS_2}"', "a.py")[0].fingerprint

    def test_marker_patterns_are_scoped_to_location(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----"
        assert scan_text(pem, "keys/a")[0].fingerprint != scan_text(pem, "keys/b")[0].fingerprint

    def test_generic_patterns_never_fingerprint_by_value(self):
        line = 'password = "Xk9#mQ2vLp"'
        assert scan_text(line, "a.py")[0].fingerprint != scan_text(line, "b.py")[0].fingerprint

    def test_fingerprint_depends_on_install_key(self):
        before = scan_text(f'k = "{AWS}"', "a.py")[0].fingerprint
        core.configure_fingerprint_key(b"another-install")
        try:
            assert scan_text(f'k = "{AWS}"', "a.py")[0].fingerprint != before
        finally:
            core.configure_fingerprint_key(core.DEFAULT_FINGERPRINT_KEY)

    def test_raw_value_never_appears_in_fingerprint(self):
        assert AWS not in scan_text(f'k = "{AWS}"', "a.py")[0].fingerprint


class TestLedger:
    async def test_occurrences_collapse_into_credentials(self, client):
        await make_scan(
            {"app/config.py": f'aws = "{AWS}"', "deploy/env.yml": f'key: "{AWS}"'},
            history={"old/settings.py": f'stripe = "{STRIPE}"'},
        )
        creds = await credentials(client)
        by_type = {c["secret_type"]: c for c in creds}
        aws = by_type["AWS Access Key"]
        assert aws["location_count"] == 2 and aws["exposure"] == "working_tree"
        assert by_type["Stripe Live Secret Key"]["exposure"] == "history_only"
        assert all(c["status"] == "open" for c in creds)
        assert aws["rotation_url"].startswith("https://console.aws.amazon.com/")

    async def test_paste_scans_are_not_projects(self, client):
        await client.post("/api/v1/scans", json={"source_type": "paste", "source_ref": f'k = "{AWS}"'})
        assert (await client.get("/api/v1/projects")).json() == []

    async def test_projects_sorted_by_open_critical(self, client):
        await make_scan({"a.py": 'x = 1'}, ref="https://github.com/acme/clean")
        await make_scan({"a.py": f'k = "{AWS}"'})
        slugs = [p["slug"] for p in (await client.get("/api/v1/projects")).json()]
        assert slugs == ["acme/api", "acme/clean"]

    async def test_unknown_project_is_404(self, client):
        assert (await client.get("/api/v1/projects/nobody/nothing")).status_code == 404


class TestTriage:
    async def _aws_fp(self, client) -> str:
        return next(c["fingerprint"] for c in await credentials(client) if c["secret_type"] == "AWS Access Key")

    async def test_triage_persists_across_future_scans(self, client):
        await make_scan({"a.py": f'k = "{AWS}"'}, age_days=2)
        fp = await self._aws_fp(client)
        resp = await client.put(f"/api/v1/projects/acme/api/credentials/{fp}",
                                json={"status": "rotated", "note": "deactivated in IAM"})
        assert resp.status_code == 200 and resp.json()["status"] == "rotated"

        # Next scan finds the same key in a different file: still rotated.
        await make_scan({"moved/b.py": f'k = "{AWS}"'})
        cred = next(c for c in await credentials(client) if c["fingerprint"] == fp)
        assert cred["status"] == "rotated" and cred["note"] == "deactivated in IAM"
        assert cred["locations"][0]["file_path"] == "moved/b.py"

    async def test_triaged_credentials_leave_the_open_count(self, client):
        await make_scan({"a.py": f'k = "{AWS}"\ns = "{STRIPE}"'})
        fp = await self._aws_fp(client)
        await client.put(f"/api/v1/projects/acme/api/credentials/{fp}", json={"status": "false_positive"})
        summary = (await client.get("/api/v1/projects/acme/api")).json()["summary"]
        assert summary["open"] == 1 and summary["false_positive"] == 1
        assert [c["status"] for c in await credentials(client, status="open")] == ["open"]

    @pytest.mark.parametrize("review_by,ok", [
        (None, False),                       # waiver needs an expiry
        (-1, False),                         # in the past
        (400, False),                        # beyond a year
        (30, True),
    ])
    async def test_accepted_risk_requires_bounded_review_date(self, client, review_by, ok):
        await make_scan({"a.py": f'k = "{AWS}"'})
        fp = await self._aws_fp(client)
        body = {"status": "accepted_risk"}
        if review_by is not None:
            body["review_by"] = (_now() + timedelta(days=review_by)).isoformat()
        resp = await client.put(f"/api/v1/projects/acme/api/credentials/{fp}", json=body)
        assert (resp.status_code == 200) is ok

    async def test_expired_waiver_reopens(self, client):
        await make_scan({"a.py": f'k = "{AWS}"'})
        fp = await self._aws_fp(client)
        async with AsyncSessionLocal() as db:
            db.add(CredentialState(source_ref=REPO, fingerprint=fp, status="accepted_risk",
                                   review_by=_now() - timedelta(days=1)))
            await db.commit()
        cred = next(c for c in await credentials(client) if c["fingerprint"] == fp)
        assert cred["status"] == "open" and cred["stored_status"] == "accepted_risk"
        assert cred["review_overdue"] is True

    async def test_rejects_unknown_and_malformed_fingerprints(self, client):
        await make_scan({"a.py": f'k = "{AWS}"'})
        base = "/api/v1/projects/acme/api/credentials"
        assert (await client.put(f"{base}/{'0' * 32}", json={"status": "rotated"})).status_code == 404
        assert (await client.put(f"{base}/not-a-print", json={"status": "rotated"})).status_code == 422
        fp = await self._aws_fp(client)
        assert (await client.put(f"{base}/{fp}", json={"status": "deleted"})).status_code == 422


    async def test_legacy_rows_without_fingerprints_can_be_triaged(self, client):
        scan_id = await make_scan({"a.py": f'k = "{AWS}"'})
        async with AsyncSessionLocal() as db:   # a row written before fingerprints existed
            row = (await db.execute(select(FindingRow).where(FindingRow.scan_id == scan_id))).scalar_one()
            row.fingerprint = None
            await db.commit()
        [cred] = await credentials(client)
        assert cred["fingerprint"].startswith("l")
        resp = await client.put(f"/api/v1/projects/acme/api/credentials/{cred['fingerprint']}",
                                json={"status": "false_positive"})
        assert resp.status_code == 200 and resp.json()["status"] == "false_positive"
        assert (await credentials(client))[0]["status"] == "false_positive"


class TestChangeTracking:
    async def test_trend_counts_new_and_removed(self, client):
        await make_scan({"a.py": f'k = "{AWS}"\ns = "{STRIPE}"'}, age_days=2)
        await make_scan({"a.py": f'k = "{AWS}"\nk2 = "{AWS_2}"'})
        trend = (await client.get("/api/v1/projects/acme/api")).json()["trend"]
        assert [(p["credentials"], p["new"], p["removed"]) for p in trend] == [(2, 2, 0), (2, 1, 1)]

    async def test_diff_ignores_moves_and_counts_credentials(self, client):
        await make_scan({"a.py": f'k = "{AWS}"', "b.py": f'k = "{AWS}"'}, age_days=1)
        latest = await make_scan({"moved/c.py": f'k = "{AWS}"'})
        diff = (await client.get(f"/api/v1/scans/{latest}/diff")).json()
        assert diff["has_baseline"] is True
        assert (diff["new_count"], diff["resolved_count"], diff["unchanged_count"]) == (0, 0, 1)

    async def test_alerts_only_for_new_untriaged_criticals(self, client):
        first = await make_scan({"a.py": f'k = "{AWS}"'}, age_days=2)
        async with AsyncSessionLocal() as db:
            assert len(await inventory.new_open_critical(db, await db.get(Scan, first))) == 1

        repeat = await make_scan({"a.py": f'k = "{AWS}"'}, age_days=1)
        async with AsyncSessionLocal() as db:
            assert await inventory.new_open_critical(db, await db.get(Scan, repeat)) == []

        # A brand-new critical key alerts, unless it was already triaged away.
        fresh = await make_scan({"a.py": f'k = "{AWS}"\nk2 = "{AWS_2}"'})
        async with AsyncSessionLocal() as db:
            new = await inventory.new_open_critical(db, await db.get(Scan, fresh))
            assert len(new) == 1
            db.add(CredentialState(source_ref=REPO, fingerprint=new[0]["fingerprint"], status="rotated"))
            await db.commit()
            assert await inventory.new_open_critical(db, await db.get(Scan, fresh)) == []

    async def test_stats_report_deduplicated_exposure(self, client):
        await make_scan({"a.py": f'k = "{AWS}"', "b.py": f'k = "{AWS}"'})
        stats = (await client.get("/api/v1/stats")).json()
        assert stats["critical_count"] == 2                      # raw findings
        assert stats["exposure"]["open_by_severity"]["CRITICAL"] == 1  # one credential


class TestStablePaths:
    def _tree(self, root, files):
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)

    def test_fingerprints_do_not_depend_on_checkout_location(self, tmp_path):
        files = {"config/app.py": 'password = "Xk9#mQ2vLp"', "keys/id_rsa.pem": "-----BEGIN RSA PRIVATE KEY-----"}
        a, b = tmp_path / "checkout-1", tmp_path / "elsewhere" / "checkout-2"
        self._tree(a, files); self._tree(b, files)
        fa = {(f.file_path, f.fingerprint) for f in core.scan_directory(str(a))[0]}
        fb = {(f.file_path, f.fingerprint) for f in core.scan_directory(str(b))[0]}
        assert fa == fb and {p for p, _ in fa} == {"config/app.py", "keys/id_rsa.pem"}

    def test_symlinks_are_not_followed(self, tmp_path):
        outside = tmp_path / "outside.py"
        outside.write_text(f'k = "{AWS}"')
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "link.py").symlink_to(outside)
        assert core.scan_directory(str(repo)) == ([], 0)

    def test_oversized_files_are_skipped(self, tmp_path):
        (tmp_path / "small.py").write_text(f'k = "{AWS}"')
        (tmp_path / "huge.json").write_text(f'"{AWS_2}"' + " " * (core.MAX_FILE_BYTES + 1))
        findings, files = core.scan_directory(str(tmp_path))
        assert files == 1 and {f.file_path for f in findings} == {"small.py"}

    def test_history_skips_vendored_directories(self, tmp_path):
        import git
        r = git.Repo.init(tmp_path)
        actor = git.Actor("t", "t@example.test")
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "a.js").write_text(f'k = "{AWS}"')
        (tmp_path / "app.py").write_text(f'k = "{AWS_2}"')
        r.index.add(["node_modules/pkg/a.js", "app.py"])
        r.index.commit("c", author=actor, committer=actor)
        findings, _ = core.scan_git_history(str(tmp_path), 10)
        assert {f.file_path for f in findings} == {"app.py"}
