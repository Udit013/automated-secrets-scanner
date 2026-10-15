"""Access control, abuse limits, and the additive schema upgrade."""

import pytest
from sqlalchemy import create_engine, inspect, text

from app import security
from app.config import settings
from app.database import AsyncSessionLocal, _apply_additive_upgrades
from app.models import Scan

PASTE = {"source_type": "paste", "source_ref": 'x = "nothing to see"'}


@pytest.fixture()
def private_mode(monkeypatch):
    monkeypatch.setattr(settings, "ACCESS_TOKEN", "t0ken-" + "x" * 32)
    return settings.ACCESS_TOKEN


class TestAccessToken:
    async def test_demo_mode_is_open(self, client):
        assert (await client.get("/api/v1/scans")).status_code == 200
        assert (await client.get("/health")).json()["auth_required"] is False

    async def test_private_mode_rejects_missing_or_wrong_token(self, client, private_mode):
        assert (await client.get("/api/v1/scans")).status_code == 401
        bad = {"Authorization": "Bearer wrong"}
        assert (await client.get("/api/v1/scans", headers=bad)).status_code == 401
        assert (await client.post("/api/v1/scans", json=PASTE, headers=bad)).status_code == 401

    async def test_private_mode_accepts_token_on_every_router(self, client, private_mode):
        auth = {"Authorization": f"Bearer {private_mode}"}
        for path in ("/api/v1/scans", "/api/v1/stats", "/api/v1/projects", "/api/v1/schedules"):
            assert (await client.get(path, headers=auth)).status_code == 200, path
        assert (await client.post("/api/v1/scans", json=PASTE, headers=auth)).status_code == 202

    async def test_health_stays_public_and_reports_mode(self, client, private_mode):
        body = (await client.get("/health")).json()
        assert body["auth_required"] is True and body["status"] == "ok"


class TestClientIp:
    class _Conn:
        def __init__(self, xff, peer="10.0.0.9"):
            self.headers = {"x-forwarded-for": xff} if xff else {}
            self.client = type("C", (), {"host": peer})()

    def test_ignores_forwarded_header_without_trusted_proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 0)
        assert security.client_ip(self._Conn("1.2.3.4")) == "10.0.0.9"

    def test_spoofed_prefix_is_ignored_behind_one_proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)
        # The client sent "6.6.6.6"; the proxy appended the real address.
        assert security.client_ip(self._Conn("6.6.6.6, 203.0.113.7")) == "203.0.113.7"


class TestLimits:
    def test_sliding_window_frees_slots_over_time(self):
        limiter = security.SlidingWindowLimiter(limit=2, window_seconds=60)
        assert limiter.check("a", now=0) == 0 and limiter.check("a", now=1) == 0
        assert limiter.check("a", now=2) > 0          # third within the window
        assert limiter.check("b", now=2) == 0         # other clients unaffected
        assert limiter.check("a", now=61) == 0        # first hit aged out

    async def test_scan_creation_is_rate_limited(self, client, monkeypatch):
        monkeypatch.setattr(security.scan_limiter, "limit", 2)
        for _ in range(2):
            assert (await client.post("/api/v1/scans", json=PASTE)).status_code == 202
        resp = await client.post("/api/v1/scans", json=PASTE)
        assert resp.status_code == 429 and int(resp.headers["Retry-After"]) > 0

    async def test_concurrent_scans_are_capped(self, client, monkeypatch):
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 2)
        async with AsyncSessionLocal() as db:
            for _ in range(2):
                db.add(Scan(source_type="github", source_ref="https://github.com/a/b", status="running"))
            await db.commit()
        resp = await client.post("/api/v1/scans", json=PASTE)
        assert resp.status_code == 429

    async def test_schedule_count_is_capped(self, client, monkeypatch):
        monkeypatch.setattr(settings, "MAX_SCHEDULES", 1)
        body = {"name": "n", "source_type": "github", "source_ref": "https://github.com/a/b",
                "cron_expression": "0 3 * * *"}
        assert (await client.post("/api/v1/schedules", json=body)).status_code == 201
        assert (await client.post("/api/v1/schedules", json=body)).status_code == 409


class TestAdditiveUpgrade:
    def test_adds_missing_column_idempotently(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
        with engine.begin() as conn:  # a findings table from before fingerprints
            conn.execute(text("CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, source_ref TEXT)"))
            conn.execute(text("CREATE TABLE findings (id VARCHAR(36) PRIMARY KEY, scan_id VARCHAR(36))"))
            conn.execute(text("INSERT INTO findings (id, scan_id) VALUES ('f1', 's1')"))
        with engine.begin() as conn:
            assert _apply_additive_upgrades(conn) == ["findings.fingerprint"]
        with engine.begin() as conn:
            assert _apply_additive_upgrades(conn) == []  # second run is a no-op
            cols = {c["name"] for c in inspect(conn).get_columns("findings")}
            assert "fingerprint" in cols
            assert conn.execute(text("SELECT id FROM findings")).scalar_one() == "f1"  # data kept

    def test_skips_index_when_legacy_rows_are_too_long(self, tmp_path):
        engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
        with engine.begin() as conn:  # a pre-2.1 paste scan stored the whole paste
            conn.execute(text("CREATE TABLE scans (id VARCHAR(36) PRIMARY KEY, source_ref TEXT)"))
            conn.execute(text("INSERT INTO scans VALUES ('s1', :ref)"), {"ref": "x = 1\n" * 2000})
        with engine.begin() as conn:
            _apply_additive_upgrades(conn)
            indexes = {i["name"] for i in inspect(conn).get_indexes("scans")}
            assert "ix_scans_source_ref" not in indexes
            assert len(conn.execute(text("SELECT source_ref FROM scans")).scalar_one()) == 12000  # untouched


class TestWebSocketAuth:
    """
    The progress socket is behind the same token, carried in the subprotocol
    header. The handshake is driven through the ASGI interface on the test's
    own event loop: Starlette's TestClient runs the app on a second loop,
    which the asyncpg pool used for the Postgres run refuses to share.
    """

    async def _handshake(self, protocols=None) -> dict:
        from app.main import app
        headers = [(b"host", b"test")]
        if protocols:
            headers.append((b"sec-websocket-protocol", ", ".join(protocols).encode()))
        scope = {
            "type": "websocket", "asgi": {"version": "3.0"}, "scheme": "ws", "http_version": "1.1",
            "path": "/api/v1/scans/ws/some-scan", "raw_path": b"/api/v1/scans/ws/some-scan",
            "query_string": b"", "root_path": "", "headers": headers,
            "client": ("127.0.0.1", 5000), "server": ("test", 80),
            "subprotocols": list(protocols or []),
        }
        inbox = [{"type": "websocket.connect"}]
        sent: list[dict] = []

        async def receive():
            if inbox:
                return inbox.pop(0)
            return {"type": "websocket.disconnect", "code": 1000}   # client leaves after the handshake

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        return sent[0]

    async def test_open_in_demo_mode(self, client):
        reply = await self._handshake()
        assert reply["type"] == "websocket.accept" and reply.get("subprotocol") is None

    async def test_rejected_without_token(self, client, private_mode):
        for protocols in (None, ["cipherwatch.v1"], ["cipherwatch.v1", "bearer.wrong"]):
            reply = await self._handshake(protocols)
            assert (reply["type"], reply.get("status")) == ("websocket.http.response.start", 401), protocols

    async def test_accepted_with_token(self, client, private_mode):
        reply = await self._handshake(["cipherwatch.v1", f"bearer.{private_mode}"])
        assert reply["type"] == "websocket.accept" and reply["subprotocol"] == "cipherwatch.v1"


class TestDemoSeeding:
    """The seeder must never mix sample projects into a real workspace."""

    async def test_seeds_an_empty_public_database(self, client):
        import seed_demo
        await seed_demo.seed()
        assert (await client.get("/health")).json()["demo"] is True

    async def test_never_seeds_a_database_with_any_scan(self, client):
        import seed_demo
        await client.post("/api/v1/scans", json=PASTE)
        await seed_demo.seed()
        assert len((await client.get("/api/v1/scans")).json()) == 1
        assert (await client.get("/health")).json()["demo"] is False

    async def test_never_seeds_a_private_workspace(self, client, private_mode):
        import seed_demo
        await seed_demo.seed()
        assert (await client.get("/api/v1/scans", headers={"Authorization": f"Bearer {private_mode}"})).json() == []
