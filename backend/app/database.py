import logging
import secrets

from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from .config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    # Pool settings only apply to non-SQLite engines
    **({} if "sqlite" in settings.DATABASE_URL else {"pool_size": 10, "max_overflow": 20}),
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


# Additive changes to tables that predate them. `create_all` creates missing
# tables but never alters existing ones, so a database created by an earlier
# version needs these applied. Each entry is idempotent: it runs only when the
# column is absent, and only ever ADDs a nullable column or an index — nothing
# here can drop or rewrite data. Anything beyond additive changes should move
# to a real migration tool (Alembic).
_ADDITIVE_UPGRADES = [
    # (table, column, column DDL, index DDL or None)
    ("findings", "fingerprint", "VARCHAR(32)",
     "CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings (fingerprint)"),
]
# (table, column, index DDL). Skipped while any value is too long to index:
# databases from before pasted content was replaced by a digest label can
# hold whole pastes in scans.source_ref, and Postgres refuses btree entries
# over ~2.7 KB, which would otherwise stop the server from starting. The
# index only speeds up lookups; nothing depends on it for correctness.
_ADDITIVE_INDEXES = [
    ("scans", "source_ref", "CREATE INDEX IF NOT EXISTS ix_scans_source_ref ON scans (source_ref)"),
]
_MAX_INDEXED_LENGTH = 300


def _apply_additive_upgrades(sync_conn) -> list[str]:
    applied = []
    insp = inspect(sync_conn)
    tables = set(insp.get_table_names())
    for table, column, ddl, index_ddl in _ADDITIVE_UPGRADES:
        if table not in tables:
            continue
        existing = {c["name"] for c in insp.get_columns(table)}
        if column not in existing:
            sync_conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            applied.append(f"{table}.{column}")
        if index_ddl:
            sync_conn.execute(text(index_ddl))
    for table, column, index_ddl in _ADDITIVE_INDEXES:
        if table not in tables:
            continue
        too_long = sync_conn.execute(
            text(f"SELECT 1 FROM {table} WHERE length({column}) > :n LIMIT 1"),
            {"n": _MAX_INDEXED_LENGTH},
        ).first()
        if too_long:
            logger.warning(
                "Not indexing %s.%s: it holds values longer than %d characters "
                "(legacy rows from before pasted content was replaced by a label).",
                table, column, _MAX_INDEXED_LENGTH,
            )
            continue
        sync_conn.execute(text(index_ddl))
    return applied


async def init_db():
    from . import models  # noqa: F401 — register every table on Base.metadata

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        applied = await conn.run_sync(_apply_additive_upgrades)
    if applied:
        logger.warning("Applied additive schema upgrades: %s", ", ".join(applied))
    await _load_fingerprint_key()


async def _load_fingerprint_key() -> None:
    """
    Fingerprints are HMACs, so they need a key that is stable for the life of
    the data. FINGERPRINT_KEY (env) wins — set it in production so the key
    lives outside the database. Otherwise one is generated on first boot and
    stored alongside the data it protects.
    """
    from .models import AppSetting
    from .scanner.core import configure_fingerprint_key

    if settings.FINGERPRINT_KEY:
        configure_fingerprint_key(settings.FINGERPRINT_KEY.encode("utf-8"))
        return
    async with AsyncSessionLocal() as db:
        row = await db.get(AppSetting, "fingerprint_key")
        if row is None:
            db.add(AppSetting(key="fingerprint_key", value=secrets.token_hex(32)))
            try:
                await db.commit()
            except IntegrityError:  # another process created it first
                await db.rollback()
            row = await db.get(AppSetting, "fingerprint_key", populate_existing=True)
        configure_fingerprint_key(bytes.fromhex(row.value))


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
