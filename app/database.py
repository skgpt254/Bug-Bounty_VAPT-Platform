from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(settings.database_url, echo=False, future=True)
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


# Columns added after the initial schema. `create_all` only creates tables
# that don't exist yet — it never ALTERs an existing table — so anyone
# upgrading with a pre-existing bugbounty.db needs these added by hand.
# This is a stand-in for a real migration tool (Alembic) which would be the
# right call once the schema needs anything more than additive columns.
_SQLITE_COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    # (table, column, "ALTER TABLE ... ADD COLUMN ..." fragment after the column name)
    ("scan_runs", "wildcard_dns", "BOOLEAN DEFAULT 0"),
    ("scan_runs", "tool_warnings", "TEXT DEFAULT ''"),
    ("subdomains", "wildcard_suspect", "BOOLEAN DEFAULT 0"),
    ("findings", "confidence", "VARCHAR(20) DEFAULT 'confirmed'"),
]


async def _run_sqlite_migrations() -> None:
    if not settings.database_url.startswith("sqlite"):
        return  # Postgres/MySQL users: manage schema changes yourself (Alembic recommended)

    async with engine.begin() as conn:
        for table, column, ddl in _SQLITE_COLUMN_MIGRATIONS:
            result = await conn.execute(text(f"PRAGMA table_info({table})"))
            existing_cols = {row[1] for row in result.fetchall()}
            if column not in existing_cols:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


async def init_db() -> None:
    # Import models so their tables register on Base.metadata before create_all.
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _run_sqlite_migrations()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
