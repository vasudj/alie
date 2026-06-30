"""Low-overhead SQLite access layer for gateway intelligence storage."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Sequence

from core.config import settings

_LOCK = threading.RLock()
_CONNECTION: sqlite3.Connection | None = None


def _resolve_db_path() -> Path:
    db_path = Path(settings.SQLITE_DB_PATH)
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parents[1] / db_path
    return db_path


def _schema_path() -> Path:
    return Path(__file__).with_name("schema.sql")


def _open_connection() -> sqlite3.Connection:
    db_path = _resolve_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        db_path,
        timeout=5.0,
        check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute(f"PRAGMA busy_timeout = {settings.SQLITE_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA temp_store = MEMORY")
    return connection


def get_connection() -> sqlite3.Connection:
    global _CONNECTION
    with _LOCK:
        if _CONNECTION is None:
            _CONNECTION = _open_connection()
        return _CONNECTION


def _as_dicts(rows: Sequence[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _run_script_sync() -> None:
    connection = get_connection()
    schema = _schema_path().read_text(encoding="utf-8")
    with _LOCK:
        connection.executescript(schema)
        connection.commit()


async def init_database() -> None:
    await asyncio.to_thread(_run_script_sync)


def _execute_sync(query: str, params: Sequence[Any] = ()) -> int:
    connection = get_connection()
    with _LOCK:
        cursor = connection.execute(query, params)
        connection.commit()
        return cursor.lastrowid or 0


def _fetchone_sync(query: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
    connection = get_connection()
    with _LOCK:
        cursor = connection.execute(query, params)
        row = cursor.fetchone()
    return dict(row) if row is not None else None


def _fetchall_sync(query: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    connection = get_connection()
    with _LOCK:
        cursor = connection.execute(query, params)
        rows = cursor.fetchall()
    return _as_dicts(rows)


def _executemany_sync(query: str, params: Iterable[Sequence[Any]]) -> None:
    connection = get_connection()
    with _LOCK:
        connection.executemany(query, params)
        connection.commit()


async def execute(query: str, params: Sequence[Any] = ()) -> int:
    return await asyncio.to_thread(_execute_sync, query, params)


async def fetchone(query: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
    return await asyncio.to_thread(_fetchone_sync, query, params)


async def fetchall(query: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    return await asyncio.to_thread(_fetchall_sync, query, params)


async def executemany(query: str, params: Iterable[Sequence[Any]]) -> None:
    await asyncio.to_thread(_executemany_sync, query, params)


async def cleanup() -> None:
    connection = get_connection()
    with _LOCK:
        connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
        connection.commit()
