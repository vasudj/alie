#!/usr/bin/env python3
"""Create and initialize the SQLite DB using the schema.sql so you can open it in DB Browser."""
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "db" / "schema.sql"
DB_DIR = Path("data")
DB_PATH = DB_DIR / "zombie_gateway.sqlite3"

DB_DIR.mkdir(parents=True, exist_ok=True)

if not SCHEMA.exists():
    raise SystemExit(f"Schema file not found: {SCHEMA}")

conn = sqlite3.connect(str(DB_PATH))
with SCHEMA.open("r", encoding="utf-8") as f:
    sql = f.read()
    conn.executescript(sql)
conn.commit()
conn.close()
print(f"Initialized SQLite DB at: {DB_PATH.resolve()}")
