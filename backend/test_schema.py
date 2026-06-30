#!/usr/bin/env python3

"""
Supabase PostgreSQL Table Exporter
----------------------------------

This script:
1. Connects to your Supabase PostgreSQL database
2. Lists all available tables
3. Exports ALL table data into a single CSV file

Usage:
------
1. Install dependencies:
   pip install psycopg2-binary pandas

2. Replace:
   YOUR_PASSWORD_HERE

3. Run:
   python export_supabase.py
"""

import psycopg2
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime

# =========================================================
# DATABASE URL
# =========================================================

DATABASE_URL = "postgresql://postgres:Postgres@123@db.guztnyfvinkoahvwptkp.supabase.co:5432/postgres"

# =========================================================
# CONNECT TO DATABASE
# =========================================================

try:
    print("[+] Connecting to database...")

    parsed = urlparse(DATABASE_URL)

    conn = psycopg2.connect(
        host=parsed.hostname,
        port=parsed.port,
        user=parsed.username,
        password=parsed.password,
        dbname=parsed.path[1:],
        sslmode="require"
    )

    cursor = conn.cursor()

    print("[+] Connected successfully!")

except Exception as e:
    print(f"[!] Connection failed: {e}")
    exit()

# =========================================================
# FETCH ALL TABLES
# =========================================================

try:
    print("[+] Fetching tables...")

    cursor.execute("""
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_type='BASE TABLE'
        AND table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY table_schema, table_name;
    """)

    tables = cursor.fetchall()

    if not tables:
        print("[!] No tables found.")
        exit()

    print(f"[+] Found {len(tables)} tables:\n")

    for schema, table in tables:
        print(f"   - {schema}.{table}")

except Exception as e:
    print(f"[!] Failed fetching tables: {e}")
    exit()

# =========================================================
# EXPORT DATA
# =========================================================

all_data = []

for schema, table in tables:
    full_table_name = f'"{schema}"."{table}"'

    try:
        print(f"[+] Exporting: {schema}.{table}")

        query = f"SELECT * FROM {full_table_name};"

        df = pd.read_sql_query(query, conn)

        if df.empty:
            print(f"    -> Empty table")
            continue

        # Add metadata columns
        df.insert(0, "__table__", table)
        df.insert(1, "__schema__", schema)

        all_data.append(df)

        print(f"    -> {len(df)} rows exported")

    except Exception as e:
        print(f"    -> Failed: {e}")

# =========================================================
# SAVE SINGLE CSV
# =========================================================

if all_data:
    final_df = pd.concat(all_data, ignore_index=True, sort=False)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"supabase_export_{timestamp}.csv"

    final_df.to_csv(output_file, index=False)

    print("\n[+] Export completed!")
    print(f"[+] File saved as: {output_file}")
    print(f"[+] Total rows: {len(final_df)}")

else:
    print("[!] No data exported.")

# =========================================================
# CLEANUP
# =========================================================

cursor.close()
conn.close()

print("[+] Connection closed.")