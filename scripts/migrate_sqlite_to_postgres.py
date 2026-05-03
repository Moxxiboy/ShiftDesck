#!/usr/bin/env python3
"""Copy the bundled SQLite database into PostgreSQL.

Usage on Render shell or locally with DATABASE_URL set:
    python scripts/migrate_sqlite_to_postgres.py --reset

--reset truncates the PostgreSQL tables first. Use it for the first production import.
"""
import argparse
import os
import sqlite3
from pathlib import Path

import psycopg2
import psycopg2.extras

TABLES = [
    "departments",
    "employees",
    "users",
    "shift_templates",
    "schedule",
    "employee_logs",
    "tickets",
    "salary_corrections",
    "bonuses",
    "user_permissions",
    "payroll_items",
    "payroll_runs",
    "schedule_month_locks",
    "feedback_reports",
    "payroll_reports",
    "notifications",
    "push_subscriptions",
]

ID_TABLES = [
    "departments",
    "employees",
    "users",
    "shift_templates",
    "schedule",
    "employee_logs",
    "tickets",
    "salary_corrections",
    "bonuses",
    "payroll_items",
    "payroll_runs",
    "schedule_month_locks",
    "feedback_reports",
    "payroll_reports",
    "notifications",
    "push_subscriptions",
]


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sqlite_columns(src, table):
    return [row[1] for row in src.execute(f"PRAGMA table_info({table})").fetchall()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite", default=str(Path(__file__).resolve().parents[1] / "instance" / "app.db"))
    parser.add_argument("--reset", action="store_true", help="TRUNCATE PostgreSQL tables before import")
    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is not set")

    sqlite_path = Path(args.sqlite)
    if not sqlite_path.exists():
        raise SystemExit(f"SQLite database not found: {sqlite_path}")

    # Import app after DATABASE_URL is set so init_db creates/migrates PostgreSQL schema.
    import app  # noqa: F401

    src = sqlite3.connect(sqlite_path)
    src.row_factory = sqlite3.Row
    pg = psycopg2.connect(database_url, cursor_factory=psycopg2.extras.RealDictCursor)
    pg.autocommit = False

    try:
        with pg.cursor() as cur:
            if args.reset:
                cur.execute("TRUNCATE " + ", ".join(quote_ident(t) for t in reversed(TABLES)) + " RESTART IDENTITY CASCADE")

            total = 0
            for table in TABLES:
                cols = sqlite_columns(src, table)
                rows = src.execute(f"SELECT * FROM {table}").fetchall()
                if not rows:
                    print(f"{table}: 0")
                    continue

                col_sql = ", ".join(quote_ident(c) for c in cols)
                placeholders = ", ".join(["%s"] * len(cols))
                sql = f"INSERT INTO {quote_ident(table)} ({col_sql}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                cur.executemany(sql, [tuple(row[c] for c in cols) for row in rows])
                total += len(rows)
                print(f"{table}: {len(rows)}")

            for table in ID_TABLES:
                cur.execute(
                    "SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE((SELECT MAX(id) FROM " + quote_ident(table) + "), 1), true)",
                    (table,),
                )

        pg.commit()
        print(f"Imported {total} rows into PostgreSQL.")
    except Exception:
        pg.rollback()
        raise
    finally:
        src.close()
        pg.close()


if __name__ == "__main__":
    main()
