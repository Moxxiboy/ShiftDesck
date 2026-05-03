from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
from functools import wraps
import sqlite3
from pathlib import Path
from io import BytesIO
from datetime import date, datetime, timedelta
import calendar
import random
import json
import os
import re
import hashlib
import hmac
import secrets
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "change-this-secret-key-in-production"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "app.db"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

APP_VERSION = "0.9.21-beta"
APP_BUILD = "2026.05.03-render-ready"

UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "static" / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_UPLOADS = {"png", "jpg", "jpeg", "pdf", "webp"}

VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_CLAIMS = {"sub": os.environ.get("VAPID_SUB", "mailto:admin@example.com")}


# ---------------- PASSWORD HASH WITHOUT SCRYPT ----------------

def generate_password_hash(password):
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()
    return f"pbkdf2_sha256${salt}${hashed}"


def check_password_hash(stored_hash, password):
    try:
        method, salt, hashed = stored_hash.split("$")

        if method != "pbkdf2_sha256":
            return False

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()

        return hmac.compare_digest(hashed, new_hash)

    except Exception:
        return False


# ---------------- DATABASE ----------------

def _pg_translate_sql(sql):
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")

    # psycopg2 uses %s placeholders. Literal % in SQL LIKE patterns must be escaped as %%.
    # Example: LIKE '%schedule%' -> LIKE '%%schedule%%'
    sql = re.sub(r"(?<!%)%(?!s)", "%%", sql)

    # SQLite placeholder compatibility.
    sql = sql.replace("?", "%s")

    # SQLite syntax compatibility.
    if "INSERT INTO" in sql and "ON CONFLICT" not in sql and "DO NOTHING" not in sql:
        # Seed inserts use INSERT OR IGNORE; after translation we add DO NOTHING.
        if "departments" in sql or "shift_templates" in sql:
            sql = sql.rstrip()
            sql += " ON CONFLICT DO NOTHING"

    return sql


class PostgresCursorCompat:
    TABLES_WITH_ID = {
        "departments", "employees", "users", "shift_templates", "schedule",
        "employee_logs", "tickets", "salary_corrections", "bonuses",
        "payroll_items", "payroll_runs", "schedule_month_locks",
        "feedback_reports", "payroll_reports", "notifications", "push_subscriptions",
    }

    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None

    @staticmethod
    def _insert_table_name(sql):
        match = re.match(r"\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql, re.IGNORECASE)
        return match.group(1).lower() if match else None

    def execute(self, sql, params=None):
        params = params or ()
        translated = _pg_translate_sql(sql)
        table_name = self._insert_table_name(translated)

        should_return_id = (
            translated.lstrip().upper().startswith("INSERT INTO")
            and table_name in self.TABLES_WITH_ID
            and " RETURNING " not in translated.upper()
            and "ON CONFLICT DO NOTHING" not in translated.upper()
            and "ON CONFLICT" not in translated.upper()
        )

        if should_return_id:
            translated = translated.rstrip().rstrip(";") + " RETURNING id"

        try:
            self.cursor.execute(translated, params)
        except Exception as e:
            print("POSTGRES SQL ERROR:", e)
            print("SQL:", translated)
            print("PARAMS:", params)
            raise

        if should_return_id:
            try:
                row = self.cursor.fetchone()
                self.lastrowid = row["id"] if row and "id" in row else None
            except Exception:
                self.lastrowid = None

        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def executemany(self, sql, seq_of_params):
        translated = _pg_translate_sql(sql)
        self.cursor.executemany(translated, seq_of_params)
        return self

    def __iter__(self):
        return iter(self.cursor)


class PostgresConnCompat:
    def __init__(self, conn):
        self.conn = conn

    def cursor(self):
        return PostgresCursorCompat(self.conn.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql, seq_of_params):
        cur = self.cursor()
        return cur.executemany(sql, seq_of_params)

    def commit(self):
        return self.conn.commit()

    def rollback(self):
        return self.conn.rollback()

    def close(self):
        return self.conn.close()


def get_db():
    if DATABASE_URL:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return PostgresConnCompat(conn)

    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def is_integrity_error(error):
    # Works both for sqlite3.IntegrityError and psycopg2 unique/foreign-key errors.
    name = error.__class__.__name__.lower()
    text = str(error).lower()
    return (
        isinstance(error, sqlite3.IntegrityError)
        or "integrity" in name
        or "unique" in name
        or "unique constraint" in text
        or "duplicate key" in text
        or "foreign key" in text
    )

def add_column_if_missing(cur, table, column, definition):
    if DATABASE_URL:
        exists = cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = %s AND column_name = %s
        """, (table, column)).fetchone()

        if not exists:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        return

    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except Exception as e:
        msg = str(e).lower()
        if "duplicate column" not in msg and "already exists" not in msg:
            raise


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            department_id INTEGER,
            hourly_rate REAL NOT NULL DEFAULT 8.00,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(department_id) REFERENCES departments(id)
        )
    """)

    add_column_if_missing(cur, "employees", "photo", "TEXT")
    add_column_if_missing(cur, "employees", "overtime_rate", "REAL NOT NULL DEFAULT 12.00")
    add_column_if_missing(cur, "employees", "position", "TEXT NOT NULL DEFAULT 'worker'")
    add_column_if_missing(cur, "employees", "manager_id", "INTEGER")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('manager', 'employee')),
            employee_id INTEGER,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    add_column_if_missing(cur, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "users", "last_seen_build", "TEXT")
    add_column_if_missing(cur, "users", "theme", "TEXT NOT NULL DEFAULT 'dark'")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS shift_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            work_date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    add_column_if_missing(cur, "schedule", "entry_type", "TEXT NOT NULL DEFAULT 'shift'")
    add_column_if_missing(cur, "schedule", "ticket_id", "INTEGER")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS employee_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(employee_id) REFERENCES employees(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            start_date TEXT,
            end_date TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            manager_comment TEXT,
            attachment TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    add_column_if_missing(cur, "tickets", "attachment", "TEXT")
    add_column_if_missing(cur, "tickets", "archived", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "tickets", "assigned_to", "INTEGER")
    add_column_if_missing(cur, "tickets", "approval_level", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(cur, "tickets", "manager_seen_at", "TEXT")
    add_column_if_missing(cur, "tickets", "responded_at", "TEXT")
    add_column_if_missing(cur, "tickets", "employee_seen_at", "TEXT")
    add_column_if_missing(cur, "tickets", "archive_after_at", "TEXT")
    add_column_if_missing(cur, "tickets", "completed_at", "TEXT")
    add_column_if_missing(cur, "tickets", "escalated_at", "TEXT")
    add_column_if_missing(cur, "tickets", "escalated_by", "INTEGER")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS salary_corrections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            gross_adjustment REAL NOT NULL DEFAULT 0,
            net_adjustment REAL NOT NULL DEFAULT 0,
            note TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(employee_id, year, month),
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bonuses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            note TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(employee_id, year, month),
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_permissions (
            user_id INTEGER PRIMARY KEY,
            can_view_calendar INTEGER NOT NULL DEFAULT 1,
            can_manage_schedule INTEGER NOT NULL DEFAULT 0,
            can_view_team INTEGER NOT NULL DEFAULT 0,
            can_process_tickets INTEGER NOT NULL DEFAULT 0,
            can_view_payroll INTEGER NOT NULL DEFAULT 0,
            can_edit_payroll INTEGER NOT NULL DEFAULT 0,
            can_view_payroll_reports INTEGER NOT NULL DEFAULT 0,
            can_manage_users INTEGER NOT NULL DEFAULT 0,
            can_view_reports INTEGER NOT NULL DEFAULT 0,
            scope TEXT NOT NULL DEFAULT 'self',
            updated_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    add_column_if_missing(cur, "user_permissions", "can_send_schedule_to_payroll", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_manage_payroll", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_view_own_payroll", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(cur, "user_permissions", "can_edit_pay_rate", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_send_payroll_notification", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_unlock_schedule", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_view_dashboard", "INTEGER NOT NULL DEFAULT 0")
    add_column_if_missing(cur, "user_permissions", "can_create_tickets", "INTEGER NOT NULL DEFAULT 1")
    add_column_if_missing(cur, "user_permissions", "can_escalate_tickets", "INTEGER NOT NULL DEFAULT 0")
    cur.execute("""
        UPDATE user_permissions
        SET can_view_dashboard = 1
        WHERE can_view_dashboard = 0
          AND (can_view_team = 1 OR can_view_payroll = 1 OR can_view_own_payroll = 1 OR can_manage_payroll = 1)
    """)
    cur.execute("""
        UPDATE user_permissions
        SET can_view_dashboard = 1
        WHERE user_id IN (SELECT id FROM users WHERE role = 'manager' AND employee_id IS NULL)
    """)

    add_column_if_missing(cur, "employees", "pay_type", "TEXT NOT NULL DEFAULT 'monthly'")
    add_column_if_missing(cur, "employees", "monthly_gross", "REAL NOT NULL DEFAULT 1000.00")
    add_column_if_missing(cur, "employees", "hourly_rate", "REAL NOT NULL DEFAULT 8.00")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            bonus REAL NOT NULL DEFAULT 0,
            correction REAL NOT NULL DEFAULT 0,
            sick_days INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            updated_by INTEGER,
            updated_at TEXT,
            UNIQUE(employee_id, year, month)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            normal_hours REAL NOT NULL DEFAULT 0,
            weekend_hours REAL NOT NULL DEFAULT 0,
            holiday_hours REAL NOT NULL DEFAULT 0,
            overtime_hours REAL NOT NULL DEFAULT 0,
            gross_base REAL NOT NULL DEFAULT 0,
            additions REAL NOT NULL DEFAULT 0,
            bonus REAL NOT NULL DEFAULT 0,
            correction REAL NOT NULL DEFAULT 0,
            sick_pay REAL NOT NULL DEFAULT 0,
            gross_total REAL NOT NULL DEFAULT 0,
            net_total REAL NOT NULL DEFAULT 0,
            breakdown TEXT,
            status TEXT NOT NULL DEFAULT 'calculated',
            sent_at TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            UNIQUE(employee_id, year, month)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS schedule_month_locks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            locked_by INTEGER,
            locked_at TEXT NOT NULL,
            reason TEXT,
            UNIQUE(year, month)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            employee_id INTEGER,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            page_url TEXT,
            browser_info TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            admin_comment TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS payroll_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            manager_user_id INTEGER NOT NULL,
            manager_employee_id INTEGER,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            employee_ids TEXT NOT NULL,
            total_hours REAL NOT NULL DEFAULT 0,
            overtime_hours REAL NOT NULL DEFAULT 0,
            holiday_hours REAL NOT NULL DEFAULT 0,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'sent',
            created_at TEXT NOT NULL,
            FOREIGN KEY(manager_user_id) REFERENCES users(id),
            FOREIGN KEY(manager_employee_id) REFERENCES employees(id)
        )
    """)

    add_column_if_missing(cur, "payroll_reports", "breakdown", "TEXT")
    add_column_if_missing(cur, "payroll_reports", "locked_at", "TEXT")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            link TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    seed_data(conn)
    conn.close()


def seed_data(conn):
    cur = conn.cursor()

    for name in ["Продажби", "Склад", "Администрация", "Поддръжка"]:
        cur.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))

    templates_data = [
        ("Сутрешна", "08:00", "16:00"),
        ("Следобедна", "16:00", "00:00"),
        ("Дневна", "09:00", "17:00"),
        ("Къса", "10:00", "14:00"),
        ("Нощна", "00:00", "08:00"),
    ]

    for item in templates_data:
        cur.execute("""
            INSERT OR IGNORE INTO shift_templates
            (name, start_time, end_time)
            VALUES (?, ?, ?)
        """, item)

    if cur.execute("SELECT COUNT(*) AS c FROM employees").fetchone()["c"] == 0:
        now = datetime.now().isoformat(timespec="seconds")
        employees_data = [
            ("Иван", "Петров", "ivan@example.com", "+359888111111", 1, 10.00, now),
            ("Мария", "Иванова", "maria@example.com", "+359888222222", 2, 9.50, now),
            ("Георги", "Димитров", "georgi@example.com", "+359888333333", 3, 11.00, now),
            ("Елена", "Стоянова", "elena@example.com", "+359888444444", 1, 12.00, now),
        ]

        cur.executemany("""
            INSERT INTO employees
            (first_name, last_name, email, phone, department_id, hourly_rate, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, employees_data)

    if cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        cur.execute("""
            INSERT INTO users
            (username, password_hash, role, employee_id, must_change_password)
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", generate_password_hash("admin123"), "manager", None, 0))

        cur.execute("""
            INSERT INTO users
            (username, password_hash, role, employee_id, must_change_password)
            VALUES (?, ?, ?, ?, ?)
        """, ("ivan", generate_password_hash("ivan123"), "employee", 1, 0))

    conn.commit()


# ---------------- HELPERS ----------------

def current_user():
    if "user_id" not in session:
        return None

    conn = get_db()
    user = conn.execute("""
        SELECT users.*, employees.first_name, employees.last_name,
               employees.email, employees.phone, employees.photo,
               employees.position, employees.manager_id
        FROM users
        LEFT JOIN employees ON employees.id = users.employee_id
        WHERE users.id = ?
    """, (session["user_id"],)).fetchone()
    conn.close()

    return user


def unread_notifications_count():
    if "user_id" not in session:
        return 0

    conn = get_db()
    count = conn.execute("""
        SELECT COUNT(*) AS c
        FROM notifications
        WHERE user_id = ? AND is_read = 0
    """, (session["user_id"],)).fetchone()["c"]
    conn.close()
    return count


@app.context_processor
def inject_globals():
    latest_notification = None
    notification_counts = {"tickets": 0, "payroll": 0, "schedule": 0, "reports": 0, "general": 0}
    if "user_id" in session:
        try:
            conn = get_db()
            latest_notification = conn.execute("""
                SELECT * FROM notifications
                WHERE user_id = ? AND is_read = 0
                ORDER BY created_at DESC
                LIMIT 1
            """, (session["user_id"],)).fetchone()
            notification_counts = notification_module_counts(session["user_id"], conn)
            conn.close()
        except Exception:
            latest_notification = None
    return {
        "current_user": current_user(),
        "unread_notifications": unread_notifications_count(),
        "notification_counts": notification_counts,
        "latest_notification": latest_notification,
        "theme": session.get("theme") or row_get(current_user(), "theme", "dark") or "dark",
        "position_labels": POSITION_LABELS if "POSITION_LABELS" in globals() else {},
        "can_edit_salary": user_can_edit_salary(current_user()),
        "user_can_process_ticket": user_can_process_ticket,
        "can_escalate_ticket": can_escalate_ticket,
        "user_can_view_salary": user_can_view_salary,
        "permission_labels": PERMISSION_LABELS,
        "permission_descriptions": PERMISSION_DESCRIPTIONS,
        "scope_labels": SCOPE_LABELS,
        "can": lambda permission_name: has_permission(current_user(), permission_name),
        "is_admin_user": is_root_admin(current_user())
    }


def wants_json_response():
    return (
        request.headers.get("X-Requested-With") == "fetch"
        or "application/json" in (request.headers.get("Accept") or "")
    )


def json_or_redirect(ok, message, redirect_url, status=200, **extra):
    if wants_json_response():
        payload = {"ok": ok, "message": message, "redirect": redirect_url}
        payload.update(extra)
        return jsonify(payload), status
    if message:
        flash(message, "success" if ok else "danger")
    return redirect(redirect_url)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        allowed_endpoints = {"change_password", "logout", "static", "manifest", "service_worker"}

        if session.get("must_change_password") == 1 and request.endpoint not in allowed_endpoints:
            flash("Трябва да смените временната си парола.", "info")
            return redirect(url_for("change_password"))

        return view(*args, **kwargs)
    return wrapped


def permission_required(permission_name, message="Нямате права за тази операция."):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or not (is_root_admin(user) or has_permission(user, permission_name)):
                flash(message, "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def manage_users_required(view):
    return permission_required("can_manage_users", "Нямате достъп до админ операции.")(view)


def manager_required(view):
    # Backward-compatible name. In ShiftDesk access is permission-based,
    # not based only on users.role == 'manager'.
    return manage_users_required(view)


def calc_hours(start_time, end_time):
    start = datetime.strptime(start_time, "%H:%M")
    end = datetime.strptime(end_time, "%H:%M")

    if end <= start:
        end += timedelta(days=1)

    return round((end - start).seconds / 3600, 2)


def log_employee(employee_id, action, details="", conn=None):
    should_close = False

    if conn is None:
        conn = get_db()
        should_close = True

    conn.execute("""
        INSERT INTO employee_logs
        (employee_id, action, details, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        employee_id,
        action,
        details,
        session.get("user_id"),
        datetime.now().isoformat(timespec="seconds")
    ))

    if should_close:
        conn.commit()
        conn.close()


def absolute_link(link):
    if not link:
        return url_for("dashboard", _external=True)
    if str(link).startswith("http://") or str(link).startswith("https://"):
        return link
    return request.host_url.rstrip("/") + str(link)


def send_push_to_user(user_id, title, message, link=None, conn=None):
    if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        print("PUSH DEBUG: missing VAPID keys")
        return False

    try:
        from pywebpush import webpush
    except Exception as e:
        print("PUSH DEBUG: pywebpush import failed:", e)
        return False

    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True

    rows = conn.execute("SELECT id, data FROM push_subscriptions WHERE user_id = ?", (user_id,)).fetchall()
    if not rows:
        print(f"PUSH DEBUG: no subscriptions for user {user_id}")
        if close_conn:
            conn.close()
        return False

    payload = json.dumps({
        "title": title,
        "body": message,
        "url": absolute_link(link),
        "icon": "/static/icon.svg"
    }, ensure_ascii=False)

    dead = []
    ok = False

    for row in rows:
        try:
            webpush(
                subscription_info=json.loads(row["data"]),
                data=payload,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
            ok = True
            print(f"PUSH DEBUG: sent to subscription {row['id']}")
        except Exception as e:
            print(f"PUSH DEBUG: send failed for subscription {row['id']}: {e}")
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in [404, 410]:
                dead.append(row["id"])

    for sid in dead:
        conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sid,))

    if close_conn:
        conn.commit()
        conn.close()

    return ok



def notification_module_from_link(link, title="", message=""):
    text = f"{link or ''} {title or ''} {message or ''}".lower()

    if "ticket" in text or "tickets" in text or "заяв" in text:
        return "tickets"

    if "payroll" in text or "salary" in text or "salar" in text or "заплат" in text or "бонус" in text or "финанс" in text:
        return "payroll"

    if "schedule" in text or "calendar" in text or "смяна" in text or "график" in text or "календар" in text:
        return "schedule"

    if "feedback" in text or "report" in text or "бъг" in text:
        return "reports"

    return "general"


def notification_module_counts(user_id, conn):
    rows = conn.execute("""
        SELECT link, title, message
        FROM notifications
        WHERE user_id = ? AND is_read = 0
    """, (user_id,)).fetchall()

    counts = {"tickets": 0, "payroll": 0, "schedule": 0, "reports": 0, "general": 0}

    for row in rows:
        module = notification_module_from_link(row["link"], row["title"], row["message"])
        counts[module] = counts.get(module, 0) + 1

    return counts


def notification_link_for_module(module):
    if module == "tickets":
        return url_for("tickets")
    if module == "payroll":
        return url_for("payroll_tools")
    if module == "schedule":
        return url_for("schedule")
    if module == "reports":
        return url_for("feedback_reports")
    return url_for("dashboard")



def mark_ticket_notifications_processed(ticket_id, employee_id, assigned_to, conn):
    """Mark pending ticket/request notifications as read after the ticket is processed."""
    candidate_user_ids = set()

    requester = user_id_for_employee(employee_id, conn)
    if requester:
        candidate_user_ids.add(requester)

    if assigned_to:
        candidate_user_ids.add(assigned_to)

    admins = conn.execute("SELECT id FROM users WHERE role = 'manager' AND employee_id IS NULL").fetchall()
    for admin in admins:
        candidate_user_ids.add(admin["id"])

    for uid in candidate_user_ids:
        conn.execute("""
            UPDATE notifications
            SET is_read = 1
            WHERE user_id = ?
              AND is_read = 0
              AND (
                    COALESCE(link, '') LIKE '%tickets%'
                 OR title LIKE '%заяв%'
                 OR title LIKE '%тикет%'
                 OR message LIKE '%заяв%'
                 OR message LIKE '%тикет%'
              )
        """, (uid,))



def notify_user(user_id, title, message, link=None, conn=None):
    should_close = False

    if conn is None:
        conn = get_db()
        should_close = True

    conn.execute("""
        INSERT INTO notifications
        (user_id, title, message, link, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
    """, (
        user_id,
        title,
        message,
        link,
        datetime.now().isoformat(timespec="seconds")
    ))

    send_push_to_user(user_id, title, message, link, conn)

    if should_close:
        conn.commit()
        conn.close()


def notify_managers(title, message, link=None, conn=None):
    should_close = False

    if conn is None:
        conn = get_db()
        should_close = True

    managers = conn.execute("SELECT id FROM users WHERE role = 'manager'").fetchall()

    for manager in managers:
        notify_user(manager["id"], title, message, link, conn)

    if should_close:
        conn.commit()
        conn.close()


def user_id_for_employee(employee_id, conn):
    row = conn.execute("""
        SELECT id FROM users
        WHERE employee_id = ?
        LIMIT 1
    """, (employee_id,)).fetchone()

    return row["id"] if row else None


def allowed_file(filename):
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_UPLOADS


def save_uploaded_file(file):
    if not file or not file.filename:
        return None

    if not allowed_file(file.filename):
        raise ValueError("Разрешени файлове: png, jpg, jpeg, webp, pdf.")

    filename = secure_filename(file.filename)
    unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}_{filename}"
    file.save(UPLOAD_DIR / unique_name)
    return unique_name


def get_period_from_request():
    start = request.args.get("start")
    end = request.args.get("end")

    if not start:
        start = date.today().replace(day=1).isoformat()

    if not end:
        end = date.today().isoformat()

    return start, end



# Approximate Bulgarian payroll calculation for employee born after 1959.
# Uses employee-side social contributions 13.78% and 10% income tax after employee contributions.
# Employer cost is approximate 18.92% on gross. These constants should be configurable later.
BG_EMPLOYEE_SOCIAL_RATE = 0.1378
BG_INCOME_TAX_RATE = 0.10
BG_EMPLOYER_SOCIAL_RATE = 0.1892


def bulgarian_payroll_breakdown(gross):
    gross = float(gross or 0)
    employee_social = round(gross * BG_EMPLOYEE_SOCIAL_RATE, 2)
    taxable_income = max(0, gross - employee_social)
    income_tax = round(taxable_income * BG_INCOME_TAX_RATE, 2)
    net = round(gross - employee_social - income_tax, 2)
    employer_social = round(gross * BG_EMPLOYER_SOCIAL_RATE, 2)
    employer_total = round(gross + employer_social, 2)

    return {
        "gross": round(gross, 2),
        "employee_social": employee_social,
        "taxable_income": round(taxable_income, 2),
        "income_tax": income_tax,
        "net": net,
        "employer_social": employer_social,
        "employer_total": employer_total
    }



STANDARD_HOURS_PER_DAY = 8
WEEKLY_SCHEDULE_HOUR_LIMIT = 60
OVERTIME_WORKDAY_MULTIPLIER = 1.50
WEEKEND_MULTIPLIER = 1.75
HOLIDAY_MULTIPLIER = 2.00
SICK_EMPLOYER_DAYS = 2
SICK_EMPLOYER_RATE = 0.70


def official_working_days(year, month):
    days = []
    last = calendar.monthrange(year, month)[1]
    for day in range(1, last + 1):
        d = date(year, month, day)
        iso = d.isoformat()
        if d.weekday() < 5 and not is_non_working_day(iso):
            days.append(iso)
    return days


def official_working_hours(year, month):
    return len(official_working_days(year, month)) * STANDARD_HOURS_PER_DAY


def shift_multiplier(work_date):
    if is_non_working_day(work_date):
        return HOLIDAY_MULTIPLIER, "holiday"
    if is_weekend(work_date):
        return WEEKEND_MULTIPLIER, "weekend"
    return 1.0, "normal"


def get_payroll_item(conn, employee_id, year, month):
    row = conn.execute("""
        SELECT * FROM payroll_items
        WHERE employee_id = ? AND year = ? AND month = ?
    """, (employee_id, year, month)).fetchone()

    if row:
        return row

    return {
        "bonus": 0,
        "correction": 0,
        "sick_days": 0,
        "notes": ""
    }


def employee_base_rate(employee, year, month):
    pay_type = row_get(employee, "pay_type", "monthly") or "monthly"
    monthly_gross = float(row_get(employee, "monthly_gross", 0) or 0)
    hourly_rate = float(row_get(employee, "hourly_rate", 0) or 0)

    if pay_type == "hourly":
        return hourly_rate

    norm_hours = official_working_hours(year, month) or 1
    return monthly_gross / norm_hours


def calculate_employee_payroll(conn, employee_id, year, month):
    employee = conn.execute("""
        SELECT employees.*, departments.name AS department,
               manager.first_name AS manager_first_name,
               manager.last_name AS manager_last_name
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN employees AS manager ON manager.id = employees.manager_id
        WHERE employees.id = ?
    """, (employee_id,)).fetchone()

    if not employee:
        return None

    first = date(year, month, 1).isoformat()
    last = date(year, month, calendar.monthrange(year, month)[1]).isoformat()
    shifts = conn.execute("""
        SELECT * FROM schedule
        WHERE employee_id = ? AND work_date BETWEEN ? AND ?
        ORDER BY work_date, start_time
    """, (employee_id, first, last)).fetchall()

    base_rate = employee_base_rate(employee, year, month)
    norm_hours = official_working_hours(year, month)
    pay_type = row_get(employee, "pay_type", "monthly") or "monthly"
    monthly_gross = float(row_get(employee, "monthly_gross", 0) or 0)

    normal_hours = 0
    weekend_hours = 0
    holiday_hours = 0
    paid_base_hours = 0
    additions = 0
    shift_rows = []

    for s in shifts:
        hours = calc_hours(s["start_time"], s["end_time"])
        multiplier, day_type = shift_multiplier(s["work_date"])

        if day_type == "holiday":
            holiday_hours += hours
        elif day_type == "weekend":
            weekend_hours += hours
        else:
            normal_hours += hours

        paid_base_hours += hours
        additions += hours * base_rate * (multiplier - 1)

        shift_rows.append({
            "date": s["work_date"],
            "start": s["start_time"],
            "end": s["end_time"],
            "hours": round(hours, 2),
            "type": day_type,
            "multiplier": multiplier
        })

    overtime_hours = max(0, paid_base_hours - norm_hours)
    # Workday overtime premium only applies to hours above monthly norm that are not already holiday/weekend premiumed.
    workday_overtime_hours = max(0, min(overtime_hours, normal_hours))
    additions += workday_overtime_hours * base_rate * (OVERTIME_WORKDAY_MULTIPLIER - 1)

    if pay_type == "monthly":
        gross_base = monthly_gross if paid_base_hours >= norm_hours else round(paid_base_hours * base_rate, 2)
    else:
        gross_base = round(paid_base_hours * base_rate, 2)

    item = get_payroll_item(conn, employee_id, year, month)
    bonus = float(row_get(item, "bonus", 0) or 0)
    correction = float(row_get(item, "correction", 0) or 0)
    sick_days = int(row_get(item, "sick_days", 0) or 0)

    daily_rate = base_rate * STANDARD_HOURS_PER_DAY
    sick_pay = min(sick_days, SICK_EMPLOYER_DAYS) * daily_rate * SICK_EMPLOYER_RATE

    gross_total = round(gross_base + additions + bonus + correction + sick_pay, 2)
    payroll = bulgarian_payroll_breakdown(gross_total)

    return {
        "employee_id": employee_id,
        "name": f"{employee['first_name']} {employee['last_name']}",
        "department": employee["department"] or "-",
        "position": row_get(employee, "position", "-") or "-",
        "email": row_get(employee, "email", "") or "",
        "phone": row_get(employee, "phone", "") or "",
        "photo": row_get(employee, "photo", "") or "",
        "manager_name": (f"{row_get(employee, 'manager_first_name', '') or ''} {row_get(employee, 'manager_last_name', '') or ''}").strip() or "-",
        "pay_type": pay_type,
        "monthly_gross": round(monthly_gross, 2),
        "base_rate": round(base_rate, 4),
        "norm_hours": round(norm_hours, 2),
        "worked_hours": round(paid_base_hours, 2),
        "normal_hours": round(normal_hours, 2),
        "weekend_hours": round(weekend_hours, 2),
        "holiday_hours": round(holiday_hours, 2),
        "overtime_hours": round(workday_overtime_hours, 2),
        "gross_base": round(gross_base, 2),
        "additions": round(additions, 2),
        "bonus": round(bonus, 2),
        "correction": round(correction, 2),
        "sick_days": sick_days,
        "sick_pay": round(sick_pay, 2),
        "gross_total": gross_total,
        "net_total": payroll["net"],
        "employee_social": payroll["employee_social"],
        "income_tax": payroll["income_tax"],
        "employer_total": payroll["employer_total"],
        "shifts": shift_rows,
        "notes": row_get(item, "notes", "") or ""
    }


def save_payroll_run(conn, row, year, month, user_id):
    breakdown = json_dumps_safe(row)
    existing = conn.execute("""
        SELECT id FROM payroll_runs
        WHERE employee_id = ? AND year = ? AND month = ?
    """, (row["employee_id"], year, month)).fetchone()

    values = (
        row["normal_hours"], row["weekend_hours"], row["holiday_hours"], row["overtime_hours"],
        row["gross_base"], row["additions"], row["bonus"], row["correction"], row["sick_pay"],
        row["gross_total"], row["net_total"], breakdown, "calculated", user_id, datetime.now().isoformat(timespec="seconds")
    )

    if existing:
        conn.execute("""
            UPDATE payroll_runs
            SET normal_hours=?, weekend_hours=?, holiday_hours=?, overtime_hours=?,
                gross_base=?, additions=?, bonus=?, correction=?, sick_pay=?,
                gross_total=?, net_total=?, breakdown=?, status=?, created_by=?, created_at=?
            WHERE id = ?
        """, (*values, existing["id"]))
    else:
        conn.execute("""
            INSERT INTO payroll_runs
            (employee_id, year, month, normal_hours, weekend_hours, holiday_hours, overtime_hours,
             gross_base, additions, bonus, correction, sick_pay, gross_total, net_total,
             breakdown, status, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (row["employee_id"], year, month, *values))




def is_schedule_month_locked(conn, year, month):
    row = conn.execute("SELECT id FROM schedule_month_locks WHERE year = ? AND month = ?", (int(year), int(month))).fetchone()
    return bool(row)


def lock_schedule_month(conn, year, month, user_id, reason="Заплатите са изпратени"):
    now = datetime.now().isoformat(timespec="seconds")
    existing = conn.execute("SELECT id FROM schedule_month_locks WHERE year = ? AND month = ?", (int(year), int(month))).fetchone()
    if existing:
        conn.execute("""
            UPDATE schedule_month_locks
            SET locked_by = ?, locked_at = ?, reason = ?
            WHERE id = ?
        """, (user_id, now, reason, existing["id"]))
    else:
        conn.execute("""
            INSERT INTO schedule_month_locks (year, month, locked_by, locked_at, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (int(year), int(month), user_id, now, reason))


def unlock_schedule_month(conn, year, month):
    conn.execute("DELETE FROM schedule_month_locks WHERE year = ? AND month = ?", (int(year), int(month)))


def payroll_history_for_employee(conn, employee_id, limit=12):
    return conn.execute("""
        SELECT * FROM payroll_runs
        WHERE employee_id = ?
        ORDER BY year DESC, month DESC, created_at DESC
        LIMIT ?
    """, (employee_id, limit)).fetchall()


def parse_employee_ids_json(value):
    try:
        data = json.loads(value or "[]")
        return [int(x) for x in data]
    except Exception:
        return []


def payroll_report_details(conn, report):
    employee_ids = parse_employee_ids_json(row_get(report, "employee_ids", "[]"))
    first_day = date(int(report["year"]), int(report["month"]), 1).isoformat()
    last_day = date(int(report["year"]), int(report["month"]), calendar.monthrange(int(report["year"]), int(report["month"]))[1]).isoformat()

    summary = build_payroll_report_summary(conn, employee_ids, first_day, last_day)

    manager_employee_id = row_get(report, "manager_employee_id")
    team_name = "-"
    if manager_employee_id:
        mgr = conn.execute("""
            SELECT departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.id = ?
        """, (manager_employee_id,)).fetchone()
        team_name = row_get(mgr, "department", "-") or "-"

    return {
        "employee_ids": employee_ids,
        "team_name": team_name,
        "summary": summary,
        "rows": summary.get("rows", []),
    }


def sync_report_to_payroll_aggressive(conn, report, user_id):
    employee_ids = parse_employee_ids_json(row_get(report, "employee_ids", "[]"))
    synced = 0
    for employee_id in employee_ids:
        row = calculate_employee_payroll(conn, employee_id, int(report["year"]), int(report["month"]))
        if row:
            save_payroll_run(conn, row, int(report["year"]), int(report["month"]), user_id)
            synced += 1
    return synced


def salary_rows(conn, start, end, employee_id=None):
    start_date = datetime.strptime(start, "%Y-%m-%d").date()
    year = start_date.year
    month = start_date.month

    params = []
    sql = """
        SELECT employees.id
        FROM employees
        WHERE employees.active = 1
    """
    if employee_id:
        sql += " AND employees.id = ?"
        params.append(employee_id)

    sql += " ORDER BY employees.first_name, employees.last_name"
    employees_list = conn.execute(sql, params).fetchall()

    result = []
    for emp in employees_list:
        row = calculate_employee_payroll(conn, emp["id"], year, month)
        if not row:
            continue
        row["id"] = row["employee_id"]
        row["salary"] = row["gross_total"]
        row["gross"] = row["gross_total"]
        row["net"] = row["net_total"]
        row["hours"] = row["worked_hours"]
        row["base_rate"] = row.get("base_rate", 0)
        row["hourly_rate"] = row.get("base_rate", 0)
        row["overtime_salary"] = row.get("additions", 0)
        row["bonus_amount"] = row.get("bonus", 0)
        row["correction_amount"] = row.get("correction", 0)
        row["shift_count"] = len(row.get("shift_rows", []))
        result.append(row)

    return result

BULGARIA_HOLIDAYS_2026 = {
    "2026-01-01":"Нова година","2026-01-02":"Почивен ден / евро","2026-03-03":"Ден на Освобождението",
    "2026-04-10":"Велики петък","2026-04-11":"Велика събота","2026-04-12":"Великден","2026-04-13":"Великден понеделник",
    "2026-05-01":"Ден на труда","2026-05-06":"Гергьовден","2026-05-24":"Ден на просветата","2026-05-25":"Почивен ден за 24 май",
    "2026-09-06":"Съединение","2026-09-07":"Почивен ден за Съединението","2026-09-22":"Независимост",
    "2026-12-24":"Бъдни вечер","2026-12-25":"Коледа","2026-12-26":"Втори ден Коледа","2026-12-28":"Почивен ден за Коледа"
}

def is_weekend(day_iso):
    return datetime.strptime(day_iso, "%Y-%m-%d").date().weekday() >= 5

def employee_week_hours(conn, employee_id, day_iso):
    d = datetime.strptime(day_iso, "%Y-%m-%d").date()
    monday = d - timedelta(days=d.weekday())
    sunday = monday + timedelta(days=6)
    rows = conn.execute("""SELECT start_time,end_time FROM schedule WHERE employee_id=? AND work_date BETWEEN ? AND ?""", (employee_id, monday.isoformat(), sunday.isoformat())).fetchall()
    return sum(calc_hours(r["start_time"], r["end_time"]) for r in rows)


def daterange_iso(start_date, end_date=None):
    if not start_date:
        return []
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date or start_date, "%Y-%m-%d").date()
    if end < start:
        start, end = end, start
    days = []
    current = start
    while current <= end:
        days.append(current.isoformat())
        current += timedelta(days=1)
    return days


def ticket_absence_type(ticket_type):
    t = (ticket_type or "").lower()
    if "болнич" in t:
        return "sick"
    if "отпуск" in t or "отпуска" in t:
        return "leave"
    return None


def create_absence_calendar_entries(conn, ticket):
    absence_type = ticket_absence_type(ticket["type"])
    if not absence_type or not ticket["start_date"]:
        return 0

    now = datetime.now().isoformat(timespec="seconds")
    label = "Болничен" if absence_type == "sick" else "Отпуска"
    created = 0

    for day in daterange_iso(ticket["start_date"], ticket["end_date"]):
        existing = conn.execute("""
            SELECT id FROM schedule
            WHERE employee_id = ?
              AND work_date = ?
              AND entry_type IN ('leave','sick')
              AND ticket_id = ?
        """, (ticket["employee_id"], day, ticket["id"])).fetchone()

        if existing:
            continue

        conn.execute("""
            INSERT INTO schedule
            (employee_id, work_date, start_time, end_time, notes, created_at, updated_at, entry_type, ticket_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ticket["employee_id"],
            day,
            "00:00",
            "00:00",
            f"{label} от заявка #{ticket['id']}",
            now,
            now,
            absence_type,
            ticket["id"]
        ))
        created += 1

    log_employee(ticket["employee_id"], f"Одобрена {label.lower()}", f"{ticket['start_date']} - {ticket['end_date'] or ticket['start_date']}", conn)
    return created

def remove_employee_shifts_for_period(conn, employee_id, start_date, end_date, reason):
    if not start_date: return 0
    end_date = end_date or start_date
    rows = conn.execute("""SELECT * FROM schedule WHERE employee_id=? AND work_date BETWEEN ? AND ? AND COALESCE(entry_type,'shift')='shift'""", (employee_id, start_date, end_date)).fetchall()
    for row in rows:
        conn.execute("DELETE FROM schedule WHERE id=?", (row["id"],))
        log_employee(employee_id, "Автоматично премахната смяна", f"{reason}: {row['work_date']}", conn)
    return len(rows)

def notify_coworkers_about_absence(conn, employee_id, start_date, end_date, reason):
    emp = conn.execute("SELECT first_name,last_name FROM employees WHERE id=?", (employee_id,)).fetchone()
    if not emp: return
    users = conn.execute("""SELECT users.id FROM users JOIN employees ON employees.id=users.employee_id WHERE employees.active=1 AND employees.id != ?""", (employee_id,)).fetchall()
    name = f"{emp['first_name']} {emp['last_name']}"
    for u in users:
        notify_user(u["id"], "Промяна в графика", f"{name} е {reason} за {start_date} - {end_date or start_date}.", url_for("schedule", view="month", year=start_date[:4], month=start_date[5:7], open_day=start_date), conn)


# ---------------- PWA ----------------

@app.route("/manifest.json")
def manifest():
    return send_from_directory(app.static_folder, "manifest.json")


@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(app.static_folder, "service-worker.js")


# ---------------- SETTINGS ----------------

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = current_user()
    if request.method == "POST":
        action = request.form.get("action")
        conn = get_db()
        try:
            if action == "profile":
                theme = request.form.get("theme", "dark")
                if theme not in ["dark", "light", "purple", "blue", "green", "orange"]:
                    theme = "dark"
                conn.execute("UPDATE users SET theme=? WHERE id=?", (theme, session["user_id"]))
                session["theme"] = theme
                conn.commit()
                if wants_json_response():
                    return jsonify({"ok": True, "message": "Темата е запазена.", "theme": theme})
                flash("Темата е запазена.", "success")

            elif action == "password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")
                db_user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

                if not check_password_hash(db_user["password_hash"], current_password):
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Текущата парола е грешна."}), 400
                    flash("Текущата парола е грешна.", "danger")
                    return redirect(url_for("settings"))

                if len(new_password) < 6:
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Новата парола трябва да е поне 6 символа."}), 400
                    flash("Новата парола трябва да е поне 6 символа.", "danger")
                    return redirect(url_for("settings"))

                if new_password != confirm_password:
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Паролите не съвпадат."}), 400
                    flash("Паролите не съвпадат.", "danger")
                    return redirect(url_for("settings"))

                conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (generate_password_hash(new_password), session["user_id"]))
                session["must_change_password"] = 0
                conn.commit()
                if wants_json_response():
                    return jsonify({"ok": True, "message": "Паролата е сменена."})
                flash("Паролата е сменена.", "success")

        except Exception as e:
            conn.rollback()
            if wants_json_response():
                return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
            flash(f"Грешка: {e}", "danger")
        finally:
            conn.close()

        return redirect(url_for("settings"))

    conn = get_db()
    employee = None
    if user["employee_id"]:
        employee = conn.execute("""SELECT employees.*, departments.name AS department FROM employees LEFT JOIN departments ON departments.id=employees.department_id WHERE employees.id=?""", (user["employee_id"],)).fetchone()
    conn.close()
    return render_template("settings.html", employee=employee, theme=session.get("theme") or row_get(user, "theme", "dark") or "dark")


@app.route("/settings/theme", methods=["POST"])
@login_required
def settings_theme_update():
    theme = request.form.get("theme", "dark")
    if theme not in ["dark", "light", "purple", "blue", "green", "orange"]:
        theme = "dark"

    conn = get_db()
    try:
        conn.execute("UPDATE users SET theme=? WHERE id=?", (theme, session["user_id"]))
        conn.commit()
        session["theme"] = theme
        return jsonify({"ok": True, "message": "Темата е сменена.", "theme": theme})
    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
    finally:
        conn.close()


# ---------------- HOLIDAYS / WORK RULES ----------------

BULGARIA_HOLIDAYS_2026 = {
    "2026-01-01": "Нова година",
    "2026-01-02": "Почивен ден",
    "2026-03-03": "Ден на Освобождението",
    "2026-04-10": "Велики петък",
    "2026-04-11": "Велика събота",
    "2026-04-12": "Великден",
    "2026-04-13": "Великден понеделник",
    "2026-05-01": "Ден на труда",
    "2026-05-06": "Гергьовден",
    "2026-05-24": "Ден на българската просвета и култура",
    "2026-05-25": "Почивен ден за 24 май",
    "2026-09-06": "Ден на Съединението",
    "2026-09-07": "Почивен ден за Съединението",
    "2026-09-22": "Ден на независимостта",
    "2026-12-24": "Бъдни вечер",
    "2026-12-25": "Коледа",
    "2026-12-26": "Втори ден Коледа",
    "2026-12-28": "Почивен ден за Коледа"
}

def get_holiday_name(day_iso):
    return BULGARIA_HOLIDAYS_2026.get(day_iso)

def is_non_working_day(day_iso):
    return is_weekend(day_iso) or bool(get_holiday_name(day_iso))


# ---------------- HIERARCHY / APPROVAL ----------------

POSITION_LABELS = {
    "worker": "Работник",
    "team_manager": "Мениджър екип",
    "deputy_director": "Заместник директор",
    "operations_director": "Оперативен директор",
    "executive_director": "Изпълнителен директор",
    "finance": "Финансов отдел"
}

def position_label(position):
    return POSITION_LABELS.get(position or "worker", position or "Работник")


PERMISSION_FIELDS = [
    "can_view_dashboard",
    "can_view_calendar",
    "can_manage_schedule",
    "can_view_team",
    "can_create_tickets",
    "can_process_tickets",
    "can_escalate_tickets",
    "can_send_schedule_to_payroll",
    "can_view_payroll",
    "can_view_own_payroll",
    "can_manage_payroll",
    "can_edit_pay_rate",
    "can_send_payroll_notification",
    "can_view_payroll_reports",
    "can_manage_users",
    "can_view_reports",
]

PERMISSION_LABELS = {
    "can_view_dashboard": "Вижда Dashboard",
    "can_view_calendar": "Вижда календар",
    "can_manage_schedule": "Управлява графици",
    "can_view_team": "Вижда екип",
    "can_create_tickets": "Създава заявки",
    "can_process_tickets": "Обработва заявки",
    "can_escalate_tickets": "Ескалира заявки",
    "can_send_schedule_to_payroll": "Изпраща график към финанси",
    "can_view_payroll": "Вижда payroll по обхват",
    "can_view_own_payroll": "Вижда своя payroll",
    "can_manage_payroll": "Управлява payroll",
    "can_edit_pay_rate": "Редактира ставки/брутни заплати",
    "can_send_payroll_notification": "Изпраща известие за заплата",
    "can_view_payroll_reports": "Вижда payroll справки",
    "can_manage_users": "Управлява потребители",
    "can_view_reports": "Вижда reports",
}

PERMISSION_DESCRIPTIONS = {
    "can_view_dashboard": "Позволява достъп до началния Dashboard екран. Ако е изключено, менюто и route-ът към Dashboard са скрити/забранени.",
    "can_view_calendar": "Позволява достъп до календара. Обхватът решава дали вижда само себе си, подчинени или всички.",
    "can_manage_schedule": "Позволява добавяне, редакция, местене и триене на смени за хората в разрешения обхват.",
    "can_view_team": "Позволява достъп до екип/служители според обхвата. Без това право потребителят не трябва да разглежда екипи.",
    "can_create_tickets": "Позволява на служител да създава заявки към прекия си ръководител.",
    "can_process_tickets": "Позволява обработка на заявки/тикети от хората в разрешения обхват.",
    "can_escalate_tickets": "Позволява изпращане на заявка към по-горно ниво в йерархията, когато прекият ръководител не може да я реши.",
    "can_send_schedule_to_payroll": "Показва бутон в календара за изпращане на график/отработени часове към финансов отдел.",
    "can_view_payroll": "Позволява разглеждане на payroll центъра и заплати според обхвата. За собствена заплата използвайте отделното право \"Вижда своя payroll\".",
    "can_view_own_payroll": "Позволява на служител да вижда само собствената си заплата/изработени часове. Не дава достъп до чужди payroll данни.",
    "can_manage_payroll": "Позволява изчисляване и записване на payroll, бонуси, корекции и болнични.",
    "can_edit_pay_rate": "Позволява редакция на тип заплащане, почасова ставка и месечна брутна заплата. Това е само за финанси/admin.",
    "can_send_payroll_notification": "Позволява изпращане на известие към служител, че заплатата му е готова.",
    "can_view_payroll_reports": "Позволява разглеждане на справки, изпратени от графика към финансов отдел.",
    "can_manage_users": "Позволява управление на потребители и достъп до административни настройки.",
    "can_view_reports": "Позволява разглеждане на bug/report страницата и потребителските препоръки."
}

SCOPE_LABELS = {
    "self": "Само себе си",
    "subordinates": "Само подчинени",
    "team_and_self": "Себе си + подчинени",
    "all": "Цялата фирма"
}


def row_get(row, key, default=None):
    if row is None:
        return default
    try:
        if hasattr(row, "keys") and key in row.keys():
            return row[key]
    except Exception:
        pass
    try:
        return row.get(key, default)
    except Exception:
        return default


def default_permissions_for_user(user):
    position = row_get(user, "position", "worker") or "worker"
    is_root = bool(user and row_get(user, "role") == "manager" and not row_get(user, "employee_id"))

    perms = {field: 0 for field in PERMISSION_FIELDS}
    perms["can_view_calendar"] = 1
    perms["can_view_dashboard"] = 0
    perms["can_view_own_payroll"] = 1
    perms["can_create_tickets"] = 1
    perms["scope"] = "self"

    if is_root:
        for field in PERMISSION_FIELDS:
            perms[field] = 1
        perms["scope"] = "all"
        return perms

    if position == "worker":
        perms["scope"] = "self"

    elif position == "team_manager":
        perms.update({
            "can_view_dashboard": 1,
            "can_manage_schedule": 1,
            "can_view_team": 1,
            "can_process_tickets": 1,
            "can_escalate_tickets": 1,
            "can_send_schedule_to_payroll": 1
        })
        perms["scope"] = "team_and_self"

    elif position in ["deputy_director", "operations_director"]:
        perms.update({
            "can_view_dashboard": 1,
            "can_manage_schedule": 1,
            "can_view_team": 1,
            "can_process_tickets": 1,
            "can_escalate_tickets": 1,
            "can_send_schedule_to_payroll": 1,
            "can_view_reports": 1
        })
        perms["scope"] = "all"

    elif position == "executive_director":
        perms.update({
            "can_view_dashboard": 1,
            "can_view_team": 1,
            "can_process_tickets": 1,
            "can_escalate_tickets": 1,
            "can_view_payroll": 1,
            "can_manage_payroll": 1,
            "can_edit_pay_rate": 1,
            "can_send_payroll_notification": 1,
            "can_view_payroll_reports": 1,
            "can_view_reports": 1
        })
        perms["scope"] = "all"

    elif position == "finance":
        perms.update({
            "can_create_tickets": 0,
            "can_view_dashboard": 1,
            "can_view_calendar": 0,
            "can_view_payroll": 1,
            "can_manage_payroll": 1,
            "can_edit_pay_rate": 1,
            "can_send_payroll_notification": 1,
            "can_view_payroll_reports": 1
        })
        perms["scope"] = "all"

    return perms


def get_user_permissions(conn, user):
    defaults = default_permissions_for_user(user)

    if not user:
        return defaults

    user_id = row_get(user, "id") or row_get(user, "user_id")
    if not user_id:
        return defaults

    row = conn.execute("SELECT * FROM user_permissions WHERE user_id = ?", (user_id,)).fetchone()
    if not row:
        return defaults

    result = defaults.copy()
    for field in PERMISSION_FIELDS:
        result[field] = int(row_get(row, field, defaults.get(field, 0)) or 0)
    result["scope"] = row_get(row, "scope", defaults["scope"]) or defaults["scope"]
    return result


def has_permission(user, permission_name, conn=None):
    if not user:
        return False

    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    perms = get_user_permissions(conn, user)
    allowed = bool(perms.get(permission_name, 0))

    if should_close:
        conn.close()

    return allowed


def permission_scope(user, conn=None):
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    perms = get_user_permissions(conn, user)
    scope = perms.get("scope", "self")

    if should_close:
        conn.close()

    return scope


def get_employee_manager_user_id(conn, employee_id):
    employee = conn.execute("SELECT manager_id FROM employees WHERE id = ?", (employee_id,)).fetchone()
    if employee and employee["manager_id"]:
        manager_user = conn.execute("SELECT id FROM users WHERE employee_id = ? LIMIT 1", (employee["manager_id"],)).fetchone()
        if manager_user:
            return manager_user["id"]
    fallback = conn.execute("SELECT id FROM users WHERE role = 'manager' ORDER BY id LIMIT 1").fetchone()
    return fallback["id"] if fallback else None

def is_root_admin(user):
    return bool(user and user["role"] == "manager" and not user["employee_id"])


def user_position(user):
    if not user:
        return "worker"
    return user["position"] or "worker"


def is_finance(user):
    return user_position(user) == "finance"


def is_executive(user):
    return user_position(user) == "executive_director"


def is_director_or_above(user):
    return user_position(user) in ["deputy_director", "operations_director", "executive_director"]


def is_team_manager(user):
    return user_position(user) == "team_manager"


def get_subordinate_ids(conn, manager_employee_id):
    if not manager_employee_id:
        return []

    result = []
    stack = [manager_employee_id]

    while stack:
        current = stack.pop()
        rows = conn.execute("SELECT id FROM employees WHERE manager_id = ? AND active = 1", (current,)).fetchall()
        for row in rows:
            eid = row["id"]
            if eid not in result:
                result.append(eid)
                stack.append(eid)

    return result


def user_can_manage_employee(user, employee_id, conn=None):
    if not user or not employee_id:
        return False

    try:
        employee_id = int(employee_id)
    except Exception:
        return False

    if is_root_admin(user):
        return True

    if not has_permission(user, "can_manage_users", conn):
        return False

    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    try:
        scope = permission_scope(user, conn)
        if scope == "all":
            return True
        if scope in ["subordinates", "team_and_self"] and user["employee_id"]:
            return employee_id in get_subordinate_ids(conn, user["employee_id"])
        return False
    finally:
        if should_close:
            conn.close()


def user_can_view_employee(user, employee_id, conn=None):
    if not user or not employee_id:
        return False

    try:
        employee_id = int(employee_id)
    except Exception:
        return False

    if is_root_admin(user):
        return True

    if user["employee_id"] and int(user["employee_id"]) == employee_id:
        return True

    if not has_permission(user, "can_view_team", conn):
        return False

    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    try:
        scope = permission_scope(user, conn)
        if scope == "all":
            return True
        if scope in ["subordinates", "team_and_self"] and user["employee_id"]:
            return employee_id in get_subordinate_ids(conn, user["employee_id"])
        return False
    finally:
        if should_close:
            conn.close()


def user_can_manage_schedule_for(user, employee_id, conn=None):
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    allowed = int(employee_id) in manageable_schedule_employee_ids(user, conn)

    if should_close:
        conn.close()

    return allowed



def allowed_schedule_employee_ids(user, conn):
    """Employees whose shifts the current user may view in the calendar."""
    if not user or not has_permission(user, "can_view_calendar", conn):
        return []

    scope = permission_scope(user, conn)

    if scope == "all":
        rows = conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()
        return [row["id"] for row in rows]

    if scope == "subordinates" and user["employee_id"]:
        return get_subordinate_ids(conn, user["employee_id"])

    if scope == "team_and_self" and user["employee_id"]:
        ids = [user["employee_id"]]
        ids.extend(get_subordinate_ids(conn, user["employee_id"]))
        return list(dict.fromkeys(ids))

    if user["employee_id"]:
        return [user["employee_id"]]

    return []


def manageable_schedule_employee_ids(user, conn):
    """Employees whose schedules the current user may create/edit/delete."""
    if not user:
        return []

    perms = get_user_permissions(conn, user)

    # Admin panel permissions are the source of truth. Defaults apply only
    # when no saved permission row exists for the user.
    if not bool(perms.get("can_manage_schedule", 0)):
        return []

    scope = perms.get("scope") or "self"

    if scope == "all":
        rows = conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()
        return [row["id"] for row in rows]

    if scope == "subordinates" and user["employee_id"]:
        return get_subordinate_ids(conn, user["employee_id"])

    if scope == "team_and_self" and user["employee_id"]:
        ids = [user["employee_id"]]
        ids.extend(get_subordinate_ids(conn, user["employee_id"]))
        return list(dict.fromkeys(ids))

    if scope == "self" and user["employee_id"]:
        return [user["employee_id"]]

    return []


def schedule_scope_label(scope):
    labels = {
        "allowed": "Всички позволени",
        "me": "Само аз",
        "team": "Моят екип"
    }
    return labels.get(scope or "allowed", "Всички позволени")


def build_payroll_report_summary(conn, employee_ids, first_day, last_day):
    if not employee_ids:
        return {
            "rows": [],
            "total_hours": 0,
            "overtime_hours": 0,
            "holiday_hours": 0
        }

    placeholders = ",".join(["?"] * len(employee_ids))
    rows = conn.execute(f"""
        SELECT schedule.*, employees.first_name, employees.last_name, departments.name AS department
        FROM schedule
        JOIN employees ON employees.id = schedule.employee_id
        LEFT JOIN departments ON departments.id = employees.department_id
        WHERE schedule.employee_id IN ({placeholders})
          AND schedule.work_date BETWEEN ? AND ?
        ORDER BY employees.first_name, employees.last_name, schedule.work_date, schedule.start_time
    """, [*employee_ids, first_day, last_day]).fetchall()

    grouped = {}
    total_hours = 0
    overtime_hours = 0
    holiday_hours = 0

    for row in rows:
        eid = row["employee_id"]
        if eid not in grouped:
            grouped[eid] = {
                "employee_id": eid,
                "name": f"{row['first_name']} {row['last_name']}",
                "department": row["department"] or "-",
                "shifts": 0,
                "hours": 0,
                "overtime_hours": 0,
                "holiday_hours": 0
            }

        hours = calc_hours(row["start_time"], row["end_time"])
        grouped[eid]["shifts"] += 1
        grouped[eid]["hours"] += hours
        total_hours += hours

        if "Работа в почивен/празничен ден" in (row["notes"] or "") or is_non_working_day(row["work_date"]):
            grouped[eid]["holiday_hours"] += hours
            holiday_hours += hours

    for item in grouped.values():
        item["overtime_hours"] = max(0, item["hours"] - 160)
        overtime_hours += item["overtime_hours"]

    return {
        "rows": list(grouped.values()),
        "total_hours": round(total_hours, 2),
        "overtime_hours": round(overtime_hours, 2),
        "holiday_hours": round(holiday_hours, 2)
    }



def user_can_view_own_payroll(user, conn=None):
    if not user or not row_get(user, "employee_id"):
        return False
    return bool(
        is_root_admin(user)
        or has_permission(user, "can_view_own_payroll", conn)
        or has_permission(user, "can_view_payroll", conn)
        or has_permission(user, "can_manage_payroll", conn)
    )


def user_can_view_salary(user, employee_id=None):
    if not user:
        return False

    if employee_id and row_get(user, "employee_id") and int(row_get(user, "employee_id")) == int(employee_id):
        return user_can_view_own_payroll(user)

    if not employee_id:
        return bool(is_root_admin(user) or has_permission(user, "can_view_payroll") or user_can_view_own_payroll(user))

    conn = get_db()
    try:
        if not (has_permission(user, "can_view_payroll", conn) or has_permission(user, "can_manage_payroll", conn)):
            return False
        scope = permission_scope(user, conn)
        if scope == "all":
            return True
        if scope in ["subordinates", "team_and_self"] and row_get(user, "employee_id"):
            return int(employee_id) in get_subordinate_ids(conn, row_get(user, "employee_id"))
        return False
    finally:
        conn.close()

def payroll_employee_ids_for(user, conn, include_self=True):
    if not user:
        return []

    if is_root_admin(user):
        return [row["id"] for row in conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()]

    ids = []
    if has_permission(user, "can_view_payroll", conn) or has_permission(user, "can_manage_payroll", conn):
        scope = permission_scope(user, conn)
        if scope == "all":
            ids = [row["id"] for row in conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()]
        elif scope == "subordinates" and user["employee_id"]:
            ids = get_subordinate_ids(conn, user["employee_id"])
        elif scope == "team_and_self" and user["employee_id"]:
            ids = [user["employee_id"], *get_subordinate_ids(conn, user["employee_id"])]

    if include_self and row_get(user, "employee_id") and user_can_view_own_payroll(user, conn):
        ids.append(row_get(user, "employee_id"))

    return list(dict.fromkeys([int(i) for i in ids if i]))


def user_can_manage_payroll_for(user, employee_id, conn=None):
    if not user or not employee_id:
        return False
    if not has_permission(user, "can_manage_payroll", conn):
        return False
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True
    try:
        managed_ids = payroll_employee_ids_for(user, conn, include_self=False)
        if permission_scope(user, conn) == "self" and row_get(user, "employee_id"):
            managed_ids.append(row_get(user, "employee_id"))
        return int(employee_id) in list(dict.fromkeys(managed_ids))
    finally:
        if should_close:
            conn.close()


def user_can_edit_salary(user):
    return bool(user and has_permission(user, "can_manage_payroll"))


def user_can_view_ticket(user, ticket):
    if not user or not ticket:
        return False

    if is_root_admin(user):
        return True

    if ticket["assigned_to"] and user["id"] == ticket["assigned_to"]:
        return True

    if user["employee_id"] and int(user["employee_id"]) == int(ticket["employee_id"]):
        return True

    if has_permission(user, "can_process_tickets"):
        conn = get_db()
        try:
            return int(ticket["employee_id"]) in ticket_employee_scope_ids(user, conn)
        finally:
            conn.close()

    return False


def user_can_process_ticket(user, ticket):
    if not user or not has_permission(user, "can_process_tickets"):
        return False

    if ticket["assigned_to"] and user["id"] == ticket["assigned_to"]:
        return True

    conn = get_db()
    try:
        scope = permission_scope(user, conn)

        if scope == "all":
            return True

        if scope in ["subordinates", "team_and_self"] and user["employee_id"]:
            return int(ticket["employee_id"]) in get_subordinate_ids(conn, user["employee_id"])

        return False
    finally:
        conn.close()


def ticket_employee_scope_ids(user, conn):
    """Employee ids whose tickets this user may process by permission scope."""
    if not user or not has_permission(user, "can_process_tickets", conn):
        return []

    if is_root_admin(user):
        rows = conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()
        return [int(r["id"]) for r in rows]

    scope = permission_scope(user, conn)
    employee_id = row_get(user, "employee_id")

    if scope == "all":
        rows = conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()
        return [int(r["id"]) for r in rows]
    if scope == "subordinates" and employee_id:
        return [int(i) for i in get_subordinate_ids(conn, employee_id)]
    if scope == "team_and_self" and employee_id:
        return [int(employee_id), *[int(i) for i in get_subordinate_ids(conn, employee_id)]]

    # Processing own tickets is intentionally not allowed by scope=self.
    return []


def ticket_visibility_sql_for_user(user, conn, table_prefix="tickets"):
    """SQL fragment for tickets visible to the user: own, assigned, or processable by scope."""
    if is_root_admin(user):
        return "1=1", []

    clauses = []
    params = []

    if row_get(user, "employee_id"):
        clauses.append(f"{table_prefix}.employee_id = ?")
        params.append(int(row_get(user, "employee_id")))

    clauses.append(f"{table_prefix}.assigned_to = ?")
    params.append(int(row_get(user, "id")))

    scoped_ids = ticket_employee_scope_ids(user, conn)
    if scoped_ids:
        placeholders = ",".join(["?"] * len(scoped_ids))
        clauses.append(f"{table_prefix}.employee_id IN ({placeholders})")
        params.extend(scoped_ids)

    if not clauses:
        return "0=1", []

    return "(" + " OR ".join(clauses) + ")", params


def next_escalation_user_id(conn, current_user_row):
    """Return the user id of the current handler's direct manager, if any."""
    employee_id = row_get(current_user_row, "employee_id")
    if not employee_id:
        return None
    return get_employee_manager_user_id(conn, employee_id)


def can_escalate_ticket(user, ticket, conn=None):
    if not user or not ticket:
        return False
    if not has_permission(user, "can_escalate_tickets", conn):
        return False
    if not user_can_process_ticket(user, ticket):
        return False
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True
    try:
        next_user = next_escalation_user_id(conn, user)
        return bool(next_user and int(next_user) != int(row_get(user, "id")))
    finally:
        if should_close:
            conn.close()

@app.template_filter("position_label")
def position_label_filter(value):
    return position_label(value)



@app.route("/set-language", methods=["POST"])
@login_required
def set_language():
    language = request.form.get("language", "bg")
    if language not in ["bg", "en"]:
        language = "bg"
    session["language"] = language
    return redirect(request.referrer or url_for("dashboard"))

# ---------------- AUTH ----------------

@app.route("/")
def index():
    return redirect(url_for("schedule"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["must_change_password"] = user["must_change_password"]

            if user["must_change_password"] == 1:
                flash("Трябва да смените временната си парола.", "info")
                return redirect(url_for("change_password"))

            flash("Успешен вход.", "success")
            return redirect(url_for("schedule"))

        flash("Грешно потребителско име или парола.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Излязохте от системата.", "info")
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(new_password) < 6:
            flash("Паролата трябва да е поне 6 символа.", "danger")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("Паролите не съвпадат.", "danger")
            return redirect(url_for("change_password"))

        conn = get_db()
        conn.execute("""
            UPDATE users
            SET password_hash = ?, must_change_password = 0
            WHERE id = ?
        """, (generate_password_hash(new_password), session["user_id"]))
        conn.commit()
        conn.close()

        session["must_change_password"] = 0

        flash("Паролата е сменена успешно.", "success")
        return redirect(url_for("schedule"))

    return render_template("change_password.html")


# ---------------- DASHBOARD ----------------

def default_after_denied_dashboard(user=None):
    user = user or current_user()
    if user and has_permission(user, "can_view_calendar"):
        return redirect(url_for("schedule"))
    if user and row_get(user, "employee_id"):
        return redirect(url_for("employee_profile", employee_id=user["employee_id"]))
    return redirect(url_for("settings"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()

    if not (is_root_admin(user) or has_permission(user, "can_view_dashboard")):
        flash("Нямате право да виждате Dashboard.", "danger")
        return default_after_denied_dashboard(user)

    conn = get_db()
    visible_ids = allowed_schedule_employee_ids(user, conn)

    if visible_ids:
        placeholders = ",".join(["?"] * len(visible_ids))
        rows = conn.execute(f"SELECT * FROM schedule WHERE employee_id IN ({placeholders})", visible_ids).fetchall()
        today_count = conn.execute(f"SELECT COUNT(*) AS c FROM schedule WHERE work_date = ? AND employee_id IN ({placeholders})", [date.today().isoformat(), *visible_ids]).fetchone()["c"]
        upcoming = conn.execute(f"""
            SELECT schedule.*, employees.first_name, employees.last_name, departments.name AS department
            FROM schedule
            JOIN employees ON employees.id = schedule.employee_id
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE work_date >= ? AND schedule.employee_id IN ({placeholders})
            ORDER BY work_date, start_time
            LIMIT 8
        """, [date.today().isoformat(), *visible_ids]).fetchall()
    else:
        rows = []
        today_count = 0
        upcoming = []

    total_hours = sum(calc_hours(r["start_time"], r["end_time"]) for r in rows)
    stats = {
        "employees": len(visible_ids),
        "departments": conn.execute("SELECT COUNT(*) AS c FROM departments").fetchone()["c"] if is_root_admin(user) or has_permission(user, "can_view_team", conn) else 0,
        "shifts": len(rows),
        "today": today_count if is_root_admin(user) or has_permission(user, "can_view_team", conn) else round(total_hours, 2)
    }

    conn.close()

    return render_template("dashboard.html", stats=stats, upcoming=upcoming)


# ---------------- EMPLOYEES ----------------

@app.route("/employees")
@login_required
def employees():
    user = current_user()
    q = request.args.get("q", "").strip()
    conn = get_db()

    if is_root_admin(user) or has_permission(user, "can_view_team", conn):
        scope = permission_scope(user, conn)
        if scope == "all":
            visible_ids = [row["id"] for row in conn.execute("SELECT id FROM employees WHERE active = 1").fetchall()]
        elif scope in ["subordinates", "team_and_self"] and user["employee_id"]:
            visible_ids = get_subordinate_ids(conn, user["employee_id"])
            if scope == "team_and_self":
                visible_ids = [user["employee_id"], *visible_ids]
        elif user["employee_id"]:
            visible_ids = [user["employee_id"]]
        else:
            visible_ids = []
    elif user["employee_id"]:
        visible_ids = [user["employee_id"]]
    else:
        visible_ids = []

    if visible_ids:
        placeholders = ",".join(["?"] * len(visible_ids))
        sql = f"""
            SELECT employees.*, departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.id IN ({placeholders})
        """
        params = list(dict.fromkeys(visible_ids))
        if q:
            sql += """
                AND (
                    first_name LIKE ?
                    OR last_name LIKE ?
                    OR email LIKE ?
                    OR departments.name LIKE ?
                )
            """
            like = f"%{q}%"
            params.extend([like, like, like, like])
        sql += " ORDER BY employees.id DESC"
        rows = conn.execute(sql, params).fetchall()
    else:
        rows = []

    conn.close()
    return render_template("employees.html", employees=rows, q=q)


@app.route("/employees/add", methods=["GET", "POST"])
@login_required
@manager_required
def employee_add():
    conn = get_db()
    departments = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()

    if request.method == "POST":
        try:
            now = datetime.now().isoformat(timespec="seconds")
            cur = conn.execute("""
                INSERT INTO employees
                (first_name, last_name, email, phone, department_id, hourly_rate, pay_type, monthly_gross, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request.form["first_name"],
                request.form["last_name"],
                request.form.get("email"),
                request.form.get("phone"),
                request.form.get("department_id") or None,
                float(request.form.get("hourly_rate") or 0),
                request.form.get("pay_type", "monthly"),
                float(request.form.get("monthly_gross") or 1000),
                now
            ))

            log_employee(cur.lastrowid, "Създаване", "Добавен нов служител", conn)
            conn.commit()
            flash("Служителят е добавен.", "success")
            return redirect(url_for("employees"))

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

    else:
        conn.close()

    return render_template("employee_form.html", employee=None, departments=departments, can_edit_pay_rate=has_permission(current_user(), "can_edit_pay_rate"))


@app.route("/employees/<int:employee_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def employee_edit(employee_id):
    user = current_user()
    conn = get_db()
    employee = conn.execute("SELECT * FROM employees WHERE id = ?", (employee_id,)).fetchone()
    departments = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()

    if not employee:
        conn.close()
        flash("Служителят не е намерен.", "danger")
        return redirect(url_for("employees"))

    if not user_can_manage_employee(user, employee_id, conn):
        conn.close()
        flash("Нямате права да редактирате този служител.", "danger")
        return redirect(url_for("employees"))

    if request.method == "POST":
        try:
            conn.execute("""
                UPDATE employees
                SET first_name = ?, last_name = ?, email = ?, phone = ?, department_id = ?, hourly_rate = ?, pay_type = ?, monthly_gross = ?
                WHERE id = ?
            """, (
                request.form["first_name"],
                request.form["last_name"],
                request.form.get("email"),
                request.form.get("phone"),
                request.form.get("department_id") or None,
                float(request.form.get("hourly_rate") or 0),
                request.form.get("pay_type", "monthly"),
                float(request.form.get("monthly_gross") or 1000),
                employee_id
            ))

            log_employee(employee_id, "Редакция", "Променени данни на служител", conn)
            conn.commit()
            flash("Промените са запазени.", "success")
            return redirect(url_for("employees"))

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

    else:
        conn.close()

    return render_template("employee_form.html", employee=employee, departments=departments, can_edit_pay_rate=has_permission(current_user(), "can_edit_pay_rate"))


@app.route("/employees/<int:employee_id>/delete", methods=["POST"])
@login_required
@manager_required
def employee_delete(employee_id):
    user = current_user()
    conn = get_db()
    if not user_can_manage_employee(user, employee_id, conn):
        conn.close()
        flash("Нямате права да деактивирате този служител.", "danger")
        return redirect(url_for("team"))
    try:
        conn.execute("UPDATE employees SET active = 0 WHERE id = ?", (employee_id,))
        log_employee(employee_id, "Деактивиране", "Служителят е маркиран като неактивен", conn)
        conn.commit()
        flash("Служителят е деактивиран.", "info")
    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("team"))

@app.route("/employees/<int:employee_id>/profile")
@login_required
def employee_profile(employee_id):
    user = current_user()

    conn = get_db()
    if not user_can_view_employee(user, employee_id, conn):
        conn.close()
        flash("Нямате право да виждате този профил.", "danger")
        return redirect(url_for("dashboard"))


    employee = conn.execute("""
        SELECT employees.*, departments.name AS department,
               manager.first_name AS manager_first_name,
               manager.last_name AS manager_last_name
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN employees AS manager ON manager.id = employees.manager_id
        WHERE employees.id = ?
    """, (employee_id,)).fetchone()

    today = date.today()
    seven_days_ago = (today - timedelta(days=7)).isoformat()

    schedules = conn.execute("""
        SELECT * FROM schedule
        WHERE employee_id = ?
          AND work_date BETWEEN ? AND ?
        ORDER BY work_date DESC, start_time DESC
    """, (employee_id, seven_days_ago, today.isoformat())).fetchall()

    logs = conn.execute("""
        SELECT * FROM employee_logs
        WHERE employee_id = ?
        ORDER BY created_at DESC
    """, (employee_id,)).fetchall()

    total_hours = sum(calc_hours(s["start_time"], s["end_time"]) for s in schedules)
    shift_count = len(schedules)

    # Sick days for the current month if payroll item exists.
    sick_row = conn.execute("""
        SELECT sick_days FROM payroll_items
        WHERE employee_id = ? AND year = ? AND month = ?
    """, (employee_id, today.year, today.month)).fetchone()
    sick_days = int(row_get(sick_row, "sick_days", 0) or 0)

    can_view_profile_salary = user_can_view_salary(user, employee_id)
    salary = None
    if can_view_profile_salary:
        # Use payroll engine for current month salary when available, but expose it only to users with salary/payroll access.
        payroll_row = calculate_employee_payroll(conn, employee_id, today.year, today.month)
        salary = row_get(payroll_row, "net_total", 0) if payroll_row else round(total_hours * float(row_get(employee, "hourly_rate", 0) or 0), 2)

    conn.close()

    return render_template(
        "profile.html",
        employee=employee,
        schedules=schedules,
        logs=logs,
        total_hours=total_hours,
        salary=salary,
        can_view_profile_salary=can_view_profile_salary,
        shift_count=shift_count,
        sick_days=sick_days
    )


@app.route("/employees/<int:employee_id>/profile-update", methods=["POST"])
@login_required
def employee_profile_update_contact(employee_id):
    user = current_user()

    can_edit = (
        is_root_admin(user)
        or has_permission(user, "can_manage_users")
        or (user["employee_id"] == employee_id)
    )

    if not can_edit:
        flash("Нямате право да редактирате този профил.", "danger")
        return redirect(url_for("employee_profile", employee_id=employee_id))

    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    photo_name = None

    try:
        if request.files.get("photo") and request.files["photo"].filename:
            photo_name = save_uploaded_file(request.files.get("photo"))

        conn = get_db()
        if photo_name:
            conn.execute("UPDATE employees SET email=?, phone=?, photo=? WHERE id=?", (email, phone, photo_name, employee_id))
        else:
            conn.execute("UPDATE employees SET email=?, phone=? WHERE id=?", (email, phone, employee_id))

        log_employee(employee_id, "Профил", "Обновени профилни данни", conn)
        conn.commit()
        conn.close()
        if wants_json_response():
            return jsonify({"ok": True, "message": "Профилът е обновен.", "email": email, "phone": phone, "photo": photo_name})
        flash("Профилът е обновен.", "success")

    except Exception as e:
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка при обновяване на профила: {e}"}), 500
        flash(f"Грешка при обновяване на профила: {e}", "danger")

    return redirect(url_for("employee_profile", employee_id=employee_id))


# ---------------- USERS MANAGEMENT ----------------

@app.route("/users")
@login_required
@manager_required
def users():
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до потребители.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    rows = conn.execute("""
        SELECT users.*, employees.first_name, employees.last_name,
               employees.email, employees.phone, employees.photo,
               employees.position, employees.manager_id
        FROM users
        LEFT JOIN employees ON employees.id = users.employee_id
        ORDER BY users.id DESC
    """).fetchall()

    employees_list = conn.execute("""
        SELECT * FROM employees
        WHERE active = 1
        ORDER BY first_name, last_name
    """).fetchall()

    conn.close()

    return render_template("users.html", users=rows, employees=employees_list)


@app.route("/users/add", methods=["POST"])
@login_required
@manager_required
def user_add():
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до потребители.", "danger")
        return redirect(url_for("dashboard"))

    username = request.form.get("username", "").strip()
    role = request.form.get("role")
    employee_id = request.form.get("employee_id") or None

    if not username or role not in ["manager", "employee"]:
        flash("Попълнете правилно данните.", "danger")
        return redirect(url_for("users"))

    if role == "employee" and not employee_id:
        flash("Служителски акаунт трябва да е свързан със служител.", "danger")
        return redirect(url_for("users"))

    if role == "manager":
        employee_id = None

    temp_password = secrets.token_urlsafe(8)
    conn = get_db()

    try:
        conn.execute("""
            INSERT INTO users
            (username, password_hash, role, employee_id, must_change_password)
            VALUES (?, ?, ?, ?, 1)
        """, (username, generate_password_hash(temp_password), role, employee_id))

        conn.commit()
        if wants_json_response():
            return jsonify({"ok": True, "message": f"Потребителят е създаден. Временна парола: {temp_password}", "redirect": url_for("users")})
        flash(f"Потребителят е създаден. Временна парола: {temp_password}", "success")

    except Exception as e:
        conn.rollback()
        if is_integrity_error(e):
            if wants_json_response():
                return jsonify({"ok": False, "message": "Потребителското име вече съществува."}), 400
            flash("Потребителското име вече съществува.", "danger")
        else:
            flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@manager_required
def user_reset_password(user_id):
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до потребители.", "danger")
        return redirect(url_for("dashboard"))

    temp_password = secrets.token_urlsafe(8)
    conn = get_db()

    try:
        conn.execute("""
            UPDATE users
            SET password_hash = ?, must_change_password = 1
            WHERE id = ?
        """, (generate_password_hash(temp_password), user_id))

        conn.commit()
        flash(f"Новата временна парола е: {temp_password}", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@manager_required
def user_delete(user_id):
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до потребители.", "danger")
        return redirect(url_for("dashboard"))

    if user_id == session.get("user_id"):
        flash("Не можете да изтриете собствения си акаунт.", "danger")
        return redirect(url_for("users"))

    conn = get_db()

    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash("Потребителят е изтрит.", "info")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("users"))


# ---------------- SCHEDULE ----------------

@app.route("/schedule", methods=["GET", "POST"])
@login_required
def schedule():
    user = current_user()
    conn = get_db()

    if request.method == "GET" and not has_permission(user, "can_view_calendar", conn):
        conn.close()
        flash("Нямате достъп до календара.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        today = date.today()
        if not manageable_schedule_employee_ids(user, conn):
            conn.close()
            return json_or_redirect(False, "Нямате права за добавяне на смени.", url_for("schedule", edit=1), 403)

        try:
            employee_ids = request.form.getlist("employee_ids")
            work_date = request.form["work_date"]
            start_time = request.form["start_time"]
            end_time = request.form["end_time"]
            notes = request.form.get("notes")
            now = datetime.now().isoformat(timespec="seconds")

            wd = datetime.strptime(work_date, "%Y-%m-%d").date()
            if is_schedule_month_locked(conn, wd.year, wd.month):
                return json_or_redirect(False, "Месецът е заключен след обработка на заплати. Отключете го, за да редактирате.", url_for("schedule", view="week", week_start=work_date, year=wd.year, month=wd.month), 423)

            if not employee_ids:
                return json_or_redirect(False, "Изберете поне един служител.", url_for("schedule", view="week", week_start=work_date, year=work_date[:4], month=work_date[5:7], edit=1), 400)

            allow_non_working = request.form.get("allow_non_working") == "1"
            if is_non_working_day(work_date) and not allow_non_working:
                return json_or_redirect(False, "Денят е почивен/празничен. Отбележете, че се налага работа в почивен ден.", url_for("schedule", view="week", week_start=work_date, year=work_date[:4], month=work_date[5:7], edit=1), 400)

            skipped = []
            created_shifts = []
            added = 0
            new_hours = calc_hours(start_time, end_time)

            for employee_id in employee_ids:
                if not user_can_manage_schedule_for(user, int(employee_id), conn):
                    er = conn.execute("SELECT first_name,last_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                    skipped.append(f"{er['first_name']} {er['last_name']}" if er else str(employee_id))
                    continue

                current_hours = employee_week_hours(conn, employee_id, work_date)
                if current_hours + new_hours > WEEKLY_SCHEDULE_HOUR_LIMIT:
                    er = conn.execute("SELECT first_name,last_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                    skipped.append(f"{er['first_name']} {er['last_name']}" if er else str(employee_id))
                    continue

                shift_notes = (notes or "") + (" · Работа в почивен/празничен ден" if is_non_working_day(work_date) else "")
                cur = conn.execute("""
                    INSERT INTO schedule
                    (employee_id, work_date, start_time, end_time, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    employee_id,
                    work_date,
                    start_time,
                    end_time,
                    shift_notes,
                    now,
                    now
                ))

                # Cross-db safe fetch of the newly inserted row.
                new_shift = conn.execute("""
                    SELECT schedule.*, employees.first_name, employees.last_name, departments.name AS department
                    FROM schedule
                    JOIN employees ON employees.id = schedule.employee_id
                    LEFT JOIN departments ON departments.id = employees.department_id
                    WHERE schedule.employee_id = ?
                      AND schedule.work_date = ?
                      AND schedule.start_time = ?
                      AND schedule.end_time = ?
                      AND schedule.created_at = ?
                    ORDER BY schedule.id DESC
                    LIMIT 1
                """, (employee_id, work_date, start_time, end_time, now)).fetchone()

                if new_shift:
                    created_shifts.append({
                        "id": new_shift["id"],
                        "work_date": new_shift["work_date"],
                        "start_time": new_shift["start_time"],
                        "end_time": new_shift["end_time"],
                        "first_name": new_shift["first_name"],
                        "last_name": new_shift["last_name"],
                        "department": row_get(new_shift, "department", "-") or "-",
                        "notes": row_get(new_shift, "notes", "") or "",
                    })

                log_employee(int(employee_id), "Смяна", f"Добавена смяна за {work_date}", conn)
                added += 1

                target_user_id = user_id_for_employee(employee_id, conn)
                if target_user_id:
                    notify_user(
                        target_user_id,
                        "Нова смяна",
                        f"Добавена е смяна за {work_date} от {start_time} до {end_time}.",
                        url_for("schedule", view="month", year=work_date[:4], month=work_date[5:7], open_day=work_date),
                        conn
                    )

            conn.commit()
            message_parts = []
            if added:
                message_parts.append("Смените са добавени.")
            if skipped:
                message_parts.append(f"Пропуснати заради лимит {WEEKLY_SCHEDULE_HOUR_LIMIT}ч/седмица: " + ", ".join(skipped))
            message = " ".join(message_parts) or "Няма добавени смени."
            target = url_for("schedule", view="week", week_start=work_date, year=work_date[:4], month=work_date[5:7], edit=1)
            if wants_json_response():
                return jsonify({"ok": added > 0, "message": message, "redirect": target, "added": added, "skipped": skipped, "shifts": created_shifts})
            if skipped:
                flash(f"Пропуснати заради лимит {WEEKLY_SCHEDULE_HOUR_LIMIT}ч/седмица: " + ", ".join(skipped), "info")
            if added:
                flash("Смените са добавени.", "success")
            return redirect(target)

        except Exception as e:
            conn.rollback()
            target = url_for("schedule")
            if wants_json_response():
                return jsonify({"ok": False, "message": f"Грешка: {e}", "redirect": target}), 500
            flash(f"Грешка: {e}", "danger")
            return redirect(target)
        finally:
            conn.close()

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))
    scope = request.args.get("scope", "allowed")
    view = request.args.get("view", "week")
    if view not in ["month", "week"]:
        view = "week"

    edit_mode = request.args.get("edit") == "1"
    selected_employee_id = request.args.get("employee_id", "").strip()
    selected_department_id = request.args.get("department_id", "").strip()

    if month < 1:
        month = 12
        year -= 1
    if month > 12:
        month = 1
        year += 1

    schedule_locked = is_schedule_month_locked(conn, year, month)
    can_unlock_schedule = bool(is_root_admin(user))
    if schedule_locked:
        edit_mode = False

    first_day = date(year, month, 1)
    last_day_num = calendar.monthrange(year, month)[1]
    last_day = date(year, month, last_day_num)

    week_start_param = request.args.get("week_start")
    if view == "week":
        try:
            selected_week_day = datetime.strptime(week_start_param, "%Y-%m-%d").date() if week_start_param else today
        except Exception:
            selected_week_day = today
        # App-style 7-day view: start exactly from the selected day.
        # Without week_start this means today is always the first visible day.
        display_start = selected_week_day
        display_end = display_start + timedelta(days=6)
    else:
        display_start = first_day
        display_end = last_day

    prev_month = month - 1
    prev_year = year
    if prev_month < 1:
        prev_month = 12
        prev_year -= 1

    next_month = month + 1
    next_year = year
    if next_month > 12:
        next_month = 1
        next_year += 1

    if view == "week":
        month_days = [(display_start + timedelta(days=i)).isoformat() for i in range(7)]
        calendar_cells = month_days[:]
    else:
        month_days = [date(year, month, day).isoformat() for day in range(1, last_day_num + 1)]
        first_weekday = first_day.weekday()
        calendar_cells = [None] * first_weekday + month_days
        while len(calendar_cells) % 7 != 0:
            calendar_cells.append(None)

    allowed_ids = allowed_schedule_employee_ids(user, conn)
    manageable_ids = manageable_schedule_employee_ids(user, conn)

    # Scope filters are still restricted by backend permissions.
    if scope == "me" and user["employee_id"]:
        visible_ids = [user["employee_id"]] if user["employee_id"] in allowed_ids else []
    elif scope == "team" and user["employee_id"]:
        team_ids = get_subordinate_ids(conn, user["employee_id"])
        visible_ids = [eid for eid in team_ids if eid in allowed_ids]
    else:
        visible_ids = allowed_ids[:]

    if selected_employee_id:
        try:
            eid = int(selected_employee_id)
            visible_ids = [eid] if eid in visible_ids else []
        except ValueError:
            visible_ids = []

    params = []
    employee_filter_sql = " AND 1 = 0"
    if visible_ids:
        placeholders = ",".join(["?"] * len(visible_ids))
        employee_filter_sql = f" AND schedule.employee_id IN ({placeholders})"
        params.extend(visible_ids)

    department_filter_sql = ""
    if selected_department_id:
        department_filter_sql = " AND employees.department_id = ?"
        params.append(selected_department_id)

    rows = conn.execute(f"""
        SELECT schedule.*, employees.first_name, employees.last_name,
               departments.name AS department, employees.hourly_rate
        FROM schedule
        JOIN employees ON employees.id = schedule.employee_id
        LEFT JOIN departments ON departments.id = employees.department_id
        WHERE schedule.work_date BETWEEN ? AND ?
        {employee_filter_sql}
        {department_filter_sql}
        ORDER BY schedule.work_date, schedule.start_time
    """, [display_start.isoformat(), display_end.isoformat(), *params]).fetchall()

    if allowed_ids:
        placeholders = ",".join(["?"] * len(allowed_ids))
        filter_employees = conn.execute(f"""
            SELECT employees.*, departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.active = 1 AND employees.id IN ({placeholders})
            ORDER BY employees.first_name, employees.last_name
        """, allowed_ids).fetchall()
    else:
        filter_employees = []

    if manageable_ids:
        placeholders = ",".join(["?"] * len(manageable_ids))
        employees_list = conn.execute(f"""
            SELECT employees.*, departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.active = 1 AND employees.id IN ({placeholders})
            ORDER BY employees.first_name, employees.last_name
        """, manageable_ids).fetchall()
    else:
        employees_list = []

    departments = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()
    templates = conn.execute("SELECT * FROM shift_templates ORDER BY start_time").fetchall()
    can_send_payroll_report_value = bool(
        is_root_admin(user)
        or get_user_permissions(conn, user).get("can_send_schedule_to_payroll")
    )
    conn.close()

    by_day = {d: [] for d in month_days}
    for row in rows:
        by_day[row["work_date"]].append(row)

    month_names = {
        1: "Януари", 2: "Февруари", 3: "Март", 4: "Април", 5: "Май", 6: "Юни",
        7: "Юли", 8: "Август", 9: "Септември", 10: "Октомври", 11: "Ноември", 12: "Декември"
    }

    return render_template(
        "schedule.html",
        days=month_days,
        calendar_cells=calendar_cells,
        by_day=by_day,
        employees=employees_list,
        filter_employees=filter_employees,
        departments=departments,
        templates=templates,
        year=year,
        month=month,
        month_name=month_names[month],
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        view=view,
        week_start=display_start.isoformat(),
        prev_week_start=(display_start - timedelta(days=7)).isoformat(),
        next_week_start=(display_start + timedelta(days=7)).isoformat(),
        display_start=display_start.isoformat(),
        display_end=display_end.isoformat(),
        holidays=BULGARIA_HOLIDAYS_2026 if "BULGARIA_HOLIDAYS_2026" in globals() else {},
        scope=scope,
        selected_employee_id=selected_employee_id,
        selected_department_id=selected_department_id,
        can_send_payroll_report=bool(has_permission(user, "can_send_schedule_to_payroll")),
        edit_mode=edit_mode,
        can_edit_schedule=bool(manageable_ids) and not schedule_locked,
        schedule_locked=schedule_locked,
        can_unlock_schedule=can_unlock_schedule,
        today_iso=date.today().isoformat(),
        weekday_labels=(lambda labels, start: labels[start:] + labels[:start])(["Пон", "Вто", "Сря", "Чет", "Пет", "Съб", "Нед"], display_start.weekday())
    )


@app.route("/schedule/unlock-month", methods=["POST"])
@login_required
def schedule_unlock_month():
    user = current_user()
    year = int(request.form.get("year"))
    month = int(request.form.get("month"))

    if not is_root_admin(user):
        flash("Само админ може да отключва заключен график.", "danger")
        return redirect(url_for("schedule", year=year, month=month))

    conn = get_db()
    try:
        unlock_schedule_month(conn, year, month)
        conn.commit()
        flash("Месецът е отключен за редакция.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Грешка при отключване: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for("schedule", view="month", year=year, month=month, edit=1))


@app.route("/schedule/<int:shift_id>/delete", methods=["POST"])
@login_required
def schedule_delete(shift_id):
    conn = get_db()

    try:
        row = conn.execute("SELECT * FROM schedule WHERE id = ?", (shift_id,)).fetchone()

        if row:
            wd = datetime.strptime(row["work_date"], "%Y-%m-%d").date()
            target = url_for("schedule", view="month", year=wd.year, month=wd.month, open_day=row["work_date"])
            if is_schedule_month_locked(conn, wd.year, wd.month):
                return json_or_redirect(False, "Този месец е заключен и смяната не може да се изтрие.", target, 423)

            if not user_can_manage_schedule_for(current_user(), int(row["employee_id"]), conn):
                return json_or_redirect(False, "Нямате права да изтриете тази смяна.", url_for("schedule"), 403)

            conn.execute("DELETE FROM schedule WHERE id = ?", (shift_id,))
            log_employee(row["employee_id"], "Изтрита смяна", f"Изтрита смяна за {row['work_date']}", conn)

            target_user_id = user_id_for_employee(row["employee_id"], conn)
            if target_user_id:
                notify_user(target_user_id, "Изтрита смяна", f"Смяната за {row['work_date']} беше изтрита.", target, conn)

            conn.commit()
            return json_or_redirect(True, "Смяната е изтрита.", url_for("schedule", view="month", year=wd.year, month=wd.month), shift_id=shift_id, work_date=row["work_date"])

        else:
            return json_or_redirect(False, "Смяната не е намерена.", url_for("schedule"), 404)

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}", "redirect": url_for("schedule")}), 500
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/api/schedule/<int:shift_id>/move", methods=["POST"])
@login_required
def move_shift(shift_id):
    data = request.get_json(force=True)
    new_date = data.get("work_date")

    if not new_date:
        return jsonify({"ok": False, "error": "Missing date"}), 400

    conn = get_db()

    try:
        row = conn.execute("SELECT * FROM schedule WHERE id = ?", (shift_id,)).fetchone()

        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Shift not found"}), 404

        old_date = datetime.strptime(row["work_date"], "%Y-%m-%d").date()
        new_date_obj = datetime.strptime(new_date, "%Y-%m-%d").date()
        if is_schedule_month_locked(conn, old_date.year, old_date.month) or is_schedule_month_locked(conn, new_date_obj.year, new_date_obj.month):
            conn.close()
            return jsonify({"ok": False, "error": "Schedule month locked"}), 403

        if not user_can_manage_schedule_for(current_user(), int(row["employee_id"]), conn):
            conn.close()
            return jsonify({"ok": False, "error": "Нямате права за тази смяна."}), 403

        conn.execute("UPDATE schedule SET work_date = ?, updated_at = ? WHERE id = ?", (new_date, datetime.now().isoformat(timespec="seconds"), shift_id))
        log_employee(row["employee_id"], "Преместена смяна", f"Смяната е преместена на {new_date}", conn)

        target_user_id = user_id_for_employee(row["employee_id"], conn)
        if target_user_id:
            notify_user(target_user_id, "Преместена смяна", f"Смяната е преместена на {new_date}.", url_for("schedule", view="month", year=new_date_obj.year, month=new_date_obj.month, open_day=new_date), conn)

        conn.commit()
        return jsonify({"ok": True})

    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

    finally:
        conn.close()


@app.route("/generate-schedule", methods=["POST"])
@login_required
def generate_schedule():
    user = current_user()
    conn = get_db()

    try:
        manageable_ids = manageable_schedule_employee_ids(user, conn)
        if not manageable_ids:
            flash("Нямате права за генериране на график или нямате подчинени.", "danger")
            conn.close()
            return redirect(url_for("schedule"))

        placeholders = ",".join(["?"] * len(manageable_ids))
        employees_list = conn.execute(f"SELECT * FROM employees WHERE active = 1 AND id IN ({placeholders})", manageable_ids).fetchall()
        templates_list = conn.execute("SELECT * FROM shift_templates ORDER BY start_time").fetchall()

        if not employees_list:
            flash("Няма активни служители.", "danger")
            conn.close()
            return redirect(url_for("schedule"))

        if not templates_list:
            flash("Няма готови смени.", "danger")
            conn.close()
            return redirect(url_for("schedule"))

        today = date.today()
        year = int(request.form.get("year", today.year))
        month = int(request.form.get("month", today.month))
        start_day = date(year, month, 1)
        now = datetime.now().isoformat(timespec="seconds")

        employee_load = {emp["id"]: 0 for emp in employees_list}
        generated_notifications = {}

        month_last = date(year, month, calendar.monthrange(year, month)[1])
        existing = conn.execute("""
            SELECT employee_id, COUNT(*) AS c
            FROM schedule
            WHERE work_date BETWEEN ? AND ?
            GROUP BY employee_id
        """, (start_day.isoformat(), month_last.isoformat())).fetchall()

        for item in existing:
            employee_load[item["employee_id"]] = item["c"]

        for i in range(calendar.monthrange(year, month)[1]):
            day = (start_day + timedelta(days=i)).isoformat()

            already_for_day = conn.execute("""
                SELECT employee_id FROM schedule WHERE work_date = ?
            """, (day,)).fetchall()
            already_ids = {r["employee_id"] for r in already_for_day}

            available = [emp for emp in employees_list if emp["id"] not in already_ids]
            available.sort(key=lambda emp: employee_load.get(emp["id"], 0))

            selected = available[:min(2, len(available))]

            for idx, emp in enumerate(selected):
                tmpl = templates_list[idx % len(templates_list)]

                conn.execute("""
                    INSERT INTO schedule
                    (employee_id, work_date, start_time, end_time, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    emp["id"],
                    day,
                    tmpl["start_time"],
                    tmpl["end_time"],
                    "Умен автоматичен график",
                    now,
                    now
                ))

                employee_load[emp["id"]] = employee_load.get(emp["id"], 0) + 1
                log_employee(emp["id"], "Автоматичен график", f"Генерирана смяна за {day}", conn)

                target_user_id = user_id_for_employee(emp["id"], conn)
                if target_user_id:
                    generated_notifications[target_user_id] = generated_notifications.get(target_user_id, 0) + 1

        for target_user_id, count in generated_notifications.items():
            notify_user(
                target_user_id,
                "Нов график",
                f"Имате {count} нови смени в графика.",
                url_for("schedule", view="month", year=year, month=month),
                conn
            )

        conn.commit()
        flash("Умният автоматичен график е генериран.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка при генериране: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("schedule"))


# ---------------- TICKETS ----------------

TICKET_AUTO_ARCHIVE_MINUTES = 10

def auto_archive_read_tickets(conn):
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute("""
        UPDATE tickets
        SET archived = 1,
            status = 'archived',
            completed_at = COALESCE(completed_at, ?),
            updated_at = ?
        WHERE archive_after_at IS NOT NULL
          AND archive_after_at <= ?
          AND COALESCE(archived, 0) = 0
          AND status = 'read'
    """, (now, now, now))



def ticket_count_where_for_user(user, conn=None):
    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True
    try:
        where, params = ticket_visibility_sql_for_user(user, conn, table_prefix="tickets")
        return "WHERE " + where, params
    finally:
        if should_close:
            conn.close()


def ticket_counts_for_user(conn, user):
    count_where, count_params = ticket_count_where_for_user(user, conn)
    return {
        "new": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='new'", count_params).fetchone()["c"],
        "pending": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='pending'", count_params).fetchone()["c"],
        "answered": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status IN ('approved','rejected')", count_params).fetchone()["c"],
        "read": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='read'", count_params).fetchone()["c"],
        "archived": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND (COALESCE(archived,0)=1 OR status='archived')", count_params).fetchone()["c"],
    }

def ticket_bucket(ticket):
    archived = int(row_get(ticket, "archived", 0) or 0)
    status = row_get(ticket, "status", "pending") or "pending"
    if archived or status == "archived":
        return "archived"
    if status == "new":
        return "new"
    if status == "pending":
        return "pending"
    if status in ["approved", "rejected"]:
        return "answered"
    if status == "read":
        return "read"
    return "pending"

@app.route("/tickets")
@login_required
def tickets():
    user = current_user()
    if is_finance(user):
        flash("Финансовият отдел работи само със заплати, бонуси и корекции.", "info")
        return redirect(url_for("salaries"))

    q = request.args.get("q", "").strip()
    bucket = request.args.get("bucket", request.args.get("status", "new"))
    if bucket == "active":
        bucket = "new"
    if bucket not in ["new", "pending", "answered", "read", "archived"]:
        bucket = "new"

    conn = get_db()
    auto_archive_read_tickets(conn)
    conn.commit()

    sql = """
        SELECT tickets.*, employees.first_name, employees.last_name, assigned.username AS assigned_username
        FROM tickets
        JOIN employees ON employees.id = tickets.employee_id
        LEFT JOIN users AS assigned ON assigned.id = tickets.assigned_to
        WHERE 1=1
    """
    params = []

    if bucket == "archived":
        sql += " AND (COALESCE(tickets.archived, 0) = 1 OR tickets.status = 'archived')"
    elif bucket == "new":
        sql += " AND COALESCE(tickets.archived, 0) = 0 AND tickets.status = 'new'"
    elif bucket == "pending":
        sql += " AND COALESCE(tickets.archived, 0) = 0 AND tickets.status = 'pending'"
    elif bucket == "answered":
        sql += " AND COALESCE(tickets.archived, 0) = 0 AND tickets.status IN ('approved','rejected')"
    elif bucket == "read":
        sql += " AND COALESCE(tickets.archived, 0) = 0 AND tickets.status = 'read'"

    visibility_sql, visibility_params = ticket_visibility_sql_for_user(user, conn, table_prefix="tickets")
    sql += " AND " + visibility_sql
    params.extend(visibility_params)

    if q:
        sql += " AND (tickets.title LIKE ? OR tickets.description LIKE ? OR tickets.type LIKE ? OR tickets.status LIKE ? OR employees.first_name LIKE ? OR employees.last_name LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like, like, like, like])

    sql += " ORDER BY tickets.updated_at DESC, tickets.created_at DESC"
    rows = conn.execute(sql, params).fetchall()

    count_where, count_params = ticket_count_where_for_user(user, conn)

    counts = {
        "new": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='new'", count_params).fetchone()["c"],
        "pending": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='pending'", count_params).fetchone()["c"],
        "answered": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status IN ('approved','rejected')", count_params).fetchone()["c"],
        "read": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND COALESCE(archived,0)=0 AND status='read'", count_params).fetchone()["c"],
        "archived": conn.execute("SELECT COUNT(*) AS c FROM tickets " + count_where + " AND (COALESCE(archived,0)=1 OR status='archived')", count_params).fetchone()["c"],
    }

    conn.close()
    return render_template("tickets.html", tickets=rows, q=q, bucket=bucket, counts=counts, show_archived=(bucket=="archived"), active_count=counts["new"]+counts["pending"]+counts["answered"]+counts["read"], archived_count=counts["archived"])


@app.route("/tickets/<int:ticket_id>/open", methods=["POST"])
@login_required
def ticket_open(ticket_id):
    user = current_user()
    conn = get_db()
    try:
        auto_archive_read_tickets(conn)
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"ok": False, "message": "Заявката не е намерена."}), 404

        if not user_can_view_ticket(user, ticket):
            return jsonify({"ok": False, "message": "Нямате достъп до тази заявка."}), 403

        now = datetime.now().isoformat(timespec="seconds")
        is_owner = user["employee_id"] and int(user["employee_id"]) == int(ticket["employee_id"])
        can_process = user_can_process_ticket(user, ticket)

        if can_process and ticket["status"] == "new":
            conn.execute("""
                UPDATE tickets
                SET status='pending', manager_seen_at=?, updated_at=?
                WHERE id=?
            """, (now, now, ticket_id))
            counts = ticket_counts_for_user(conn, user)
            conn.commit()
            return jsonify({"ok": True, "message": "Заявката е маркирана като видяна.", "status": "pending", "status_label": "Чака", "counts": counts})

        if is_owner and ticket["status"] in ["approved", "rejected"] and not row_get(ticket, "employee_seen_at"):
            archive_after = (datetime.now() + timedelta(minutes=TICKET_AUTO_ARCHIVE_MINUTES)).isoformat(timespec="seconds")
            conn.execute("""
                UPDATE tickets
                SET status='read', employee_seen_at=?, archive_after_at=?, updated_at=?
                WHERE id=?
            """, (now, archive_after, now, ticket_id))
            counts = ticket_counts_for_user(conn, user)
            conn.commit()
            return jsonify({"ok": True, "message": "Отговорът е маркиран като прочетен.", "status": "read", "status_label": "Прочетено", "archive_after_at": archive_after, "counts": counts})

        counts = ticket_counts_for_user(conn, user)
        conn.commit()
        return jsonify({"ok": True, "message": "Отворено.", "status": ticket["status"], "counts": counts})

    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
    finally:
        conn.close()

@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def ticket_new():
    user = current_user()

    if not user["employee_id"]:
        flash("Този акаунт не е свързан със служител и не може да създава заявки.", "danger")
        return redirect(url_for("tickets"))

    if not has_permission(user, "can_create_tickets"):
        flash("Нямате право да създавате заявки.", "danger")
        return redirect(url_for("tickets"))

    if request.method == "POST":
        conn = get_db()

        try:
            now = datetime.now().isoformat(timespec="seconds")
            ticket_type = request.form.get("type", "")
            uploaded_attachment = request.files.get("attachment")
            if uploaded_attachment and uploaded_attachment.filename and ticket_absence_type(ticket_type) != "sick":
                raise ValueError("Файл може да се прикачва само към заявка за болничен.")
            attachment_name = save_uploaded_file(uploaded_attachment) if ticket_absence_type(ticket_type) == "sick" else None

            assigned_to = get_employee_manager_user_id(conn, user["employee_id"])
            ticket_cur = conn.execute("""
                INSERT INTO tickets
                (employee_id, type, title, description, start_date, end_date, status, manager_comment, attachment, assigned_to, approval_level, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user["employee_id"],
                ticket_type,
                request.form["title"],
                request.form.get("description"),
                request.form.get("start_date") or None,
                request.form.get("end_date") or None,
                "new",
                None,
                attachment_name,
                assigned_to,
                1,
                now,
                now
            ))

            ticket_id = ticket_cur.lastrowid
            ticket_link = url_for("tickets", bucket="new", open_ticket=ticket_id)
            if assigned_to:
                notify_user(assigned_to, "Нова заявка", f"{user['first_name'] or user['username']} изпрати заявка: {request.form['title']}", ticket_link, conn)
            else:
                notify_managers("Нова заявка", f"{user['first_name'] or user['username']} изпрати заявка: {request.form['title']}", ticket_link, conn)

            conn.commit()
            if wants_json_response():
                return jsonify({"ok": True, "message": "Заявката е изпратена.", "redirect": url_for("tickets")})
            flash("Заявката е изпратена.", "success")
            return redirect(url_for("tickets"))

        except Exception as e:
            conn.rollback()
            if wants_json_response():
                return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

    return render_template("ticket_form.html")


@app.route("/tickets/<int:ticket_id>/update", methods=["POST"])
@login_required
def ticket_update(ticket_id):
    raw_status = (request.form.get("status") or "").strip()
    manager_comment = request.form.get("manager_comment", "")

    status_map = {
        "чака": "pending",
        "чакащ": "pending",
        "чакаща": "pending",
        "pending": "pending",
        "одобрено": "approved",
        "одобрена": "approved",
        "approved": "approved",
        "отказано": "rejected",
        "отказана": "rejected",
        "rejected": "rejected",
        "приключено": "closed",
        "приключена": "closed",
        "closed": "closed",
        "архив": "archived",
        "архивирано": "archived",
        "archived": "archived",
        "прочетено": "read",
        "read": "read",
    }
    allowed = ["pending", "approved", "rejected", "closed", "archived", "read"]

    conn = get_db()

    try:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()

        if not ticket:
            if wants_json_response():
                return jsonify({"ok": False, "message": "Заявката не е намерена."}), 404
            flash("Заявката не е намерена.", "danger")
            return redirect(url_for("tickets"))

        if not user_can_process_ticket(current_user(), ticket):
            if wants_json_response():
                return jsonify({"ok": False, "message": "Нямате права да обработвате тази заявка."}), 403
            flash("Нямате права да обработвате тази заявка.", "danger")
            return redirect(url_for("tickets"))

        # Ако формата е само за коментар и не подаде статус, запази текущия статус.
        if not raw_status:
            status = row_get(ticket, "status", "pending") or "pending"
        else:
            status = status_map.get(raw_status.lower(), raw_status)

        if status not in allowed:
            if wants_json_response():
                return jsonify({"ok": False, "message": f"Невалиден статус: {raw_status}"}), 400
            flash(f"Невалиден статус: {raw_status}", "danger")
            return redirect(url_for("tickets"))

        now = datetime.now().isoformat(timespec="seconds")
        archive_value = 1 if status in ["closed", "archived"] else 0
        responded_at = now if status in ["approved", "rejected", "closed"] else row_get(ticket, "responded_at")

        conn.execute("""
            UPDATE tickets
            SET status = ?, manager_comment = ?, archived = ?, responded_at = ?, updated_at = ?
            WHERE id = ?
        """, (status, manager_comment, archive_value, responded_at, now, ticket_id))

        if status == "approved" and ticket_absence_type(ticket["type"]):
            remove_employee_shifts_for_period(conn, ticket["employee_id"], ticket["start_date"], ticket["end_date"], ticket["type"])
            create_absence_calendar_entries(conn, ticket)
            notify_coworkers_about_absence(conn, ticket["employee_id"], ticket["start_date"], ticket["end_date"], ticket["type"])

        mark_ticket_notifications_processed(ticket_id, ticket["employee_id"], ticket["assigned_to"], conn)

        target_user_id = user_id_for_employee(ticket["employee_id"], conn)
        if target_user_id:
            labels = {"pending": "чака", "approved": "одобрена", "rejected": "отказана", "closed": "приключена", "read": "прочетена"}
            target_bucket = "pending" if status == "pending" else "answered" if status in ["approved", "rejected"] else "read" if status == "read" else "archived" if status in ["closed", "archived"] else "new"
            notify_user(target_user_id, "Обновена заявка", f"Заявката '{ticket['title']}' е {labels.get(status, status)}.", url_for("tickets", bucket=target_bucket, open_ticket=ticket_id), conn)

        counts = ticket_counts_for_user(conn, current_user()) if wants_json_response() else None
        conn.commit()

        if wants_json_response():
            labels = {"pending": "Чака", "approved": "Одобрено", "rejected": "Отказано", "closed": "Приключено", "read": "Прочетено"}
            return jsonify({"ok": True, "message": "Заявката е обновена.", "status": status, "status_label": labels.get(status, status), "archived": archive_value, "counts": counts})

        flash("Заявката е обновена.", "success")

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("tickets"))


# ---------------- NOTIFICATIONS ----------------

@app.route("/notifications")
@login_required
def notifications():
    user = current_user()
    if is_finance(user):
        flash("Финансовият отдел няма нужда от заявки/известия в тази версия.", "info")
        return redirect(url_for("salaries"))

    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 100
    """, (session["user_id"],)).fetchall()
    conn.close()
    return render_template("notifications.html", notifications=rows)



@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def notifications_mark_one_read_api(notification_id):
    conn = get_db()
    conn.execute("""
        UPDATE notifications
        SET is_read = 1
        WHERE id = ? AND user_id = ?
    """, (notification_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/notifications/mark-read", methods=["POST"])
@login_required
def notifications_mark_read():
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    flash("Известията са маркирани като прочетени.", "success")
    return redirect(url_for("dashboard"))



@app.route("/api/notifications/module-counts")
@login_required
def notifications_module_counts_api():
    conn = get_db()
    counts = notification_module_counts(session["user_id"], conn)
    conn.close()
    return jsonify({"ok": True, "counts": counts, "total": sum(counts.values())})


@app.route("/api/notifications/unread-count")
@login_required
def notifications_unread_count_api():
    return jsonify({"ok": True, "count": unread_notifications_count()})



@app.route("/api/push-status")
@login_required
def push_status():
    conn = get_db()
    sub_count = conn.execute(
        "SELECT COUNT(*) AS c FROM push_subscriptions WHERE user_id = ?",
        (session["user_id"],)
    ).fetchone()["c"]
    conn.close()

    return jsonify({
        "ok": True,
        "https": request.is_secure,
        "vapid_configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY),
        "subscription_count": sub_count,
        "user_id": session["user_id"]
    })


@app.route("/api/push-public-key")
@login_required
def push_public_key():
    return jsonify({"ok": True, "configured": bool(VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY), "publicKey": VAPID_PUBLIC_KEY})


@app.route("/api/push-subscribe", methods=["POST"])
@login_required
def push_subscribe():
    data = request.get_json(force=True)
    endpoint = data.get("endpoint", "")
    if not endpoint:
        return jsonify({"ok": False, "error": "Missing endpoint"}), 400
    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM push_subscriptions WHERE user_id = ? AND endpoint = ?", (session["user_id"], endpoint)).fetchone()
        if existing:
            conn.execute("UPDATE push_subscriptions SET data = ?, created_at = ? WHERE id = ?", (json_dumps_safe(data), datetime.now().isoformat(timespec="seconds"), existing["id"]))
        else:
            conn.execute("INSERT INTO push_subscriptions (user_id, endpoint, data, created_at) VALUES (?, ?, ?, ?)", (session["user_id"], endpoint, json_dumps_safe(data), datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        return jsonify({"ok": True})
    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        conn.close()


@app.route("/api/push-test", methods=["POST"])
@login_required
def push_test():
    if not is_root_admin(current_user()):
        return jsonify({"ok": False, "error": "Само админ може да изпраща тест push."}), 403

    conn = get_db()
    sent = send_push_to_user(
        session["user_id"],
        "Тестово push известие",
        "Ако push е настроен, ще получиш системно известие.",
        url_for("dashboard"),
        conn
    )

    notify_user(
        session["user_id"],
        "Тестово push известие",
        "Изпратен е тест към устройството.",
        url_for("dashboard"),
        conn
    )

    conn.commit()
    conn.close()
    return jsonify({"ok": True, "sent": bool(sent)})



def json_dumps_safe(data):
    import json
    return json.dumps(data, ensure_ascii=False)


# ---------------- SALARIES ----------------

@app.route("/salaries")
@login_required
def salaries():
    user = current_user()
    start, end = get_period_from_request()
    conn = get_db()

    requested_employee_id = request.args.get("employee_id", type=int)

    if requested_employee_id:
        if user_can_view_salary(user, requested_employee_id):
            rows = salary_rows(conn, start, end, requested_employee_id)
        else:
            rows = []
    elif is_root_admin(user) or has_permission(user, "can_view_payroll", conn):
        scope = permission_scope(user, conn)
        if scope == "all":
            rows = salary_rows(conn, start, end)
        else:
            visible_ids = allowed_schedule_employee_ids(user, conn)
            scoped_rows = []
            for eid in visible_ids:
                if user_can_view_salary(user, eid):
                    scoped_rows.extend(salary_rows(conn, start, end, eid))
            rows = scoped_rows
    elif row_get(user, "employee_id") and user_can_view_own_payroll(user, conn):
        rows = salary_rows(conn, start, end, user["employee_id"])
    else:
        rows = []

    total_hours = round(sum(row["hours"] for row in rows), 2)
    total_salary = round(sum(row["gross"] for row in rows), 2)

    conn.close()

    return render_template(
        "salaries.html",
        rows=rows,
        start=start,
        end=end,
        total_hours=total_hours,
        total_salary=total_salary,
        can_edit_salary=user_can_edit_salary(user)
    )



@app.route("/schedule/clear-month", methods=["POST"])
@login_required
def schedule_clear_month():
    user = current_user()
    conn_perm = get_db()
    can_clear_all = is_root_admin(user) or (has_permission(user, "can_manage_schedule", conn_perm) and permission_scope(user, conn_perm) == "all")
    conn_perm.close()
    if not can_clear_all:
        flash("Нямате права да изтривате целия месечен график.", "danger")
        return redirect(url_for("schedule"))

    year=int(request.form.get("year")); month=int(request.form.get("month"))
    first_day=date(year,month,1); last_day=date(year,month,calendar.monthrange(year,month)[1])
    conn=get_db()
    try:
        rows=conn.execute("SELECT * FROM schedule WHERE work_date BETWEEN ? AND ?", (first_day.isoformat(), last_day.isoformat())).fetchall()
        for row in rows:
            log_employee(row["employee_id"], "Изтрит месечен график", f"Изтрита смяна за {row['work_date']}", conn)
            uid=user_id_for_employee(row["employee_id"], conn)
            if uid: notify_user(uid, "Изтрит график", f"Графикът за {month:02d}.{year} беше изтрит за корекции.", url_for("schedule",year=year,month=month), conn)
        conn.execute("DELETE FROM schedule WHERE work_date BETWEEN ? AND ?", (first_day.isoformat(), last_day.isoformat()))
        conn.commit(); flash(f"Графикът за {month:02d}.{year} е изтрит.", "info")
    except Exception as e:
        conn.rollback(); flash(f"Грешка при изтриване на месеца: {e}", "danger")
    finally: conn.close()
    return redirect(url_for("schedule", year=year, month=month))



@app.route("/tickets/<int:ticket_id>/escalate", methods=["POST"])
@login_required
def ticket_escalate(ticket_id):
    user = current_user()
    conn = get_db()
    try:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            if wants_json_response():
                return jsonify({"ok": False, "message": "Заявката не е намерена."}), 404
            flash("Заявката не е намерена.", "danger")
            return redirect(url_for("tickets"))

        if not can_escalate_ticket(user, ticket, conn):
            if wants_json_response():
                return jsonify({"ok": False, "message": "Нямате право или няма по-горно ниво за ескалация."}), 403
            flash("Нямате право или няма по-горно ниво за ескалация.", "danger")
            return redirect(url_for("tickets"))

        next_user_id = next_escalation_user_id(conn, user)
        now = datetime.now().isoformat(timespec="seconds")
        comment = (request.form.get("manager_comment") or row_get(ticket, "manager_comment") or "").strip()
        escalation_note = f"Ескалирана от {row_get(user, 'first_name') or row_get(user, 'username')} на {now}."
        comment = (comment + "\n" + escalation_note).strip() if comment else escalation_note

        conn.execute("""
            UPDATE tickets
            SET assigned_to = ?, approval_level = COALESCE(approval_level, 1) + 1,
                status = 'new', manager_seen_at = NULL, manager_comment = ?,
                escalated_at = ?, escalated_by = ?, updated_at = ?
            WHERE id = ?
        """, (next_user_id, comment, now, row_get(user, "id"), now, ticket_id))

        notify_user(
            next_user_id,
            "Ескалирана заявка",
            f"Заявката '{ticket['title']}' е ескалирана към вас.",
            url_for("tickets", bucket="new", open_ticket=ticket_id),
            conn
        )

        conn.commit()
        if wants_json_response():
            counts = ticket_counts_for_user(conn, user)
            return jsonify({"ok": True, "message": "Заявката е ескалирана.", "status": "new", "status_label": "Нова", "counts": counts})
        flash("Заявката е ескалирана.", "success")
    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("tickets"))

@app.route("/tickets/request-shift", methods=["POST"])
@login_required
def ticket_request_shift():
    user = current_user()

    if not user["employee_id"]:
        flash("Този акаунт не е свързан със служител.", "danger")
        return redirect(url_for("tickets"))

    if not has_permission(user, "can_create_tickets"):
        flash("Нямате право да създавате заявки.", "danger")
        return redirect(url_for("tickets"))

    preferred_date = request.form.get("preferred_date")
    preferred_time = request.form.get("preferred_time", "")
    description = request.form.get("description", "")

    if not preferred_date:
        flash("Изберете дата.", "danger")
        return redirect(url_for("tickets"))

    conn = get_db()

    try:
        now = datetime.now().isoformat(timespec="seconds")
        title = f"Искам смяна на {preferred_date}"
        assigned_to = get_employee_manager_user_id(conn, user["employee_id"])

        ticket_cur = conn.execute("""
            INSERT INTO tickets
            (employee_id, type, title, description, start_date, end_date, status, manager_comment, attachment, assigned_to, approval_level, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["employee_id"],
            "Смяна/корекция в графика",
            title,
            f"Предпочитан час: {preferred_time}. {description}",
            preferred_date,
            preferred_date,
            "new",
            None,
            None,
            assigned_to,
            1,
            now,
            now
        ))

        ticket_id = ticket_cur.lastrowid
        ticket_link = url_for("tickets", bucket="new", open_ticket=ticket_id)
        if assigned_to:
            notify_user(
                assigned_to,
                "Нова заявка за смяна",
                f"{user['first_name'] or user['username']} иска смяна на {preferred_date}.",
                ticket_link,
                conn
            )
        else:
            notify_managers(
                "Нова заявка за смяна",
                f"{user['first_name'] or user['username']} иска смяна на {preferred_date}.",
                ticket_link,
                conn
            )

        conn.commit()
        flash("Заявката е изпратена.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("tickets"))



# ---------------- PERMISSIONS ----------------

@app.route("/permissions")
@login_required
def permissions_admin():
    user = current_user()

    if not is_root_admin(user):
        flash("Само admin може да управлява правата.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    users_rows = conn.execute("""
        SELECT users.id AS id, users.id AS user_id, users.username, users.role, users.employee_id,
               employees.first_name, employees.last_name, employees.position
        FROM users
        LEFT JOIN employees ON employees.id = users.employee_id
        ORDER BY users.id DESC
    """).fetchall()

    rows = []
    for row in users_rows:
        perms = get_user_permissions(conn, row)
        item = {
            "user_id": row_get(row, "user_id"),
            "username": row_get(row, "username", ""),
            "role": row_get(row, "role", ""),
            "employee_id": row_get(row, "employee_id"),
            "first_name": row_get(row, "first_name"),
            "last_name": row_get(row, "last_name"),
            "position": row_get(row, "position")
        }

        for field in PERMISSION_FIELDS:
            item[field] = int(perms.get(field, 0) or 0)

        item["scope"] = perms.get("scope", "self")
        rows.append(item)

    conn.close()

    return render_template(
        "permissions.html",
        rows=rows,
        permission_fields=PERMISSION_FIELDS,
        permission_labels=PERMISSION_LABELS,
        permission_descriptions=PERMISSION_DESCRIPTIONS,
        scope_labels=SCOPE_LABELS
    )


@app.route("/permissions/<int:user_id>/update", methods=["POST"])
@login_required
def permissions_update(user_id):
    user = current_user()

    if not is_root_admin(user):
        flash("Само admin може да управлява правата.", "danger")
        return redirect(url_for("dashboard"))

    scope = request.form.get("scope", "self")
    if scope not in SCOPE_LABELS:
        scope = "self"

    values = {}
    for field in PERMISSION_FIELDS:
        values[field] = 1 if request.form.get(field) == "1" else 0

    conn = get_db()

    try:
        existing = conn.execute("SELECT user_id FROM user_permissions WHERE user_id = ?", (user_id,)).fetchone()

        if existing:
            set_sql = ", ".join([f"{field} = ?" for field in PERMISSION_FIELDS])
            conn.execute(f"""
                UPDATE user_permissions
                SET {set_sql}, scope = ?, updated_at = ?
                WHERE user_id = ?
            """, (
                *[values[field] for field in PERMISSION_FIELDS],
                scope,
                datetime.now().isoformat(timespec="seconds"),
                user_id
            ))
        else:
            fields_sql = ", ".join(PERMISSION_FIELDS)
            placeholders = ", ".join(["?"] * (len(PERMISSION_FIELDS) + 3))
            conn.execute(f"""
                INSERT INTO user_permissions
                (user_id, {fields_sql}, scope, updated_at)
                VALUES ({placeholders})
            """, (
                user_id,
                *[values[field] for field in PERMISSION_FIELDS],
                scope,
                datetime.now().isoformat(timespec="seconds")
            ))

        conn.commit()
        if wants_json_response():
            active_count = sum(values.values())
            return jsonify({"ok": True, "message": "Правата са запазени.", "active_count": active_count, "scope": scope})
        flash("Правата са запазени.", "success")

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка при запис на права: {e}"}), 500
        flash(f"Грешка при запис на права: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("permissions_admin"))



# ---------------- TEAM / BONUS / REPORTS ----------------

@app.route("/set-theme", methods=["POST"])
@login_required
def set_theme():
    theme = request.form.get("theme", "dark")
    if theme not in ["dark", "light"]:
        theme = "dark"
    session["theme"] = theme
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/team")
@login_required
def team():
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_view_team")):
        flash("Нямате достъп до Екип.", "danger")
        return redirect(url_for("dashboard"))

    q = request.args.get("q", "").strip()
    status = request.args.get("status", "active")
    active_filter = 0 if status == "inactive" else 1
    conn = get_db()
    sql = """
        SELECT employees.*, departments.name AS department,
               manager.first_name AS manager_first_name, manager.last_name AS manager_last_name,
               users.id AS user_id, users.username, users.role, users.must_change_password
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN employees AS manager ON manager.id = employees.manager_id
        LEFT JOIN users ON users.employee_id = employees.id
        WHERE employees.active = ?
    """
    params = [active_filter]

    scope = permission_scope(user, conn)
    if not is_root_admin(user) and scope != "all":
        if scope in ["subordinates", "team_and_self"] and user["employee_id"]:
            subordinate_ids = get_subordinate_ids(conn, user["employee_id"])
            if scope == "team_and_self":
                subordinate_ids = [user["employee_id"], *subordinate_ids]
        elif user["employee_id"]:
            subordinate_ids = [user["employee_id"]]
        else:
            subordinate_ids = []
        if subordinate_ids:
            placeholders = ",".join(["?"] * len(subordinate_ids))
            sql += f" AND employees.id IN ({placeholders})"
            params.extend(list(dict.fromkeys(subordinate_ids)))
        else:
            sql += " AND 1 = 0"
    if q:
        sql += """
            AND (
                employees.first_name LIKE ? OR employees.last_name LIKE ? OR employees.email LIKE ?
                OR employees.phone LIKE ? OR departments.name LIKE ? OR users.username LIKE ?
            )
        """
        like = f"%{q}%"
        params.extend([like, like, like, like, like, like])
    sql += " ORDER BY COALESCE(employees.manager_id, 0), employees.first_name, employees.last_name"
    employees_list = conn.execute(sql, params).fetchall()
    managers = conn.execute("SELECT id, first_name, last_name, position FROM employees WHERE active = 1 ORDER BY first_name, last_name").fetchall()
    active_count = conn.execute("SELECT COUNT(*) AS c FROM employees WHERE active = 1").fetchone()["c"]
    inactive_count = conn.execute("SELECT COUNT(*) AS c FROM employees WHERE active = 0").fetchone()["c"]
    conn.close()
    return render_template(
        "team.html",
        employees=employees_list,
        managers=managers,
        q=q,
        status=status,
        active_count=active_count,
        inactive_count=inactive_count,
        position_labels=POSITION_LABELS
    )

@app.route("/team/<int:employee_id>/create-access", methods=["POST"])
@login_required
@manager_required
def team_create_access(employee_id):
    user = current_user()
    conn_check = get_db()
    if not user_can_manage_employee(user, employee_id, conn_check):
        conn_check.close()
        flash("Нямате права да създавате достъп за този служител.", "danger")
        return redirect(url_for("team"))
    conn_check.close()

    username = request.form.get("username", "").strip()

    if not username:
        flash("Въведете потребителско име.", "danger")
        return redirect(url_for("team"))

    temp_password = secrets.token_urlsafe(8)
    conn = get_db()

    try:
        existing = conn.execute("SELECT id FROM users WHERE employee_id = ?", (employee_id,)).fetchone()
        if existing:
            flash("Този служител вече има достъп.", "info")
            conn.close()
            return redirect(url_for("team"))

        conn.execute("""
            INSERT INTO users
            (username, password_hash, role, employee_id, must_change_password)
            VALUES (?, ?, 'employee', ?, 1)
        """, (username, generate_password_hash(temp_password), employee_id))

        conn.commit()
        flash(f"Достъпът е създаден. Временна парола: {temp_password}", "success")

    except Exception as e:
        conn.rollback()
        if is_integrity_error(e):
            flash("Потребителското име вече съществува.", "danger")
        else:
            flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("team"))


@app.route("/team/<int:employee_id>/hierarchy", methods=["POST"])
@login_required
@manager_required
def team_update_hierarchy(employee_id):
    user = current_user()
    conn_check = get_db()
    if not user_can_manage_employee(user, employee_id, conn_check):
        conn_check.close()
        flash("Нямате права да променяте този служител.", "danger")
        return redirect(url_for("team"))
    conn_check.close()

    position = request.form.get("position", "worker")
    manager_id = request.form.get("manager_id") or None
    if position not in POSITION_LABELS:
        position = "worker"
    if manager_id and int(manager_id) == employee_id:
        flash("Служител не може да бъде ръководител на себе си.", "danger")
        return redirect(url_for("team"))
    conn = get_db()
    try:
        conn.execute("UPDATE employees SET position = ?, manager_id = ? WHERE id = ?", (position, manager_id, employee_id))
        conn.commit(); flash("Йерархията е обновена.", "success")
    except Exception as e:
        conn.rollback(); flash(f"Грешка: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("team"))



@app.route("/team/<int:employee_id>/active", methods=["POST"])
@login_required
@manager_required
def team_toggle_active(employee_id):
    user = current_user()
    conn_perm = get_db()
    if not user_can_manage_employee(user, employee_id, conn_perm):
        conn_perm.close()
        flash("Нямате права да променяте този служител.", "danger")
        return redirect(url_for("team"))
    conn_perm.close()

    active = 1 if request.form.get("active") == "1" else 0
    conn = get_db()
    try:
        emp = conn.execute("SELECT first_name, last_name, active FROM employees WHERE id = ?", (employee_id,)).fetchone()
        if not emp:
            flash("Служителят не е намерен.", "danger")
            return redirect(url_for("team"))

        conn.execute("UPDATE employees SET active = ? WHERE id = ?", (active, employee_id))
        action = "Активиран служител" if active else "Деактивиран служител"
        details = f"{emp['first_name']} {emp['last_name']} -> {'активен' if active else 'неактивен'}"
        log_employee(employee_id, action, details, conn)
        conn.commit()
        flash("Статусът на служителя е обновен.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("team", status=request.form.get("return_status", "active")))



@app.route("/bonuses", methods=["GET", "POST"])
@login_required
def bonuses():
    user = current_user()
    if not user_can_edit_salary(user):
        flash("Само финансов отдел/изпълнителен директор може да прави корекции по заплати.", "danger")
        return redirect(url_for("dashboard"))

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))

    conn = get_db()

    if request.method == "POST":
        employee_id = int(request.form.get("employee_id"))
        year = int(request.form.get("year"))
        month = int(request.form.get("month"))
        amount = float(request.form.get("amount") or 0)
        note = request.form.get("note", "")

        try:
            conn.execute("""
                INSERT INTO bonuses (employee_id, year, month, amount, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(employee_id, year, month)
                DO UPDATE SET amount = excluded.amount, note = excluded.note
            """, (
                employee_id,
                year,
                month,
                amount,
                note,
                datetime.now().isoformat(timespec="seconds")
            ))

            conn.commit()
            flash("Бонусът е запазен.", "success")

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

        return redirect(url_for("bonuses", year=year, month=month))

    rows = conn.execute("""
        SELECT employees.id, employees.first_name, employees.last_name,
               departments.name AS department,
               COALESCE(bonuses.amount, 0) AS bonus,
               bonuses.note
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN bonuses ON bonuses.employee_id = employees.id
            AND bonuses.year = ?
            AND bonuses.month = ?
        WHERE employees.active = 1
        ORDER BY employees.first_name, employees.last_name
    """, (year, month)).fetchall()

    conn.close()
    return render_template("bonuses.html", rows=rows, year=year, month=month)


def monthly_report_data(conn, employee_id, year, month):
    first_day = date(year, month, 1)
    last_day = date(year, month, calendar.monthrange(year, month)[1])

    employee = conn.execute("""
        SELECT employees.*, departments.name AS department,
               manager.first_name AS manager_first_name,
               manager.last_name AS manager_last_name
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN employees AS manager ON manager.id = employees.manager_id
        WHERE employees.id = ?
    """, (employee_id,)).fetchone()

    rows = conn.execute("""
        SELECT *
        FROM schedule
        WHERE employee_id = ? AND work_date BETWEEN ? AND ?
        ORDER BY work_date, start_time
    """, (employee_id, first_day.isoformat(), last_day.isoformat())).fetchall()

    bonus = conn.execute("""
        SELECT COALESCE(amount, 0) AS amount, note
        FROM bonuses
        WHERE employee_id = ? AND year = ? AND month = ?
    """, (employee_id, year, month)).fetchone()

    total_hours = 0
    overtime_hours = 0
    base_pay = 0
    overtime_pay = 0

    weekly_hours = {}

    for row in rows:
        h = calc_hours(row["start_time"], row["end_time"])
        total_hours += h

        day_obj = datetime.strptime(row["work_date"], "%Y-%m-%d").date()
        week_key = day_obj.isocalendar()[:2]

        before = weekly_hours.get(week_key, 0)
        normal = max(0, min(h, 40 - before))
        overtime = max(0, h - normal)

        weekly_hours[week_key] = before + h

        overtime_rate = employee["overtime_rate"] if "overtime_rate" in employee.keys() and employee["overtime_rate"] else employee["hourly_rate"] * 1.5

        base_pay += normal * employee["hourly_rate"]
        overtime_pay += overtime * overtime_rate
        overtime_hours += overtime

    bonus_amount = bonus["amount"] if bonus else 0
    total_pay = base_pay + overtime_pay + bonus_amount

    return {
        "employee": employee,
        "rows": rows,
        "year": year,
        "month": month,
        "total_hours": total_hours,
        "overtime_hours": overtime_hours,
        "base_pay": base_pay,
        "overtime_pay": overtime_pay,
        "bonus": bonus_amount,
        "bonus_note": bonus["note"] if bonus else "",
        "total_pay": total_pay
    }


@app.route("/reports/monthly/<int:employee_id>")
@login_required
def report_monthly(employee_id):
    user = current_user()

    if not user_can_view_salary(user, employee_id):
        flash("Нямате право да изтегляте този отчет.", "danger")
        return redirect(url_for("dashboard"))

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))

    conn = get_db()
    data = monthly_report_data(conn, employee_id, year, month)
    conn.close()

    # Simple PDF generation using reportlab if available.
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        y = height - 24 * mm
        employee = data["employee"]
        c.setFont("Helvetica-Bold", 16)
        c.drawString(20 * mm, y, "ShiftDesk Monthly Report")
        y -= 10 * mm

        c.setFont("Helvetica", 11)
        c.drawString(20 * mm, y, f"Employee: {employee['first_name']} {employee['last_name']}")
        y -= 7 * mm
        c.drawString(20 * mm, y, f"Department: {employee['department'] or '-'}")
        y -= 7 * mm
        c.drawString(20 * mm, y, f"Period: {month:02d}.{year}")
        y -= 12 * mm

        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Summary")
        y -= 8 * mm

        c.setFont("Helvetica", 11)
        summary = [
            ("Total hours", data["total_hours"]),
            ("Overtime hours", data["overtime_hours"]),
            ("Base pay EUR", data["base_pay"]),
            ("Overtime pay EUR", data["overtime_pay"]),
            ("Bonus EUR", data["bonus"]),
            ("Total EUR", data["total_pay"]),
        ]

        for label, value in summary:
            c.drawString(24 * mm, y, f"{label}: {value:.2f}")
            y -= 7 * mm

        y -= 6 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Shifts")
        y -= 8 * mm

        c.setFont("Helvetica", 9)
        for row in data["rows"]:
            if y < 25 * mm:
                c.showPage()
                y = height - 20 * mm
                c.setFont("Helvetica", 9)

            hours = calc_hours(row["start_time"], row["end_time"])
            c.drawString(20 * mm, y, f"{row['work_date']}   {row['start_time']}-{row['end_time']}   {hours:.2f}h")
            y -= 6 * mm

        c.save()
        buffer.seek(0)

        filename = f"report_{employee_id}_{year}_{month:02d}.pdf"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")

    except Exception:
        # Fallback: text file if reportlab is not installed.
        employee = data["employee"]
        content = []
        content.append("ShiftDesk Monthly Report")
        content.append(f"Employee: {employee['first_name']} {employee['last_name']}")
        content.append(f"Period: {month:02d}.{year}")
        content.append(f"Total hours: {data['total_hours']:.2f}")
        content.append(f"Overtime hours: {data['overtime_hours']:.2f}")
        content.append(f"Base pay EUR: {data['base_pay']:.2f}")
        content.append(f"Overtime pay EUR: {data['overtime_pay']:.2f}")
        content.append(f"Bonus EUR: {data['bonus']:.2f}")
        content.append(f"Total EUR: {data['total_pay']:.2f}")

        buffer = BytesIO("\\n".join(content).encode("utf-8"))
        filename = f"report_{employee_id}_{year}_{month:02d}.txt"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype="text/plain")


@app.route("/reports/monthly")
@login_required
def my_monthly_report():
    user = current_user()

    if not user["employee_id"]:
        flash("Този акаунт не е свързан със служител.", "danger")
        return redirect(url_for("dashboard"))

    return redirect(url_for("report_monthly", employee_id=user["employee_id"], year=request.args.get("year", date.today().year), month=request.args.get("month", date.today().month)))




@app.route("/salary-corrections", methods=["GET", "POST"])
@login_required
def salary_corrections():
    user = current_user()
    if not user_can_edit_salary(user):
        flash("Само финансов отдел/изпълнителен директор може да прави корекции по заплати.", "danger")
        return redirect(url_for("salaries"))

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))

    conn = get_db()

    if request.method == "POST":
        employee_id = int(request.form.get("employee_id"))
        year = int(request.form.get("year"))
        month = int(request.form.get("month"))
        gross_adjustment = float(request.form.get("gross_adjustment") or 0)
        net_adjustment = float(request.form.get("net_adjustment") or 0)
        note = request.form.get("note", "")

        try:
            conn.execute("""
                INSERT INTO salary_corrections
                (employee_id, year, month, gross_adjustment, net_adjustment, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(employee_id, year, month)
                DO UPDATE SET
                    gross_adjustment = excluded.gross_adjustment,
                    net_adjustment = excluded.net_adjustment,
                    note = excluded.note
            """, (
                employee_id,
                year,
                month,
                gross_adjustment,
                net_adjustment,
                note,
                datetime.now().isoformat(timespec="seconds")
            ))
            conn.commit()
            flash("Корекцията е запазена.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")
        finally:
            conn.close()

        return redirect(url_for("salary_corrections", year=year, month=month))

    rows = conn.execute("""
        SELECT employees.id, employees.first_name, employees.last_name,
               departments.name AS department,
               COALESCE(salary_corrections.gross_adjustment, 0) AS gross_adjustment,
               COALESCE(salary_corrections.net_adjustment, 0) AS net_adjustment,
               salary_corrections.note
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN salary_corrections ON salary_corrections.employee_id = employees.id
            AND salary_corrections.year = ?
            AND salary_corrections.month = ?
        WHERE employees.active = 1
        ORDER BY employees.first_name, employees.last_name
    """, (year, month)).fetchall()

    conn.close()
    return render_template("salary_corrections.html", rows=rows, year=year, month=month)




def payroll_month_label(year, month):
    names = [
        "Януари", "Февруари", "Март", "Април", "Май", "Юни",
        "Юли", "Август", "Септември", "Октомври", "Ноември", "Декември"
    ]
    try:
        return f"{names[int(month)-1]} {int(year)}"
    except Exception:
        return f"{month}.{year}"


def payroll_run_display(row):
    data = {}
    try:
        data = json.loads(row_get(row, "breakdown", "{}") or "{}")
    except Exception:
        data = {}
    return {
        "year": int(row_get(row, "year", 0) or 0),
        "month": int(row_get(row, "month", 0) or 0),
        "label": payroll_month_label(row_get(row, "year", 0), row_get(row, "month", 0)),
        "status": row_get(row, "status", "calculated") or "calculated",
        "created_at": row_get(row, "created_at", "") or "",
        "worked_hours": float(row_get(row, "normal_hours", 0) or 0) + float(row_get(row, "weekend_hours", 0) or 0) + float(row_get(row, "holiday_hours", 0) or 0) + float(row_get(row, "overtime_hours", 0) or 0),
        "gross_total": float(row_get(row, "gross_total", 0) or 0),
        "net_total": float(row_get(row, "net_total", 0) or 0),
        "breakdown": data,
    }


@app.route("/payroll/me")
@login_required
def payroll_me():
    user = current_user()
    if not user_can_view_own_payroll(user):
        flash("Нямате право да виждате собствен payroll.", "danger")
        if row_get(user, "employee_id"):
            return redirect(url_for("employee_profile", employee_id=user["employee_id"]))
        return redirect(url_for("schedule"))

    today = date.today()
    year = request.args.get("year", today.year, type=int)
    month = request.args.get("month", today.month, type=int)
    if month < 1 or month > 12:
        month = today.month
    employee_id = int(user["employee_id"])

    conn = get_db()
    employee = conn.execute("""
        SELECT employees.*, departments.name AS department
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        WHERE employees.id = ?
    """, (employee_id,)).fetchone()

    saved_run = conn.execute("""
        SELECT * FROM payroll_runs
        WHERE employee_id = ? AND year = ? AND month = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (employee_id, year, month)).fetchone()

    current = calculate_employee_payroll(conn, employee_id, year, month) or {}
    saved_display = payroll_run_display(saved_run) if saved_run else None
    if saved_display and saved_display.get("breakdown"):
        selected = dict(current)
        selected.update(saved_display["breakdown"] or {})
        selected["status"] = saved_display["status"]
        selected["created_at"] = saved_display["created_at"]
        selected["is_saved"] = True
    elif saved_display:
        selected = dict(current)
        selected.update({
            "gross_total": saved_display["gross_total"],
            "net_total": saved_display["net_total"],
            "status": saved_display["status"],
            "created_at": saved_display["created_at"],
            "is_saved": True,
        })
    else:
        selected = dict(current)
        selected["status"] = "preview"
        selected["created_at"] = ""
        selected["is_saved"] = False

    history_rows = conn.execute("""
        SELECT * FROM payroll_runs
        WHERE employee_id = ?
        ORDER BY year DESC, month DESC, created_at DESC
        LIMIT 18
    """, (employee_id,)).fetchall()
    history = [payroll_run_display(r) for r in history_rows]
    conn.close()

    prev_year, prev_month = (year - 1, 12) if month == 1 else (year, month - 1)
    next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)

    return render_template(
        "payroll_me.html",
        employee=employee,
        payroll=selected,
        history=history,
        year=year,
        month=month,
        month_label=payroll_month_label(year, month),
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month
    )


@app.route("/payroll-tools", methods=["GET", "POST"])
@login_required
def payroll_tools():
    user = current_user()
    today = date.today()
    year = int(request.values.get("year", today.year))
    month = int(request.values.get("month", today.month))

    if user_can_view_own_payroll(user) and not (is_root_admin(user) or has_permission(user, "can_manage_payroll") or has_permission(user, "can_view_payroll")):
        return redirect(url_for("payroll_me", year=year, month=month))

    if not (is_root_admin(user) or has_permission(user, "can_manage_payroll") or has_permission(user, "can_view_payroll")):
        flash("Нямате достъп до payroll.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        if request.method == "POST":
            action = request.form.get("action")

            if not has_permission(user, "can_manage_payroll", conn):
                if wants_json_response():
                    return jsonify({"ok": False, "message": "Нямате права да управлявате payroll."}), 403
                flash("Нямате права да управлявате payroll.", "danger")
                return redirect(url_for("payroll_tools", year=year, month=month))

            if action == "update_rate":
                if not has_permission(user, "can_edit_pay_rate", conn):
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Нямате право да редактирате ставки."}), 403
                    flash("Нямате право да редактирате ставки.", "danger")
                    return redirect(url_for("payroll_tools", year=year, month=month))

                employee_id = int(request.form.get("employee_id"))
                if not user_can_manage_payroll_for(user, employee_id, conn):
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Нямате право върху този служител."}), 403
                    flash("Нямате право върху този служител.", "danger")
                    return redirect(url_for("payroll_tools", year=year, month=month))
                pay_type = request.form.get("pay_type", "monthly")
                if pay_type not in ["monthly", "hourly"]:
                    pay_type = "monthly"

                conn.execute("""
                    UPDATE employees
                    SET pay_type = ?, monthly_gross = ?, hourly_rate = ?
                    WHERE id = ?
                """, (
                    pay_type,
                    float(request.form.get("monthly_gross") or 0),
                    float(request.form.get("hourly_rate") or 0),
                    employee_id
                ))
                conn.commit()
                if wants_json_response():
                    return jsonify({"ok": True, "message": "Ставката/брутната заплата е запазена."})
                flash("Ставката/брутната заплата е запазена.", "success")
                return redirect(url_for("payroll_tools", year=year, month=month))

            if action == "update_item":
                employee_id = int(request.form.get("employee_id"))
                if not user_can_manage_payroll_for(user, employee_id, conn):
                    if wants_json_response():
                        return jsonify({"ok": False, "message": "Нямате право върху този служител."}), 403
                    flash("Нямате право върху този служител.", "danger")
                    return redirect(url_for("payroll_tools", year=year, month=month))
                bonus = float(request.form.get("bonus") or 0)
                correction = float(request.form.get("correction") or 0)
                sick_days = int(request.form.get("sick_days") or 0)
                notes = request.form.get("notes", "").strip()

                existing = conn.execute("""
                    SELECT id FROM payroll_items
                    WHERE employee_id = ? AND year = ? AND month = ?
                """, (employee_id, year, month)).fetchone()

                if existing:
                    conn.execute("""
                        UPDATE payroll_items
                        SET bonus=?, correction=?, sick_days=?, notes=?, updated_by=?, updated_at=?
                        WHERE id=?
                    """, (bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds"), existing["id"]))
                else:
                    conn.execute("""
                        INSERT INTO payroll_items
                        (employee_id, year, month, bonus, correction, sick_days, notes, updated_by, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (employee_id, year, month, bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds")))

                conn.commit()
                if wants_json_response():
                    return jsonify({"ok": True, "message": "Payroll данните са запазени.", "bonus": bonus, "correction": correction, "sick_days": sick_days})
                flash("Payroll данните са запазени.", "success")
                return redirect(url_for("payroll_tools", year=year, month=month))

            if action == "calculate_all":
                employee_ids = payroll_employee_ids_for(user, conn, include_self=False)
                employees_list = [{"id": eid} for eid in employee_ids]
                for emp in employees_list:
                    row = calculate_employee_payroll(conn, emp["id"], year, month)
                    if row:
                        save_payroll_run(conn, row, year, month, session["user_id"])
                conn.commit()
                if wants_json_response():
                    return jsonify({"ok": True, "message": "Заплатите са изчислени и записани."})
                flash("Заплатите са изчислени и записани.", "success")
                return redirect(url_for("payroll_tools", year=year, month=month))

        first = date(year, month, 1)
        last = date(year, month, calendar.monthrange(year, month)[1])
        employee_ids = payroll_employee_ids_for(user, conn)
        rows = []
        for eid in employee_ids:
            rows.extend(salary_rows(conn, first.isoformat(), last.isoformat(), eid))
        for row in rows:
            row["history"] = payroll_history_for_employee(conn, row["employee_id"], 12)
        total_gross = round(sum(r["gross_total"] for r in rows), 2)
        total_net = round(sum(r["net_total"] for r in rows), 2)
        total_employer_cost = round(sum(r["employer_total"] for r in rows), 2)
        total_hours = round(sum(r["worked_hours"] for r in rows), 2)
        total_holiday = round(sum(r["holiday_hours"] for r in rows), 2)
        total_weekend = round(sum(r["weekend_hours"] for r in rows), 2)
        total_overtime = round(sum(r["overtime_hours"] for r in rows), 2)
        active_employees = len(employee_ids)
        norm_hours = official_working_hours(year, month)
        work_days = len(official_working_days(year, month))

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")
        return redirect(url_for("payroll_tools", year=year, month=month))

    finally:
        conn.close()

    return render_template(
        "payroll_tools.html",
        rows=rows,
        year=year,
        month=month,
        active_employees=active_employees,
        norm_hours=norm_hours,
        work_days=work_days,
        total_gross=total_gross,
        total_net=total_net,
        total_employer_cost=total_employer_cost,
        total_hours=total_hours,
        total_holiday=total_holiday,
        total_weekend=total_weekend,
        total_overtime=total_overtime,
        can_manage=has_permission(user, "can_manage_payroll"),
        can_edit_rate=has_permission(user, "can_edit_pay_rate"),
        can_notify=has_permission(user, "can_send_payroll_notification")
    )





@app.route("/api/payroll/ping", methods=["GET"])
@login_required
def payroll_action_ping():
    return jsonify({"ok": True, "message": "Payroll API OK"})


@app.route("/api/payroll/action", methods=["POST"])
@login_required
def payroll_action_api():
    user = current_user()
    year = int(request.form.get("year", date.today().year))
    month = int(request.form.get("month", date.today().month))
    action = request.form.get("action", "")

    conn = get_db()
    try:
        if not has_permission(user, "can_manage_payroll", conn):
            return jsonify({"ok": False, "message": "Нямате права да управлявате payroll."}), 403

        if action == "preview":
            employee_id = int(request.form.get("employee_id"))
            pay_type = request.form.get("pay_type", "monthly")
            if pay_type not in ["monthly", "hourly"]:
                pay_type = "monthly"

            monthly_gross = float(request.form.get("monthly_gross") or 0)
            hourly_rate = float(request.form.get("hourly_rate") or 0)
            bonus = float(request.form.get("bonus") or 0)
            correction = float(request.form.get("correction") or 0)
            sick_days = int(request.form.get("sick_days") or 0)
            notes = request.form.get("notes", "").strip()

            conn.execute("""
                UPDATE employees
                SET pay_type = ?, monthly_gross = ?, hourly_rate = ?
                WHERE id = ?
            """, (pay_type, monthly_gross, hourly_rate, employee_id))

            existing = conn.execute("""
                SELECT id FROM payroll_items
                WHERE employee_id = ? AND year = ? AND month = ?
            """, (employee_id, year, month)).fetchone()

            if existing:
                conn.execute("""
                    UPDATE payroll_items
                    SET bonus=?, correction=?, sick_days=?, notes=?, updated_by=?, updated_at=?
                    WHERE id=?
                """, (bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds"), existing["id"]))
            else:
                conn.execute("""
                    INSERT INTO payroll_items
                    (employee_id, year, month, bonus, correction, sick_days, notes, updated_by, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (employee_id, year, month, bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds")))

            row = calculate_employee_payroll(conn, employee_id, year, month)
            conn.rollback()
            return jsonify({"ok": True, "message": "Преизчислено.", "payroll": row})

        if action == "calculate_all":
            employees_list = conn.execute("SELECT id FROM employees WHERE active = 1 ORDER BY first_name, last_name").fetchall()
            calculated = 0
            skipped = 0

            for emp in employees_list:
                row = calculate_employee_payroll(conn, emp["id"], year, month)
                if row:
                    save_payroll_run(conn, row, year, month, session["user_id"])
                    calculated += 1
                else:
                    skipped += 1

            conn.commit()
            return jsonify({
                "ok": True,
                "message": f"Изчислени заплати: {calculated}. Пропуснати: {skipped}.",
                "calculated": calculated,
                "skipped": skipped
            })

        if action == "update_rate":
            if not has_permission(user, "can_edit_pay_rate", conn):
                return jsonify({"ok": False, "message": "Нямате право да редактирате ставки."}), 403

            employee_id = int(request.form.get("employee_id"))
            pay_type = request.form.get("pay_type", "monthly")
            if pay_type not in ["monthly", "hourly"]:
                pay_type = "monthly"

            monthly_gross = float(request.form.get("monthly_gross") or 0)
            hourly_rate = float(request.form.get("hourly_rate") or 0)

            conn.execute("""
                UPDATE employees
                SET pay_type = ?, monthly_gross = ?, hourly_rate = ?
                WHERE id = ?
            """, (pay_type, monthly_gross, hourly_rate, employee_id))

            row = calculate_employee_payroll(conn, employee_id, year, month)
            conn.commit()
            return jsonify({"ok": True, "message": "Ставката/брутната заплата е запазена.", "payroll": row})

        if action == "update_item":
            employee_id = int(request.form.get("employee_id"))
            bonus = float(request.form.get("bonus") or 0)
            correction = float(request.form.get("correction") or 0)
            sick_days = int(request.form.get("sick_days") or 0)
            notes = request.form.get("notes", "").strip()

            existing = conn.execute("""
                SELECT id FROM payroll_items
                WHERE employee_id = ? AND year = ? AND month = ?
            """, (employee_id, year, month)).fetchone()

            if existing:
                conn.execute("""
                    UPDATE payroll_items
                    SET bonus=?, correction=?, sick_days=?, notes=?, updated_by=?, updated_at=?
                    WHERE id=?
                """, (bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds"), existing["id"]))
            else:
                conn.execute("""
                    INSERT INTO payroll_items
                    (employee_id, year, month, bonus, correction, sick_days, notes, updated_by, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (employee_id, year, month, bonus, correction, sick_days, notes, session["user_id"], datetime.now().isoformat(timespec="seconds")))

            row = calculate_employee_payroll(conn, employee_id, year, month)
            conn.commit()
            return jsonify({
                "ok": True,
                "message": "Payroll данните са запазени.",
                "bonus": bonus,
                "correction": correction,
                "sick_days": sick_days,
                "payroll": row
            })

        return jsonify({"ok": False, "message": "Непознато payroll действие."}), 400

    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "message": f"Payroll грешка: {type(e).__name__}: {e}"}), 500

    finally:
        conn.close()


@app.route("/feedback", methods=["GET", "POST"])
@login_required
def feedback_reports():
    user = current_user()

    if request.method == "POST":
        report_type = request.form.get("type", "bug")
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        page_url = request.form.get("page_url", "").strip()
        browser_info = request.form.get("browser_info", "").strip()

        if not title or not description:
            flash("Попълнете заглавие и описание.", "danger")
            return redirect(url_for("feedback_reports"))

        conn = get_db()

        try:
            now = datetime.now().isoformat(timespec="seconds")

            report_cur = conn.execute("""
                INSERT INTO feedback_reports
                (user_id, username, employee_id, type, title, description, page_url, browser_info, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
            """, (
                session.get("user_id"),
                user["username"],
                user["employee_id"],
                report_type,
                title,
                description,
                page_url,
                browser_info,
                now,
                now
            ))

            report_id = report_cur.lastrowid
            report_link = url_for("feedback_reports", open_feedback=report_id)
            # Notify root admins / managers without employee profile.
            admins = conn.execute("SELECT id FROM users WHERE role = 'manager' AND employee_id IS NULL").fetchall()
            for admin in admins:
                notify_user(
                    admin["id"],
                    "Нов report",
                    f"{user['username']} изпрати: {title}",
                    report_link,
                    conn
                )

            conn.commit()
            flash("Благодарим! Сигналът е изпратен.", "success")

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

        return redirect(url_for("feedback_reports"))

    conn = get_db()

    if is_root_admin(user) or has_permission(user, "can_view_reports", conn):
        rows = conn.execute("""
            SELECT *
            FROM feedback_reports
            ORDER BY created_at DESC
            LIMIT 200
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT *
            FROM feedback_reports
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 100
        """, (session.get("user_id"),)).fetchall()

    conn.close()

    return render_template("feedback.html", reports=rows)


@app.route("/feedback/<int:report_id>/update", methods=["POST"])
@login_required
def feedback_update(report_id):
    user = current_user()

    if not (is_root_admin(user) or has_permission(user, "can_view_reports")):
        flash("Нямате права да обработвате reports.", "danger")
        return redirect(url_for("feedback_reports"))

    status = request.form.get("status", "open")
    admin_comment = request.form.get("admin_comment", "")

    if status not in ["open", "in_progress", "fixed", "rejected"]:
        status = "open"

    conn = get_db()

    try:
        conn.execute("""
            UPDATE feedback_reports
            SET status = ?, admin_comment = ?, updated_at = ?
            WHERE id = ?
        """, (
            status,
            admin_comment,
            datetime.now().isoformat(timespec="seconds"),
            report_id
        ))

        conn.commit()
        flash("Report-ът е обновен.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("feedback_reports"))




@app.context_processor
def inject_build_info():
    show_build_popup = False
    try:
        if session.get("user_id"):
            u = current_user()
            show_build_popup = (row_get(u, "last_seen_build") != APP_BUILD)
    except Exception:
        show_build_popup = False
    return {
        "app_version": APP_VERSION,
        "app_build": APP_BUILD,
        "show_build_popup": show_build_popup,
    }


@app.route("/api/build/seen", methods=["POST"])
@login_required
def mark_build_seen():
    conn = get_db()
    try:
        conn.execute("UPDATE users SET last_seen_build=? WHERE id=?", (APP_BUILD, session["user_id"]))
        conn.commit()
        return jsonify({"ok": True, "message": "Build marked as seen.", "build": APP_BUILD})
    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "message": str(e)}), 500
    finally:
        conn.close()


@app.route("/whats-new")
@login_required
def whats_new():
    return redirect(url_for("changelog"))

@app.route("/changelog")
@login_required
def changelog():
    current_release = {"version": APP_VERSION, "build": APP_BUILD, "title": "ShiftDesk Beta"}
    changes = [
        {
            "version": "0.9.21 Beta",
            "title": "Render-ready и база данни",
            "items": [
                "Подготвена е системата за Render deployment с PostgreSQL чрез DATABASE_URL.",
                "Добавен е health check endpoint /healthz за deploy проверка.",
                "Добавен е SQLite → PostgreSQL migration script за прехвърляне на текущите данни.",
                "SECRET_KEY и UPLOAD_DIR вече могат да се задават през environment variables.",
                "Изчистени са orphan notifications и е направена последна диагностика на база, templates, routes и JS."
            ]
        },
        {
            "version": "0.9.20 Beta",
            "title": "Личен payroll и профил",
            "items": [
                "Добавен е изчистен екран „Моето възнаграждение“ в профила.",
                "Служителят вижда собствен payroll само ако има право can_view_own_payroll.",
                "Личният payroll вече не стои като отделен елемент в страничното меню.",
                "Payroll notification към служител води към личния payroll екран."
            ]
        },
        {
            "version": "0.9.19 Beta",
            "title": "Mobile app UI",
            "items": [
                "Мобилната версия е преработена като app shell с долна навигация.",
                "Topbar-ът показва центрирано ShiftDesk BETA и потребителя.",
                "Менюто на mobile се отваря от bottom navigation и се затваря със swipe.",
                "Calendar bottom sheet се затваря със swipe надолу и няма излишен X на телефон."
            ]
        },
        {
            "version": "0.9.18 Beta",
            "title": "Tickets cleanup и escalation",
            "items": [
                "Добавени са права can_create_tickets и can_escalate_tickets.",
                "Служител подава заявка към прекия си ръководител според йерархията.",
                "Ескалацията изпраща тикета едно ниво нагоре и известява следващия ръководител.",
                "Прикачване на файл се позволява само при тип „Болничен“ и се проверява backend-side.",
                "Видимостта на тикетите е изчистена по permissions + scope + hierarchy."
            ]
        },
        {
            "version": "0.9.17 Beta",
            "title": "Permissions, payroll flow и dashboard право",
            "items": [
                "Достъпът е затегнат по permissions + scope + hierarchy, вместо само по role.",
                "Добавено е право can_view_dashboard за показване и достъп до Dashboard.",
                "Календарният месец се заключва когато finance маркира payroll справката като „Обработена“.",
                "Payroll notify вече не заключва месеца самостоятелно.",
                "Само root admin може да отключи заключен месец за корекции."
            ]
        },
        {
            "version": "0.9.16 Beta",
            "title": "Календар, notifications и pop-out стабилизация",
            "items": [
                "Календарът използва стабилен desktop pop-out и mobile bottom sheet за детайли.",
                "В календара се виждат само имената на desktop, а часовете се показват на mobile.",
                "Edit mode работи без refresh за добавяне и изтриване на смени.",
                "Notification pop-out вече не маркира известието като прочетено при X/Затвори.",
                "Бутонът „Отвори“ води към правилния ticket, ден, payroll месец или report."
            ]
        }
    ]
    return render_template("changelog.html", changes=changes, current_release=current_release)


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")




@app.route("/schedule/send-payroll-report", methods=["POST"])
@login_required
def send_payroll_report():
    user = current_user()

    if not has_permission(user, "can_send_schedule_to_payroll"):
        flash("Нямате права да изпращате график към финансов отдел.", "danger")
        return redirect(url_for("schedule"))

    year = int(request.form.get("year"))
    month = int(request.form.get("month"))
    notes = request.form.get("notes", "").strip()

    first_day = date(year, month, 1)
    last_day = date(year, month, calendar.monthrange(year, month)[1])

    conn = get_db()

    try:
        # Scope is still controlled by hierarchy/permissions.
        if is_root_admin(user):
            employee_ids = allowed_schedule_employee_ids(user, conn)
        elif permission_scope(user, conn) in ["subordinates", "team_and_self"] and user["employee_id"]:
            employee_ids = get_subordinate_ids(conn, user["employee_id"])
            if permission_scope(user, conn) == "team_and_self":
                employee_ids = [user["employee_id"], *employee_ids]
        elif permission_scope(user, conn) == "self" and user["employee_id"]:
            employee_ids = [user["employee_id"]]
        else:
            employee_ids = allowed_schedule_employee_ids(user, conn)

        if not employee_ids:
            flash("Няма служители за справка.", "danger")
            conn.close()
            return redirect(url_for("schedule", year=year, month=month))

        summary = build_payroll_report_summary(
            conn,
            employee_ids,
            first_day.isoformat(),
            last_day.isoformat()
        )

        now = datetime.now().isoformat(timespec="seconds")

        report_cur = conn.execute("""
            INSERT INTO payroll_reports
            (manager_user_id, manager_employee_id, year, month, employee_ids, total_hours, overtime_hours, holiday_hours, notes, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent', ?)
        """, (
            session["user_id"],
            user["employee_id"],
            year,
            month,
            json.dumps(employee_ids),
            summary["total_hours"],
            summary["overtime_hours"],
            summary["holiday_hours"],
            notes,
            now
        ))

        finance_users = conn.execute("""
            SELECT users.id
            FROM users
            LEFT JOIN employees ON employees.id = users.employee_id
            WHERE employees.position = 'finance'
               OR (users.role = 'manager' AND users.employee_id IS NULL)
        """).fetchall()

        sender_name = user["first_name"] or user["username"]
        report_id = report_cur.lastrowid
        report_link = url_for("payroll_reports", open_report=report_id)

        for finance_user in finance_users:
            notify_user(
                finance_user["id"],
                "Нова payroll справка",
                f"{sender_name} изпрати справка за {month:02d}.{year}.",
                report_link,
                conn
            )

        conn.commit()
        flash("Справката е изпратена към финансов отдел.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка при изпращане на справка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("schedule", year=year, month=month))



@app.route("/payroll/<int:employee_id>/<int:year>/<int:month>/notify", methods=["POST"])
@login_required
def payroll_notify_employee(employee_id, year, month):
    user = current_user()
    if not has_permission(user, "can_send_payroll_notification"):
        flash("Нямате право да изпращате известия за заплата.", "danger")
        return redirect(url_for("payroll_tools", year=year, month=month))

    conn = get_db()
    try:
        if not user_can_manage_payroll_for(user, employee_id, conn):
            flash("Нямате право върху този служител.", "danger")
            return redirect(url_for("payroll_tools", year=year, month=month))

        row = calculate_employee_payroll(conn, employee_id, year, month)
        if not row:
            flash("Служителят не е намерен.", "danger")
            return redirect(url_for("payroll_tools", year=year, month=month))

        save_payroll_run(conn, row, year, month, session["user_id"])
        conn.execute("""
            UPDATE payroll_runs
            SET status = 'sent', sent_at = ?
            WHERE employee_id = ? AND year = ? AND month = ?
        """, (datetime.now().isoformat(timespec="seconds"), employee_id, year, month))

        target_user_id = user_id_for_employee(employee_id, conn)
        if target_user_id:
            notify_user(
                target_user_id,
                "Заплатата е готова",
                f"Заплата за {month:02d}.{year}: нетно {row['net_total']:.2f}€ / брутно {row['gross_total']:.2f}€.",
                url_for("payroll_me", year=year, month=month),
                conn
            )

        conn.commit()
        if wants_json_response():
            return jsonify({"ok": True, "message": "Известието за заплата е изпратено.", "status": "sent"})
        flash("Известието за заплата е изпратено.", "success")

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("payroll_tools", year=year, month=month))


@app.route("/payroll/<int:year>/<int:month>/notify-all", methods=["POST"])
@login_required
def payroll_notify_all(year, month):
    user = current_user()
    if not has_permission(user, "can_send_payroll_notification"):
        flash("Нямате право да изпращате известия за заплата.", "danger")
        return redirect(url_for("payroll_tools", year=year, month=month))

    conn = get_db()
    sent = 0
    skipped = 0
    try:
        employee_ids = payroll_employee_ids_for(user, conn, include_self=False)
        employees_list = [{"id": eid} for eid in employee_ids]
        for emp in employees_list:
            row = calculate_employee_payroll(conn, emp["id"], year, month)
            if not row:
                skipped += 1
                continue

            save_payroll_run(conn, row, year, month, session["user_id"])
            conn.execute("""
                UPDATE payroll_runs
                SET status = 'sent', sent_at = ?
                WHERE employee_id = ? AND year = ? AND month = ?
            """, (datetime.now().isoformat(timespec="seconds"), emp["id"], year, month))

            target_user_id = user_id_for_employee(emp["id"], conn)
            if target_user_id:
                notify_user(
                    target_user_id,
                    "Заплатата е готова",
                    f"Заплата за {month:02d}.{year}: нетно {row['net_total']:.2f}€ / брутно {row['gross_total']:.2f}€.",
                    url_for("payroll_me", year=year, month=month),
                    conn
                )
                sent += 1
            else:
                skipped += 1

        conn.commit()
        message = f"Изпратени известия: {sent}. Пропуснати: {skipped}."
        if wants_json_response():
            return jsonify({"ok": True, "message": message, "sent": sent, "skipped": skipped})
        flash(message, "success")
    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка при изпращане на всички заплати: {e}"}), 500
        flash(f"Грешка при изпращане на всички заплати: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for("payroll_tools", year=year, month=month))


@app.route("/payroll-reports")
@login_required
def payroll_reports():
    user = current_user()

    if not (is_root_admin(user) or has_permission(user, "can_view_payroll_reports")):
        flash("Нямате достъп до payroll справки.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    rows = conn.execute("""
        SELECT payroll_reports.*,
               users.username AS manager_username,
               employees.first_name AS manager_first_name,
               employees.last_name AS manager_last_name
        FROM payroll_reports
        JOIN users ON users.id = payroll_reports.manager_user_id
        LEFT JOIN employees ON employees.id = payroll_reports.manager_employee_id
        ORDER BY payroll_reports.created_at DESC
        LIMIT 200
    """).fetchall()

    reports = []
    for r in rows:
        item = dict(r)
        details = payroll_report_details(conn, r)
        item["team_name"] = details["team_name"]
        item["employee_rows"] = details["rows"]
        item["employee_count"] = len(details["employee_ids"])
        reports.append(item)

    conn.close()

    return render_template("payroll_reports.html", reports=reports)


@app.route("/payroll-reports/<int:report_id>/status", methods=["POST"])
@login_required
def payroll_report_status(report_id):
    user = current_user()

    if not (is_root_admin(user) or has_permission(user, "can_manage_payroll")):
        flash("Нямате права да обработвате payroll справки.", "danger")
        return redirect(url_for("dashboard"))

    status = request.form.get("status", "sent")
    if status not in ["sent", "reviewed", "processed"]:
        status = "sent"

    conn = get_db()

    try:
        report = conn.execute("SELECT * FROM payroll_reports WHERE id = ?", (report_id,)).fetchone()
        if not report:
            flash("Справката не е намерена.", "danger")
            return redirect(url_for("payroll_reports"))

        synced = 0
        locked = False
        locked_at = None

        if status == "processed":
            report_employee_ids = parse_employee_ids_json(row_get(report, "employee_ids", "[]"))
            blocked_ids = [eid for eid in report_employee_ids if not user_can_manage_payroll_for(user, eid, conn)]
            if blocked_ids:
                message = "Нямате payroll права върху всички служители в тази справка."
                if wants_json_response():
                    return jsonify({"ok": False, "message": message}), 403
                flash(message, "danger")
                return redirect(url_for("payroll_reports"))

            synced = sync_report_to_payroll_aggressive(conn, report, session["user_id"])
            lock_schedule_month(
                conn,
                int(report["year"]),
                int(report["month"]),
                session["user_id"],
                "Заключен автоматично след обработена payroll справка"
            )
            locked = True
            locked_at = datetime.now().isoformat(timespec="seconds")
            conn.execute("UPDATE payroll_reports SET status = ?, locked_at = ? WHERE id = ?", (status, locked_at, report_id))
            message = f"Статусът е обновен. Прехвърлени към Payroll: {synced} служители. Календарът за {int(report['month']):02d}.{int(report['year'])} е заключен."
        else:
            conn.execute("UPDATE payroll_reports SET status = ? WHERE id = ?", (status, report_id))
            message = "Статусът е обновен."

        conn.commit()
        if wants_json_response():
            return jsonify({"ok": True, "message": message, "status": status, "synced": synced, "locked": locked})

    except Exception as e:
        conn.rollback()
        if wants_json_response():
            return jsonify({"ok": False, "message": f"Грешка: {e}"}), 500
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("payroll_reports"))




@app.route("/debug/permissions")
@login_required
def permissions_debug():
    user = current_user()
    if not is_root_admin(user):
        flash("Само admin има достъп до debug права.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    users_rows = conn.execute("""
        SELECT users.id AS id, users.id AS user_id, users.username, users.role, users.employee_id,
               employees.first_name, employees.last_name, employees.position
        FROM users
        LEFT JOIN employees ON employees.id = users.employee_id
        ORDER BY users.id
    """).fetchall()

    debug_rows = []
    for u in users_rows:
        perms = get_user_permissions(conn, u)
        visible_ids = allowed_schedule_employee_ids(u, conn)
        manageable_ids = manageable_schedule_employee_ids(u, conn)

        visible = []
        if visible_ids:
            placeholders = ",".join(["?"] * len(visible_ids))
            visible = conn.execute(f"""
                SELECT id, first_name, last_name
                FROM employees
                WHERE id IN ({placeholders})
                ORDER BY first_name, last_name
            """, visible_ids).fetchall()

        manageable = []
        if manageable_ids:
            placeholders = ",".join(["?"] * len(manageable_ids))
            manageable = conn.execute(f"""
                SELECT id, first_name, last_name
                FROM employees
                WHERE id IN ({placeholders})
                ORDER BY first_name, last_name
            """, manageable_ids).fetchall()

        debug_rows.append({
            "user": u,
            "perms": perms,
            "visible": visible,
            "manageable": manageable
        })

    conn.close()
    return render_template("permissions_debug.html", rows=debug_rows, permission_labels=PERMISSION_LABELS, scope_labels=SCOPE_LABELS)



# ---------------- DEPARTMENTS ----------------

@app.route("/departments", methods=["GET", "POST"])
@login_required
@manager_required
def departments():
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до отдели.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if name:
            try:
                conn.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (name,))
                conn.commit()
                flash("Отделът е добавен.", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Грешка: {e}", "danger")

    rows = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()
    conn.close()

    return render_template("departments.html", departments=rows)


# ---------------- DATABASE VIEW ----------------

@app.route("/database")
@login_required
@manager_required
def database():
    user = current_user()
    if not (is_root_admin(user) or has_permission(user, "can_manage_users")):
        flash("Нямате достъп до базата.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    tables = {}

    for table in [
        "users",
        "employees",
        "departments",
        "shift_templates",
        "schedule",
        "employee_logs",
        "tickets",
        "notifications",
        "push_subscriptions",
        "bonuses",
        "salary_corrections",
        "feedback_reports",
        "payroll_reports",
        "user_permissions"
    ]:
        tables[table] = conn.execute(f"SELECT * FROM {table} LIMIT 100").fetchall()

    conn.close()
    return render_template("database.html", tables=tables)


# ---------------- FILTERS ----------------

@app.template_filter("hours")
def hours_filter(row):
    return calc_hours(row["start_time"], row["end_time"])


@app.template_filter("money")
def money_filter(value):
    try:
        if value is None:
            value = 0
        return f"€{float(value):.2f}"
    except Exception:
        return "€0.00"




@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "app": "ShiftDesk", "version": APP_VERSION, "build": APP_BUILD})


# ---------------- RUN ----------------

@app.template_filter("dtpretty")
def datetime_pretty_filter(value):
    if not value:
        return "-"
    text = str(value).replace("T", " ")
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return text[:16]


@app.template_filter("datepretty")
def date_pretty_filter(value):
    if not value:
        return "-"
    try:
        d = datetime.fromisoformat(str(value)).date()
        return d.strftime("%d.%m.%Y")
    except Exception:
        return str(value)


def boot_database():
    try:
        init_db()
        print("Database initialized.")
    except Exception as e:
        print("Database init failed:", e)


if __name__ != "__main__":
    boot_database()


if __name__ == "__main__":
    boot_database()
    app.run(host="0.0.0.0", port=5050, debug=True, use_reloader=False)
