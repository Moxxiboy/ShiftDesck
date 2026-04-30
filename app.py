from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, send_from_directory
from functools import wraps
import sqlite3
from pathlib import Path
from io import BytesIO
from datetime import date, datetime, timedelta
import calendar
import random
import os
import hashlib
import hmac
import secrets
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "app.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
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

def get_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


def add_column_if_missing(cur, table, column, definition):
    try:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except sqlite3.OperationalError:
        pass


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
    if "user_id" in session:
        try:
            conn = get_db()
            latest_notification = conn.execute("""
                SELECT * FROM notifications
                WHERE user_id = ? AND is_read = 0
                ORDER BY created_at DESC
                LIMIT 1
            """, (session["user_id"],)).fetchone()
            conn.close()
        except Exception:
            latest_notification = None
    return {
        "current_user": current_user(),
        "unread_notifications": unread_notifications_count(),
        "latest_notification": latest_notification,
        "theme": session.get("theme", "dark"),
        "position_labels": POSITION_LABELS if "POSITION_LABELS" in globals() else {},
        "can_edit_salary": user_can_edit_salary(current_user()),
        "user_can_process_ticket": user_can_process_ticket
    }


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


def manager_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user or user["role"] != "manager":
            flash("Нямате права за тази операция.", "danger")
            return redirect(url_for("dashboard"))

        return view(*args, **kwargs)
    return wrapped


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
        return url_for("notifications", _external=True)
    if str(link).startswith("http://") or str(link).startswith("https://"):
        return link
    return request.host_url.rstrip("/") + str(link)


def send_push_to_user(user_id, title, message, link=None, conn=None):
    if not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return False
    try:
        from pywebpush import webpush
    except Exception:
        return False
    close_conn = False
    if conn is None:
        conn = get_db()
        close_conn = True
    rows = conn.execute("SELECT id, data FROM push_subscriptions WHERE user_id = ?", (user_id,)).fetchall()
    payload = json.dumps({"title": title, "body": message, "url": absolute_link(link), "icon": "/static/icon.svg"}, ensure_ascii=False)
    dead = []
    ok = False
    for row in rows:
        try:
            webpush(subscription_info=json.loads(row["data"]), data=payload, vapid_private_key=VAPID_PRIVATE_KEY, vapid_claims=VAPID_CLAIMS)
            ok = True
        except Exception as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in [404, 410]:
                dead.append(row["id"])
    for sid in dead:
        conn.execute("DELETE FROM push_subscriptions WHERE id = ?", (sid,))
    if close_conn:
        conn.commit()
        conn.close()
    return ok


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


def salary_rows(conn, start, end, employee_id=None):
    params = [start, end]
    extra = ""
    if employee_id:
        extra = " AND employees.id = ?"
        params.append(employee_id)
    rows = conn.execute(f"""
        SELECT employees.id, employees.first_name, employees.last_name,
               employees.hourly_rate, employees.overtime_rate,
               departments.name AS department, schedule.start_time,
               schedule.end_time, schedule.work_date
        FROM schedule
        JOIN employees ON employees.id = schedule.employee_id
        LEFT JOIN departments ON departments.id = employees.department_id
        WHERE schedule.work_date BETWEEN ? AND ?
        {extra}
        ORDER BY employees.first_name, schedule.work_date
    """, params).fetchall()
    grouped = {}
    for row in rows:
        eid = row["id"]
        if eid not in grouped:
            grouped[eid] = {"id": eid, "name": f"{row['first_name']} {row['last_name']}", "department": row["department"] or "-", "hourly_rate": row["hourly_rate"], "hours": 0, "overtime_hours": 0, "salary": 0, "shifts": 0}
        h = calc_hours(row["start_time"], row["end_time"])
        before = grouped[eid]["hours"]
        normal = max(0, min(h, 40 - before))
        overtime = max(0, h - normal)
        overtime_rate = row["overtime_rate"] or (row["hourly_rate"] * 1.5)
        grouped[eid]["hours"] += h
        grouped[eid]["overtime_hours"] += overtime
        grouped[eid]["salary"] += normal * row["hourly_rate"] + overtime * overtime_rate
        grouped[eid]["shifts"] += 1
    return list(grouped.values())

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

def remove_employee_shifts_for_period(conn, employee_id, start_date, end_date, reason):
    if not start_date: return 0
    end_date = end_date or start_date
    rows = conn.execute("""SELECT * FROM schedule WHERE employee_id=? AND work_date BETWEEN ? AND ?""", (employee_id, start_date, end_date)).fetchall()
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
        notify_user(u["id"], "Промяна в графика", f"{name} е {reason} за {start_date} - {end_date or start_date}.", url_for("schedule"), conn)


# ---------------- PWA ----------------

@app.route("/manifest.json")
def manifest():
    return send_from_directory(static, "manifest.json")


@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(static, "service-worker.js")


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
                email = request.form.get("email")
                phone = request.form.get("phone")
                theme = request.form.get("theme", "dark")
                photo_name = None
                if request.files.get("photo") and request.files["photo"].filename:
                    photo_name = save_uploaded_file(request.files.get("photo"))
                if user["employee_id"]:
                    if photo_name:
                        conn.execute("UPDATE employees SET email=?, phone=?, photo=? WHERE id=?", (email, phone, photo_name, user["employee_id"]))
                    else:
                        conn.execute("UPDATE employees SET email=?, phone=? WHERE id=?", (email, phone, user["employee_id"]))
                session["theme"] = theme
                flash("Настройките са запазени.", "success")
            elif action == "password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")
                db_user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
                if not check_password_hash(db_user["password_hash"], current_password):
                    flash("Текущата парола е грешна.", "danger"); conn.close(); return redirect(url_for("settings"))
                if len(new_password) < 6:
                    flash("Новата парола трябва да е поне 6 символа.", "danger"); conn.close(); return redirect(url_for("settings"))
                if new_password != confirm_password:
                    flash("Паролите не съвпадат.", "danger"); conn.close(); return redirect(url_for("settings"))
                conn.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (generate_password_hash(new_password), session["user_id"]))
                session["must_change_password"] = 0
                flash("Паролата е сменена.", "success")
            conn.commit()
        except Exception as e:
            conn.rollback(); flash(f"Грешка: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("settings"))
    conn = get_db(); employee = None
    if user["employee_id"]:
        employee = conn.execute("""SELECT employees.*, departments.name AS department FROM employees LEFT JOIN departments ON departments.id=employees.department_id WHERE employees.id=?""", (user["employee_id"],)).fetchone()
    conn.close()
    return render_template("settings.html", employee=employee)


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

def is_weekend(day_iso):
    return datetime.strptime(day_iso, "%Y-%m-%d").date().weekday() >= 5

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
    if not user:
        return False

    if is_root_admin(user) or is_executive(user) or user_position(user) == "operations_director":
        return True

    if not user["employee_id"]:
        return False

    should_close = False
    if conn is None:
        conn = get_db()
        should_close = True

    allowed = employee_id in get_subordinate_ids(conn, user["employee_id"])

    if should_close:
        conn.close()

    return allowed


def user_can_manage_schedule_for(user, employee_id, conn=None):
    # Team managers can schedule only direct/indirect subordinates.
    # Directors/root admin can schedule everyone.
    return user_can_manage_employee(user, int(employee_id), conn)


def user_can_view_salary(user, employee_id=None):
    # Worker sees only own salary.
    # Finance sees salaries.
    # Executive sees total/financial overview.
    # Root admin can see all.
    if not user:
        return False

    if is_root_admin(user) or is_finance(user) or is_executive(user):
        return True

    if employee_id and user["employee_id"] == employee_id:
        return True

    return False


def user_can_edit_salary(user):
    # Salary corrections are only for finance, executive and root admin.
    return bool(user and (is_root_admin(user) or is_finance(user) or is_executive(user)))


def user_can_view_ticket(user, ticket):
    if not user:
        return False

    if is_root_admin(user) or is_executive(user):
        return True

    if ticket["assigned_to"] and user["id"] == ticket["assigned_to"]:
        return True

    if user["employee_id"] == ticket["employee_id"]:
        return True

    return False


def user_can_process_ticket(user, ticket):
    if not user:
        return False

    if is_root_admin(user) or is_executive(user):
        return True

    if ticket["assigned_to"] and user["id"] == ticket["assigned_to"]:
        return True

    if user["employee_id"] and (is_team_manager(user) or is_director_or_above(user)):
        conn = get_db()
        try:
            return int(ticket["employee_id"]) in get_subordinate_ids(conn, user["employee_id"])
        finally:
            conn.close()

    return False

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
    return redirect(url_for("dashboard"))


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
            return redirect(url_for("dashboard"))

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
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()

    if user["role"] == "employee" and user["employee_id"]:
        return redirect(url_for("employee_profile", employee_id=user["employee_id"]))

    conn = get_db()

    if user["role"] == "manager":
        stats = {
            "employees": conn.execute("SELECT COUNT(*) AS c FROM employees WHERE active = 1").fetchone()["c"],
            "departments": conn.execute("SELECT COUNT(*) AS c FROM departments").fetchone()["c"],
            "shifts": conn.execute("SELECT COUNT(*) AS c FROM schedule").fetchone()["c"],
            "today": conn.execute("SELECT COUNT(*) AS c FROM schedule WHERE work_date = ?", (date.today().isoformat(),)).fetchone()["c"],
        }

        upcoming = conn.execute("""
            SELECT schedule.*, employees.first_name, employees.last_name, departments.name AS department
            FROM schedule
            JOIN employees ON employees.id = schedule.employee_id
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE work_date >= ?
            ORDER BY work_date, start_time
            LIMIT 8
        """, (date.today().isoformat(),)).fetchall()

    else:
        rows = conn.execute("SELECT * FROM schedule WHERE employee_id = ?", (user["employee_id"],)).fetchall()
        total_hours = sum(calc_hours(r["start_time"], r["end_time"]) for r in rows)
        emp = conn.execute("SELECT hourly_rate FROM employees WHERE id = ?", (user["employee_id"],)).fetchone()

        stats = {
            "employees": 1,
            "departments": 0,
            "shifts": len(rows),
            "today": round(total_hours * (emp["hourly_rate"] if emp else 0), 2)
        }

        upcoming = conn.execute("""
            SELECT schedule.*, employees.first_name, employees.last_name, departments.name AS department
            FROM schedule
            JOIN employees ON employees.id = schedule.employee_id
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employee_id = ? AND work_date >= ?
            ORDER BY work_date, start_time
            LIMIT 8
        """, (user["employee_id"], date.today().isoformat())).fetchall()

    conn.close()

    return render_template("dashboard.html", stats=stats, upcoming=upcoming)


# ---------------- EMPLOYEES ----------------

@app.route("/employees")
@login_required
def employees():
    user = current_user()
    q = request.args.get("q", "").strip()
    conn = get_db()

    if user["role"] == "employee":
        rows = conn.execute("""
            SELECT employees.*, departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.id = ?
        """, (user["employee_id"],)).fetchall()
    else:
        sql = """
            SELECT employees.*, departments.name AS department
            FROM employees
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employees.active = 1
        """
        params = []

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
                (first_name, last_name, email, phone, department_id, hourly_rate, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                request.form["first_name"],
                request.form["last_name"],
                request.form.get("email"),
                request.form.get("phone"),
                request.form.get("department_id") or None,
                float(request.form.get("hourly_rate") or 0),
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

    return render_template("employee_form.html", employee=None, departments=departments)


@app.route("/employees/<int:employee_id>/edit", methods=["GET", "POST"])
@login_required
@manager_required
def employee_edit(employee_id):
    conn = get_db()
    employee = conn.execute("SELECT * FROM employees WHERE id = ?", (employee_id,)).fetchone()
    departments = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()

    if not employee:
        conn.close()
        flash("Служителят не е намерен.", "danger")
        return redirect(url_for("employees"))

    if request.method == "POST":
        try:
            conn.execute("""
                UPDATE employees
                SET first_name = ?, last_name = ?, email = ?, phone = ?, department_id = ?, hourly_rate = ?
                WHERE id = ?
            """, (
                request.form["first_name"],
                request.form["last_name"],
                request.form.get("email"),
                request.form.get("phone"),
                request.form.get("department_id") or None,
                float(request.form.get("hourly_rate") or 0),
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

    return render_template("employee_form.html", employee=employee, departments=departments)


@app.route("/employees/<int:employee_id>/delete", methods=["POST"])
@login_required
@manager_required
def employee_delete(employee_id):
    conn = get_db()
    try:
        conn.execute("UPDATE employees SET active = 0 WHERE id = ?", (employee_id,))
        log_employee(employee_id, "Деактивиране", "Служителят е маркиран като неактивен", conn)
        conn.commit()
        flash("Служителят е деактивиран.", "info")
    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("team"))

@app.route("/employees/<int:employee_id>/profile")
@login_required
def employee_profile(employee_id):
    user = current_user()

    if user["role"] == "employee" and user["employee_id"] != employee_id:
        flash("Можете да виждате само своя профил.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()

    employee = conn.execute("""
        SELECT employees.*, departments.name AS department,
               manager.first_name AS manager_first_name,
               manager.last_name AS manager_last_name
        FROM employees
        LEFT JOIN departments ON departments.id = employees.department_id
        LEFT JOIN employees AS manager ON manager.id = employees.manager_id
        WHERE employees.id = ?
    """, (employee_id,)).fetchone()

    schedules = conn.execute("""
        SELECT * FROM schedule
        WHERE employee_id = ?
        ORDER BY work_date DESC
    """, (employee_id,)).fetchall()

    logs = conn.execute("""
        SELECT * FROM employee_logs
        WHERE employee_id = ?
        ORDER BY created_at DESC
    """, (employee_id,)).fetchall()

    total_hours = sum(calc_hours(s["start_time"], s["end_time"]) for s in schedules)
    salary = round(total_hours * (employee["hourly_rate"] if employee else 0), 2)

    conn.close()

    return render_template("profile.html", employee=employee, schedules=schedules, logs=logs, total_hours=total_hours, salary=salary)


# ---------------- USERS MANAGEMENT ----------------

@app.route("/users")
@login_required
@manager_required
def users():
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
        flash(f"Потребителят е създаден. Временна парола: {temp_password}", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("Потребителското име вече съществува.", "danger")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@manager_required
def user_reset_password(user_id):
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

    if request.method == "POST":
        today = date.today()
        if not (is_root_admin(user) or is_team_manager(user) or is_director_or_above(user)):
            conn.close()
            flash("Нямате права за добавяне на смени.", "danger")
            return redirect(url_for("schedule"))

        try:
            employee_ids = request.form.getlist("employee_ids")
            work_date = request.form["work_date"]
            start_time = request.form["start_time"]
            end_time = request.form["end_time"]
            notes = request.form.get("notes")
            now = datetime.now().isoformat(timespec="seconds")

            if not employee_ids:
                flash("Изберете поне един служител.", "danger")
                return redirect(url_for("schedule", year=work_date[:4], month=work_date[5:7]))

            allow_non_working = request.form.get("allow_non_working") == "1"
            if is_non_working_day(work_date) and not allow_non_working:
                flash("Денят е почивен/празничен. Отбележете, че се налага работа в почивен ден.", "danger")
                return redirect(url_for("schedule", year=work_date[:4], month=work_date[5:7]))

            skipped = []
            added = 0
            new_hours = calc_hours(start_time, end_time)

            for employee_id in employee_ids:
                if not user_can_manage_schedule_for(user, int(employee_id), conn):
                    er = conn.execute("SELECT first_name,last_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                    skipped.append(f"{er['first_name']} {er['last_name']}" if er else str(employee_id))
                    continue

                current_hours = employee_week_hours(conn, employee_id, work_date)
                if current_hours + new_hours > 40:
                    er = conn.execute("SELECT first_name,last_name FROM employees WHERE id=?", (employee_id,)).fetchone()
                    skipped.append(f"{er['first_name']} {er['last_name']}" if er else str(employee_id))
                    continue

                conn.execute("""
                    INSERT INTO schedule
                    (employee_id, work_date, start_time, end_time, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    employee_id,
                    work_date,
                    start_time,
                    end_time,
                    (notes or "") + (" · Работа в почивен/празничен ден" if is_non_working_day(work_date) else ""),
                    now,
                    now
                ))

                log_employee(int(employee_id), "Смяна", f"Добавена смяна за {work_date}", conn)
                added += 1

                target_user_id = user_id_for_employee(employee_id, conn)
                if target_user_id:
                    notify_user(
                        target_user_id,
                        "Нова смяна",
                        f"Добавена е смяна за {work_date} от {start_time} до {end_time}.",
                        url_for("schedule"),
                        conn
                    )

            conn.commit()
            if skipped:
                flash("Пропуснати заради лимит 40ч/седмица: " + ", ".join(skipped), "info")
            if added:
                flash("Смените са добавени.", "success")
            return redirect(url_for("schedule", year=work_date[:4], month=work_date[5:7]))

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")
            return redirect(url_for("schedule"))
        finally:
            conn.close()

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))

    if month < 1:
        month = 12
        year -= 1
    if month > 12:
        month = 1
        year += 1

    first_day = date(year, month, 1)
    last_day_num = calendar.monthrange(year, month)[1]
    last_day = date(year, month, last_day_num)

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

    month_days = [date(year, month, day).isoformat() for day in range(1, last_day_num + 1)]
    first_weekday = first_day.weekday()
    calendar_cells = [None] * first_weekday + month_days
    while len(calendar_cells) % 7 != 0:
        calendar_cells.append(None)

    if user["role"] == "manager":
        rows = conn.execute("""
            SELECT schedule.*, employees.first_name, employees.last_name,
                   departments.name AS department, employees.hourly_rate
            FROM schedule
            JOIN employees ON employees.id = schedule.employee_id
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE work_date BETWEEN ? AND ?
            ORDER BY work_date, start_time
        """, (first_day.isoformat(), last_day.isoformat())).fetchall()
    else:
        rows = conn.execute("""
            SELECT schedule.*, employees.first_name, employees.last_name,
                   departments.name AS department, employees.hourly_rate
            FROM schedule
            JOIN employees ON employees.id = schedule.employee_id
            LEFT JOIN departments ON departments.id = employees.department_id
            WHERE employee_id = ? AND work_date BETWEEN ? AND ?
            ORDER BY work_date, start_time
        """, (user["employee_id"], first_day.isoformat(), last_day.isoformat())).fetchall()

    employees_list = conn.execute("SELECT * FROM employees WHERE active = 1 ORDER BY first_name").fetchall()
    templates = conn.execute("SELECT * FROM shift_templates ORDER BY start_time").fetchall()
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
        templates=templates,
        year=year,
        month=month,
        month_name=month_names[month],
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        holidays=BULGARIA_HOLIDAYS_2026 if "BULGARIA_HOLIDAYS_2026" in globals() else {}
    )

@app.route("/schedule/<int:shift_id>/delete", methods=["POST"])
@login_required
@manager_required
def schedule_delete(shift_id):
    conn = get_db()

    try:
        row = conn.execute("SELECT * FROM schedule WHERE id = ?", (shift_id,)).fetchone()

        if row:
            conn.execute("DELETE FROM schedule WHERE id = ?", (shift_id,))
            log_employee(row["employee_id"], "Изтрита смяна", f"Изтрита смяна за {row['work_date']}", conn)

            target_user_id = user_id_for_employee(row["employee_id"], conn)
            if target_user_id:
                notify_user(target_user_id, "Изтрита смяна", f"Смяната за {row['work_date']} беше изтрита.", url_for("schedule"), conn)

            conn.commit()
            flash("Смяната е изтрита.", "info")

        else:
            flash("Смяната не е намерена.", "danger")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("schedule"))


@app.route("/api/schedule/<int:shift_id>/move", methods=["POST"])
@login_required
@manager_required
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

        conn.execute("UPDATE schedule SET work_date = ?, updated_at = ? WHERE id = ?", (new_date, datetime.now().isoformat(timespec="seconds"), shift_id))
        log_employee(row["employee_id"], "Преместена смяна", f"Смяната е преместена на {new_date}", conn)

        target_user_id = user_id_for_employee(row["employee_id"], conn)
        if target_user_id:
            notify_user(target_user_id, "Преместена смяна", f"Смяната е преместена на {new_date}.", url_for("schedule"), conn)

        conn.commit()
        return jsonify({"ok": True})

    except Exception as e:
        conn.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

    finally:
        conn.close()


@app.route("/generate-schedule", methods=["POST"])
@login_required
@manager_required
def generate_schedule():
    user = current_user()
    conn = get_db()

    try:
        if not (is_root_admin(user) or is_team_manager(user) or is_director_or_above(user)):
            flash("Нямате права за генериране на график.", "danger")
            conn.close()
            return redirect(url_for("schedule"))

        if is_team_manager(user) and user["employee_id"]:
            subordinate_ids = get_subordinate_ids(conn, user["employee_id"])
            if subordinate_ids:
                placeholders = ",".join(["?"] * len(subordinate_ids))
                employees_list = conn.execute(f"SELECT * FROM employees WHERE active = 1 AND id IN ({placeholders})", subordinate_ids).fetchall()
            else:
                employees_list = []
        else:
            employees_list = conn.execute("SELECT * FROM employees WHERE active = 1").fetchall()
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
                    notify_user(target_user_id, "Нова автоматична смяна", f"Генерирана е смяна за {day}: {tmpl['start_time']} - {tmpl['end_time']}.", url_for("schedule"), conn)

        conn.commit()
        flash("Умният автоматичен график е генериран.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка при генериране: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("schedule"))


# ---------------- TICKETS ----------------

@app.route("/tickets")
@login_required
def tickets():
    user = current_user()
    if is_finance(user):
        flash("Финансовият отдел работи само със заплати, бонуси и корекции.", "info")
        return redirect(url_for("salaries"))
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "active")
    show_archived = status == "archived"
    conn = get_db()
    sql = """
        SELECT tickets.*, employees.first_name, employees.last_name, assigned.username AS assigned_username
        FROM tickets
        JOIN employees ON employees.id = tickets.employee_id
        LEFT JOIN users AS assigned ON assigned.id = tickets.assigned_to
        WHERE COALESCE(tickets.archived, 0) = ?
    """
    params = [1 if show_archived else 0]
    if is_root_admin(user) or is_executive(user):
        pass
    elif is_team_manager(user) or is_director_or_above(user):
        sql += " AND (tickets.assigned_to = ? OR tickets.employee_id = ?)"
        params.extend([user["id"], user["employee_id"]])
    else:
        sql += " AND tickets.employee_id = ?"
        params.append(user["employee_id"])
    if q:
        sql += " AND (tickets.title LIKE ? OR tickets.description LIKE ? OR tickets.type LIKE ? OR tickets.status LIKE ? OR employees.first_name LIKE ? OR employees.last_name LIKE ?)"
        like = f"%{q}%"
        params.extend([like, like, like, like, like, like])
    sql += " ORDER BY tickets.created_at DESC"
    rows = conn.execute(sql, params).fetchall()
    count_base = "FROM tickets WHERE COALESCE(archived, 0) = ?"
    active_params = [0]; archived_params = [1]
    if is_root_admin(user) or is_executive(user):
        pass
    elif is_team_manager(user) or is_director_or_above(user):
        count_base += " AND (assigned_to = ? OR employee_id = ?)"
        active_params.extend([user["id"], user["employee_id"]])
        archived_params.extend([user["id"], user["employee_id"]])
    else:
        count_base += " AND employee_id = ?"
        active_params.append(user["employee_id"])
        archived_params.append(user["employee_id"])
    active_count = conn.execute("SELECT COUNT(*) AS c " + count_base, active_params).fetchone()["c"]
    archived_count = conn.execute("SELECT COUNT(*) AS c " + count_base, archived_params).fetchone()["c"]
    conn.close()
    return render_template("tickets.html", tickets=rows, q=q, status=status, show_archived=show_archived, active_count=active_count, archived_count=archived_count)

@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def ticket_new():
    user = current_user()

    if not user["employee_id"]:
        flash("Този акаунт не е свързан със служител и не може да създава заявки.", "danger")
        return redirect(url_for("tickets"))

    if request.method == "POST":
        conn = get_db()

        try:
            now = datetime.now().isoformat(timespec="seconds")
            attachment_name = save_uploaded_file(request.files.get("attachment"))

            assigned_to = get_employee_manager_user_id(conn, user["employee_id"])
            conn.execute("""
                INSERT INTO tickets
                (employee_id, type, title, description, start_date, end_date, status, manager_comment, attachment, assigned_to, approval_level, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user["employee_id"],
                request.form["type"],
                request.form["title"],
                request.form.get("description"),
                request.form.get("start_date") or None,
                request.form.get("end_date") or None,
                "pending",
                None,
                attachment_name,
                assigned_to,
                1,
                now,
                now
            ))

            if assigned_to:
                notify_user(assigned_to, "Нова заявка", f"{user['first_name'] or user['username']} изпрати заявка: {request.form['title']}", url_for("tickets"), conn)
            else:
                notify_managers("Нова заявка", f"{user['first_name'] or user['username']} изпрати заявка: {request.form['title']}", url_for("tickets"), conn)

            conn.commit()
            flash("Заявката е изпратена.", "success")
            return redirect(url_for("tickets"))

        except Exception as e:
            conn.rollback()
            flash(f"Грешка: {e}", "danger")

        finally:
            conn.close()

    return render_template("ticket_form.html")


@app.route("/tickets/<int:ticket_id>/update", methods=["POST"])
@login_required
@manager_required
def ticket_update(ticket_id):
    status = request.form.get("status")
    manager_comment = request.form.get("manager_comment", "")
    allowed = ["pending", "approved", "rejected", "closed"]

    if status not in allowed:
        flash("Невалиден статус.", "danger")
        return redirect(url_for("tickets"))

    conn = get_db()

    try:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()

        if not ticket:
            flash("Заявката не е намерена.", "danger")
            conn.close()
            return redirect(url_for("tickets"))

        if not user_can_process_ticket(current_user(), ticket):
            flash("Нямате права да обработвате тази заявка.", "danger")
            conn.close()
            return redirect(url_for("tickets"))

        archive_value = 1 if status in ["approved", "rejected", "closed"] else 0
        conn.execute("""
            UPDATE tickets
            SET status = ?, manager_comment = ?, archived = ?, updated_at = ?
            WHERE id = ?
        """, (status, manager_comment, archive_value, datetime.now().isoformat(timespec="seconds"), ticket_id))
        if status == "approved" and ticket["type"] in ["Отпуска", "Болничен"]:
            remove_employee_shifts_for_period(conn, ticket["employee_id"], ticket["start_date"], ticket["end_date"], ticket["type"])
            notify_coworkers_about_absence(conn, ticket["employee_id"], ticket["start_date"], ticket["end_date"], ticket["type"])
        target_user_id = user_id_for_employee(ticket["employee_id"], conn)
        if target_user_id:
            labels = {"pending": "чака", "approved": "одобрена", "rejected": "отказана", "closed": "приключена"}
            notify_user(target_user_id, "Обновена заявка", f"Заявката '{ticket['title']}' е {labels.get(status, status)}.", url_for("tickets"), conn)

        conn.commit()
        flash("Заявката е обновена.", "success")

    except Exception as e:
        conn.rollback()
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


@app.route("/notifications/mark-read", methods=["POST"])
@login_required
def notifications_mark_read():
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    flash("Известията са маркирани като прочетени.", "success")
    return redirect(url_for("notifications"))


@app.route("/api/notifications/unread-count")
@login_required
def notifications_unread_count_api():
    return jsonify({"ok": True, "count": unread_notifications_count()})


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

    notify_user(session["user_id"], "Тестово push известие", "Ако push е настроен, ще получиш системно известие.", url_for("notifications"))
    return jsonify({"ok": True})


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

    if is_root_admin(user) or is_finance(user) or is_executive(user):
        rows = salary_rows(conn, start, end)
    elif user["employee_id"]:
        rows = salary_rows(conn, start, end, user["employee_id"])
    else:
        rows = []

    total_hours = round(sum(row["hours"] for row in rows), 2)
    total_salary = round(sum(row["salary"] for row in rows), 2)

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
@manager_required
def schedule_clear_month():
    user = current_user()
    if not (is_root_admin(user) or is_executive(user) or user_position(user) == "operations_director"):
        flash("Само директор/админ може да изтрива целия месечен график.", "danger")
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

@app.route("/tickets/request-shift", methods=["POST"])
@login_required
def ticket_request_shift():
    user = current_user()

    if not user["employee_id"]:
        flash("Този акаунт не е свързан със служител.", "danger")
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

        conn.execute("""
            INSERT INTO tickets
            (employee_id, type, title, description, start_date, end_date, status, manager_comment, attachment, assigned_to, approval_level, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["employee_id"],
            "Искам смяна",
            title,
            f"Предпочитан час: {preferred_time}. {description}",
            preferred_date,
            preferred_date,
            "pending",
            None,
            None,
            assigned_to,
            1,
            now,
            now
        ))

        if assigned_to:
            notify_user(
                assigned_to,
                "Нова заявка за смяна",
                f"{user['first_name'] or user['username']} иска смяна на {preferred_date}.",
                url_for("tickets"),
                conn
            )
        else:
            notify_managers(
                "Нова заявка за смяна",
                f"{user['first_name'] or user['username']} иска смяна на {preferred_date}.",
                url_for("tickets"),
                conn
            )

        conn.commit()
        flash("Заявката за смяна е изпратена.", "success")

    except Exception as e:
        conn.rollback()
        flash(f"Грешка: {e}", "danger")

    finally:
        conn.close()

    return redirect(url_for("tickets"))


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
    if not (is_root_admin(user) or is_team_manager(user) or is_director_or_above(user)):
        flash("Нямате достъп до Екип.", "danger")
        return redirect(url_for("dashboard"))

    if is_finance(user):
        flash("Финансовият отдел няма достъп до Екип.", "danger")
        return redirect(url_for("salaries"))

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

    if not (is_root_admin(user) or is_executive(user) or user_position(user) == "operations_director"):
        subordinate_ids = get_subordinate_ids(conn, user["employee_id"]) if user["employee_id"] else []
        if subordinate_ids:
            placeholders = ",".join(["?"] * len(subordinate_ids))
            sql += f" AND employees.id IN ({placeholders})"
            params.extend(subordinate_ids)
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

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("Потребителското име вече съществува.", "danger")

    except Exception as e:
        conn.rollback()
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

    if user["role"] != "manager" and user["employee_id"] != employee_id:
        flash("Можете да изтегляте само своя отчет.", "danger")
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




@app.route("/payroll-tools")
@login_required
def payroll_tools():
    user = current_user()
    if not user_can_edit_salary(user):
        flash("Само финансов отдел/изпълнителен директор има достъп до payroll инструментите.", "danger")
        return redirect(url_for("dashboard"))

    today = date.today()
    year = int(request.args.get("year", today.year))
    month = int(request.args.get("month", today.month))
    first = date(year, month, 1)
    last = date(year, month, calendar.monthrange(year, month)[1])

    conn = get_db()
    rows = salary_rows(conn, first.isoformat(), last.isoformat())
    total_gross = round(sum(r["salary"] for r in rows), 2)
    total_net = round(total_gross * 0.78, 2)
    total_hours = round(sum(r["hours"] for r in rows), 2)
    total_overtime = round(sum(r.get("overtime_hours", 0) for r in rows), 2)
    active_employees = conn.execute("SELECT COUNT(*) AS c FROM employees WHERE active = 1").fetchone()["c"]
    conn.close()

    return render_template(
        "payroll_tools.html",
        rows=rows,
        year=year,
        month=month,
        total_gross=total_gross,
        total_net=total_net,
        total_hours=total_hours,
        total_overtime=total_overtime,
        active_employees=active_employees
    )




# ---------------- FEEDBACK / HELP ----------------

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

            conn.execute("""
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

            # Notify root admins / managers without employee profile.
            admins = conn.execute("SELECT id FROM users WHERE role = 'manager' AND employee_id IS NULL").fetchall()
            for admin in admins:
                notify_user(
                    admin["id"],
                    "Нов report",
                    f"{user['username']} изпрати: {title}",
                    url_for("feedback_reports"),
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

    if is_root_admin(user):
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

    if not is_root_admin(user):
        flash("Само админ може да обработва reports.", "danger")
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


@app.route("/help")
@login_required
def help_page():
    return render_template("help.html")



# ---------------- DEPARTMENTS ----------------

@app.route("/departments", methods=["GET", "POST"])
@login_required
@manager_required
def departments():
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
    conn = get_db()
    tables = {}

    for table in ["users", "employees", "departments", "shift_templates", "schedule", "employee_logs", "tickets", "notifications", "push_subscriptions"]:
        tables[table] = conn.execute(f"SELECT * FROM {table} LIMIT 100").fetchall()

    conn.close()
    return render_template("database.html", tables=tables)


# ---------------- FILTERS ----------------

@app.template_filter("hours")
def hours_filter(row):
    return calc_hours(row["start_time"], row["end_time"])


@app.template_filter("money")
def money_filter(value):
    return f"€{float(value):.2f}"


# ---------------- RUN ----------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5050, debug=True, use_reloader=False)
