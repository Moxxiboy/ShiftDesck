# ShiftDesk pre-deploy diagnostics

Date: 2026-05-03
Base: latest working ZIP in this conversation
Target: Render + PostgreSQL

## Result

Status: ready for Render test deploy after setting environment variables.

## Fixed in this package

1. PostgreSQL compatibility
   - Fixed the PostgreSQL compatibility cursor so `INSERT INTO user_permissions` does not try `RETURNING id`. `user_permissions` has `user_id` as primary key, not `id`.
   - Kept `RETURNING id` only for tables that actually have an `id` column.
   - Added PostgreSQL-friendly handling for integrity/duplicate username errors.

2. Deployment config
   - `SECRET_KEY` now comes from environment variable.
   - `UPLOAD_DIR` can now be configured by environment variable.
   - Added `/healthz` route for deployment health checks.
   - Bumped service-worker cache name to avoid stale cached UI.

3. SQLite database cleanup
   - SQLite integrity check: OK.
   - Added missing permission columns to bundled SQLite DB:
     - `can_create_tickets`
     - `can_escalate_tickets`
   - Removed orphan notifications for deleted/nonexistent users.
   - Checked foreign-key-like relations manually for users, employees, schedule, tickets, payroll and permissions.

4. PostgreSQL migration helper
   - Added `scripts/migrate_sqlite_to_postgres.py`.
   - This can copy the bundled SQLite data into PostgreSQL with `--reset`.

## Checks performed

- Python syntax: OK
- App AST parse: OK
- Template `url_for(...)` endpoint references: OK
- Template inline JavaScript syntax: OK
- `static/service-worker.js` syntax: OK
- SQLite `PRAGMA integrity_check`: OK
- Missing user/employee references: OK
- Missing schedule employee references: OK
- Missing ticket employee/assignee references: OK
- Missing payroll employee references: OK
- Missing notification user references: OK after cleanup
- Missing permission user references: OK

## Required Render environment variables

Recommended minimum:

```text
DATABASE_URL=<Render PostgreSQL internal database URL>
SECRET_KEY=<long random secret>
```

Optional:

```text
UPLOAD_DIR=/var/data/uploads
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
VAPID_SUB=mailto:admin@example.com
```

If file uploads must survive deploys/restarts, use a Render persistent disk and set `UPLOAD_DIR` to that disk path.

## Importing current local data into PostgreSQL

After creating the Render PostgreSQL database and setting `DATABASE_URL`, run once from a shell:

```bash
python scripts/migrate_sqlite_to_postgres.py --reset
```

Use `--reset` only for the first import or when you intentionally want PostgreSQL to be replaced by the bundled SQLite data.

## Notes

- The app still supports SQLite locally when `DATABASE_URL` is not set.
- On Render, `DATABASE_URL` switches the app to PostgreSQL.
- The app initializes/migrates tables on boot.
- Root admin remains the account with `role='manager'` and `employee_id IS NULL`.

## Changelog update

- APP_VERSION updated to `0.9.21-beta`.
- APP_BUILD updated to `2026.05.03-render-ready`.
- `/changelog` and the build update popup now include the latest calendar, permissions, tickets, payroll, mobile UI and Render/PostgreSQL changes.
