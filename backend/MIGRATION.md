# Backend security and migration notes

## Local setup

1. Create `backend/.env` from `.env.example`, set a unique random `FLASK_SECRET_KEY`, the intended database path, and only the exact frontend origins. Never commit `.env` or a database file.
2. Install `requirements-dev.txt` for development/testing (`requirements.txt` is included), then run `python backend/run.py` from the repository root. The app creates its schema and the original sample menu if needed; it deliberately creates no staff accounts.
3. Create local accounts interactively with `flask --app backend/server.py create-admin <username>` or `flask --app backend/server.py create-staff <username> waiter|chef`. Use the prompt; no password is stored in source or command history.
4. Run tests with `pytest backend/tests`.

## Legacy SQLite password migration

Back up the database through a secure, authorized process before migration. Never commit or copy its contents into the repository. Point `DATABASE_PATH` at the local migration copy and run:

```text
flask --app backend/server.py migrate-passwords
```

The command replaces plaintext staff passwords with Werkzeug password hashes, skips already-hashed values, reports only a count, and does not display credentials. A successful login also upgrades that account's legacy plaintext password if the migration command has not yet been run. Confirm all accounts can authenticate before retiring the original database; rotate any credentials that may have been exposed.

## API compatibility and cutover

The existing routes and menu/order JSON shapes remain. The login response now also returns a signed, expiring bearer token. All staff operations require `Authorization: Bearer <token>`; the frontend admin and kitchen pages now store the token in `sessionStorage` and attach it to protected calls. The customer menu and order submission remain public. Order creation ignores client-supplied item names/prices/totals and calculates the existing 10% service charge from current menu prices.

The current HTML still points at the PythonAnywhere API URL. Do not deploy the updated frontend separately from a compatible secured backend: the legacy API does not issue or enforce bearer tokens, while the new backend requires them for staff operations. In staging, point the frontend at the staged API, verify CORS, staff access, order flows, and price totals, then plan a coordinated cutover and rollback. No production service is changed by this repository work.

Configure a shared Redis-compatible `RATELIMIT_STORAGE_URI` for multi-worker deployment; the example's in-memory rate-limit store is for local development only. Terminate HTTPS at the deployment edge and keep production secrets outside Git.
