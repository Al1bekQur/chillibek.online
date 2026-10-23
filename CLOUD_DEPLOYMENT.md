# Chillibek Cloud Deployment Preparation

This document describes the prepared target architecture:

```text
Internet -> HTTPS reverse proxy -> Chillibek FastAPI WAF -> Flask backend -> PostgreSQL
```

Production PythonAnywhere remains untouched. Perform migration only from an authorized database export.

## Services

- `postgres`: private PostgreSQL database with persistent Docker volume.
- `backend`: Flask API. It is exposed only inside the private Docker network.
- `waf`: public entry point on port `8080` for local/VPS testing. Put HTTPS in front of this service before production traffic.

Only the WAF should be reachable from the internet. PostgreSQL and Flask must stay private.

## Required Secrets

Set these in a server-side env file or secret manager, never in Git:

```text
POSTGRES_PASSWORD=<strong random password>
FLASK_SECRET_KEY=<strong random 32+ character secret>
WAF_DASHBOARD_USERNAME=<operator username>
WAF_DASHBOARD_PASSWORD_HASH=<Werkzeug password hash>
WAF_DASHBOARD_SESSION_SECRET=<strong random 32+ character secret>
```

Generate the dashboard password hash locally:

```bash
python -c "from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass('Dashboard password: ')))"
```

## VPS Deployment Outline

1. Install Docker Engine and Docker Compose plugin on the Linux VPS.
2. Clone the repository and checkout `dev` or the reviewed release branch.
3. Create an env file outside Git with the required secrets.
4. Build and start services:

```bash
docker compose --env-file /secure/path/chillibek.env up -d --build
```

5. Check health:

```bash
docker compose ps
curl http://127.0.0.1:8080/health
```

6. Configure an HTTPS reverse proxy such as Nginx or Caddy in front of the WAF.
7. Restrict direct access to Docker private networks and only expose the HTTPS entry point.

## Database Schema and Migrations

The SQLAlchemy schema lives in `backend/db.py`. Alembic files live in `backend/migrations`.

Run migrations with:

```bash
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DB alembic upgrade head
```

The backend also creates missing tables at startup for local prototype convenience. For production, run Alembic migrations explicitly and review them before deployment.

## Authorized SQLite Import

Use only an authorized local SQLite export. Do not connect tooling to PythonAnywhere production.

```bash
python backend/tools/import_sqlite_to_postgres.py \
  --sqlite-path /secure/export/chillibek.sqlite3 \
  --postgres-url postgresql+psycopg://USER:PASSWORD@HOST:5432/DB
```

The importer refuses to migrate legacy plaintext staff passwords. If legacy plaintext credentials are present, rotate/reset staff credentials:

```bash
python backend/tools/import_sqlite_to_postgres.py \
  --sqlite-path /secure/export/chillibek.sqlite3 \
  --postgres-url postgresql+psycopg://USER:PASSWORD@HOST:5432/DB \
  --reset-staff
```

Then recreate staff accounts through the backend CLI with new passwords.

## Security Notes

- Do not expose PostgreSQL or Flask directly to the internet.
- Terminate HTTPS before the WAF and forward only to the WAF container.
- Keep WAF dashboard credentials separate from restaurant staff credentials.
- Rotate all staff passwords if there is any evidence legacy plaintext credentials were exposed.
- Use centralized logging for WAF events before production deployment.
- Replace in-memory rate limit storage with Redis or another shared backend for multi-worker deployments.

## Remaining Production Work

- Choose VPS/firewall rules and HTTPS reverse proxy.
- Create a secure secrets management process.
- Run a test migration with synthetic data first.
- Run authorized staging tests through the WAF before DNS cutover.
- Plan rollback before switching production traffic.
