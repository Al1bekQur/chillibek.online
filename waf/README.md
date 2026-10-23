# Chillibek WAF Phase 1

The live Security Settings panel extends this original proxy. See
[`SETTINGS_DEPLOYMENT.md`](../SETTINGS_DEPLOYMENT.md) for current controls, API,
persistence, local startup, tests and public routing requirements. On local HTTP,
set `WAF_SECURE_COOKIES=false` before starting the Dashboard; public HTTPS defaults
to Secure cookies. This does not deploy `/settings` to the public domain.

This directory contains the first working Web Application Firewall prototype for the Chillibek diploma project. It is an independent Python reverse proxy built with FastAPI, httpx, and Uvicorn.

## Architecture

Browser or API client traffic is sent to the WAF at `http://127.0.0.1:8080`. The WAF inspects the request and forwards allowed traffic to the fixed local Flask backend at `http://127.0.0.1:5000`.

The upstream address is configured in code through `WAFSettings` and is not taken from user input. This prevents clients from choosing arbitrary proxy targets and reduces SSRF risk.

## Detection

The WAF inspects:

- HTTP method and path metadata
- Query string
- Selected textual headers: `User-Agent`, `Content-Type`, `Accept`, `Referer`
- Textual request bodies, including JSON and form data

Phase 1 includes configurable Python rules for:

- `SQLI-001`: common SQL injection markers
- `XSS-001`: common script tags, event handlers, and JavaScript URLs
- `TRAV-001`: path traversal and sensitive local file markers

Each rule contributes a risk score. Requests at or above the block threshold receive HTTP 403.

## Safe Logging

Logs are written as JSON lines to `waf/logs/waf.log`. Records include timestamp, client IP, method, path, whether a query exists, content length, matched rule IDs, risk score, decision, and status code.

The WAF does not log raw request bodies, passwords, cookies, authorization headers, access tokens, or full query values.

## Local Setup

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

Start the Flask backend:

```powershell
$env:FLASK_APP = "backend/server.py"
.\.venv\Scripts\flask.exe run --host 127.0.0.1 --port 5000
```

Start the WAF in a second terminal:

```powershell
.\.venv\Scripts\python.exe -m waf.run
```

Check availability:

```powershell
Invoke-WebRequest http://127.0.0.1:8080/health
Invoke-WebRequest http://127.0.0.1:8080/api/menu
```

## Security Dashboard

The WAF includes a separate read-only dashboard at:

```text
http://127.0.0.1:8080/dashboard
```

Dashboard authentication is independent from restaurant staff authentication. Configure it with environment variables before starting the WAF:

```powershell
$env:WAF_DASHBOARD_USERNAME = "analyst"
$env:WAF_DASHBOARD_SESSION_SECRET = "<random 32+ character secret>"
$env:WAF_DASHBOARD_PASSWORD_HASH = "<Werkzeug password hash>"
```

Generate a password hash locally without printing the password in source code:

```powershell
.\.venv\Scripts\python.exe -c "from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass('Dashboard password: ')))"
```

For local manual startup, you can also use the helper script. It prompts for a dashboard username and password, hashes the password in memory, creates a random session secret, and starts the WAF:

```powershell
.\.venv\Scripts\python.exe waf\scripts\start_dashboard.py
```

The dashboard reads real structured WAF events from `waf/logs/waf.log`. It shows totals, allowed and blocked requests, block rate, attack categories, risk scores, matched rule IDs, recent events, filters, pagination, an activity chart, and a read-only rule overview.

Dashboard endpoints are reserved by the WAF and are not proxied to Flask:

- `GET /dashboard`
- `GET|POST /dashboard/login`
- `POST /dashboard/logout`
- `GET /dashboard/api/summary`
- `GET /dashboard/api/events`
- `GET /dashboard/api/rules`

The dashboard APIs require the WAF dashboard session cookie. They do not expose raw request bodies, authorization headers, cookies, tokens, passwords, or full query values.

## Tests

Run all tests:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests waf\tests
```

The WAF tests use synthetic local ASGI requests and do not contact production services.

## Configuration

Default settings are in `waf/config.py`:

- Upstream: `http://127.0.0.1:5000`
- WAF listen address: `127.0.0.1:8080`
- Maximum request size: 1 MiB
- Upstream timeout: 5 seconds
- Block threshold: 5
- Log path: `waf/logs/waf.log`

## Known Limitations

This is a Phase 1 prototype, not a production WAF.

- Regex rules can produce false positives and false negatives.
- It does not parse SQL, JavaScript, HTML, multipart uploads, or nested encodings deeply.
- It does not perform behavioral anomaly detection.
- Dashboard authentication is suitable for local prototype use; production deployment should use HTTPS, stronger account management, and secret rotation.
- It should be placed in front of a backend that is not directly reachable by users.
- It currently uses local file logging, which should be replaced or centralized for cloud deployment.
