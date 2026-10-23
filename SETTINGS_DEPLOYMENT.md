# CHILLIBEK WAF settings — implementation and deployment

## Current status

The `dev` branch contains the WAF/settings implementation and deployment preparation.
The approved static publication release is restricted to `settings/index.html`,
`settings/settings.css`, and `settings/settings.js` on `main`. GitHub Pages already
publishes `main` at the repository root with HTTPS and the existing custom domain.
No production DNS, PythonAnywhere service, restaurant API URL or Python runtime is
changed by this release. Public publication must be checked against the live URL;
a successful Git push alone is not deployment verification.

Without a deployed WAF API, the public page displays **WAF API not connected**,
shows no live configuration and disables all eight switches plus Save/Reset.
The page requests only same-origin `/waf-api/settings`, with no PythonAnywhere fallback.
Assets use relative paths for GitHub Pages. Both hosts canonicalize `/settings`
to `/settings/` so those paths resolve consistently. Future backend/HTTPS/DNS
instructions below are preparation only, outside this static publication release.

The development changes include the earlier PostgreSQL/cloud migration foundation.
It remains on `dev` and does not run migrations against production.

## Architecture found in the checkout

- `index.html`, `admin.html`, `kitchen.html`: static restaurant clients. All three
  currently use `https://kali.pythonanywhere.com/api` directly. They are unchanged.
- `CNAME`: `chillibek.online`. There is no checked-in Pages workflow. The GitHub API
  confirms the existing Pages source is `main` at `/`, using the legacy branch build
  with HTTPS enforced. Pages configuration and production DNS are unchanged.
- `backend/server.py`: Flask menu, staff authentication/roles, orders, application
  validation and independent Flask-Limiter limits. Earlier local changes introduce
  SQLAlchemy/PostgreSQL support. Those controls remain active with every WAF policy.
- `waf/app.py`: the existing FastAPI/httpx reverse proxy. It continues forwarding to
  its configured, fixed upstream. No additional WAF was introduced.
- `waf/dashboard.py`: existing authenticated Dashboard and JSON-lines event views.
  Settings reuse its operator account/session, separate from restaurant staff tokens.

GitHub Pages serves static files; it cannot execute Flask, FastAPI or the policy API.
See [GitHub's Pages description](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).
DNS alone cannot route different paths on a domain to different hosting services.

## Implemented controls

All eight controls use actual backend state:

| Control | Request-processing effect |
| --- | --- |
| Master WAF: Block / Monitor | Block rejects enabled-rule matches; Monitor forwards requests and retains detections if event logging is enabled. There is no unauthenticated bypass mode. |
| SQL Injection | Gates existing `SQLI-001` regex detection. |
| XSS | Gates existing `XSS-001` regex detection independently. |
| Path Traversal | Gates existing `TRAV-001` normalized/decoded regex detection independently. |
| Rate Limiting | `RATE-001`: 120 proxy requests/client IP/60-second fixed window by default; HTTP 429 in Block mode. Counters are shared across processes using the same local policy database. |
| Suspicious Header Detection | `HEADER-001`: duplicate Content-Length, Content-Length with Transfer-Encoding, method-override headers, header control bytes. HTTP 403 in Block mode. |
| Request Size | `SIZE-001`: streaming body-size check against 1 MiB by default; stops reading on exceedance in Block mode, HTTP 413. |
| Security Event Logging | Gates request decision/event writes, including allowed requests and upstream failures. Existing events remain available. Does not affect operator access auditing or configuration auditing. |

Defaults: Block mode and all modules ON. Threshold remains the existing score of 5.
Inspection of textual bodies now covers the entire accepted body rather than only
its first 8 KiB. The regex detector still has the existing limits: pattern matching
can miss attacks or produce false positives, and does not deeply parse multipart/binary data.
HTTP servers may reject malformed framing before the WAF receives a request; this
toggle cannot disable those protocol checks. Flask and the HTTPS proxy retain their
own request limits/authentication/validation regardless of WAF settings.

## Static frontend and APIs

`settings/index.html`, `settings/settings.css` and `settings/settings.js` form a
buildless, responsive dark control panel. GitHub Pages can serve `/settings/` from
that directory (normally redirecting `/settings` to `/settings/`). The WAF itself
redirects `/settings` to `/settings/` and serves the page/assets there for local operation.

Frontend requests use **same-origin** `/waf-api/settings`; no credentials, tokens,
policy defaults presented as live state, or arbitrary backend URL are embedded.
Without the API, controls are disabled and show Unknown. Login is available on HTTP
401. Every toggle sends a complete policy with its revision and waits for the server;
there is no optimistic ON state. Failed/ambiguous writes trigger a fresh read.
Refresh, focus and a 30-second visible-page refresh synchronize actual server state.
Save Settings re-applies the current confirmed policy; individual changes auto-save.
Reset to Defaults persists the real default policy. Last update uses persisted UTC
timestamps displayed in the browser's local timezone; initial defaults have no fake date.

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `GET /waf-api/settings` | WAF operator session | Policy, revision, update timestamp/actor, CSRF token, defaults and limits. |
| `PUT /waf-api/settings` | Operator session + session-bound signed `X-CSRF-Token` | Atomic complete-policy update with expected revision. |
| `POST /waf-api/settings/reset` | Same | Restore defaults with expected revision. |
| `/dashboard/login` | Existing password hash authentication + login CSRF | Establish operator session; `?next=/settings` returns to the panel. |

PUT body: `{"revision": 0, "policy": {"mode":"block", "sql_injection":true,
"xss":true, "path_traversal":true, "rate_limiting":true, "suspicious_headers":true,
"request_size":true, "event_logging":true}}`. Reset body: `{"revision":0}`.
Unknown/missing fields, non-boolean switch values, unsupported mode and invalid
revision return 422. Concurrent stale revisions return 409. Missing/invalid sessions
return 401 (503 if operator authentication has not been configured); bad CSRF returns
403. Storage failures return 503, never a successful configuration acknowledgement.
Settings APIs have no cross-origin credential allowance and are never cached.

Operator cookies are HttpOnly, SameSite=Strict and Secure by default. Session lifetime
is eight hours. Login throttling (5 attempts/IP/60-second window) and authentication
are always enabled even if proxy rate limiting is switched off. Restaurant staff
tokens cannot authorize WAF settings. Authentication, CSRF, authorization and auditing
have no switches in the policy model.

## Persistent storage and hot reload

`WAF_POLICY_PATH` selects a SQLite file on a **durable local filesystem**. Without
that variable the database is `policy.sqlite3` beside the configured event log.
The Docker example explicitly uses `/app/waf/local/policy.sqlite3` in `waf-policy`.
Each request reads one validated policy snapshot. Updates are visible on the next
request without restarting; requests already in progress finish using their snapshot.
Multiple workers on one server must use the same file. Do not use separate ephemeral
container files, network-filesystem SQLite, or multiple independent server replicas.

`configuration_audit` stores actor, UTC timestamp, action, before/after policy and
revisions; access/failed attempts store bounded paths/methods/status, without request
bodies, credentials, CSRF/session values or query strings. Policy changes and their
configuration audit insert commit in the same transaction; audit failure rolls back
the mutation. Audits remain active when Security Event Logging is OFF.
Protect this volume with server file permissions, back it up using SQLite's backup
API, and retain audit backups according to operational needs. A server administrator
can alter a local SQLite file: this is an application audit trail, not tamper-proof storage.
Deleting the policy database loses state and audit history and restores defaults on
the next start/read. Do not delete the named volume during upgrades.

## Local operation

Use the existing virtual environment and operator credentials:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:WAF_SECURE_COOKIES = "false" # HTTP loopback only; keep true on public HTTPS
.\.venv\Scripts\python.exe waf\scripts\start_dashboard.py
```

Open `http://127.0.0.1:8080/settings`. The existing helper prompts for synthetic/local
operator credentials and creates a session secret for that process. To retain sessions
across restarts, configure a stable secret and password hash and use `python -m waf.run`.
Policy persistence does not require preserving the temporary helper session secret.
Run Flask separately as described in `waf/README.md` to forward restaurant requests.

## Public deployment path (requires explicit approval)

The recommended prepared path is one HTTPS entry point with static assets plus
the existing server WAF. `deploy/nginx-settings.conf.example` is an uninstalled template:

```text
chillibek.online:443
  /, /index.html, /admin.html, /kitchen.html -> exported static restaurant files
  /settings -> /settings/ -> exported static control panel
  /waf-api/*, /dashboard/*, /health -> existing FastAPI WAF management routes
  /api/* -> existing FastAPI WAF -> private Flask backend -> persistent database
```

Required authorized steps:

1. Provision a server capable of running ASGI/Uvicorn (or the prepared Docker stack),
   persistent volumes, HTTPS reverse proxy and secret storage. Keep Flask/PostgreSQL
   private. Compose binds WAF port 8080 to host loopback; expose only ports 80/443.
2. Configure `WAF_DASHBOARD_USERNAME`, `WAF_DASHBOARD_PASSWORD_HASH` (Werkzeug hash),
   a stable random 32+ character `WAF_DASHBOARD_SESSION_SECRET`, `WAF_SECURE_COOKIES=true`,
   the durable `WAF_POLICY_PATH`, and the actual `WAF_UPSTREAM_BASE_URL`.
   Set the database/Flask secrets required by the existing Compose setup. Escape `$`
   in password hashes as required by Compose env-file syntax (single-quoted values).
3. Configure Uvicorn's `FORWARDED_ALLOW_IPS` via Compose's `WAF_TRUSTED_PROXY_IPS`
   for **only the actual trusted HTTPS proxy peer IP**. With a host proxy and Docker,
   this can be a Docker bridge gateway IP; inspect the chosen network rather than
   guessing it. With Uvicorn running directly on the host, loopback is normally correct.
   Do not use `*`. Nginx overwrites X-Forwarded-For with the actual peer IP; otherwise
   every client could share a proxy counter, or spoof its own rate-limit identity.
4. Export only `index.html`, `admin.html`, `kitchen.html`, and the `settings/` directory
   into `/srv/chillibek-public`. Never serve the repository root (it contains backend
   source, Git metadata, and potentially secret files). No frontend build is required.
5. Obtain/install a valid certificate for the exact public hostnames, enable HTTPS
   redirects, install/review the Nginx template and validate with `nginx -t` on staging.
   GitHub Pages certificates protect Pages only; a new server/edge needs its own TLS
   configuration. DNS validation can obtain certificates before a routing cutover.
6. **After explicit DNS approval**, point the apex A/AAAA (and `www` if used) to the
   chosen HTTPS entry point or use an approved edge/CDN for path routing. Remove stale
   conflicting records, preserve unrelated MX/TXT entries and verify both IPv4/IPv6.
   The `CNAME` file is not an API router. Keep a record of the old DNS/Pages settings
   and a rollback plan. No such changes have been made by this implementation.
7. Test login, every toggle, persistence and unauthenticated rejection on staging
   with synthetic data. Verify the actual forwarded IP and Secure cookies. Then
   test the public host after approved rollout.

### Retaining GitHub Pages

To retain Pages as the static origin for the public host, an authorized HTTPS edge
must dispatch `/waf-api/*` and `/dashboard*` to the Python WAF, leaving static paths
on Pages. Disable caching of all management paths/cookies. Preserve the public Host,
scheme, paths and cookies, and allow only that trusted edge to the origin. Verify
origin TLS and prevent a proxy loop; DNS cannot do this path split on its own.
Without such an edge, uploading `settings/` to Pages produces the UI but **not a
functional settings panel**. A separate `api.` hostname would require a deliberate
frontend/auth/CORS design and is not the same-origin architecture implemented here.

### Restaurant traffic coverage and PythonAnywhere

The unchanged restaurant pages still call `kali.pythonanywhere.com/api`; their traffic
does **not** pass through the new WAF merely because `/settings` exists. To protect
those requests after approval, change all three static `API_URL` values to `/api`
on the reviewed deployment, route `/api/*` through the WAF, and use a private/restricted
backend so direct public-origin requests cannot bypass the WAF. This future URL
cutover is intentionally not applied to the current restaurant pages.

If keeping PythonAnywhere as upstream, the WAF server must be able to reach it and
the upstream must have an enforced restriction to prevent bypass. A publicly reachable
unrestricted PythonAnywhere API remains a bypass. Existing Flask WSGI hosting does
not automatically run FastAPI; provision an ASGI-capable service separately. See
[PythonAnywhere's ASGI deployment guidance](https://help.pythonanywhere.com/pages/ASGICommandLine/)
and verify account availability before selecting that host. No PythonAnywhere
application, database, ASGI service or certificate has been changed here.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q
node --check settings/settings.js
```

Tests use temporary SQLite databases and synthetic local ASGI/HTTP transports only.
They cover module independence, Block/Monitor behavior, persistence/recreated apps,
live reads across workers, strict validation, authorization, CSRF, stale revisions,
reset, audit preservation/rollback, event logging, public static routes, and existing
restaurant/Dashboard behavior. See the final implementation report for observed results
and any browser, Docker or HTTPS validation limits.

Before the static publication push, the isolated production checkout also passed
the real-browser static-only checks: relative assets, all management controls
disabled, the explicit disconnected message, Refresh, no mutation/PythonAnywhere
requests and mobile layout. The production restaurant pages are excluded from the
release diff; their live HTTP bodies were fingerprinted for post-publication comparison.

Observed local results: **63 Python tests passed**, JavaScript syntax checks passed,
`git diff --check` passed, and **7 real headless Chrome checks passed** with no
uncaught JavaScript exceptions. Browser checks exercised actual operator login,
live toggle persistence and refresh, a deliberately rejected ON update retaining
the OFF state, Master mode, Save/Reset, API failure and expired-session handling,
plus desktop (1440 px) and mobile (390 px) layouts without horizontal overflow.
Screenshots are local ignored artifacts at `waf/local/settings-desktop.png` and
`waf/local/settings-mobile.png`.

The Python integration tests also use the real Flask restaurant app behind the
existing WAF transport with temporary synthetic data: menu retrieval/CORS, staff
login, order creation, server-calculated totals, and role/auth restrictions pass
in both Block and Monitor modes. `index.html`, `admin.html`, `kitchen.html`, and
`CNAME` have no changes. Docker is not installed in this environment; container
builds, Nginx configuration validation on a server, public TLS and DNS were not run.

To repeat the optional browser checks, start a temporary synthetic server:

```powershell
.\.venv\Scripts\python.exe -m uvicorn waf.tests.browser_fixture:create_test_app --factory --host 127.0.0.1 --port 8765
```

Start an isolated headless Chrome (not a personal browser profile) with
`--headless=new --remote-debugging-port=9222 --user-data-dir=<temporary-isolated-directory>`.
Then run `node waf/tests/browser_settings.mjs` using Node 24+. The test connects
only to the loopback browser/WAF, closes that dedicated browser on completion and
writes ignored screenshots. Stop the synthetic server afterwards. Neither the
fixture's test credentials nor its temporary database are used in production.

## Files created or modified by this settings implementation

Created:

- `settings/index.html`, `settings/settings.css`, `settings/settings.js`: public static panel.
- `waf/policy.py`: strict policy models, persistent transactional storage, audit and shared counters.
- `waf/settings_api.py`: authenticated settings/reset APIs and local static route serving.
- `waf/tests/test_settings.py`: synthetic policy/security and real-Flask proxy integration tests.
- `waf/tests/browser_fixture.py`, `waf/tests/browser_settings.mjs`: isolated real-browser verification.
- `deploy/nginx-settings.conf.example`: uninstalled public HTTPS/static/API routing example.
- `SETTINGS_DEPLOYMENT.md`: architecture, deployment requirements and implementation report.

Modified:

- `waf/app.py`: hot policy reads and toggled protections in the existing request pipeline.
- `waf/config.py`: policy path, Secure cookies and rate settings; earlier environment changes retained.
- `waf/rules.py`: category selection and suspicious-header inspection.
- `waf/dashboard.py`: reused authentication, Secure/session-specific cookies, login return route,
  settings link and actual rule states/categories in the existing Dashboard.
- `waf/scripts/start_dashboard.py`: explicit HTTP-loopback cookie handling for the local helper.
- `waf/tests/test_dashboard.py`: explicit non-Secure cookies for its HTTP-only synthetic fixture.
- `waf/README.md`: pointer to current settings/local/deployment instructions.
- `requirements.txt`: explicit Pydantic 2 dependency; earlier database dependencies retained.
- `waf/Dockerfile`: includes the static settings assets in the prepared WAF image.
- `docker-compose.yml`: durable policy volume, Secure cookies, trusted-proxy environment and
  loopback WAF port binding. This file was already untracked preparation at task start.

All pre-existing restaurant frontend changes remain on `dev`; the three production
restaurant files on `main` must remain byte-for-byte unchanged. The static release
uses an isolated checkout based on the expected `main` revision and normal pushes,
without force-pushing or merging the entire development branch.

The optional `waf/tests/browser_static_settings.mjs` test verifies the static-only
release using a dedicated headless Chrome: relative CSS/JS loading, the disconnected
message, disabled management buttons, Refresh, mobile layout and absence of mutation
or PythonAnywhere requests. It supports the local static release preview and the
exact public URL `https://chillibek.online/settings/` without using any credentials.
