# Centralized WAF configuration and manual deployment

This supersedes earlier Settings/Demo and two-service proxy instructions. See
[WAF_COVERAGE.md](WAF_COVERAGE.md) for the audit and matrix. Pushing `dev` does not
deploy the backend. Verification must not publish `main`, reload production, run
production migrations, or change live staff/menu/order data.

## Policy

`WAF_POLICY_PATH` names the one durable SQLite policy/counter/audit store shared by
WSGI workers on the same host. Keep its existing location outside replaceable
checkouts. Logs default to `waf/logs/waf.log`; `WAFSettings.log_path` can select a
protected persistent directory. Back up runtime state before cutover; do not
create a fresh empty policy when an approved store exists.

| Setting | Default | Effect |
| --- | --- | --- |
| `mode` | `block` | Block denies enabled detections; Monitor forwards/logs optional detections; Disabled is test-only |
| `sql_injection`, `xss`, `path_traversal`, `command_injection` | true each | Independent content detectors on all backend routes |
| `rate_limiting` | true | Global/route windows and optional concurrency; OFF skips their counting/enforcement |
| `rate_limit_requests` / `rate_limit_window_seconds` | 120 / 60 | Requests per verified IP |
| `route_limit_requests` / `route_limit_window_seconds` | 90 / 60 | Requests per safe route template and IP |
| `bot_detection` | true | Count backend 404s and detect repeated probing; OFF skips both |
| `bot_detection_limit` / `bot_detection_window_seconds` | 12 / 60 | Recent missing-route responses flag subsequent requests |
| `request_size` / `request_size_bytes` | true / 1048576 | Optional limit; hard parser/resource ceilings remain |
| `suspicious_headers` | true | Optional header heuristics; framing safety remains mandatory |
| `event_logging` | true | Traffic decisions; configuration/block/unblock audits remain independent |
| `brute_force` | true | Real staff account/IP admission and failure counters; REQUIRED in production |
| `login_max_attempts` | 5 | Failed credentials per normalized account across IPs |
| `login_ip_max_attempts` | 20 | Failed credentials per IP across accounts |
| `login_window_seconds` | 900 | Failure/escalation window |
| `login_initial_lockout_seconds` | 30 | First automatic lock |
| `login_lockout_multiplier` | 2 | Escalation at subsequent thresholds within the window |
| `login_max_lockout_seconds` | 900 | Maximum lock duration |

`waf/policy.py` validates numeric bounds and lockout relationships. Settings returns
effective deployment caps: global requests capped by `WAFSettings.rate_limit_requests`
(120), route requests by `route_limit_requests` (90), optional bytes by
`max_request_bytes` (1 MiB). Raise those deployment caps explicitly if needed.
The hard transport ceiling is 4 MiB; Flask's body-parsing ceiling remains 1 MiB.
HEAD/OPTIONS consume enabled request limits too.

Production defaults to `allow_disabled_mode=False`. Disabled mode and
`brute_force=False` are rejected, and inconsistent stored policies fail closed.
**Production staff admission remains enforced in Monitor**, using the configured
thresholds/durations. Settings reports REQUIRED and
`effective.login_abuse=enforced_production`. This is the same shared admission
policy, not an undisclosed second credential throttle. Operator login retains
mandatory independent control-plane protection.

Only separate staging with disposable/nonproduction data may use
`allow_disabled_mode=True`. There, OFF disables the corresponding module across
routes and Monitor observes login abuse without automatic denial. Existing
automatic locks are suspended while OFF, not deleted; re-enabling can resume an
unexpired lock. Successful login resets the account counter, not the IP counter.
Account/IP counters, expiry and escalation persist across workers/restarts.

Automatic locks affect staff login only. Manual IP holds cover all backend routes
in Block mode; account holds cover staff login. Production Monitor still honors
manual holds at login. The panel reports scope and enforcement. Unblock requires
an operator session, CSRF and same origin, and audits actor/prior block details.
Restaurant bearer tokens cannot administer the WAF.

## Reproduce verification

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/centralized-tests.xml
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
```

Tests use temporary database paths and synthetic admin/waiter/chef accounts. WSGI
tests call `protect_wsgi(real_flask_app)` through Werkzeug's WSGI client, with no
production network calls. The matrix covers ON/OFF/Monitor for content, rate and
bot controls, size/headers, snapshot consistency, authentication, production
monitoring, audited unblock and preserved restaurant data.

For browser verification, start `python -m waf.tests.browser_wsgi_fixture`, then
dedicated headless Chrome with port 9222 and a temporary isolated profile. Run
`node waf/tests/browser_settings.mjs`. It exercises the real JavaScript and
synthetic WSGI server: all eleven controls, persistence, rejected writes, session
expiry and desktop/mobile layouts. Stop the fixture afterward. Restart it before
retrying a failed run that changed test settings.

See [WAF_VERIFICATION.md](WAF_VERIFICATION.md) for actual results and limitations.

## Manual PythonAnywhere deployment

1. Record the reviewed SHA and current WSGI file. Take consistent backups of the
   restaurant database, policy/audit store, secrets configuration and WSGI file;
   verify restoration on staging. Use SQLite's backup facility or a drained process,
   not a naive copy of a running database. Retain existing paths and secret keys.
2. Install the exact commit into a separate staging checkout/environment. Install
   `requirements-dev.txt` and run the verification above. Never run guessing or
   attack loops against live staff credentials.
3. Use a disposable database or an approved sanitized backup. Verify menu counts,
   staff roles, totals and order transitions. Leave production database files and
   PostgreSQL volumes untouched.
4. Prepare the managed WSGI file from `deploy/pythonanywhere_wsgi.py.example`.
   Import the compatible Flask app and export
   `application = protect_wsgi(restaurant, settings, trust_pythonanywhere_proxy=True)`.
   Verify the host overwrites X-Real-IP; missing metadata fails closed. Scheme must
   come from managed WSGI. Use explicit existing database/policy paths. Raw Flask
   intentionally returns 503 on production APIs.
5. Check CORS origins, operator password hash/session secret, secure cookies,
   `TESTING=False` and `allow_disabled_mode=False`. Deployed index/admin/kitchen
   must use the existing compatible bearer-token API at
   `https://kali.pythonanywhere.com/api`.
6. After staging review and explicit deployment authorization, update production
   code/WSGI and reload manually. This WAF change requires no restaurant schema
   migration, import, staff recreation or password rotation. Existing app startup
   can create missing tables/seed an empty menu, so verify that the configured
   database is the populated existing database before importing production code.
7. Perform small read-only smoke checks: health, menu, normal operator login,
   revision/capabilities, event views and required login protection. Repeated
   failures belong in staging with disposable credentials. Compare counts/roles
   to the backup; a normal staff login belongs to the staff owner's workflow.

Rollback: restore the prior reviewed WSGI file/code and reload manually, preserving
database, policy and secrets. Runtime-data recovery requires a separately reviewed
procedure; never restore production data automatically.

## Other WSGI hosts and Docker staging

`backend.wsgi:application` exports the protected callable for managed WSGI hosting.
`python -m backend.run` starts the same pipeline on loopback for local development.
Werkzeug's development server is not an internet production server.

For a verified single reverse proxy, `WAF_TRUSTED_PROXY_IPS` lists exact source IPs.
That proxy must overwrite X-Forwarded-For with one client IP and X-Forwarded-Proto
with `http`/`https`, preserving Host. Missing metadata/chains from a trusted peer
fail closed; headers from other peers are ignored. PythonAnywhere-specific trust
is only for that host. Verify client-IP separation and HTTPS scheme on staging
before cutover, or shared proxy-IP counters can affect unrelated clients.

Compose prepares `postgres`, `migrate` and one `waf` service containing the
in-process WAF/Flask pipeline. Existing `postgres-data`, `waf-policy`, `waf-logs`
volume names are preserved. There is no separate raw Flask service/second WAF.
Use an isolated Compose project and fresh volumes for staging: `up` can run
migrations/startup seeding and must not target production volumes automatically.
Docker execution was unavailable in this workspace; see verification limitations.
