# Live WAF settings deployment

## Release status — 2026-10-31

The static public Settings and Dashboard gateways were published to `main` at
`59725b8f89b5827a0b02306b3c80f79dfaffb2b9`; GitHub Pages run 28 succeeded.
The restaurant staff authentication fix was published to `main` at
`9e18983cf914d237fcafb0ab7fe8063485c4d037`; GitHub Pages run 29 succeeded.
Cache-busted public `admin.html` and `kitchen.html` responses contain the staff
token storage and Bearer-header API wrapper. An uncached response was stale.
The live public `/settings/` returned 200 and contained the fixed “Manage live WAF”
link, with no management API client or credentials.

PythonAnywhere read-only checks on 2026-10-31 returned `/settings/` 200,
`/dashboard/login` 200, anonymous `/waf-api/settings` 401, and `/api/menu` 200.
The unauthenticated Settings page returning 200 differs from the current source
route, which should redirect to login. The policy API still rejects anonymous
access; however, this does not verify page-level authentication or authenticated
policy reads, writes, persistence, enforcement, or dashboard events. No
PythonAnywhere source, WSGI configuration, policy database, or operator account
was changed. Use the update and acceptance steps below before claiming the live
backend release is complete.

The centralized login policy, Active Blocks, and Login Abuse Demo changes in
this development release are not deployed to PythonAnywhere. Publishing to
GitHub Pages does not update the backend; the Demo Lab must not be described as
live until the manual backend update and acceptance checks below succeed.

## Routing and authentication

```text
https://chillibek.online/settings/       Public static gateway; no API requests
           Manage live WAF link
https://kali.pythonanywhere.com/settings
           Source expectation: anonymous -> 303 /dashboard/login?next=/settings
           Authenticated: 308 /settings/ then the existing control panel
https://kali.pythonanywhere.com/waf-api/settings
           Same-origin dashboard session; signed session-bound CSRF for writes
https://kali.pythonanywhere.com/settings/demo
           Operator-authenticated, isolated login-abuse demonstration
```

Production observation on 2026-10-31: anonymous `/settings/` returned 200 while
anonymous `/waf-api/settings` returned 401. Investigate and correct any
PythonAnywhere static mapping that bypasses the WSGI settings route; do not make
the WAF API or policy public.

The public gateway retains the dark design, describes all eleven controls and
offers Dashboard and Restaurant links. It stays publicly accessible and works
without JavaScript. It displays no live policy or connection claim.

`waf/templates/settings.html` preserves the existing settings interface and is
served by the protected WSGI application after dashboard authentication. Its
relative CSS/JS routes are served by that application with `Cache-Control:
no-store`. Public navigation uses fixed HTTPS destinations; return URLs, query
parameters, tokens and credentials are not forwarded from Pages.

The existing HttpOnly, Secure, SameSite=Strict dashboard cookie remains on the
PythonAnywhere host. Browser fetches use `credentials: 'same-origin'`. There is no
cross-site session-cookie dependency or management CORS allowance. An initial
cross-site navigation may require sign-in because of SameSite=Strict; subsequent
panel requests and dashboard navigation use the same operator session.

## Controls, persistence and safeguards

All eleven controls are preserved: Master Block/Monitor, SQL Injection, XSS,
Path Traversal, Command Injection, Suspicious Headers, Rate Limiting, Request Size,
Login Abuse, Scanner Behavior and Security Event Logging.

`GET /waf-api/settings` returns the stored policy, revision, actor/timestamp,
limits, defaults and session-bound CSRF token. Each switch PUTs the complete
policy with the expected revision and waits for the committed server response.
It never changes to a speculative saved state. Failed or ambiguous writes trigger
a fresh read; unavailable APIs clear the policy and disable controls. Save
re-applies the confirmed policy; Reset persists defaults. Refresh, focus and a
30-second visible-page poll read actual server state.

The existing durable SQLite policy file is reused. Each inspected request reads
the latest validated snapshot, including across workers/reloads sharing that
file. Do not change its path or replace it with an empty database. Configuration
updates and before/after audit events commit in one transaction. Authentication,
CSRF, audit, mandatory HTTP safety and restaurant authorization remain active
regardless of switch values. Foreign Origin and cross-site/same-site fetch
metadata cannot authorize writes. Bare and nested `/waf-api` routes authenticate
before validation and cannot fall through to the restaurant backend.

The WAF `PolicyStore` is also Flask's login-policy and lockout store. In the
protected WSGI deployment, Flask receives that exact store from the adapter;
standalone Flask uses the configured `WAF_POLICY_PATH` (or its documented
database-sidecar default). There are no independent Flask login counters or
hardcoded Flask-Limiter staff-login decorators. Defaults are 5 failed attempts per
account or 20 per IP in 900 seconds, with a 30-second initial lockout, 2x
progression and a 900-second maximum. Account/IP thresholds, tracking window,
initial duration, multiplier and cap are editable within validated bounds; the
account threshold is 1–100, IP threshold 1–1000, window 60–86400 seconds,
initial lockout 5–3600 seconds, multiplier 1–10 and maximum 30–86400 seconds;
the maximum must be at least the initial duration. A successful account login
clears that account's failure counter.
The Settings response and page display effective global, per-route, and body-size
limits after applying any lower WAF deployment ceilings. The configured policy
is persistent; the WAF's hard request-body ceiling remains mandatory even when
optional request-size protection is off or the isolated demo uses Disabled mode.

Block mode enforces enabled request/login controls and active blocks. Monitor
mode continues detection and event recording but suspends optional blocks,
including manual blocks; blocks remain stored and their effective state is shown
in Settings. Disabled mode also suspends optional controls, but `allow_disabled_mode`
defaults to false and must only be enabled in an isolated synthetic test
deployment. Production rejects Disabled mode and a disabled Login Abuse switch.
Even in isolated Disabled mode, incorrect passwords remain incorrect, operator
authentication/authorization/CSRF/auditing and protocol safety remain enforced.
The production Login Abuse control cannot be turned off, though validated
thresholds can be relaxed.

The Active Blocks panel lists masked account identifiers or IPs, rule, reason,
attempt count, start/expiry and remaining time. Manual block/unblock actions are
authenticated, CSRF protected and audited; an unblock removes the matching live
enforcement record immediately. Expiration is persisted to the block audit
history when the shared store next observes the elapsed deadline.

The scanner threshold and tracking window are also persistent policy fields and
are enforced by the WAF from the same policy snapshot as its other request
controls.

## Login Abuse Demo Lab

`/settings/demo` and its `/waf-api/demo*` endpoints require the WAF operator
session. Writes and synthetic login attempts also require the session-bound
CSRF token and same-origin request checks. The demo accepts only the synthetic
username `demo_waiter`; it does not call Flask, query the staff table, create a
restaurant token, or read/write orders. Its SQLite policy/counter/block store is
derived from the existing policy path with a `-demo` filename suffix and is
separate from both the production policy store and restaurant database.

WAF OFF sets Disabled only in that isolated demo policy: repeated incorrect
passwords return actual HTTP 401 responses without recording a lockout, while
password verification remains active. WAF ON uses the same `PolicyStore`
admission, failure, lockout, expiration, and audit methods as staff Login Abuse.
The page caps each batch at 20 sequential requests and stops on the first HTTP
429. Threshold is configurable from 1–20 and lockout from 30–3600 seconds.
Automatic blocks, remaining time, recent block audit and an immediate
CSRF-protected unblock are shown in the demo operator page. Demo settings and
blocks persist across WSGI reloads without changing production staff-login
policy.

The page displays the synthetic demo-only password after operator
authentication. It is not a WAF management credential and is not accepted by
the restaurant staff-login endpoint.

## PythonAnywhere update commands

Use a PythonAnywhere **Bash console**. Obtain the existing checkout, virtualenv,
WSGI filename and policy filename from the current Web tab/WSGI/environment
configuration; do not guess them or paste secrets. These commands preserve the
installed WSGI file and allow the reviewed shared login-policy integration in
`backend/server.py`, `backend/login_guard.py` and its focused test. They reject
other backend changes, frontend/restaurant changes, dependencies, schema tooling
and the WSGI deployment example. If a check fails, stop and review that
difference in staging; do not reset or force the checkout.
Do not configure a static `/settings` mapping that bypasses the WSGI routes.

```bash
set -euo pipefail
read -r -p 'Existing live Git checkout (absolute path): ' LIVE_CHECKOUT
read -r -p 'Existing web-app virtualenv (absolute path): ' LIVE_VENV
read -r -p 'Existing Web-tab WSGI filename (absolute path): ' LIVE_WSGI
read -r -p 'Existing WAF policy SQLite filename (absolute path): ' LIVE_POLICY
read -r -p 'Tested dev commit from the final report: ' RELEASE_COMMIT

test -d "$LIVE_CHECKOUT/.git"
test -x "$LIVE_VENV/bin/python"
test -f "$LIVE_WSGI"
test -f "$LIVE_POLICY"
cd "$LIVE_CHECKOUT"
test "$(git branch --show-current)" = dev
test -z "$(git status --porcelain)"
git fetch origin dev
test "$(git rev-parse "$RELEASE_COMMIT^{commit}")" = "$(git rev-parse origin/dev)"
git merge-base --is-ancestor HEAD "$RELEASE_COMMIT"
UNEXPECTED_BACKEND=$(git diff --name-only HEAD "$RELEASE_COMMIT" -- backend \
  | grep -Ev '^backend/(server.py|login_guard.py|tests/test_backend_advanced_security.py)$' || true)
test -z "$UNEXPECTED_BACKEND"
git diff --exit-code HEAD "$RELEASE_COMMIT" -- \
  index.html admin.html kitchen.html CNAME requirements.txt \
  requirements-dev.txt deploy alembic.ini docker-compose.yml
git diff --stat HEAD "$RELEASE_COMMIT"

# Consistent private policy/audit backup; no database migration or policy update.
umask 077
BACKUP_DIR="$HOME/.local/share/chillibek-release-backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
git rev-parse HEAD > "$BACKUP_DIR/previous-commit.txt"
cp -p -- "$LIVE_WSGI" "$BACKUP_DIR/wsgi.py"
"$LIVE_VENV/bin/python" - "$LIVE_POLICY" "$BACKUP_DIR/policy.sqlite3" <<'PY'
import sqlite3, sys
from pathlib import Path
source = sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True)
target = sqlite3.connect(sys.argv[2])
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY

git merge --ff-only "$RELEASE_COMMIT"
"$LIVE_VENV/bin/python" -m pip check
"$LIVE_VENV/bin/python" -m compileall -q waf
test -f waf/templates/settings.html
test -f settings/settings.js
cmp -- "$LIVE_WSGI" "$BACKUP_DIR/wsgi.py"

# Reload the EXISTING web app. This does not rewrite its WSGI configuration.
touch "$LIVE_WSGI"
# Alternatively click Reload on its existing Web tab instead of touch.
```

No dependency was added by this release, so no live dependency upgrade is needed.
Keep the current password hash, session secret, Secure-cookie configuration,
Flask/database settings, policy path and event path. Do not run Alembic, database
initialization, seed scripts or the example WSGI configuration during this update.

After reload, run benign anonymous checks:

```bash
for path in /settings /settings/ /dashboard /dashboard/login /waf-api/settings /api/menu; do
  curl --silent --show-error --output /dev/null \
    --write-out "$path HTTP %{http_code} redirect %{redirect_url}\n" \
    "https://kali.pythonanywhere.com$path"
done
```

Expected: settings and dashboard 303 to login, login 200, policy API 401, menu 200.
Then open `/settings` in a browser, sign in with the existing account and verify
Connected, eleven switches, the stored revision and real actor/timestamp. Check
Dashboard and Restaurant navigation. Complete authorized policy-change and restore
checks, verify the recorded audit before/after events, reload the existing app and
confirm the saved policy again. Do not use production orders or staff-password
failures as test fixtures. Local synthetic enforcement checks are documented below.

To inspect audit metadata without exposing sessions or credentials, use the
existing policy filename in a read-only SQLite connection:

```bash
"$LIVE_VENV/bin/python" - "$LIVE_POLICY" <<'PY'
import sqlite3, sys
from pathlib import Path
with sqlite3.connect(Path(sys.argv[1]).resolve().as_uri() + '?mode=ro', uri=True) as db:
    print(db.execute('SELECT revision, updated_at, updated_by FROM policy WHERE id=1').fetchone())
    for event in db.execute("SELECT timestamp, actor, action FROM configuration_audit WHERE action IN ('update','reset') ORDER BY id DESC LIMIT 10"):
        print(event)
PY
```

For a source rollback, do not reload the old source against the migrated policy
JSON: the previous release validates an older, exact policy shape. First back up
the current policy database as above. Restore the release's changed source files
from the recorded previous commit, then transactionally project the current
policy row onto the previous schema before reloading. This retains the common
protection switches, revision, audit history and database file; newer threshold
settings cannot be represented by the previous source. Do not restore the
pre-deployment database backup unless deliberately discarding policy changes
made since that backup.

Run this using the existing virtualenv and policy path after restoring source but
before reloading. It refuses an unexpected policy shape and records the rollback
in the existing audit table:

```bash
"$LIVE_VENV/bin/python" - "$LIVE_POLICY" <<'PY'
import json, sqlite3, sys
from datetime import datetime, timezone
from pathlib import Path

keys = {
    "mode", "sql_injection", "xss", "path_traversal", "rate_limiting",
    "suspicious_headers", "request_size", "event_logging",
    "command_injection", "brute_force", "bot_detection",
}
with sqlite3.connect(Path(sys.argv[1])) as db:
    db.execute("BEGIN IMMEDIATE")
    row = db.execute("SELECT value FROM policy WHERE id=1").fetchone()
    if row is None:
        raise RuntimeError("Stored WAF policy is missing")
    current = json.loads(row[0])
    if not keys <= current.keys() or current["mode"] not in {"block", "monitor"}:
        raise RuntimeError("Policy is not compatible with this source rollback")
    legacy = {key: current[key] for key in keys}
    timestamp = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE policy SET value=?, revision=revision+1, updated_at=?, "
        "updated_by=? WHERE id=1",
        (json.dumps(legacy), timestamp, "source-rollback"),
    )
    db.execute(
        "INSERT INTO configuration_audit(timestamp, actor, action, details) "
        "VALUES (?, ?, ?, ?)",
        (timestamp, "source-rollback", "policy_schema_rollback",
         json.dumps({"retained_fields": sorted(keys)})),
    )
```

Then reload the existing app and run the anonymous checks above. Keep the
pre-deployment backup private for recovery; do not replace the live database.

## GitHub Pages publication — completed 2026-10-31

Commit `59725b8f89b5827a0b02306b3c80f79dfaffb2b9` fast-forwarded `main` and changed
only `settings/index.html` and `dashboard/index.html`. Pages run 28 completed
successfully. A live read-only check confirmed that
`https://chillibek.online/settings/` returns 200, links directly to the WAF host,
and does not request the management API. The public page does not display a live
policy. PythonAnywhere backend acceptance remains a separate required step.

## Reproducible local verification

On the current development worktree, the full backend/WAF suite passed
**224 tests**; the public Settings route tests passed **4 tests**; both Settings
JavaScript files passed Node syntax checks. These are local results and do not
verify the PythonAnywhere release or the not-yet-deployed Demo Lab.

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
node --check settings/demo.js
git diff --check
```

Latest repeatable local results on 2026-10-31: **215 Python tests passed**,
**4 Node routing tests passed**, and `node --check settings/settings.js` passed.
The earlier release also recorded **8 authenticated Chrome browser checks** and
**4 public gateway browser checks**; those browser suites were not rerun in this
task. All eleven controls have WSGI-level independent enforcement,
update, restore, already-running worker and recreated-application persistence checks.
The suite covers authentication, CSRF, malformed inputs, stale revisions, audit
events/rollback, SQLi/XSS/traversal/command/header/size/rate behavior, WAF login/probe
enforcement, event logging and real Flask menu, staff roles and order transitions.
The login-abuse WSGI test seeds only WAF failure counters and uses a valid synthetic
staff login to distinguish WAF enforcement from mandatory backend limits.

Browser checks use the real WSGI wrapper and Flask with temporary synthetic data:

```powershell
# Separate terminal; fixture overrides inherited database configuration.
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture
# Another terminal for the static gateway.
.\.venv\Scripts\python.exe -m http.server 8766 --bind 127.0.0.1
```

Start a dedicated headless Chrome with `--remote-debugging-port=9222` and an
isolated temporary `--user-data-dir`, then run `node waf/tests/browser_settings.mjs`.
Start a fresh dedicated browser for `node waf/tests/browser_static_settings.mjs`.
Both scripts close only that QA browser; stop the temporary servers afterwards.
Screenshots are ignored local artifacts under `waf/local/`. Desktop/mobile layout,
all eleven switches, rejected-write reconciliation, unavailable APIs and expired
sessions passed with no uncaught JavaScript exceptions in the earlier recorded
browser run. No PythonAnywhere login, policy write, attack simulation, database
migration, or backend deployment was performed for this release.
