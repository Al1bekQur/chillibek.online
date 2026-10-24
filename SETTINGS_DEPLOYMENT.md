# Live WAF settings deployment

## Release status — 2026-10-24

The operator reports that the PythonAnywhere WSGI adapter and administrator
credentials are already deployed. This release connects public navigation to an
authenticated settings interface on that existing application. No production
WSGI configuration, database, credentials, Pages branch or DNS is changed by this
development task. The commands below are prepared for the operator to run.

Read-only HTTPS checks before this release: public `/settings/` returned 200;
PythonAnywhere `/settings` returned 308 to `/settings/`, which returned 200;
`/dashboard/login` returned 200; anonymous `/waf-api/settings` returned 401;
`/api/menu` returned 200. These checks do **not** establish that authenticated live
updates work. Production must be updated and tested before declaring this release
operational.

## Routing and authentication

```text
https://chillibek.online/settings/       Public static gateway; no API requests
           Manage live WAF link
https://kali.pythonanywhere.com/settings
           Anonymous: 303 /dashboard/login?next=/settings
           Authenticated: 308 /settings/ then the existing control panel
https://kali.pythonanywhere.com/waf-api/settings
           Same-origin dashboard session; signed session-bound CSRF for writes
```

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

## PythonAnywhere update commands

Use a PythonAnywhere **Bash console**. Obtain the existing checkout, virtualenv,
WSGI filename and policy filename from the current Web tab/WSGI/environment
configuration; do not guess them or paste secrets. These commands preserve the
installed WSGI file and refuse an update that also changes restaurant code,
dependencies, schema tooling or the WSGI deployment example. If a check fails,
stop and review that difference in staging; do not reset or force the checkout.
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
git diff --exit-code HEAD "$RELEASE_COMMIT" -- \
  backend index.html admin.html kitchen.html CNAME requirements.txt \
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

For a source rollback, restore only this release's changed WAF/settings files from
the recorded previous commit and reload the existing app. Keep the current policy
database; do not overwrite newer operator changes with a backup automatically.

## GitHub Pages publication — after backend verification

The established publication target is `main` at `/`; verify Settings → Pages still
uses that source and the custom domain `chillibek.online`. No source/DNS change is
needed. This task only pushes `dev`; it does not merge or publish `main`.

Prepare a narrow release branch from `origin/main`, using the same tested commit
as above. These commands copy only public navigation and shared styling, avoiding
unrelated restaurant/backend changes on `dev`:

```bash
git fetch origin main dev
read -r -p 'Tested dev commit from the final report: ' RELEASE_COMMIT
git worktree add -b release/live-waf-settings ../chillibek-pages-settings origin/main
cd ../chillibek-pages-settings
git restore --source="$RELEASE_COMMIT" -- settings/index.html settings/settings.css dashboard/index.html
git add -- settings/index.html settings/settings.css dashboard/index.html
git diff --cached --check
git diff --cached --stat
git commit -m "Publish live WAF management navigation"
git push -u origin release/live-waf-settings
```

Open a PR from `release/live-waf-settings` to `main`. Review the three-file
allowlist and merge manually only after PythonAnywhere passes acceptance. Wait for
the Pages deployment, then verify `https://chillibek.online/settings/` stays public,
loads the design and prominent action, and requests no management APIs. Follow
Manage live WAF to the backend login and confirmed policy. Check the public
Dashboard gateway and restaurant menu. A Git push alone is not live verification.

## Reproducible local verification

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
git diff --check
```

Observed for this release: **215 Python tests passed**, **4 Node routing tests
passed**, **8 authenticated Chrome browser checks passed** and **4 public gateway
browser checks passed**. All eleven controls have WSGI-level independent enforcement,
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
sessions passed with no uncaught JavaScript exceptions. No production policy write,
login, attack simulation, database migration or deployment was performed.
