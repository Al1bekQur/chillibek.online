# Combined Stored XSS and CSP release

This procedure supersedes the individual publication steps in the historical
XSS/CSP reports. Source dependency: XSS/input fix `e99669a` is already included in
CSP commit `c430b07a167fc9f9665aecd4ff115a1d5ea0fe95`. Release preparation adds
offline artifacts, backup/schema rehearsal and benign HTTP checks, not an attack
module or another policy engine. Use the **full release-preparation SHA from the
final report**, not a moving `dev` tip. Nothing below was executed on production.

## Readiness and architecture

The code and combined release are locally verified. **Production activation is
conditional**, pending verified account paths, existing database/credential
compatibility, backups/recovery, mappings, dependency installation and storage
reliability. The installed live commit, headers, database engine and Pages
publishing source were not queried. No local test establishes live protection.

```text
chillibek.online (Pages gateways, after separate publication)
  -> browser address changes to kali.pythonanywhere.com
  -> same ProtectedWSGI / ProtocolGuard / centralized PolicyStore
     -> restaurant HTML + external assets + response CSP
     -> /api -> existing WAF inspection -> in-process secured Flask
     -> /settings/ and Dashboard -> separate authenticated WAF operator
```

One policy file remains outside the release directory. Its settings, login
counters/holds, configuration audit and bounded CSP reports persist across reloads.
Existing staff/accounts/orders stay in the existing restaurant DB. Safe DOM
rendering works independently of optional XSS/CSP switches. See
[CSP_DEPLOYMENT.md](CSP_DEPLOYMENT.md) for directives, modes and route coverage.

The Free-compatible alternative is **top-level navigation**, not an origin proxy:
the full application runs on the existing PythonAnywhere hostname/WSGI slot.
No DNS change or additional paid service is introduced. Pages gateway HTML itself
is not dynamically governed by the backend CSP; the destination document is.
Keeping `chillibek.online` in the address bar needs separately approved hosting /
edge routing. PythonAnywhere custom-domain hosting requires a paid account;
changing DNS alone does not turn GitHub Pages into a WAF proxy.
[PythonAnywhere custom domains](https://help.pythonanywhere.com/pages/CustomDomains/),
[GitHub Pages static hosting](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).

Provider constraints checked in vendor documentation on 2026-11-03:

| Constraint | Release consequence |
| --- | --- |
| Free advertises one web app/worker, two consoles, 512 MiB storage and monthly web-app expiry | Reuse that app; no extra staging slot is assumed. Run disposable WSGI tests in a console/local environment; measure asset latency, disk use and backups, and renew the app. |
| New Free accounts do not include MySQL; older account eligibility depends on creation date/region | Do not assume a free replacement database or silently change engines. This release's deployment rehearsal is SQLite; MySQL/server-database migration is not supplied or verified. |
| SQLite runs on the provider filesystem and is discouraged for production | Existing policy SQLite remains a reliability gate even if the restaurant uses another engine. Use one worker, preserve rollback journaling, stage locking/reload tests. If reliable operation cannot be demonstrated, stop production promotion. |
| Web-tab static mappings bypass framework handling | No mapping may shadow restaurant HTML, management, APIs or reports. Do not expose the checkout/runtime directories wholesale. |

[Free features](https://help.pythonanywhere.com/pages/FreeAccountsFeatures/),
[database availability](https://help.pythonanywhere.com/pages/KindsOfDatabases/),
[filesystem/SQLite limitations](https://help.pythonanywhere.com/pages/MySiteIsSlow/),
[static mappings](https://help.pythonanywhere.com/pages/StaticFiles/).
These are provider descriptions, not verified entitlements or measured capacity
of this account. Dependency versions are constrained to those tested on Windows /
Python 3.11.9; Linux wheel installation and provider runtime validation remain gates.

## What is shipped and what is published

From a reviewed immutable Git commit, `python -m deploy.release build` emits:

| Artifact | Exact purpose |
| --- | --- |
| `backend-source.zip` | All tracked source from that commit, including all restaurant HTML/assets, backend/WAF modules, templates, deployment tools, tests and documents. Required runtime paths/HTML contracts are checked. No ignored local files are read. Known runtime/secret path patterns and symlinks are refused. Install privately, never as a Pages artifact. |
| `pages-site.zip` | Exactly eight public files listed below: three restaurant gateways, existing Settings/Dashboard gateways, Settings CSS, unchanged CNAME and .nojekyll. |
| `pages-fallback.zip` | Same public shell, but three actual safe-DOM restaurant pages and seven restaurant JS/CSS assets (15 files total). Emergency compatible Pages frontend; optional dynamic restaurant CSP is lost. Requires the secured API to remain active. |
| `manifest.json` | Full source SHA, per-file SHA-256 and archive SHA-256. Repeated builds of the same commit produce identical archives. No self-referential release SHA is embedded in source documents. |

Exact `pages-site.zip` mapping:

```text
deploy/pages-gateway/index.html   -> index.html
deploy/pages-gateway/admin.html   -> admin.html
deploy/pages-gateway/kitchen.html -> kitchen.html
settings/index.html              -> settings/index.html
settings/settings.css            -> settings/settings.css
dashboard/index.html             -> dashboard/index.html
CNAME                            -> CNAME (chillibek.online, unchanged)
generated empty file             -> .nojekyll
```

Do not merge all of `dev` into the Pages tree. Do not copy gateways over the
backend's actual restaurant HTML. Old optional static files may still exist in a
main checkout; only the listed entry points/assets are changed by publication.

## 1. Pin the release and prepare a separate candidate

The following are **operator commands for later authorized deployment**, not a
script run by this task. Bash commands run in a PythonAnywhere console. Keep the
current live checkout/venv/WSGI import untouched during candidate preparation.
Verify the actual Web-tab WSGI file, virtualenv, mappings, database engine/path,
HTTPS settings and Pages publishing source first. Stop if Pages is not configured
to publish `main` root; adapt the reviewed publication to its real source.

```bash
set -eu
umask 077
read -r -p 'Full verified release SHA from the report: ' RELEASE_SHA
test "${#RELEASE_SHA}" -eq 40
REPO=https://github.com/Al1bekQur/chillibek.online.git
BASE="$HOME/chillibek-releases"
mkdir -p "$BASE"
CANDIDATE="$BASE/source-$RELEASE_SHA"
git clone --branch dev --single-branch "$REPO" "$CANDIDATE"
test "$(git -C "$CANDIDATE" branch --show-current)" = dev
test -z "$(git -C "$CANDIDATE" status --porcelain)"
git -C "$CANDIDATE" fetch origin dev
git -C "$CANDIDATE" merge --ff-only "$RELEASE_SHA"
test "$(git -C "$CANDIDATE" rev-parse HEAD)" = "$RELEASE_SHA"
```

For an already existing **non-live candidate checkout**, skip clone and use the
same clean-tree/fetch/`merge --ff-only`/exact-SHA checks. If remote `dev` has advanced
past the reviewed SHA, the exact-SHA check stops this recipe: review a new release
or prepare an explicitly pinned separate worktree, never reset/force-update a
working live tree. A candidate checkout is not made live merely by updating Git.

```bash
cd "$CANDIDATE"
python3.11 -m venv "$BASE/venv-$RELEASE_SHA"
PYTHON="$BASE/venv-$RELEASE_SHA/bin/python"
"$PYTHON" -m pip install -r requirements-dev.txt -c deploy/constraints-verified.txt
"$PYTHON" -m pip check
ARTIFACTS="$BASE/artifacts-$RELEASE_SHA"
"$PYTHON" -m deploy.release build --ref "$RELEASE_SHA" --output "$ARTIFACTS"
"$PYTHON" -m zipfile -l "$ARTIFACTS/pages-site.zip"
```

Do not install into the live virtualenv. `constraints-verified.txt` records tested
versions; it is not a wheel hash lock or proof those wheels work on PythonAnywhere.
Installation failure, disk exhaustion or an incompatible Python version is a stop.

## 2. Back up existing state before activation

Record these paths from the running app; do not guess them from examples. Keep
passwords/DSNs out of terminal history, Git, artifacts and public directories.
Use a maintenance window: pause staff mutations, finish pending carts, preserve
existing orders, and keep a rollback operator available. There is no promise of
zero downtime between activating a secured API and publishing compatible staff
navigation. Do not disable authorization to keep old staff clients running.

```bash
read -r -p 'Existing live WSGI configuration file: ' WSGI_FILE
read -r -p 'Existing private environment file: ' ENV_FILE
read -r -p 'Existing restaurant SQLite file (absolute path): ' RESTAURANT_DB
read -r -p 'Existing policy SQLite file (absolute path): ' POLICY_DB
read -r -p 'Existing event log (absolute path): ' EVENT_LOG
test -f "$WSGI_FILE" && test -f "$ENV_FILE"
test -f "$RESTAURANT_DB" && test -f "$POLICY_DB"
BACKUP="$BASE/backup-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$BACKUP"
cp -p "$WSGI_FILE" "$BACKUP/wsgi.py"
cp -p "$ENV_FILE" "$BACKUP/private.env"
if test -f "$EVENT_LOG"; then cp -p "$EVENT_LOG" "$BACKUP/events.log"; fi
"$PYTHON" -m deploy.release backup-sqlite --source "$RESTAURANT_DB" --destination "$BACKUP/restaurant.sqlite3"
"$PYTHON" -m deploy.release backup-sqlite --source "$POLICY_DB" --destination "$BACKUP/policy.sqlite3"
"$PYTHON" -m pip freeze > "$BACKUP/candidate-packages.txt"
```

Also record the **old** source SHA/location, old Web-tab virtualenv and Python
version, static mappings and installed package list using its existing interpreter.
Back up the old source tree/revision privately with the existing release mechanism;
do not rely solely on uncommitted code being recoverable from Git. SQLite backup
uses its consistent backup API, never a raw copy of an active database. Backups
are private, exclusive new destinations and never restored by these tools.
Pause other writers for a common cutover point across the two independently
backed-up DBs. Confirm disk space **before** creating archives/backups.

If the restaurant is **not SQLite**, stop the SQLite-specific recipe. Have the
current engine's authorized DBA procedure produce a consistent private dump and
restoration rehearsal. PostgreSQL foundation tests do not prove this account's
live engine/data or a MySQL cutover. Keep its existing DSN and driver unchanged;
engine conversion is not part of this release.

## 3. Rehearse schema, policy and restaurant compatibility

```bash
"$PYTHON" -m deploy.release check-sqlite --restaurant "$BACKUP/restaurant.sqlite3" --policy "$BACKUP/policy.sqlite3"
```

Exit 0 means the supported schema/summary gates passed; exit 2 stops promotion.
This check never instantiates PolicyStore against its input: it rehearses the
actual migration on a temporary copy and verifies prior fields survive. It checks
required columns, nonempty menu/staff, canonical staff usernames/roles, order
statuses/JSON and mandatory production login protection. It does not repair data,
verify passwords, add accounts or scan every business constraint. Legacy password
storage is reported without values; normal successful login may rehash a legacy
password while retaining the same password, so approve that compatibility behavior
explicitly. Do not run bulk migrate-passwords or create-admin against production.

The CSP policy upgrade adds a field/table and an audited revision once; old values
must survive. Backend startup may add missing auxiliary tables and seed an empty
menu; empty/missing/incompatible restaurant schemas are a **stop**, not permission
to initialize/import/seed. Do not run Alembic `upgrade`, DB import, cleanup or
password reset as a speculative release step.

Verify that each backup opens and restores to another private staging copy. The
backup regression verifies full menu/staff/order row equality; production backups
still require an operator recovery rehearsal. Never exercise restaurant mutations
against the backup intended as the final recovery point.

Run full tests with inherited production DB/policy/proxy overrides cleared in that
test process only:

```bash
env -u DATABASE_URL -u WAF_POLICY_PATH -u WAF_TRUSTED_PROXY_IPS \
  "$PYTHON" -m pytest backend/tests waf/tests -q
```

Node/Chrome staging commands and disposable fixture setup are in
[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md). Test menu/cart/order, staff
login, waiter/chef transitions, Admin add/edit/delete/image URL assignment, CSP
injection and policy persistence on disposable data. Use private **copies** of
legacy data only in an explicitly controlled additional compatibility rehearsal;
the automated suites in this task used synthetic DBs exclusively.

## 4. Activate backend and actual frontend together

Before activation, privately edit a **copy** of `deploy/pythonanywhere_wsgi.py.example`
to use the exact candidate path and the existing private environment file. The
reviewed environment must preserve the existing `FLASK_SECRET_KEY`, operator
username/password hash/session secret, DB selection and PolicyStore path. Add or
verify these nonsensitive path/hosting entries without replacing other settings:

```text
WAF_SERVE_FRONTEND=true
WAF_POLICY_PATH=<existing absolute policy file>
WAF_EVENT_LOG_PATH=<existing absolute event log>
WAF_SECURE_COOKIES=true
```

The revised WSGI example refuses a missing/relative policy path before importing
Flask, validates existing SQLite files for both DATABASE_PATH and DATABASE_URL,
and rejects event logs pointing at the selected DB or policy file. It uses the
configured paths instead of overriding them with a guessed runtime directory.
The existing database must be verified before importing the
app. Keep `TESTING=False`, production login safeguards and verified proxy trust.
Do not export raw Flask or run a second proxy/ASGI listener. No new security key
or policy database is created as a release convenience.

Review/remove static mappings shadowing `/`, restaurant HTML/assets, `/api`,
`/waf-api`, `/settings`, `/dashboard` and `/csp-report`. Keep DB/config/runtime files
private. With separate production approval, install the reviewed WSGI copy, select
the candidate virtualenv in the Web tab and click **Reload**. Keep the previous
source/venv/WSGI available. Do not replace live DB files with test or backup files.

### Benign health checks after the authorized reload

```bash
cd "$CANDIDATE"
"$PYTHON" -m deploy.release verify-http --origin https://kali.pythonanywhere.com --csp enforce
```

This performs only GETs, validates real document policy mode and required assets,
relative API base, health/menu availability, anonymous protected API rejection and
Settings login redirect. It does not follow cross-origin redirects, authenticate,
submit reports/orders, inject payloads or test passwords. Default TLS verification
stays enabled. It does create ordinary access/audit observations, as GETs normally do.
If the preserved master/CSP policy is Monitor/Report-Only or OFF, use the matching
`--csp report-only` or `--csp off`; do not call that Enforce coverage. Choose Enforce
through audited Settings after staging/observation if required for promotion.

Sign in normally to the single WAF `/settings/` and verify effective CSP,
production login guard, existing thresholds/holds, audit and reporting. Reload
documents after changing modes. Confirm the saved revision survives a managed
reload. The policy migration itself should add only the documented CSP defaults
and one audit revision. Verify the installed source SHA/path against the release
manifest and WSGI import; `/health` does not advertise a source SHA. No successful
HTTP check alone proves which Git revision is installed.

Keep all injection, failed-login and mutation probes on staging. Normal production
menu reads and authorized sign-in are sufficient at this gate. Direct staff to
the protected hostname during the coordinated cutover; origin-bound sessions do
not migrate. Never transfer tokens in query strings or disable auth for old clients.

## 5. Separately publish the Pages gateways

Only after the protected destination is ready, prepare the exact public artifact
in a separate clone/worktree. This is a **later, separately reviewed main
publication**, not a merge of backend source. Preserve CNAME/DNS.

```bash
PUBLICATION="$BASE/pages-$RELEASE_SHA"
git clone --branch main --single-branch "$REPO" "$PUBLICATION"
test -z "$(git -C "$PUBLICATION" status --porcelain)"
git -C "$PUBLICATION" fetch origin main
git -C "$PUBLICATION" merge --ff-only origin/main
"$PYTHON" -m zipfile -e "$ARTIFACTS/pages-site.zip" "$PUBLICATION"
git -C "$PUBLICATION" add -- .nojekyll CNAME index.html admin.html kitchen.html settings/index.html settings/settings.css dashboard/index.html
git -C "$PUBLICATION" diff --cached --check
git -C "$PUBLICATION" diff --cached --stat
git -C "$PUBLICATION" diff --cached
git -C "$PUBLICATION" commit -m "Navigate restaurant to verified WAF-hosted release $RELEASE_SHA"
# STOP for review/publication approval; only then:
git -C "$PUBLICATION" push origin HEAD:main
```

If the remote advances, normal push rejects; review/reconcile without force push.
For PR-based protection, push a publication branch and merge through the configured
review flow instead. Do not change repository Pages source or branch protection
automatically. Main publication is effective only if it is the verified configured
publishing source. No such publication was performed by this task.

After publication, inspect `/`, `/index.html`, `/admin.html`, `/kitchen.html`,
`/settings/`, `/dashboard/` with a fresh browser. Restaurant gateways must navigate
to their fixed backend documents, drop query/fragment and receive real CSP there.
Observe that the address bar changes. Verify document headers and legitimate
scripts. Existing open/cached Pages documents need refresh; pending carts should
have been completed, and staff must sign in again on the new origin.
Only record full application coverage for sessions on that verified destination,
not for the GitHub Pages origin or old tabs.

## Rollback without discarding credentials, orders or audit

1. **CSP compatibility failure:** use audited Settings to select Report-Only/OFF
   and reload documents. Keep safe DOM, API authorization, production login guard
   and independent hosting safeguards active. Confirm with `verify-http` using the
   actual effective mode. This rollback changes no restaurant records.
2. **Destination hosting unavailable after Pages cutover:** publish
   `pages-fallback.zip` through the same reviewed process, adding all three actual
   HTML pages, `restaurant-dom.js` and six page JS/CSS files as well as the public
   shell. It is a compatible safe-DOM frontend calling the secured API directly;
   dynamic CSP on its Pages documents is lost. Backend availability is still
   required; an API outage needs backend recovery too. Never claim fallback Pages
   has inherited CSP headers. Only then disable the frontend opt-in if desired.
3. **Code failure:** reactivate a previously staged **CSP-schema-compatible**
   source/venv/WSGI release, preserving the same explicit DB/policy/log paths and
   secrets. `c430b07` is the compatible source baseline for this prep-only change;
   use the correctly adapted WSGI configuration, not its old guessed-path example.
   No destructive Git reset is required: switch the private WSGI import/venv back
   to the retained release and reload, then run benign checks.
4. **Older pre-CSP binary:** do not run it blindly against an upgraded policy DB;
   it rejects `csp`. Drain writers and obtain a separately reviewed policy-schema
   recovery preserving later settings, holds and audits. No automatic downgrade
   or whole-policy restore is provided.
5. **Data recovery is separate:** do not restore the restaurant DB to roll back
   code or CSP, and do not overwrite current policy/audit with the pre-release
   backup casually. That would discard new orders or security state. If genuine
   data corruption requires recovery, stop writes and use the validated engine
   recovery procedure with explicit authority and post-backup change accounting.

Final acceptance records: exact SHA, private paths/venvs, backup checksums,
schema/policy rehearsal result, document/asset checks, effective CSP mode, operator
audit/reload persistence, publication commit and observed destination. Until
those account-side gates pass, status is **release prepared; production unverified**.
