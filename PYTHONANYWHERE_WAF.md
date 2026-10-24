# PythonAnywhere Free: protect the actual restaurant API

> **Current settings release, 2026-10-24:** the operator reports that the protected
> WSGI adapter and WAF credentials are now deployed. Use
> [`SETTINGS_DEPLOYMENT.md`](SETTINGS_DEPLOYMENT.md) for the current public gateway,
> authenticated server-side interface, eleven controls, verified test results and
> exact update/publication commands. The historical pre-cutover status and proposed
> JavaScript redirect below are superseded by that guide. This development task
> does not modify the installed WSGI configuration or production database.

## Decision and scope

The user confirmed that `kali` is on **Free / Beginner**. A protected WSGI entry
point can serve the existing website slot without buying another provider or
opening another website. This is a local implementation and staging result, not
confirmation that the account's live application has been changed.

The finalized development changes may be committed and pushed to `dev` under the
current authorization. No `main` release, DNS edit, PythonAnywhere configuration
change, production login, production write, attack simulation or database migration
is part of this work.
All behavioral/security verification uses synthetic accounts and temporary local
databases. Account-specific paths, Python version, quota, database engine and
static mappings still need a read-only check in the account. There is no connected
PythonAnywhere account tool available; the provider plugin search found none.

## Hosting evidence

| Capability | What is actually documented | Consequence |
| --- | --- | --- |
| Free account | One web app at `username.pythonanywhere.com`, restricted outbound Internet. | Reuse the current `kali.pythonanywhere.com` app; no second public staging app is assumed. [Plans](https://www.pythonanywhere.com/pricing/) |
| WSGI | Flask is loaded through the Web tab's WSGI configuration. `app.run()` does not publish a server. | Export the protected WSGI callable from that configuration. [Flask hosting](https://help.pythonanywhere.com/pages/Flask/) |
| ASGI | FastAPI/ASGI hosting exists as an experimental service with separate limitations and undecided long-term pricing. | Do not assume this account has a free extra ASGI slot or convert the live site to the beta service. [ASGI guide](https://help.pythonanywhere.com/pages/ASGICommandLine/) |
| Outbound access | Free-account connections are restricted by the provider's proxy allowlist. | Run Flask locally in the same worker; do not make an HTTP request back to `kali.pythonanywhere.com` or to a second origin. [Restrictions](https://help.pythonanywhere.com/pages/403ForbiddenError/) |
| Client IP | `REMOTE_ADDR` is the load balancer; provider-overwritten `X-Real-IP` identifies the client. Arbitrary forwarded-for prefixes are untrusted. | Enable the adapter's PythonAnywhere-specific trust mode only on that provider. [Client IPs](https://help.pythonanywhere.com/pages/WebAppClientIPAddresses) |
| SQLite | Available to everyone, but slow on the network filesystem; the provider advises against production SQLite, particularly with multiple workers. | The existing SQLite policy store is suitable for local proof and a carefully validated single-worker prototype. It is not a promise of production durability/performance. [Database support](https://help.pythonanywhere.com/pages/KindsOfDatabases), [filesystem/SQLite warning](https://help.pythonanywhere.com/pages/MySiteIsSlow/) |
| MySQL/PostgreSQL | MySQL is included on paid plans and grandfathered free accounts created before the documented January 2026 cutoff; PostgreSQL is a paid add-on. | Do not assume a new free account has MySQL, or deploy the prepared PostgreSQL Docker setup. The account's database entitlement is unverified. [Database support](https://help.pythonanywhere.com/pages/KindsOfDatabases) |
| Custom domains | Traditional custom-domain hosting requires a paid account. | Leave the public domain on GitHub Pages; management opens on the existing HTTPS PythonAnywhere hostname. [Custom domains](https://help.pythonanywhere.com/pages/CustomDomains/) |

A free worker is not a network-edge firewall or a DDoS service: requests reach
PythonAnywhere's HTTP server before this application inspects them. Provider
protocol/body/time limits still apply independently of the eight policy controls.

### Storage limitation that must not be hidden

`PolicyStore` still uses the existing transactional SQLite format and audit tables.
Changing to JSON files would weaken its atomic configuration/audit guarantees, so
this adapter does not do that. Keep rollback journaling (do not enable SQLite WAL
on the provider's network filesystem), use one worker, and do not run concurrent
console jobs that write the live policy file. Verify locks, reload persistence,
latency and disk quota on staging before promotion. `database locked`, I/O errors,
or corrupt configuration return 503 rather than bypassing protection.

The provider explicitly recommends a server database for production. This change
does not implement or claim to validate a MySQL policy store. If dependable
production operation cannot be demonstrated with the existing single-worker
SQLite storage, **stop the rollout**. A free account without grandfathered MySQL
cannot meet that stronger storage requirement using the prepared code alone.
Do not silently buy a service, invent a free database, or claim this hosting issue
has been solved. The restaurant database itself must also retain its current
engine/data until an authorized migration has been staged and backed up.

## Current URLs and coverage

| Component | URL / configuration |
| --- | --- |
| Production restaurant | `https://chillibek.online/`, `/admin.html`, `/kitchen.html` (GitHub Pages). |
| Existing restaurant API | All three frontend files use `https://kali.pythonanywhere.com/api`. These URLs are unchanged. |
| Public settings | `https://chillibek.online/settings/`; currently the published version has no connected same-origin WAF API. |
| Existing WAF endpoints | `/settings` -> `/settings/`; `GET /waf-api/settings`; `PUT /waf-api/settings`; `POST /waf-api/settings/reset`. |
| Dashboard | `/dashboard`, `GET/POST /dashboard/login`, `POST /dashboard/logout`; authenticated `/dashboard/api/summary`, `/events`, `/rules`. |
| Standalone FastAPI proxy | Configured by `WAF_UPSTREAM_BASE_URL`; defaults to `http://127.0.0.1:5000`. Still supported separately; it is not needed as a listening server on PythonAnywhere. |

When the protected entry point is actually installed, calls to the existing API
URL go through inspection directly. There is no additional public backend URL to
hide or restrict: the raw Flask application is invoked in-process and is never
exported as another public server. Ensure there is no second web app, alternate
hostname or unprotected WSGI export serving the same API, and no Web-tab static
mapping intercepts `/api`, `/waf-api`, `/dashboard` or runtime/database files. Those
account settings cannot be verified from this checkout.

```text
Restaurant browser -> kali.pythonanywhere.com managed WSGI entry
                         -> existing FastAPI WAF (adapted with a2wsgi)
                            -> existing rules + current policy + event/audit storage
                            -> local WSGI transport -> original Flask callable
                               -> existing restaurant database

chillibek.online/settings/  --top-level navigation--> kali.pythonanywhere.com/settings/
chillibek.online/dashboard/ --top-level navigation--> kali.pythonanywhere.com/dashboard
                                                    -> separate WAF operator login
```

Management stays on the PythonAnywhere origin. Its page uses the existing
same-origin policy API, signed HttpOnly/Secure/SameSite=Strict operator cookie,
session-bound CSRF token and persistent audit. Restaurant bearer tokens or a
restaurant-admin role do not grant WAF administration. No management CORS allowance,
third-party cookie dependency, token in URL or credential in public JavaScript
is introduced. The settings redirect uses fixed trusted destinations; user-supplied
query strings and fragments are not forwarded. Dashboard has a public static
gateway, not an unauthenticated copy of the event dashboard.

With GitHub Pages alone, an HTTP server-side path proxy on `chillibek.online` is
not available. The no-new-provider choice is to navigate management to the backend
hostname. Keeping the address bar on the original domain would require a separate
approved edge/routing arrangement; this implementation does not claim otherwise.

## Code prepared

- `waf/wsgi.py`: adapts the existing WAF with pinned `a2wsgi==1.10.10`. The outbound
  transport is replaced by a direct call to the supplied WSGI application, even if
  a remote upstream was configured. No HTTP self-call or arbitrary proxy target.
- The adapter starts its event-loop thread lazily in the actual worker, avoiding
  an inherited pre-fork event loop. The application still occupies one WSGI slot.
- The provider-overwritten client IP reaches both WAF and Flask limits; the scheme
  comes from the managed server's WSGI environment, not a client forwarding header.
  Missing/invalid trusted IP metadata fails closed instead of sharing/spoofing a
  counter. This trust option is off by default outside PythonAnywhere.
- `waf/app.py` / `waf/config.py`: the WSGI adapter can forward existing Flask
  `Set-Cookie` headers, including multiple cookies, without logging them. The
  standalone proxy keeps its earlier default header behavior.
- `settings/settings.js`: prepared public-host redirect to the backend-hosted
  version of the same settings panel; no redirect on the backend or local staging.
- `settings/index.html`: the Restaurant navigation returns to the actual public
  restaurant hostname when the panel is hosted on PythonAnywhere.
- `dashboard/index.html`: public Pages gateway to the authenticated backend route.
- `deploy/pythonanywhere_wsgi.py.example`: reviewable WSGI entry-point template.
  Its project/runtime paths are examples, not verified account paths.
- `waf/tests/test_wsgi.py`, `waf/tests/test_management_routes.mjs` and
  `waf/tests/browser_wsgi_fixture.py`: synthetic protocol, role, toggle and browser
  staging of the actual WSGI -> WAF -> Flask stack.
- `waf/policy.py`: reject incomplete stored policies as corrupt configuration
  instead of silently filling missing controls with defaults. Invalid storage
  remains untouched and requests fail closed with 503.

The eight controls use the existing request-processing implementation:
Block/Monitor, SQLi, XSS, traversal, per-client rate, suspicious headers, request
size and event logging. Policy updates commit with their audit and apply to the
next request without an app reload. Authentication/authorization, login throttling
and configuration audit remain active when optional detection/logging is OFF.
HTTP parser protections and Flask's own size/validation/auth limits remain active.

## Compatibility: two deployment paths

**Inspection-only wrapper:** keep the account's existing Flask import, application
object and database exactly as they are, and wrap that callable with `protect_wsgi`.
This avoids a restaurant database or bearer-token migration and preserves whatever
authentication the existing application currently enforces. The actual legacy
PythonAnywhere source is not in this checkout and has not been inspected; this
path is not a claim that its existing authorization is secure or compatible.
Staging must verify its real login, roles, cookies and responses using synthetic data.

**Secured-backend cutover:** this checkout's Flask API requires bearer tokens for
staff operations and calculates order totals on the server. The current production
`main` staff pages do not attach those bearer tokens; the `dev` admin/kitchen pages
do. Deploying the secured backend without its compatible staff pages would break
staff workflows. This path therefore needs an approved coordinated update of those
pages, with the same restaurant API URLs, a verified database copy and credential
migration/rotation as described in `backend/MIGRATION.md`. Never disable backend
authorization to make the old pages work. No restaurant HTML is modified in this task.

## Exact next deployment action — separate approval required

1. **Read-only account preflight:** open the existing app's Web tab and record its
   WSGI file/import, Python and virtualenv versions, single-worker setting, static
   mappings, existing database engine/path and account disk usage/expiry. Do not
   paste secrets or database contents. Confirm Python 3.10+ (the source uses 3.10+
   type syntax), installed dependencies and a writable private runtime directory.
   Confirm that no raw API alternative is served outside the protected entry point.
2. Select the inspection-only or secured cutover path above. Back up the current
   WSGI file, source version, private environment and database using the database's
   consistent backup mechanism. SQLite: `sqlite3.Connection.backup()` into a private
   directory; MySQL: an authorized consistent dump. Verify restoration to a separate
   staging copy. Do not place any backup under a static mapping or Git checkout.
3. With **explicit approval**, copy code to a separate account staging directory
   and install dependencies in a separate virtualenv. Do not replace the live WSGI
   file yet. Use a synthetic database and synthetic WAF/staff accounts, never the
   live database, for the staging tests below. Free has only one website slot, so
   a second publicly hosted staging site is not assumed: run WSGI tests in the
   staging environment/console or retain local staging before the approved cutover.
4. Configure private `WAF_DASHBOARD_USERNAME`, a Werkzeug
   `WAF_DASHBOARD_PASSWORD_HASH`, a distinct stable random 32+ character
   `WAF_DASHBOARD_SESSION_SECRET`, and explicit absolute policy/event paths. Keep
   `WAF_SECURE_COOKIES=true`; enable HTTPS/redirects through the provider's Web tab
   as appropriate. Do not reuse restaurant credentials. No credentials are generated
   or stored by the checked-in deployment example.
   For the secured-backend path, explicitly set the verified existing database
   location and Flask secret too; the example refuses to use a default missing
   SQLite path instead of silently creating an empty replacement database.
5. After storage and compatibility validation, review the exact candidate WSGI file
   and rollback procedure. **Only with the separate production approval**, replace
   the current entry point with `application = protect_wsgi(original_flask_app,
   settings, trust_pythonanywhere_proxy=True)` and reload that same existing web app.
   Never export the raw Flask callable or run a separate localhost proxy/server.
6. Check only benign production menu retrieval, TLS, unauthenticated management
   rejection and authorized operator sign-in/configuration reads. Confirm the normal
   menu request appears as a real event. Do not submit production test orders,
   injected payloads, repeated invalid logins or destructive requests. Attack and
   mutation checks remain on staging. Keep the old entry point available for rollback.
7. Only once the backend routes are verified live, request/obtain the separate Git
   publication approval and release the prepared management navigation files to
   `main`. Do not publish them first: the current backend may return 404. Include
   compatible staff pages only if the secured-backend path was selected and approved.
   No DNS change or new provider is required for this hostname-navigation design.

Until that protected entry point is installed and verified, **real restaurant
traffic is not established as protected by this work**, and the already-published
settings page remains disconnected. No local test result proves a live rollout.

## Staging verification

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q
node --test waf/tests/test_management_routes.mjs
```

For a real browser against the managed WSGI protocol (not Uvicorn), start:

```powershell
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture
```

This binds only `127.0.0.1:8765`, overrides inherited database configuration, creates
temporary synthetic databases and uses test-only credentials. It is never a public
deployment entry point. Start a dedicated isolated headless Chrome as described in
`SETTINGS_DEPLOYMENT.md`, then run `node waf/tests/browser_settings.mjs`. Stop the
fixture afterwards. The script closes the dedicated QA browser itself.

Tests verify actual Flask menu/ordering transitions, staff login/role restrictions,
server-calculated totals, CORS and existing cookie sessions, separate WAF admin
auth/CSRF, SQLi/XSS/traversal independence, Monitor, size/header/rate/logging controls,
policy persistence across recreated wrappers, real Dashboard events, always-on
audit/login controls and absence of outbound HTTP during request forwarding.

Observed local verification: **87 Python tests passed** (the previous 77 plus
eight independent control/persistence cases and two incomplete-policy cases),
**6 Node routing tests passed**, and **8 real Chrome browser checks passed against
the WSGI staging stack with the real Flask backend**. Every control is saved,
verified after a browser refresh, and restored independently; server tests also
check live updates, recreated workers, unrelated rules and mandatory audit/CSRF.
JavaScript syntax and Git whitespace checks passed. These are local
staging results; no PythonAnywhere deployment or filesystem reliability test has
been performed. The restaurant HTML, CNAME and existing database/migrations are
unchanged. The current GitHub Pages and PythonAnywhere services are not modified.

Benign public GETs on 2026-10-23 confirmed the current settings page returns 200,
the public `/dashboard/` returns 404, and the PythonAnywhere menu returns 200 with
14 public items. The local system CA store initially rejected its TLS chain;
validation with the maintained CA bundle succeeded. The presented wildcard leaf
certificate is valid until 2026-12-20. No TLS validation was disabled for API reads,
and no production staff login, order submission or attack payload was sent.
