# CSP architecture, migration and rollback

Development baseline: `e99669a657a500da464cf4dbf56abeb64aec76f5`; this release
includes that earlier, unpublished XSS/input fix. No production request, DNS
change, deployment, account change or restaurant database operation was performed
while implementing CSP. A `dev` push does not publish GitHub Pages or reload WSGI.

## Delivery architecture and truthful coverage

Use the **existing protected WSGI application** to deliver restaurant documents
and their fixed external assets. Opt in with `WAF_SERVE_FRONTEND=true`, set before
importing `waf.config` in the reviewed WSGI configuration/environment. Default is
false. There is no additional listening server, security engine, configuration
file/store or Demo Lab. The existing PolicyStore owns CSP and report retention.

```text
Pages index/admin/kitchen migration gateways (manual publication only)
  -> top-level navigation to existing PythonAnywhere HTTPS hostname
  -> ProtectedWSGI -> ProtocolGuard -> one PolicyStore snapshot
     -> opt-in restaurant HTML/assets OR authenticated management HTML/assets
     -> HTML response CSP finalization
  -> browser loads self-hosted scripts/styles; restaurant requests /api
     -> the same WAF -> in-process Flask -> existing restaurant database
```

| Document or route | Current source behavior | Dynamic CSP coverage |
| --- | --- | --- |
| GitHub Pages `/`, `/index.html`, `/admin.html`, `/kitchen.html` | Original app remains usable with external assets and the earlier safe DOM fix | **No backend-header coverage. Live publication is unverified.** |
| Optional `deploy/pages-gateway/*.html` published over the three Pages entry documents | Fixed navigation to matching PythonAnywhere document, no query/fragment/credential forwarding | Static restrictive meta policy on gateway only; destination receives real response headers |
| WAF `/`, `/index.html`, `/admin.html`, `/kitchen.html` GET/HEAD | Served only when frontend hosting is enabled; API base becomes `/api` | Enforce / Report-Only / OFF, from request snapshot |
| WAF `/dashboard/login`, `/dashboard`, `/settings/` HTML | Existing auth/CSRF; external JS/CSS | Same CSP policy and modes |
| `/settings` | Auth redirect / canonical redirect | CSP evaluated on destination HTML |
| `/restaurant-dom.js`, `/restaurant-{index,admin,kitchen}.{js,css}` | Exact fixed asset routes, opt-in; no arbitrary filesystem path | Loaded under document CSP; no HTML policy needed on assets |
| `/dashboard/dashboard.{js,css}`, `/settings/settings.{js,css}` | Static authored code/style, no embedded secrets | Loaded under management document CSP |
| All existing `/api/*` methods and routes | Existing centralized request inspection, login policy and Flask integrity/RBAC | JSON response CSP is not document protection; independent restrictive API headers remain |
| POST `/csp-report` | Mandatory report validation and quotas | Browser telemetry, not optional request XSS/SQLi inspection |
| GET `/dashboard/api/csp` | WAF operator authentication | Redacted telemetry and explicit coverage description |
| Existing `/waf-api/*`, `/dashboard/api/{summary,events,rules}`, `/health` | Existing responsibilities preserved | JSON/API responses do not govern another document |
| Unknown backend routes/methods | Existing inspected proxy/Flask or HTTP 405; assets do not use a wildcard route | Existing missing-endpoint logging/bot detection preserved |

The existing full API/method matrix remains in [WAF_COVERAGE.md](WAF_COVERAGE.md).
Settings and Dashboard describe **served HTML**, configured and effective modes,
the hosting opt-in, and Pages as **NOT COVERED**. They never infer live deployment
from source settings. No live edge, mappings, installed commit or capacity was
verified. Customers continue to see unprotected old Pages documents until a
reviewed migration is published; API headers cannot close that gap.

This option reuses the existing HTTPS hostname and WSGI slot without assuming a
new paid plan, custom domain entitlement or proxy service. Users will see the
PythonAnywhere hostname. Keeping `chillibek.online` in the address bar requires a
separately approved header-capable host/edge and routing design. Performance,
quotas, SQLite/network filesystem behavior and account entitlements still need
staging validation; the existing hosting caveats in
[PYTHONANYWHERE_WAF.md](PYTHONANYWHERE_WAF.md) apply.

## Policy contract

`Policy.csp` is a validated nested immutable model. Existing complete policies
migrate transactionally once: add CSP defaults, increment revision, audit
`schema_upgrade`, retain every old setting. Incomplete/corrupt rows still fail
closed. API/store snapshots use JSON-compatible arrays consistently. Existing
authenticated, CSRF-protected, optimistic-revision Settings updates audit CSP
changes along with other policy fields. No restaurant schema/data migration.

| Configured CSP | Master Block | Master Monitor | Master Disabled (isolated tests only) |
| --- | --- | --- | --- |
| ON / `enforce` | `Content-Security-Policy` | `Content-Security-Policy-Report-Only` | No optional CSP header |
| REPORT-ONLY / `report-only` | Report-Only header | Report-Only header | No optional CSP header |
| OFF / `off` | No optional CSP header | No optional CSP header | No optional CSP header |

The same effective mode covers management and opt-in restaurant HTML. A policy
change governs the **next response**, not an already open document: reload all
three pages when verifying a change. Report-Only observes; it does not prevent
execution. OFF does not turn off safe DOM rendering, auth/RBAC, CSRF, password
checks, login safeguards, `nosniff`, Referrer-Policy, HTTPS HSTS or mandatory
transport limits. `X-Frame-Options: DENY` remains independent; relaxing
`frame-ancestors` will not allow framing in browsers enforcing that header.
The backend's existing restrictive JSON response CSP also remains independent.

Defaults:

```text
default-src 'none'; script-src-attr 'none'; style-src-attr 'none';
script-src 'self'; style-src 'self';
img-src 'self' https://images.unsplash.com data:; connect-src 'self';
object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self';
require-trusted-types-for 'script'; trusted-types 'none'; report-uri /csp-report
```

Settings expose all eight requested source directives and a Trusted Types
checkbox. Sources are 1–10 unique tokens per directive: `'self'`, lone `'none'`,
exact ASCII HTTPS origins (use punycode for international hostnames), or `data:`
for images only. HTTP origins are accepted only for loopback test fixtures.
Script/style/connect must keep `'self'` to preserve management assets and API
access. Arbitrary directives, paths, credentials, controls, Unicode header bytes,
wildcards, `unsafe-inline` and `unsafe-eval` are rejected. A configured external
script origin is trusted executable code: approve it carefully. No third-party
script is necessary by default.

Scripts/styles/handlers in all three restaurant documents and WAF Dashboard/login
have been externalized. Static controls bind authored functions via
`addEventListener`; data attributes do not contain executable source. Existing
text/node rendering stays effective even with CSP OFF. Authored property-level
style changes (display, transform, timers) continue to work; no inline style
attribute exception is needed.

Trusted Types forbids string-to-HTML/script sinks in supporting browsers, with
no permissive default policy. It adds defense against future DOM sink mistakes;
it does not replace safe rendering or cover unsupported browsers. CSP does not
stop malicious trusted scripts, browser extensions or a compromised origin, and
does not repair authorization, CSRF, sensitive storage or arbitrary business logic.
Staff bearer tokens remain origin-bound sessionStorage as before. CSP OFF and
Report-Only remain operator choices, not safe ways to test real staff credentials.

## Reporting contract and privacy

POST `/csp-report` supports legacy `application/csp-report` and bounded
`application/reports+json` batches (type `csp-violation`). The response policy
advertises `report-uri` for the tested browser path; no Reporting-Endpoints or
`report-to` delivery is claimed. Reports require same-origin document URLs in a
fixed restaurant/management path allowlist, recognized directives and disposition
`enforce` or `report`. When supplied, Origin and Fetch Metadata must be same-origin.
Reports are not credential-authenticated evidence: nonbrowser clients can forge
them, so Dashboard labels them untrusted observations.

Mandatory limits survive OFF and other WAF switches: 8 KiB body before normal
routing (also applies without Content-Length), 1–10 reports/batch, 30 requests/IP
and 200 total requests per sliding minute, 1,000 retained reports, newest 100
returned to authenticated operators. Global quota is checked before per-IP
counter creation. Existing transport capacity/time ceilings also apply. Errors
are controlled 400/403/413/415/429 responses. Quota counters use the adapter's
verified client IP; hosting proxy trust must be configured correctly.

Only receipt timestamp, directive, fixed document path, redacted resource label,
client-asserted disposition and **receipt revision** are stored. Strip document
query/fragment; no script sample, policy text, cookies, headers, referrer, raw body
or full blocked URL. Resource is inline/eval/Trusted Types label, same-origin,
approved origin or generic external resource. Receipt revision does not prove
which response policy the browser had. Dashboard builds cells with textContent.
Reports are a bounded separate table in the existing policy database, collected
regardless of the optional backend event-log switch; no raw-report logging.
Normal backend allow/detect/block logs retain their existing meaning.

## Inventory reviewed

| Source | CSP-relevant resources / changes |
| --- | --- |
| `index.html`, `admin.html`, `kitchen.html` | Each previously had one inline app script/style block and literal event handlers. Now use `restaurant-dom.js` plus corresponding `restaurant-*.js/.css`; admin's two literal styles became CSS rules. |
| `restaurant-dom.js` | Existing safe DOM/URL/type helpers retained; no HTML trust policy added. |
| `restaurant-*.js` | Same menu/cart/auth/edit/order/archive workflows; API base comes from document dataset. No eval, Function constructor, innerHTML assignment or insertAdjacentHTML. |
| `waf/dashboard.py` | Login and Dashboard external stylesheet, external Dashboard script; safe CSP report table added. |
| `waf/templates/settings.html`, `settings/settings.js/.css` | External assets already; new CSP form uses safe DOM and same-origin authenticated API. |
| `settings/index.html` | Static public gateway/description, not a live control panel; no JS or API client. |
| `dashboard/index.html` | Existing fixed management redirect, no app script; inline static presentation remains on the Pages-only gateway, outside dynamic management CSP. |
| `deploy/pages-gateway/*.html` | Optional fixed restaurant migration destinations; no JS, inline event handlers, dynamic URLs or styles. |
| Images/fonts/other resources | Seed menu images use images.unsplash.com; browser fixtures fulfill them locally. No script CDN, web font CDN, analytics, worker or third-party stylesheet. Operator-saved image origins may need explicit staging approval; they are not silently allowed. |

## Manual release order

1. Review `dev` and [CSP_VERIFICATION.md](CSP_VERIFICATION.md). Create consistent
   backups of existing WSGI config, environment, source, **policy DB/audit**, and
   restaurant DB using the current engine's backup method; protect credentials.
   Record installed versions, policy revision and file paths. Do not initialize,
   seed, replace or restore the restaurant database to deploy this change.
2. Stage the combined earlier XSS/input fix and this CSP release with disposable
   accounts/data. Use the exact production entry-point design and existing engine
   settings; keep production credentials/configuration out of tests. Verify that
   `DATABASE_PATH`/`DATABASE_URL` still selects the intended existing database and
   `WAF_POLICY_PATH` still selects the existing persistent policy file outside the
   checkout. Stage the one-time policy upgrade and locking/reload behavior.
3. Prepare **all backend and frontend files together** in a reviewed server
   release directory. Keep the existing protected `application` export; never
   export raw Flask, add a second public API, enable `TESTING` or weaken production
   login safeguards. Set `WAF_SERVE_FRONTEND=true` before imports for the selected
   release. Do not run `browser_wsgi_fixture` as a deployment server.
4. Review PythonAnywhere Web-tab static mappings. A mapping for `/` or any protected
   document must not intercept these responses; reserve `/api`, `/waf-api`,
   `/dashboard`, `/settings`, `/csp-report`, restaurant HTML and assets for this
   application. Never map database/runtime/configuration files. Provider static
   mappings bypass framework headers; code cannot correct a shadowed route.
5. With separate deployment approval, activate/reload the reviewed backend release
   first. Defaults enforce CSP; on staging prove that boot works, then choose a
   deliberate Report-Only rollout using authenticated Settings if needed. Verify
   real HTTPS **document response** headers on index/Admin/Kitchen/login/Settings/
   Dashboard, external asset MIME types, `/api` routing, policy persistence,
   approved image hosts and reports. Use disposable accounts on staging for
   attack probes; do not inject payloads into production menu/staff records.
6. Check normal restaurant functionality without altering production records.
   If compatible after observation, set Enforce and reload documents. Do not
   publish Pages navigation before the protected destination is ready. Existing
   Pages customers still need the earlier safe DOM fix until migration completes.
7. In a **separate reviewed `main` publication**, replace Pages root `index.html`,
   `admin.html`, `kitchen.html` with the corresponding files from
   `deploy/pages-gateway/`. Keep actual restaurant HTML/assets in the server
   release; do not copy gateway files over them. The committed gateways are opt-in
   artifacts and are not active merely because this commit is on `dev`. Include
   existing public Settings/Dashboard gateways and unchanged CNAME as appropriate.
   Both `/` and `/index.html` then resolve to the index gateway. No DNS change is
   required for this hostname-changing migration.
8. Verify final navigation/headers after publication with separate authorization.
   Existing open/cached Pages documents need refresh. Browser sessions/cart live
   on their previous origin; staff sign in again, and pending carts should be
   finished before cutover. Never transfer tokens in URLs or copy credentials.
   Only then report actual production coverage; record gaps instead of claiming
   protection from the Settings switch alone.

## Rollback

- For CSP incompatibility, use audited Settings to select Report-Only or OFF and
  reload documents. Keep safe DOM rendering, API validation and production login
  policy active. Prefer this fast reversible rollback; it changes no menu/order.
- For hosting failure, first restore Pages documents from a **compatible safe-DOM
  release**, including all external assets, through a reviewed publication. Do not
  point gateways at an unavailable destination. This temporarily loses dynamic
  frontend CSP; record that loss. Then disable the frontend hosting opt-in and
  reload the protected WSGI app if required; management/API remain protected.
- Roll back code only to a tested CSP-schema-compatible release. Older binaries
  reject the new `csp` field: blindly checking out `e99669a` with the upgraded
  policy DB can fail closed. If an older binary is essential, drain writers and
  stage a reviewed policy-schema downgrade/backup recovery preserving later audit
  records, operator changes and login state. No automatic downgrade is supplied.
  Never overwrite the restaurant DB to roll back CSP, and never restore an entire
  policy backup casually because it would discard recent security state/audits.

## Delivery references

- [W3C CSP meta delivery](https://www.w3.org/TR/CSP3/#meta-element): meta cannot
  supply Report-Only or frame-ancestors/report-uri behavior; a static meta policy
  cannot make a backend setting dynamic on Pages. This is why opt-in document
  hosting and navigation migration were implemented.
- [MDN Trusted Types directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for): supported browsers can restrict script/HTML sinks; verify browser support separately.
- [MDN report-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/report-uri): legacy reporting is deprecated but remains the explicitly tested delivery path; future Reporting API rollout is separate.
- [PythonAnywhere static files](https://help.pythonanywhere.com/pages/StaticFiles/): static mappings can bypass application processing, so account mapping review is a deployment prerequisite.
