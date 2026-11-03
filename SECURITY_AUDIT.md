# Chillibek WAF security and architecture audit

Implementation update: A01/A02 input failures and A06 dynamic restaurant rendering
are addressed in [XSS_FIX_VERIFICATION.md](XSS_FIX_VERIFICATION.md). This audit
remains a historical account of its stated baseline, including its line references.
CSP and the other deferred audit findings were not implemented in that stage.
Subsequent CSP work and the tested resolution path for A05 are documented in
[CSP_DEPLOYMENT.md](CSP_DEPLOYMENT.md) and [CSP_VERIFICATION.md](CSP_VERIFICATION.md).
Live frontend coverage remains unverified and requires manual migration; the
audit below retains its original baseline and line numbers.

Audit date: **2026-11-03**. Source baseline: **`b27aa6a76a6163fe37d34128bcb7a80466039e54`**, branch `dev`.

This is a source audit plus bounded, disposable local checks. The production URLs
supplied by the owner are `https://chillibek.online` and
`https://kali.pythonanywhere.com`. **No HTTP request was sent to either production
application; neither was scanned, exploited, reconfigured or deployed to.** Their installed commits,
response headers, PythonAnywhere mappings, credentials and current policy are
therefore unverified. Vendor documentation was consulted separately. Only this
document and [SECURITY_IMPLEMENTATION_PLAN.md](SECURITY_IMPLEMENTATION_PLAN.md)
are intended for this commit. No new security feature or Demo Lab was implemented.

Line references below refer to the baseline above. Severity describes practical
impact with stated prerequisites, not a CVSS score. **Confirmed** means observed
locally or directly established by source. **Potential** means an impact depends
on an unverified deployment, compromised input contract, concurrency or business
requirement. A passing regression suite is not proof that all malicious inputs
are handled correctly.

## Executive assessment

The centralized WSGI architecture is substantially sound: one policy snapshot
crosses into Flask through an internal object; API authentication and RBAC remain
mandatory; SQL uses bound parameters; production staff login remains bounded;
management mutations require independent operator authentication and CSRF.
There is no active second Demo policy in this baseline.

The first implementation should fix **request-processing exceptions**: malformed
HTML can crash the enabled XSS detector, and oversized numeric strings can produce
application 500s. Then preserve manual-block precedence under late login outcomes.
These are concrete regressions to address before extending the module catalog.

The largest browser-architecture gap is **CSP delivery for the public frontend**.
API CSP does not protect HTML served by GitHub Pages. Current frontend scripts and
event handlers also need preparation before strict CSP enforcement. No working
remote Stored XSS, SQLi, RBAC bypass, IDOR, command execution or server-side SSRF
exploit was confirmed in the audited application paths.

## Architecture and trust boundaries

```text
Browser receives restaurant HTML/JS from chillibek.online / intended GitHub Pages
  | document execution, sessionStorage, rendering, images: outside backend WAF
  | fetch to configured backend API
  v
Managed hosting HTTP parser and verified proxy metadata
  -> ProtectedWSGI -> ProtocolGuard
  -> management authentication/audit OR centralized restaurant inspection
  -> one immutable policy snapshot and revision
  -> in-process HTTPX WSGI transport, trusted environment object
  -> Flask entry guard -> authentication/RBAC -> validated bound SQL
  -> staff credential outcomes -> shared policy state -> WAF traffic record
```

- Public API origins are fixed in [index.html:159](index.html#L159),
  [admin.html:122–133](admin.html#L122-L133) and
  [kitchen.html:129–140](kitchen.html#L129-L140). `CNAME:1` identifies the public
  domain, but does not establish the actual Pages publishing branch or live edge.
- [waf/wsgi.py:77–87](waf/wsgi.py#L77-L87) forces the supplied Flask callable as the
  upstream. [43–47](waf/wsgi.py#L43-L47) injects the internal policy object;
  [waf/app.py:306–314](waf/app.py#L306-L314) strips client forwarding metadata.
- [waf/app.py:113–116](waf/app.py#L113-L116) admits one policy revision;
  [backend/server.py:292–301](backend/server.py#L292-L301) reuses it for login.
  [backend/server.py:250–258](backend/server.py#L250-L258) denies raw production
  Flask API access without that object. `TESTING=True` is a deliberate unit-test
  exception and must never be the production configuration.
- ProtocolGuard precedes management/proxy dispatch, but the hosting parser runs
  first. WSGI cannot recover duplicate wire headers discarded by that parser
  ([waf/protocol.py:1–5,16–37](waf/protocol.py#L1-L37)).
- PolicyStore validates durable policy, serializes writes with `BEGIN IMMEDIATE`,
  checks revisions and audits changes
  ([waf/policy.py:189–233](waf/policy.py#L189-L233)). It is a same-host SQLite
  design, not multi-host replication or a tamper-resistant external audit service.
- The public Settings page is a gateway, not a live-policy viewer
  ([settings/index.html:26–30](settings/index.html#L26-L30)). The authenticated
  panel is served by [waf/settings_api.py:38–53](waf/settings_api.py#L38-L53).

## Findings register

| ID | Finding | Severity | Evidence status / scope |
| --- | --- | --- | --- |
| A01 | Malformed HTML causes XSS-detector 500 and missing traffic event | Medium | Confirmed through real local WSGI, unauthenticated query |
| A02 | Oversized numeric string raises instead of returning validation error | Low | Confirmed local public order request; no order committed |
| A03 | Late failure can replace a manual account hold with an automatic lock | Medium | Confirmed store transition; real request exploit needs an in-flight race |
| A04 | Logout does not revoke copied operator cookies or staff bearer tokens | Medium | Operator replay confirmed locally; requires possession of valid material |
| A05 | Public frontend has no repository-delivered CSP; backend policy cannot cover it | Medium | Confirmed source/topology gap; live edge headers unverified |
| A06 | HTML templates and executable attribute interpolation depend on API types | Low | Confirmed patterns; current Stored/DOM XSS not demonstrated |
| A07 | Duplicate-parameter semantics are accepted without an explicit contract | Low | Confirmed JSON last-wins/query multi-value behavior; no current auth bypass |
| A08 | Public order creation lacks a business authenticity/replay boundary | Medium | Public design confirmed; operational abuse impact is potential |
| A09 | Log growth, full reads and unbounded result buffering affect availability | Medium | Source confirmed; exhaustion/performance impact not load-tested |
| A10 | Some audit paths, rule states and category labels are misleading | Low | Confirmed source and local rules response |
| A11 | Early hosting denials do not receive the normal security headers | Low | Confirmed local capacity 429; proxy errors also precede the middleware |
| A12 | Historical measurement tooling is currently unreproducible | Low | Confirmed isolated model-validation check, not a runtime bypass |

### A01 — XSS parser exceptions are not contained

[waf/rules.py:95–99](waf/rules.py#L95-L99) calls `HTMLParser.feed()` without
handling its parser assertions. The harmless malformed marker `<![audit]>` raises
`AssertionError` in this environment. [waf/app.py:182–189](waf/app.py#L182-L189)
only protects value collection, then invokes detection outside that `try` block;
the outer middleware catches only SQLite/OS errors
([97–99](waf/app.py#L97-L99)).

Observed on a temporary real WSGI fixture: `GET /api/menu` with that query returned
**500 with XSS ON**, created no traffic-log file, and returned **200 with XSS OFF**.
The pure detector also raised. This stops the request rather than bypassing Flask
authentication; a process-wide outage was not demonstrated. Ordinary malformed
input should not become an uncaught error or disappear from traffic accounting.

Required fix: explicitly contain supported parser failure classes, define a stable
sanitized result/error policy, and log it. Preserve switch semantics: disabling
optional XSS must not run that parser; mandatory malformed-request validation must
have its own documented reason. Do not simply catch every programming exception
and label it an attack. Acceptance is in plan task P1.

### A02 — Numeric conversion lacks a pre-conversion size bound

[backend/server.py:105–116](backend/server.py#L105-L116) accepts arbitrarily long
digit strings before `int(value)`. A disposable `POST /api/orders` with one item
and a 5,000-digit quantity returned **500**, because Python's integer-string limit
raised `ValueError`; the normal 1–99 bounds were never reached. This input fits
inside existing body-size limits. The invalid request committed no order.

Bound the representation before conversion, handle expected conversion failures
as 400, and cover route IDs/other integer fields as well. Do not remove Python's
integer safety limit. This is an error-handling/availability issue, not SQLi.

### A03 — Manual block precedence is not preserved on late outcomes

Both block types use a unique identity, and automatic failure processing performs
`INSERT OR REPLACE` without preserving a manual row
([waf/policy.py:369–395](waf/policy.py#L369-L395)); manual creation uses the same
identity ([409–435](waf/policy.py#L409-L435)). Admission and outcome recording are
separate transactions ([331–359](waf/policy.py#L331-L359)).

Local state-machine check: create a **3,600-second manual account hold**, then
record a failure at a configured one-failure threshold. It becomes an automatic
hold with **at most 30 seconds** remaining. In actual operation this can occur
when an already admitted password check finishes after the operator creates a
hold. Newly arriving requests would normally be rejected, so an unrestricted
manual-lock bypass was not demonstrated.

Preserve manual rows until explicit unblock/expiry; record late outcomes without
weakening them. Add concurrent admission/failure/manual-block tests. Keep audited
unblock ([454–467](waf/policy.py#L454-L467)) and existing restaurant records intact.

### A04 — Signed authentication material has expiry, but no per-session revocation

Operator cookies contain a random session ID, but authentication only validates
signature, age and username
([waf/dashboard.py:92–99,177–192](waf/dashboard.py#L92-L99)). Logout verifies CSRF
and deletes the browser cookie, without revoking it server-side
([103–116](waf/dashboard.py#L103-L116)). A copied synthetic cookie still authorized
`GET /waf-api/settings` after local logout when restored to the test client.

Staff logout removes sessionStorage only
([admin.html:176–181](admin.html#L176-L181),
[kitchen.html:220–224](kitchen.html#L220-L224)). Tokens encode a staff ID and expire
after eight hours; current role/account existence is checked every request
([backend/server.py:154–180,202,348–350](backend/server.py#L154-L180)). No password
version or token revocation is checked. Operator password-hash replacement also
does not itself invalidate an existing correctly signed cookie with the same
username/secret. Theft is a prerequisite, not a demonstrated unauthenticated login.

Define explicit logout/password-reset/revocation semantics before adding session
state. Retain expiry, fresh role checks, CSRF and secure cookies. Browser-readable
staff tokens amplify any future same-origin XSS; switching them to cookies without
designing CSRF protection would introduce a different risk.

Legacy credential compatibility is still present: a non-KDF stored password is
compared directly and upgraded after successful verification
([backend/server.py:327–335](backend/server.py#L327-L335)). No real staff table was
inspected, so the presence of such rows is unknown. Plan an authorized inventory
and migration/rotation decision, not an automatic audit-time rewrite. Unknown-user
checks also skip the KDF ([318–325](backend/server.py#L318-L325)); any practical
username-timing signal remains potential and was not measured against production.

### A05 — Browser policy is attached to the wrong response for frontend protection

[backend/server.py:238–247](backend/server.py#L238-L247) protects API responses;
[waf/app.py:89–95](waf/app.py#L89-L95) supplies a hashed CSP for backend management
HTML. Neither controls the restaurant document returned by the separate frontend
origin. No CSP meta policy exists in the six inspected HTML files.

The local browser fixture confirmed `script-src 'self'` prevents each current
restaurant inline application script from initializing. It is not safe to add
that policy directly to the current pages and declare the deployment complete.
The public edge might supply independent headers; that was not measured.

Document-origin policy delivery, compatibility, rollout and limits are specified
below and in plan P2. This is a defense-in-depth gap, not proof of existing XSS.

### A06 — Rendering is escaped in important contexts, but remains fragile

Application JavaScript inventory: `index.html:158–362`, `admin.html:121–342`,
`kitchen.html:128–382`, `settings/settings.js:1–296`, and the generated Dashboard
script in `waf/dashboard.py:467` onward. The public Settings gateway has no script;
the authenticated Settings template loads the same external settings script.
There are no external script-CDN dependencies in these application documents.
The three tracked `.mjs` files are test tooling, not served application scripts;
the static-browser tool accepts a production URL argument and was not used for a
production check. This audit's browser fixture intercepted all requests instead.

Reviewed sinks and their current data flow:

| Surface | Evidence | Current conclusion |
| --- | --- | --- |
| Menu cards | [index.html:160–163,178–207](index.html#L160-L207) | Names/descriptions/weight/price and quoted image URL are HTML-escaped; IDs enter inline handlers and attribute names without runtime type checks |
| Cart/details controls | [index.html:218–239,313–336](index.html#L218-L239) | Text escaped or assigned via innerText; generated controls still interpolate IDs/quantities and style attributes |
| Image detail | [index.html:315](index.html#L315) | URL assignment is not HTML parsing, but relies on backend scheme validation; remote images can still track browsers |
| Admin list/search | [admin.html:193–220,298–311](admin.html#L193-L220) | Names/weight/list price escaped; search price is unescaped and IDs enter inline handlers. Current server emits integer price/ID |
| Kitchen cards/archive | [kitchen.html:236–306,340–377](kitchen.html#L236-L306) | Item text, dates and table text escaped; action handlers interpolate integer order IDs |
| Edit forms/login errors | [admin.html:164–173,324–334](admin.html#L324-L334) | `.value`/innerText assignments, not HTML interpretation |
| Settings UI | [settings/settings.js:85–112,130–187](settings/settings.js#L85-L112) | createElement/textContent; same-origin fetch; no raw-data HTML sink found |
| Dashboard JS/login template | [waf/dashboard.py:350–360,502–545](waf/dashboard.py#L502-L545) | Escaped server token and DOM textContent rendering; hashed inline script/style authorized by backend CSP |

An empty-string `innerHTML` clear or static fixed markup is not an exploitable
sink by itself. Backend validation and integer database IDs constrain the
unescaped numeric positions ([backend/server.py:119–150](backend/server.py#L119-L150),
[backend/db.py:34–44,57–72](backend/db.py#L34-L72)). Backend HTML-shaped strings can
be stored as data with the optional detector off; this does not itself execute.

Three isolated Chrome checks rendered representative HTML-shaped menu/order data
literally without executing its handler. They are representative checks, not an
exhaustive HTML/browser corpus. A malformed legacy record or compromised API
contract could still reach executable interpolation. Replace generated handlers
with event listeners and construct data-bearing DOM safely; validate received
IDs/numbers/URLs. Do not use a regex WAF as an output encoder.

### A07 — HPP and duplicate JSON need an explicit contract

WAF JSON uses ordinary `json.loads`, so duplicate object keys collapse before
inspection ([waf/parsing.py:17–35](waf/parsing.py#L17-L35)). Flask's default JSON
decoding also selects the last key in this environment. Local parsing confirmed
the earlier duplicate was discarded; no WAF/backend semantic disagreement or
authorization bypass was shown. Query `parse_qsl` preserves both duplicates
([12–14](waf/parsing.py#L12-L14)); restaurant views currently do not use query
values for data operations. Operator forms explicitly select the first parsed
value ([waf/dashboard.py:63–66,106–108](waf/dashboard.py#L63-L66)).

Strict object field sets reject unsupported fields but cannot detect a key already
discarded by decoding. Choose route-specific singleton/repeated semantics. Reject
duplicate credential/security fields before interpretation, test nested JSON and
encoded query names, and keep wire-header ambiguity as a mandatory hosting/parser
boundary. Do not advertise an HPP module that does not exist.

### A08 — Public ordering is a business-abuse surface, not a missing staff RBAC check

`POST /api/orders` intentionally has no staff decorator
([backend/server.py:393–461](backend/server.py#L393-L461)); anyone able to reach it
can submit a well-formed order for tables 1–15 using existing menu IDs. Prices,
names and totals are reconstructed from the database, so client price tampering
is constrained. CORS limits browser reads/preflights, not direct HTTP clients.

There is no table-bound proof, order idempotency or replay deduplication. Fake or
duplicate orders are therefore a potential operational problem even below the
request-rate limit. Product requirements must define whether public ordering is
intended and what confirms a table's presence. Do not silently require staff login
or call this an IDOR exploit. Existing account locks also intentionally allow
failed guesses across IPs to lock a named account: availability versus guessing
resistance needs review, not removal of mandatory production protection.

### A09 — Storage and result sizes remain resource risks

- Every logged request appends to a file without application-managed rotation
  ([waf/app.py:335–355](waf/app.py#L335-L355)). Dashboard limits retained lines but
  scans the entire file on every read
  ([waf/dashboard.py:216–231](waf/dashboard.py#L216-L231)). Policy audit rows have
  no retention task ([waf/policy.py:225–233](waf/policy.py#L225-L233)).
- Failure-counter windows reset when an identity returns, but there is no global
  pruning of abandoned expired staff-login identities in that path
  ([waf/policy.py:351–407](waf/policy.py#L351-L407)). Counter cleanup needs a policy
  that preserves active locks and escalation, rather than deleting security state
  indiscriminately.
- Orders/archive/menu use `fetchall()` with no pagination
  ([backend/server.py:277–281,463–485](backend/server.py#L463-L485)); the transport
  buffers the whole response ([waf/wsgi.py:47–51](waf/wsgi.py#L47-L51)). Request
  bounds do not bound an accumulated database's response size.
- ProtocolGuard buffers each body before optional inspection, with a 4 MiB hard
  ceiling, shared 128 total/32-per-client admission and five-second body deadline
  ([waf/protocol.py:48–51,74–91](waf/protocol.py#L74-L91),
  [waf/config.py:31–35](waf/config.py#L31-L35)). Concurrent near-limit bodies can
  consume substantial memory even while every configured limit is obeyed. No
  separate application URI-length bound is evident in this guard.
- SQLite writes on admission/counters/audit serialize. This can fail closed on
  storage errors; durable state is valuable, but finite disk, lock contention,
  shared-NAT rate limits and worker capacity need measured staging budgets.

No high-volume test, disk-fill experiment or production capacity claim was made.
Plan retention, bounded reads/responses and small controlled performance tests.

### A10 — Logging and UI semantics need another accuracy pass

- `safe_path` recognizes restaurant API paths but maps `/waf-api/blocks`, block
  IDs, `/dashboard/api/events`, `/dashboard/api/summary` and `/dashboard/api/rules`
  to `/[unrecognized]` ([waf/app.py:268–276](waf/app.py#L268-L276)). Management
  access audit consequently loses operation specificity. Block actions themselves
  still have explicit action audits.
- `/dashboard/api/rules` returns configured booleans, even when master mode is
  Disabled ([waf/dashboard.py:155–171](waf/dashboard.py#L155-L171)); its renderer
  labels them ON ([531–544](waf/dashboard.py#L531-L544)). This was confirmed on an
  isolated Disabled policy. The Settings panel instead displays INACTIVE and
  required production login state correctly
  ([settings/settings.js:148–186](settings/settings.js#L148-L186)).
- Routine `AUTH-FAIL-001` and `BOT-PROBE-001` observations are not all categorized
  in the rule catalog and can be counted as `other` under “Attack Categories”
  ([waf/dashboard.py:24–35,307–315](waf/dashboard.py#L307-L315)). A failed password
  or one 404 is an observation, not proof of an attack.
- Allowed/detected/blocked/upstream_error and policy revision are useful, but no
  correlation ID links admission, late completion and audit records
  ([waf/app.py:240–250,339–352](waf/app.py#L339-L352)). Timeout can precede a real
  synchronous Flask thread finishing; the hard transport semaphore stays held
  appropriately ([waf/wsgi.py:55–73](waf/wsgi.py#L55-L73)). Do not equate 504 with
  proof that no write occurred or retry orders blindly.

### A11 — Early deny paths bypass normal header decoration

The capacity/storage early responses are returned before `secure_send` is installed
([waf/protocol.py:49–70](waf/protocol.py#L49-L70)). A local HTTPS capacity-denied
request returned 429 without nosniff or HSTS. Trusted-proxy metadata failures return
before ASGI middleware entirely ([waf/wsgi.py:119–142](waf/wsgi.py#L119-L142)).
This is inconsistent hardening and observability, not demonstrated code execution.
Centralize safe headers across successful/error/early-denial responses without
weakening the denial; distinguish hosting errors from optional-module blocks.
Storage unavailable cannot guarantee an audit write to that same unavailable store.

### A12 — Historical verification must not be presented as current effectiveness

[waf/scripts/security_report.py:76](waf/scripts/security_report.py#L76) builds a
Policy with `False` for every field except mode, including strict integer fields.
An isolated reproduction produced **13 validation errors**. The full historical
benchmark/output-writing command was deliberately not run. Even correcting that
constructor alone would not make a production-mode optional-brute-force-OFF
benchmark valid. Existing JSON/report numbers are historical, not this audit's
measurement. Broad dependency ranges and the lack of a complete lock also mean a
fresh install may differ ([requirements.txt](requirements.txt)). `pip check`
passing establishes dependency consistency, not absence of CVEs.

Other maintenance observations: `RATELIMIT_STORAGE_URI`/Flask-Limiter dependency
remain although the central limiter uses PolicyStore; restaurant `login_attempts`
and policy `rate_windows` are legacy schema artifacts, not an active second
firewall ([backend/server.py:204](backend/server.py#L204),
[backend/db.py:25–32](backend/db.py#L25-L32),
[waf/policy.py:113–128](waf/policy.py#L113-L128)). Do not drop production tables
merely to tidy this audit.

## Backend route and enforcement matrix

`C` = SQLi/XSS/traversal/command detectors on path, query, parsed body and selected
headers; `R` = rate and optional concurrency; `B` = 404-history bot detector;
`H/S` = optional headers/size. Protocol hard limits and Flask auth/integrity remain
independent. A route's OFF baseline can legitimately be 400/401/403/404/405.

| Method / route | Consumer | Mandatory auth and data operation | Optional WAF | Evidence |
| --- | --- | --- | --- | --- |
| GET `/api/menu` | index/admin | Public; SELECT menu | C/R/B/H/S | [server:277–281](backend/server.py#L277-L281) |
| POST `/api/staff/login` | admin/kitchen | JSON credentials, password verification, signed bearer; shared account/IP login admission | C/R/B/H/S; login abuse at auth boundary | [server:283–350](backend/server.py#L283-L350) |
| POST `/api/menu/add` | admin | Admin; full validated payload; bound INSERT | C/R/B/H/S | [server:352–365](backend/server.py#L352-L365) |
| PUT `/api/menu/edit/:id` | admin | Admin; validated payload, bound UPDATE, 404 absent | C/R/B/H/S | [server:367–382](backend/server.py#L367-L382) |
| DELETE `/api/menu/delete/:id` | admin | Admin; bound DELETE, 404 absent | C/R/B/H/S | [server:384–391](backend/server.py#L384-L391) |
| POST `/api/orders` | index | Public; bounded item IDs/quantities/table; DB prices/name/total; INSERT | C/R/B/H/S | [server:393–461](backend/server.py#L393-L461) |
| GET `/api/orders` | kitchen | Admin/waiter/chef; active-order SELECT | C/R/B/H/S | [server:473–478](backend/server.py#L473-L478) |
| GET `/api/orders/archive` | kitchen | Admin/waiter; completed-order SELECT | C/R/B/H/S | [server:480–485](backend/server.py#L480-L485) |
| PUT `/api/orders/:id` | kitchen | Admin/waiter/chef; role-specific transitions and compare-and-update | C/R/B/H/S | [server:487–533](backend/server.py#L487-L533) |
| DELETE `/api/orders/:id` | kitchen | Admin/waiter; waiter pending-only; compare-and-delete | C/R/B/H/S | [server:535–549](backend/server.py#L535-L549) |
| HEAD on GET routes | HTTP clients | Flask GET semantics without response body; same role checks | C/R/B/H/S | [WAF catch-all:109](waf/app.py#L109); representative HEAD test |
| OPTIONS on API routes | Browser preflight | Automatic Flask OPTIONS; explicit CORS response, not staff data access | C/R/B/H/S | [CORS:227–235](backend/server.py#L227-L235); representative OPTIONS test |
| Unknown API / unsupported method | HTTP clients | Flask 404/405 after inspection | C/R/B/H/S | [route tests:20–34](waf/tests/test_route_coverage.py#L20-L34) |
| Implicit `/static/<path:filename>` | Flask default static handler; no backend/static assets found | Framework static directory boundary; no custom user-file reader/upload | Protected catch-all when publicly wrapped; no dedicated route fixture | [Flask creation:194](backend/server.py#L194), [catch-all:109](waf/app.py#L109) |

Role permissions are restaurant-wide. No owner/table assignment column exists
([backend/db.py:47–72](backend/db.py#L47-L72)); an authorized waiter accessing other
orders is therefore not a confirmed IDOR. If per-waiter/table tenancy becomes a
requirement, object-level checks must accompany that new model.

Bound SQL is used throughout. The variable `IN` clause constructs **placeholder
count**, not SQL from item values ([server:427–433](backend/server.py#L427-L433));
the adapter converts parameters to named bindings
([backend/db.py:125–127,174–206](backend/db.py#L174-L206)). No request-driven shell,
server URL fetch, upload handler or arbitrary file reader was found. Fixed Settings
FileResponse paths are not client-selected filesystem paths.

### Control plane: separate mandatory security, same hosting guard

| Route group | Access / purpose | Evidence |
| --- | --- | --- |
| GET `/health` | Storage liveness, public, no staff data | [waf/app.py:101–107](waf/app.py#L101-L107) |
| GET/POST `/dashboard/login` | Login-CSRF cookie/form, operator hash, fixed attempt throttle and durable lockout | [dashboard:45–101](waf/dashboard.py#L45-L101), [app:67–71](waf/app.py#L67-L71) |
| POST `/dashboard/logout` | Authenticated, signed session-bound CSRF | [dashboard:103–116](waf/dashboard.py#L103-L116) |
| GET `/dashboard` | Authenticated HTML or login redirect | [dashboard:118–123](waf/dashboard.py#L118-L123) |
| GET `/dashboard/api/summary`, `/events`, `/rules` | Operator-only sanitized telemetry/catalog | [dashboard:125–172](waf/dashboard.py#L125-L172) |
| GET `/settings`, `/settings/` | Operator-only HTML and canonical redirect | [settings_api:38–45](waf/settings_api.py#L38-L45) |
| GET `/settings/settings.js`, `/settings/settings.css` | Fixed static assets, no secrets | [settings_api:47–53](waf/settings_api.py#L47-L53) |
| GET `/waf-api/settings` | Operator-only policy, effective state and block history | [settings_api:113–121](waf/settings_api.py#L113-L121) |
| PUT `/waf-api/settings`, POST `/waf-api/settings/reset` | Operator, signed CSRF, origin/fetch-metadata checks, validated full policy/revision, audit | [settings_api:58–75,123–145](waf/settings_api.py#L123-L145) |
| POST `/waf-api/blocks`, DELETE `/waf-api/blocks/:id` | Same mutation boundary; reason/duration validation and audited unblock | [settings_api:20–32,147–163](waf/settings_api.py#L147-L163) |
| Other `/waf-api` paths/methods | Authenticate then 404; never forward | [settings_api:165–170](waf/settings_api.py#L165-L170) |

The actual Flask/WAF route inventory includes `/dashboard/api/rules`, which the
earlier route-coverage narrative omitted. The existing matrix test enumerates
Flask API methods, not every FastAPI management route or every HEAD/OPTIONS case
([waf/tests/test_route_coverage.py:155–164](waf/tests/test_route_coverage.py#L155-L164)).
Extend inventory drift checks accordingly; do not claim exhaustive wire-level tests.

## Every current toggle and enforcement mode

| Control | Block ON | OFF / Monitor | Independent boundary |
| --- | --- | --- | --- |
| SQLi | SQLI-001 score 6, threshold normally 5 | OFF skips detector; Monitor logs/forwards matches | Parameterized SQL remains |
| XSS | XSS-001 score 6 | OFF skips detector; Monitor should forward, but A01 currently throws before mode handling | Escaping/DOM construction and CSP are separate |
| Traversal | TRAV-001 score 6 | OFF skips; Monitor records | Static directory/path boundaries remain |
| Command injection | CMD-001 score 6 | OFF skips; Monitor records | No backend execution sink exists |
| Rate limiting | Global and route windows plus optional proxy leases | OFF skips these counters/admission; Monitor records excess and forwards | Protocol and hard transport capacity remain |
| Suspicious headers | HEADER-001 method-override heuristics | OFF skips heuristic; Monitor records | HTTP framing/control-byte checks remain mandatory |
| Request size | SIZE-001, effective minimum of policy/deployment cap | OFF skips optional limit; Monitor records | 4 MiB hard body and Flask 1 MiB parsing ceiling remain |
| Brute force | Shared real `/api/staff/login` account/IP failures, AUTH-001 | OFF/Disabled allowed only in explicit isolated staging; production Monitor still enforces login | Password verification and operator protection always remain |
| Bot detection | BOT-001 after recent backend 404 history | OFF skips count/check; Monitor records | Not a bot identity proof or general flood/DDoS defense |
| Event logging | JSONL decisions and revision/mode | OFF skips traffic logging; Monitor + logging OFF rejected by API | Configuration/block/unblock audit remains |
| Master mode | `block` enforces enabled optional rules | `monitor` observes; `disabled` test-only | Auth, RBAC, input integrity, protocol safeguards and production login remain |

Sources: [waf/policy.py:17–47](waf/policy.py#L17-L47),
[waf/app.py:117–250](waf/app.py#L117-L250),
[waf/enforcement.py:10–29](waf/enforcement.py#L10-L29),
[waf/settings_api.py:123–131](waf/settings_api.py#L123-L131).
Existing numeric deployment caps are returned explicitly; they can reduce a saved
threshold. There is no CSP, IDOR, CSRF, HPP, upload or SSRF ON/OFF module today.
Do not imply that adding such a checkbox is protection.

No duplicate optional Flask limiter remains. Mandatory operator throttling and
production staff admission serve different authentication boundaries. Protocol
capacity and application integrity checks intentionally survive optional OFF.
An automatic login IP lock is enforced at staff login, not public menu/order
traffic; explicit manual IP holds cover backend routes in Block mode. Management
remains accessible under its independent mandatory controls.

## Security-module applicability and gaps

| Area | Current protection | Missing / risk / applicability | Required tests |
| --- | --- | --- | --- |
| SQLi | Bound SQL plus optional normalized heuristics | Heuristics cannot prove SQL safety; broader dialect/false-positive corpus needed | Encodings/comments, benign food text, parameters bound with module OFF, every route |
| XSS | Escaping, text nodes in control plane; optional parser | A01; executable attributes; no document CSP proof | Malformed HTML, stored data to every renderer, entity/Unicode cases, no token access/execution |
| CSP | Backend API restrictive CSP; management hash policy | Public document delivery absent in source; no runtime frontend CSP switch | Actual document policy, inline handlers blocked, intended scripts/styles/images/API allowed, meta limits |
| Traversal | Optional canonical markers; fixed server paths/framework static boundary | No custom file read endpoint; literal marker is not file access | Encoded/backslash paths, no file disclosure with detector OFF, exact hosting static mappings |
| Brute force | Shared account/IP counters, escalation, expiry, manual unblock | A03/A04; intentional account-lock availability tradeoff; separate admission/outcome can overshoot with concurrent checks | Disposable admin/chef, distributed IPs, bounded parallel attempts, manual precedence, reset/logout semantics |
| Command injection | Optional executable-token heuristics; no execution sink | Finite command list (e.g. unlisted shell builtins not matched); no current command execution surface | Rule ON/OFF, literal punctuation, substitutions; prove no subprocess call rather than run commands |
| HTTP flood | Optional windows/leases; hard capacity/body/header/time bounds | App cannot stop upstream network floods; NAT aggregation, URI/response/disk limits and host capacity need budgets | Small deterministic threshold cases; separate bounded staging load test, no production flood |
| IDOR | Role lookup on each bearer request; role-specific order transitions | Restaurant-wide access is current model; no per-table/owner tenancy | Full role x operation x state matrix, absent IDs, role revocation, future ownership constraints if required |
| CSRF | Bearer header/JSON on staff API; signed CSRF and same-origin operator writes | Public orders are unauthenticated abuse, not authenticated CSRF; future cookie auth changes threat model | Missing/foreign/replayed-session CSRF, hostile Origin/preflight, simple form/text content rejected; no disabling core CSRF |
| HPP | All query pairs inspected; duplicate sensitive headers rejected as visible to ASGI | A07; JSON last-wins, operator forms first-wins; no explicit route ambiguity contract | Duplicate/encoded names, nested duplicate JSON, form repetitions, raw parser framing in isolated harness |
| Malicious upload | No upload/processing route; API JSON requirements reject multipart | Not an active upload surface; multipart WAF inspection is not antivirus | 415/no file creation for file bodies, hard size bounds; only if a real upload feature is approved: MIME/signature/storage/execution tests |
| SSRF | No request-driven server fetch; protected transport forced in-process; image URL syntax/literal-local checks | Browser image privacy/DNS/redirect restrictions are not server SSRF; future URL fetching would need egress controls | Assert no outbound connection on real WSGI; URL schemes/private literals; future redirects/DNS tests use stub resolvers/transport |
| Bot detection | Counts recent 404 responses, not User-Agent | Normal missing paths can count; valid-route bots not identified; no distributed bot proof | 404 threshold/expiry/OFF, benign missing favicon, monitor labels, valid-route limits independently |

## Frontend CSP delivery and infrastructure assessment

### What can actually protect the public HTML

1. **Keep GitHub Pages and use an early meta CSP after refactoring.** This is a
   source-controlled static policy, not a live backend toggle. It can restrict
   scripts, handlers, images and API connections. It cannot provide HTTP-only
   frame-ancestor protection or Report-Only delivery. A fresh static nonce would
   not be a per-response unpredictable nonce; prefer external assets or generated
   hashes for unavoidable static blocks. The CSP3 specification documents these
   delivery limitations ([W3C CSP3 §3.3](https://www.w3.org/TR/CSP3/#meta-element)).
2. **Use a verified header-capable edge in front of the public origin**, or serve
   frontend documents from an approved managed application host. This can provide
   header CSP, frame protection and staged Report-Only. It requires a separate
   infrastructure/deployment decision; none was made here. A backend header alone
   or adding a `_headers` file without an actual consuming host is not delivery.
3. **Do not label the frontend protected until the document itself proves it.**
   Browser policy must accompany the HTML, with resource inventory and functional
   checks. GitHub documents Pages as static hosting, not Flask execution
   ([GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)).
   No configurable public response-header layer is established by this repository.

Changing scripts alone is insufficient: dynamic inline `onclick` strings and
static/generated style attributes also require work. Hashing one script block
does not authorize its inline event attributes. Replace those with event listeners
([MDN script-src-attr](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src-attr)).
Inventory from actual HTML parsing, excluding attributes inside JS template strings:

| File | Inline scripts | Style blocks | Literal event attributes | Literal style attributes | CSP meta |
| --- | ---: | ---: | ---: | ---: | ---: |
| index.html | 1 | 1 | 13 | 0 | 0 |
| admin.html | 1 | 1 | 7 | 2 | 0 |
| kitchen.html | 1 | 1 | 4 | 0 | 0 |
| settings/index.html | 0 | 0 | 0 | 0 | 0 |
| dashboard/index.html | 0 | 1 | 0 | 0 | 0 |
| waf/templates/settings.html | 0 | 0 | 0 | 0 | 0 |

The static Dashboard gateway's inline style also needs externalization or its own
hash. System fonts do not need an external font CDN. Image URLs are currently
admin-selected HTTP/HTTPS, not a strict approved-origin list. A future restrictive
`img-src` requires inventory and an explicit decision about existing images;
neither this audit nor the plan automatically rewrites menu records.

### Infrastructure controls and deployment gates

- **PythonAnywhere:** the template enables X-Real-IP trust only for that provider
  ([deploy/pythonanywhere_wsgi.py.example:19–36](deploy/pythonanywhere_wsgi.py.example#L19-L36)).
  Its documentation identifies X-Real-IP as load-balancer metadata and warns
  against trusting an arbitrary X-Forwarded-For chain
  ([provider guidance](https://help.pythonanywhere.com/pages/WebAppClientIPAddresses)).
  Live overwrite behavior, HTTPS WSGI scheme, app export and absence of shadowing
  static mappings remain deployment checks. The code's `http`/`https` validity
  check does not prove the production scheme is correct.
- **Static mappings:** PythonAnywhere can serve mapped files outside the web
  framework ([static-file guidance](https://help.pythonanywhere.com/pages/StaticFiles/)).
  Mapping `/api`, `/settings`, `/dashboard`, policy/runtime directories or the
  checkout broadly could bypass guards or expose files. No live mapping was read.
- **Generic proxies:** [waf/wsgi.py:132–144](waf/wsgi.py#L132-L144) only trusts exact
  configured peers, requires one IP and a valid scheme, and rejects chains. The
  immediate upstream must overwrite headers and preserve Host. No application
  trusted-host allowlist is configured; assess any Host/absolute-redirect impact
  with the actual edge rather than declaring a proven Host-header exploit.
- **CORS:** exact configured origins, Content-Type/Authorization and limited
  methods are defined in [backend/server.py:224–235](backend/server.py#L224-L235).
  No credentialed cross-origin cookie mode is enabled there. Production values
  are unknown. CORS is not an authentication/flood firewall.
- **Headers:** API and management headers are valuable but origin-scoped; A11
  covers exceptions. Public HSTS/frame/nosniff/referrer headers are unverified.
  Never infer public HTML headers from an API response.
- **Persistence:** stable external policy paths, backups, permissions, finite log
  retention and same-host worker visibility are required. SQLite corruption fails
  closed; accidental path changes can create a fresh store. Application import
  calls schema initialization/seeds an empty menu
  ([backend/server.py:78–80,606–611](backend/server.py#L606-L611)), so even an audit
  import must use disposable paths. The example explicitly checks the existing DB.
- **Docker:** Compose has one protected application and private PostgreSQL with
  named volumes ([docker-compose.yml:19–60](docker-compose.yml#L19-L60)); startup
  can run migrations. Its CLI uses Werkzeug `run_simple`
  ([backend/run.py:3–12](backend/run.py#L3-L12)), suitable for local staging, not
  public production ([Flask deployment guidance](https://flask.palletsprojects.com/en/stable/deploying/)).
  Docker/PostgreSQL runtime was not tested here. Do not run Compose against live
  volumes to validate this documentation.
- **Release provenance:** no tracked `.github` workflow was found, but repository
  Pages settings/webhooks and the installed production SHA were not inspected.
  A `dev` documentation push is not proof of frontend or backend deployment.

## Checks performed and reproducibility

| Check | Actual result |
| --- | --- |
| Full existing backend/WAF pytest suite | **278 passed**, 0 failures/errors/skips, **220.88 s** |
| Additional disposable audit probes | **7 passed**, **8.62 s**; they assert current findings, not fixed behavior |
| Existing Node management-route tests | **4 passed**, 0 failed |
| Isolated Chrome audit | **6 checks passed**: literal rendering and strict-CSP incompatibility on three pages; **11 page/resource/API requests intercepted locally, zero forwarded** |
| Python syntax | 37 maintained source files parsed successfully |
| JavaScript syntax | index/admin/kitchen inline scripts, Settings JS, existing browser harness and generated Dashboard script passed |
| `pip check` | No broken requirements; not a vulnerability-advisory scan |
| Historical benchmark constructor | 13 Policy validation errors reproduced without executing benchmark/output updates |
| Production requests, load/flood tests, live header probes | **Not performed** |

Baseline commands, from repository root, in a shell with no production DB/policy
variables inherited:

```powershell
$env:DATABASE_URL=''; $env:WAF_POLICY_PATH=''; $env:WAF_TRUSTED_PROXY_IPS=''
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/audit-tests.xml
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
.\.venv\Scripts\python.exe -m pip check
```

Additional audit harnesses are **ignored local artifacts**, not new product pages:
`waf/local/audit_probes.py`, `waf/local/audit_frontend.mjs`, and JUnit files
`audit-tests.xml`/`audit-probes.xml`. They are excluded from the documentation commit.
The probe cases are described in A01–A04/A07/A10/A11; the browser fixture fulfills
every page/API/image request locally and never submits real staff credentials.
Representative successful escaping does not prove every renderer/type combination.
For durable regression cases to add in the next implementation, see plan P1–P7.

Limitations: no production topology confirmation, raw managed-edge smuggling test,
container build, real PostgreSQL concurrency test, dependency-CVE advisory scan,
large-scale bot/flood test, exhaustive browser corpus or proof of absence of other
vulnerabilities. Runtime data, secrets, schemas, application source and deployment
settings remain unchanged by this audit commit.
