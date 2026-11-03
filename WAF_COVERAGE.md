# Centralized WAF coverage

Combined release readiness and measurable activation gates:
[RELEASE_PROCEDURE.md](RELEASE_PROCEDURE.md),
[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md). Coverage is not established on
production until the protected documents and API are actually activated/verified.

Current architecture on `dev`. See [SETTINGS_DEPLOYMENT.md](SETTINGS_DEPLOYMENT.md)
for configuration and manual deployment. Earlier phase reports are historical.
No restaurant database migration is part of this change.

Current XSS/input regression status: [XSS_FIX_VERIFICATION.md](XSS_FIX_VERIFICATION.md).
Malformed HTML marked sections are handled by the existing optional XSS detector:
Block denies, Monitor records/forwards, OFF does not call it. Invalid Unicode/JSON
remains mandatory PARSE-001 validation. Payload integers and URL IDs are bounded
before conversion. Restaurant output uses DOM text/nodes independently of policy;
customer order item payloads contain IDs/quantities, not stored menu markup.
CSP now uses the same PolicyStore for WAF-served HTML. See
[CSP_DEPLOYMENT.md](CSP_DEPLOYMENT.md) for modes, document/route coverage,
opt-in frontend hosting, reporting and manual Pages migration. Backend headers
still do not protect existing GitHub Pages restaurant documents.

## Request pipeline and audit

```text
Managed WSGI server (verified client IP/scheme)
  -> ProtectedWSGI
  -> ProtocolGuard: framing and hard size/time/capacity ceilings
  -> one policy snapshot
  -> management authentication/audit OR opt-in fixed frontend OR restaurant proxy
  -> proxy inspection, rate/concurrency and bot checks
  -> InProcessTransport: trusted Python environment handoff, no network forwarding
  -> Flask: protected-entry check, authentication and application validation
  -> login_guard: shared account/IP admission and credential outcome
  -> WAF: outcome logging and response; snapshot-derived CSP on served HTML
```

`ProtectedWSGI` replaces the upstream with the actual Flask callable. Forwarding
headers are sanitized. The policy, revision and store reach authentication in an
internal Python object, never a client header. Authentication uses the admitted
snapshot even if another worker changes settings during a request. The next
request sees the committed revision. There is no second optional Flask firewall.
Raw production Flask API requests return 503; application unit tests explicitly
use Flask `TESTING`. Production must leave `TESTING` false.

The audit found and corrected:

- HEAD stopped at FastAPI instead of sharing Flask's inspected route.
- Standalone Flask rate limiting duplicated a subset of WAF enforcement.
- Login reread policy after WAF admission, allowing two revisions per request.
- Automatic login IP locks also denied public menu/order traffic.
- Monitor detections and staff lockouts were labeled `allowed` in traffic logs.
- Demo login used a second persistent policy and synthetic endpoint. Its routes,
  navigation, script and template are removed. Existing `*-demo.sqlite3` files are
  left untouched and unused.
- Docker had a separate proxy and raw Flask service. The prepared topology now
  runs the same single protected WSGI application.

## Route matrix

**C** = SQLi, XSS, traversal and command injection across decoded path, query,
parsed body fields and selected textual headers. **R** = per-IP/per-route rate
and optional concurrency. **B** = missing-route probe detection. **S/H** = optional
size and suspicious headers. All listed routes have C/R/B/S/H coverage. Bot
history uses actual backend 404 outcomes, independently of User-Agent labels.

| Method and route | Frontend consumer | Mandatory application boundary | Optional modules | WSGI ON/OFF tests |
| --- | --- | --- | --- | --- |
| GET `/api/menu` | index, admin | Public parameterized read | C/R/B/S/H | Yes |
| POST `/api/orders` | index | Schema, table/item/quantity bounds, server prices | C/R/B/S/H | Yes |
| POST `/api/staff/login` | admin, kitchen | Password verification, signed token, shared account/IP admission | C/R/B/S/H + login abuse | Yes, disposable admin and chef |
| POST `/api/menu/add` | admin | Admin role, bounded menu fields, safe image URL | C/R/B/S/H | Yes |
| PUT `/api/menu/edit/:id` | admin | Admin, validated fields, existing record | C/R/B/S/H | Yes |
| DELETE `/api/menu/delete/:id` | admin | Admin, existing record | C/R/B/S/H | Yes |
| GET `/api/orders` | kitchen | Admin, waiter or chef | C/R/B/S/H | Yes |
| GET `/api/orders/archive` | kitchen | Admin or waiter | C/R/B/S/H | Yes |
| PUT `/api/orders/:id` | kitchen | Role-specific transitions, atomic stale-state check | C/R/B/S/H | Yes |
| DELETE `/api/orders/:id` | kitchen | Admin or waiter; waiter pending-only; stale-state check | C/R/B/S/H | Yes |
| HEAD `/api/menu` | HTTP clients | GET semantics, no response body | C/R/B/S/H | Yes |
| OPTIONS `/api/menu` | Representative CORS preflight | Existing explicit origin/method/header policy | C/R/B/S/H | Yes |
| GET `/api/unknown` | Unknown-route probe | Flask 404 | C/R/B/S/H | Yes |
| PATCH `/api/menu` | Unsupported-method probe | Flask 405 | C/R/B/S/H | Yes |

Flask's automatic HEAD/OPTIONS for other routes use the same catch-all.
`test_matrix_covers_all_flask_rules_and_methods` fails if a new restaurant API
method lacks a matrix case. Query probes replay on every method using disposable
admin tokens. Mutations deliberately use invalid schemas or nonexistent IDs,
avoiding stored attack strings. Existing WSGI workflow tests separately verify
real orders, calculated totals, roles and archive behavior. Focused security tests
cover parsed bodies and encoded variants.

## Control plane and hosting boundaries

These routes use mandatory management security, independently of restaurant
switches, so policy changes and unblock remain available during an incident.

| Route | Boundary |
| --- | --- |
| GET `/health` | Policy storage health; no credentials or restaurant data |
| GET/POST `/dashboard/login` | Operator password/CSRF; fixed attempt cap and durable account/IP lockout |
| POST `/dashboard/logout` | Operator session and CSRF |
| GET `/dashboard` | Operator session; anonymous redirect |
| GET `/dashboard/api/events`, `/dashboard/api/summary` | Operator session, sanitized records and decision filters |
| GET `/settings`, `/settings/` | Operator session, canonical redirect |
| GET `/settings/settings.js`, `/settings/settings.css` | Static assets, no secrets |
| GET `/waf-api/settings` | Operator session, policy/effective limits/blocks/history |
| PUT `/waf-api/settings` | Operator session, signed session-bound CSRF, same origin, complete validated policy, revision check, audit |
| POST `/waf-api/settings/reset` | Same mutation boundary and audit |
| POST `/waf-api/blocks` | Same boundary; finite-duration IP/account hold and reason |
| DELETE `/waf-api/blocks/:id` | Same boundary; audited actor and prior block details |
| Other `/waf-api` paths/methods | Authenticate then 404; never forward to Flask |
| Removed `/settings/demo*` | No handler; inspected backend 404 |

ProtocolGuard precedes both dispatch paths. Framing, duplicate sensitive headers,
unsupported encoding, hard body/header bounds, read timeouts and hard capacity
remain active with optional modules off. Flask retains its 1 MiB body-parsing
ceiling, input validation, roles, token expiry, parameterized SQL and security
headers. Safe restaurant DOM rendering remains mandatory. Settings reports both WAF and
backend body ceilings.

## Traffic and audit decisions

Backend JSONL records include UTC timestamp, verified IP, safe route template,
method, query-present flag, content length, rule IDs, risk score, HTTP status,
policy revision/mode and enforcement source.

- `allowed`: WAF forwarded without an enabled match. A 400/401/403/404/405 can
  still be an application validation/authentication response.
- `detected`: WAF forwarded and recorded a match: monitor detections, failed
  credentials or missing-route observations.
- `blocked`: optional Block-mode denial, staff admission denial, manual hold or
  mandatory protocol/policy safeguard. Rule IDs identify the cause.
- `upstream_error`: transport failure/deadline, not a detector decision.

The failure reaching a login threshold remains a credential failure (401) and
creates a lock. Later attempts receive 429 and Retry-After. `AUTH-FAIL-001` records
failed credentials; `AUTH-001` records threshold/admission. Isolated OFF suppresses
these optional detections/counters; bad passwords still return 401.

Configuration and block/unblock audit stays durable with traffic logging off.
Bodies, passwords, bearer/session tokens, raw query values and arbitrary path
payloads are excluded from traffic logs. Account views are masked and counter
keys hashed. The host must protect runtime files and manage retention. Detection
is heuristic and does not replace application input/authorization boundaries.
