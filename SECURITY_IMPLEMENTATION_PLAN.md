# Chillibek WAF security implementation plan

Implementation status: the earlier XSS/input stage is recorded in
[XSS_FIX_VERIFICATION.md](XSS_FIX_VERIFICATION.md). Subsequent P2/P3 CSP delivery
work is recorded in [CSP_DEPLOYMENT.md](CSP_DEPLOYMENT.md) and
[CSP_VERIFICATION.md](CSP_VERIFICATION.md). The original plan below is historical;
production migration and live coverage verification remain manual requirements.

Prepared **2026-11-03**, against source baseline
**`b27aa6a76a6163fe37d34128bcb7a80466039e54`** on `dev`.
This document plans future work; **no listed fix, feature, production configuration
change or deployment was performed**. Findings, exact source evidence and current
test results are in [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

## Scope and decision rules

1. Extend the existing protected WSGI pipeline and PolicyStore. Do not introduce
   another firewall, Demo Lab, public attack endpoint or separate policy sandbox
   service. Tests use private fixtures and disposable data.
2. Fix confirmed errors before adding new detection categories. A regex match is
   evidence of a heuristic, not proof of exploitability. A new switch is not a
   security feature unless its real enforcement path and limitations are verified.
3. Authentication, RBAC, password checks, SQL parameterization, safe rendering,
   input integrity, management CSRF, audit and hosting bounds remain mandatory.
   Optional OFF must not disable them or be advertised as doing so.
4. Production staff credentials must never become an unrestricted guessing target.
   Keep the current production guard requirement, including Monitor. Experimental
   OFF behavior belongs only in explicit isolated staging with disposable accounts.
5. Preserve menu, orders, staff, secret keys and existing database/policy paths.
   No table cleanup, migration, password reset, data rewrite or image URL rewrite
   is implicit in a code fix. Any necessary future migration needs a separate,
   reviewed data-preservation and rollback plan.
6. Keep implementation PRs small enough to review. Acceptance below is required
   evidence before a separate deployment decision; it does not authorize rollout.

## Priorities and dependencies

| Priority / task | Findings | Deliverable and dependency | Acceptance gate |
| --- | --- | --- | --- |
| **P1a — first task: contain request parser failures** | A01, A02 | Small patch and real WSGI regressions; no new module | Malformed HTML/numeric inputs never create uncaught 500s; valid traffic and all modes preserved |
| **P1b — preserve manual login holds** | A03 | Atomic state transition rule and race regressions | Late outcomes never shorten/remove a manual hold; unblock remains audited |
| **P2 — frontend rendering/CSP readiness** | A05, A06 | Safe DOM/event handling, external assets, resource contract; starts after P1a | Existing restaurant flows work; strict local browser policy is compatible and blocks injected execution |
| **P3 — actual frontend CSP delivery** | A05 | Choose meta or approved header delivery after P2 | Policy accompanies the public document; truthful scope/status; manual staging review |
| **P4 — auth lifecycle and abuse requirements** | A04, A08 | Revocation design; public ordering/replay and lockout availability decision | Defined logout/reset semantics and business rules; production guessing remains bounded |
| **P5 — request ambiguity contract** | A07 | Singleton/repeated field rules at existing boundaries | Duplicate security fields rejected deterministically; benign repeated fields explicitly supported where applicable |
| **P6 — truthful telemetry and finite resources** | A09, A10, A11 | Header finalization, route/rule catalog, retention, bounded read/response plan | All response paths accounted for; no misleading effective state; retention preserves required audits |
| **P7 — reproducible verification and staging release** | A12, infrastructure gates | Repair benchmark, dependency snapshot, complete inventories, approved host checks | Current reproducible artifacts; no production-effectiveness claim from a small corpus |

Severity and scheduling differ: A01 is Medium but is the first task because it is
an unauthenticated, small-input failure in an enabled security control. A05 is a
larger architecture change and must not be rushed by adding a breaking CSP header.
No Critical/High exploit was confirmed in this audit; an unverified production
deployment cannot be rated safe or vulnerable solely from this source baseline.

## P1a — recommended first implementation task

**Problem:** [waf/rules.py:95–99](waf/rules.py#L95-L99) can raise on malformed HTML;
[backend/server.py:105–116](backend/server.py#L105-L116) can raise converting a long
numeric string. Local current behavior is documented in audit A01/A02.

Implementation requirements:

- Handle specific expected HTML parser/input failures at the existing inspection
  boundary. Define whether malformed inspection input produces a sanitized
  validation denial or a detector result; distinguish it from programming errors.
- Preserve optional semantics: XSS OFF skips the optional parser; Monitor logs
  detections and forwards otherwise valid traffic. Mandatory invalid JSON/framing
  handling must not be disguised as optional XSS enforcement.
- Validate numeric representation length/range before conversion and handle
  expected conversion errors as 400. Include large route IDs and all integer
  payload fields in the review. Retain Python's conversion safety limits.
- Ensure a sanitized event exists for the chosen failure path, with actual status,
  policy revision, safe route and correct enforcement source. Do not log rejected
  bodies, exception messages containing input, secrets or tokens.

Acceptance criteria:

1. Add regression cases through `protect_wsgi(real_flask_app)`, with
   `TESTING=False`, temporary restaurant/policy/log files and disposable staff.
2. Test `<![audit]>`, incomplete marked sections, malformed HTML declarations,
   ordinary less-than text, valid CDATA-like text and oversized numeric strings.
   Test both query and appropriate JSON string positions.
3. The first malformed-HTML example no longer returns an uncaught 500. Document
   exact expected Block/Monitor/OFF behavior before asserting it. OFF must not
   call the optional HTML parser. Numeric representation overflow returns 400
   independently of optional detector switches, and commits no order/menu change.
4. Existing 278 regression cases remain green, plus the new cases; Python/JS
   results, failures/skips and relevant browser behavior are reported accurately.
5. No live route is used as a test target. No dependency, schema, production
   settings or restaurant-record change is required for this task.

## P1b — manual block and authentication outcome invariants

Keep the single PolicyStore. Within its transaction, preserve active manual state
when recording an outcome from a request admitted earlier. Automatic failure
counting must not replace a manual row or reset its duration/reason/actor history.
Define precedence when an automatic block exists and an operator adds a hold.
Avoid using a blanket database replacement operation to resolve these cases.

Required tests:

- Admit a request, create a 3,600-second synthetic account/IP hold, then finish a
  failed password check at threshold. The manual hold remains manual with its
  original expiry and reason. Test the reverse operation order as well.
- Use barriers in a bounded concurrent fixture to verify actual ordering, not
  sleeps against live credentials. Test success/failure/expiry/policy-change races.
- Check account/IP thresholds, escalation, restart visibility and current policy
  snapshot semantics. Document bounded in-flight overshoot rather than promising
  exactly N password checks under unrestricted parallelism.
- Require operator authentication, same origin and CSRF for unblock; assert actor,
  identity masking and cleared intended counters. Unblocking one identity must
  not silently clear a different independent hold.

Acceptance: no manual hold is weakened by late automatic outcomes; monitoring and
isolated OFF semantics remain honest; restaurant records are unchanged.

## P2 — prepare the public frontend for browser policy

The actual rendering evidence is in audit A06. Do not label all `innerHTML` calls
vulnerabilities: fixed markup/empty clears and correctly escaped text have different
risks from executable attribute interpolation.

Implementation requirements:

- Externalize application scripts in index/admin/kitchen, and move static/generated
  inline event handlers to `addEventListener` or delegated handlers. Use stable
  DOM/data attributes containing validated IDs, not string-built JavaScript.
- Build data-bearing elements with DOM APIs/textContent. Validate API response
  shape and finite safe integer IDs/prices/quantities before rendering or routing.
  Preserve backend validation as the mandatory trust boundary.
- Keep image scheme/origin decisions separate from HTML escaping. Propose an image
  origin contract covering existing menu assets and future admin inputs. Do not
  silently replace stored image URLs or claim browser images are server SSRF.
- Externalize style blocks/attributes or maintain justified static hashes. Review
  generated styles and direct style-property changes in real browsers; avoid a
  blanket `unsafe-inline` exception just to make the page appear functional.
- Keep staff token storage and error text free of HTML interpretation; document
  that sessionStorage is accessible to same-origin script. Do not switch to cookie
  authentication as an incidental frontend refactor.
- Include the public Settings and Dashboard gateways in the resource inventory.
  Keep the authenticated control panel's working hash/external-asset policy intact.

Acceptance criteria:

1. Under a local strict policy, menu/category/detail/cart/order flows work; admin
   search/add/edit/delete work against disposable data; waiter/chef transitions,
   timers, archive, login/logout and expired-token behavior work as designed.
2. Representative malicious names/descriptions/table/item strings render literally
   across cards, cart, search, details and archive; no handler executes, no
   script-created request escapes the fixture, no bearer token is exposed.
3. Malformed response IDs/prices/types fail safely without creating executable
   handler attributes, arbitrary URL requests or unexpected state changes.
4. Verify narrow and desktop layouts, keyboard/events and allowed image/API loads.
   Use a browser harness that intercepts **all** requests before navigation, so
   copying production API URLs from source cannot accidentally contact production.
5. Store-versus-render tests use temporary records only. The frontend remains
   correct with the optional WAF XSS detector OFF; output safety is mandatory.

## P3 — choose real CSP delivery before adding any CSP control

CSP must govern the **HTML document's execution context**, not merely the JSON
response it fetches. Backend management CSP is already a separate working scope.

| Option | Can provide | Limitations and decision gate |
| --- | --- | --- |
| GitHub Pages HTML meta policy | Static script/resource restrictions after refactor | Early placement; no Report-Only meta, no frame-ancestors/report-uri/sandbox via meta; build/release required for a change |
| Approved header-capable edge for public origin | Header CSP, frame protection and Report-Only rollout | Actual host/edge must consume the configuration; DNS/header delivery and rollback need explicit approval |
| Approved host serving the frontend documents | Per-response policy/nonce integration when correctly designed | Hosting/routing/cookie/origin changes need review; do not add a second WAF to accomplish this |

GitHub Pages is static hosting ([GitHub documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages)).
Meta policy has specific delivery limits ([CSP3 §3.3](https://www.w3.org/TR/CSP3/#meta-element)).
Hashes/nonces for script elements do not automatically authorize inline handlers;
external listeners avoid that compatibility problem
([MDN script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src)).
Static reusable nonces are not unpredictable per-response authorization.

An illustrative policy **only after P2 and image inventory**, not a deployment command:

```text
default-src 'none'; base-uri 'none'; object-src 'none';
script-src 'self'; script-src-attr 'none';
style-src 'self'; style-src-attr 'none';
img-src 'self' https://images.unsplash.com data:;
connect-src https://kali.pythonanywhere.com;
form-action 'self'
```

This example deliberately does not promise that all current admin-selected image
origins will work. `data:` is relevant to the current decorative SVG background;
its necessity should be reassessed after external CSS changes. A header-delivered
version can additionally specify `frame-ancestors 'none'`. Do not place that
directive in meta and claim framing protection. Confirm hashes across actual
build bytes if retaining inline blocks. Inventory every permitted resource rather
than broadening to `https:` or wildcard scripts to silence console errors.

Acceptance criteria:

- Local browser tests show the policy on the document, legitimate functionality,
  forbidden inline execution/resource attempts, and permitted image/API traffic.
- If using headers, stage Report-Only first, inspect sanitized observations, then
  propose enforcement. If using meta, test enforcement on isolated pages; do not
  invent a meta Report-Only phase. Source placement precedes governed resources.
- CSP reporting, if proposed, uses bounded rate/body/storage, redaction and no
  credential samples. It must not become an unauthenticated log-amplification API.
- A backend “CSP ON” switch must not claim public frontend coverage unless a real,
  authenticated, verified document/edge delivery path exists. Static meta requires
  a release, not PolicyStore hot reload. Prefer clear scope/build status over a
  misleading runtime checkbox. Browser security can remain mandatory hardening,
  separate from the optional request XSS detector.
- Final production header/document validation is a **later authorized deployment
  task**, not part of this audit or a reason to probe the current live frontend.

## P4 — authentication lifecycle and business-abuse decisions

Specify the intended lifecycle before implementing revocation: operator logout,
password changes, staff password reset, staff deletion/role changes, stolen-token
response and session expiry. Decide between server-tracked session IDs/token
versions and shorter lifetime plus explicitly documented residual validity. Do not
represent browser deletion as server revocation. Existing staff deletion/current
role checks should remain effective immediately.

Acceptance tests must copy a synthetic session/token, logout/reset/change role in
disposable state, replay the old material, and assert the newly documented result.
If revocation is promised, old material must fail. Secret rotation is a broad
emergency invalidation, not a normal logout API. Keep secure/HttpOnly/SameSite
operator cookies, CSRF and eight-hour expiry until a reviewed policy replaces them.

For public orders, obtain a product decision: intentionally open ordering versus
table-bound access, acceptable duplicate/retry behavior, cancellation rights and
staff scope. If table proof/idempotency is selected, design it in the existing
application with bounded replay state; use authorized disposable fixtures. Staff
RBAC must not be silently attached to the public customer flow. A WAF IP limit or
bot label cannot establish table presence. A timeout must not cause a blind order
retry when an in-process write may have finished later.

Account-lockout review must preserve production guessing resistance. Test targeted
lock availability, recovery, IP/account distribution, spoofed metadata rejection
and manual override using synthetic accounts. No live credential guessing and no
new always-active hidden throttle that contradicts a displayed optional switch.

## P5 — define HTTP parameter ambiguity and applicability

- Reject duplicate security-relevant JSON keys before losing them to decoding;
  document nested-object behavior and align WAF/application parsers.
- Treat credentials, CSRF and singleton mutation fields as single-valued. Specify
  repeated query/form semantics before adding filters that consume them.
- Test duplicate/encoded field names, query/body collisions, mixed content types,
  duplicate Authorization/Cookie/Content-Length/Content-Type, and parser limits.
  WSGI tests cover the real application path; raw framing tests need a private
  parser harness because WSGI cannot observe discarded wire headers.
- No upload or request-driven server fetch surface exists today. Preserve JSON
  requirements, fixed file paths and in-process transport. Do not build speculative
  antivirus/SSRF modules to claim coverage of nonexistent processing features.
  If approved future features add these sinks, threat-model validation, egress,
  redirects/DNS, storage, MIME/signatures and execution boundaries first.
- Authorization/CSRF/HPP input integrity should have clear mandatory boundaries.
  Do not add an OFF switch that permits privilege bypass or ambiguous credentials.

## P6 — telemetry, response hardening and resource budgets

Implement effective state separately from configured intent. The catalog should
report configured, active and enforcing states, mandatory production exceptions,
and the policy revision. Manual holds and hosting ceilings must have explicit
scope. In Disabled staging, a configured detector must not be displayed simply ON.

Add safe templates for **all** control-plane operations and a route inventory
check that includes `/dashboard/api/rules`, assets, redirects, HEAD/OPTIONS and
namespace fallbacks. Never solve missing templates by logging arbitrary raw URIs.
Distinguish ordinary failed credentials/404s from threshold detections and confirmed
blocks. Add a correlation ID if needed for late transport outcomes; never treat
a request timeout as evidence that an order was not committed.

Ensure security headers apply to 2xx/3xx/4xx/5xx, early capacity/proxy/storage denies
and handler errors at the appropriate document origin. Errors stay sanitized and
fail closed. An unavailable policy/audit store cannot guarantee a write to itself;
specify an operational alert/fallback rather than promising impossible audit durability.

Define log rotation/retention, bounded tail reads, file permissions, disk alerts,
audit backup/retention, expired-counter cleanup and safe event schemas. Counter
cleanup must preserve active blocks and the documented escalation window.
Add pagination or bounded result
contracts for growing lists, with compatible frontend changes. Separate request,
URI, response, DB connection, body-memory and concurrency budgets. Measure small
staging scenarios with explicit stop conditions; do not saturate production or
fill any disk to prove a limit. Preserve cross-worker durability and avoid a
second counter store that disagrees with the existing switches.

## Safe ON/OFF verification matrix

All cases below use the same protected WSGI pipeline, temporary databases/logs,
synthetic staff and controlled client IPs. Establish the route's normal application
status first. OFF means no enforcement by **that optional detector**, not successful
authentication or accepted invalid data. Reset state deliberately between cases;
test suspension/resumption of unexpired automatic locks without deleting evidence.

| Control / area | Safe fixture | ON/Block expectation | OFF / Monitor and mandatory expectation |
| --- | --- | --- | --- |
| SQLi | Inert query marker such as `' OR 1=1 --` on every matrix method | 403 with SQLI-001 | OFF reaches baseline; Monitor records/forwards; bound SQL never turns marker into SQL |
| XSS | Inert `<script>audit()</script>` string; never executed; malformed `<![audit]>` for P1a | Known detector blocks; malformed case has defined non-500 handling | OFF skips optional parser; Monitor records without optional denial; rendering never executes stored fixture strings |
| Traversal | `../../audit-missing` in query; no actual file reads | Detector-specific result | OFF still cannot read outside any allowed static directory; fixed paths unchanged |
| Command injection | Literal `x; whoami` string, no subprocess mock execution | CMD-001 result | OFF passes literal to baseline validation; assert no execution sink/call |
| Rate / HTTP bursts | Limit 2 in fixture; 3 sequential harmless reads | Third denied with RATE-001 | OFF bypasses optional counters; Monitor records; hard capacity still independently bounded/labeled |
| Optional concurrency | Small barrier-controlled private requests | Optional lease threshold observed | OFF does not acquire optional leases; hard transport capacity remains; always release/drain fixtures |
| Header heuristic | X-HTTP-Method-Override on a benign route | HEADER-001 | OFF reaches baseline; malformed framing remains mandatory HTTP-001 regardless |
| Body size | Harmless JSON plus padding around a small fixture threshold | SIZE-001 at optional threshold | OFF/Monitor retain hard transport and Flask parser ceilings, reported distinctly |
| Brute force | Disposable admin/chef, threshold 2, test clock; bounded attempts from controlled IPs | Failure threshold followed by 429/Retry-After; audited recovery | OFF only in isolated staging; Monitor observes there; production disallows OFF and enforces staff admission in Monitor |
| Bot detection | Two private nonexistent paths, then benign read | BOT-001 at configured threshold | OFF skips history/check; Monitor records; ordinary single 404 is not labeled a proven bot |
| Traffic logging | One allowed/detected/blocked request with synthetic secrets | Accurate redacted events/revision/status | OFF suppresses traffic file updates only; configuration/unblock audit remains; Monitor+logging OFF rejected |
| Master modes | One benign case and each detector case, isolated mode changes | Block enforces enabled optional rules | Monitor records; Disabled test-only; auth/RBAC/input/protocol boundaries remain |
| CSP | Intercepted local documents/resources; sentinel execution variable | Under delivered enforcing policy, unauthorized script/handler cannot set sentinel | Compare policy absent/Report-Only only on isolated fixture; escaping/auth still hold; no fake runtime frontend toggle |
| IDOR/RBAC | Two disposable staff identities per role and orders in each state | Forbidden operations always 401/403 | No permissive OFF state; object-scope tests depend on approved tenancy requirement |
| CSRF | Missing, wrong-session and foreign-origin mutation tokens | Denied on management regardless of mode | No permissive OFF; bearer-only staff API retains explicit auth/JSON/CORS contract |
| HPP | Repeated singleton JSON/form/query keys with harmless values | Defined mandatory rejection/normalization contract after P5 | No toggle permits ambiguous credentials; confirm current benign repeated semantics where explicitly supported |
| Uploads | Tiny inert multipart file, no executable content or disk writes | API rejects unsupported type; no file created | Remains rejected with optional content modules OFF; future upload capability requires its own approved tests |
| SSRF | Stubbed transport/DNS; fake URLs and local-IP literals, no outbound connection | No request-driven server fetch | OFF cannot create a fetch sink; browser-image policy tested with intercepted requests |

Existing route tests cover four content categories, rate, bot, optional headers and
size across explicit API methods. Future acceptance must also include successful
authenticated writes in disposable state, every role/state transition, nested/body
variants and the new error/race cases. Do not claim every raw wire variant or all
HEAD/OPTIONS combinations from representative route tests alone.

## P7 — verification artifacts and release requirements

Repair the historical benchmark's Policy construction with valid numeric defaults
and explicit boolean changes. Keep its OFF experiment isolated, and report the
mandatory production guard separately. Use safe synthetic callables and no database
URLs inherited from production. Small corpus accuracy is a regression result,
not an internet detection rate or production capacity measurement.

Record exact Python/package versions and a reproducible dependency snapshot for
future release builds. Assess dependency advisories in a separately scoped check;
`pip check` only tests installed-package consistency. No dependency upgrades or
obsolete-table removals are part of this documentation commit.

### Preconditions before a later deployment

1. Obtain an explicit release/deployment decision for the specific reviewed commit
   and chosen CSP delivery method. A push to `dev` is not authorization to publish
   `main`, change Pages settings/DNS, reload PythonAnywhere or alter live policy.
2. Record the installed frontend/backend SHA, actual WSGI entry file, environment
   paths, Pages source and static mappings through authorized account inspection.
   Verify `application = protect_wsgi(...)`, `TESTING=False`, required login guard
   and stable existing database/policy paths.
3. Confirm real client IP separation and HTTPS scheme with the actual provider.
   PythonAnywhere X-Real-IP trust is provider-specific; generic proxies require
   exact trusted peers and overwritten single-hop metadata. Verify no static
   mapping shadows protected namespaces or exposes source/runtime/secrets.
4. Back up existing restaurant data, policy/audit state and configuration consistently.
   Verify restoration on staging; retain secret keys and named volumes. Never run
   migration/import/seeding/cleanup as a smoke test against production.
5. Stage the exact commit with disposable/sanitized data and fresh isolated runtime
   paths. Run regression tests, new error/race cases, real browser workflows, policy
   ON/OFF tests and bounded resource checks. Require zero unexplained failures.
6. For public CSP, prove actual document delivery, resource compatibility and
   Report-Only/enforcement behavior appropriate to the chosen host. API headers,
   local source strings and a UI switch are insufficient evidence.
7. Only after authorization, deploy manually with rollback steps. Production smoke
   checks should be small and non-destructive: health, public menu, normal operator
   access and effective policy. Repeated failures/attack cases stay on disposable
   staging accounts. No production guessing or exploit loops.
8. Compare expected counts/roles/order workflow against the staged preservation
   checks. Roll back code/WSGI/header delivery manually if needed, preserving runtime
   data. Data restoration is a separately reviewed recovery operation.

No implementation is complete merely because a checklist is filled: attach actual
test output, policy/route evidence and deployment limitations to each reviewed
change. The current audit is complete when these two documents are reviewed,
committed and pushed to `dev`; none of the future tasks above is implicitly done.
