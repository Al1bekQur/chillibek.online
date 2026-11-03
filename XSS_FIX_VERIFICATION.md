# XSS rendering and input-processing fixes

Work on `dev`, starting from audit commit
`1c62988c81626e811e2ffe11495ce23f71e09884`. The audit's A01/A02 and A06 references
identify the original parser, integer and rendering paths. This release fixes
those paths without adding CSP, changing PolicyStore, or creating another engine
or Demo Lab. Production was not contacted, changed or deployed to.

## Behavior and evidence

### Malformed HTML and Unicode

`HTMLParser.feed()` asserts on malformed marked sections such as `<![audit]>`.
The existing XSS detector now catches that parser-specific assertion and returns
an optional XSS match. It does not swallow arbitrary exceptions around the entire
request or treat a programming error as an attack.

| Input / policy | Actual expected response | Traffic record |
| --- | --- | --- |
| Malformed marked section, XSS ON + Block | 403 | `blocked`, XSS-001 |
| Same input, XSS ON + Monitor | Backend baseline (200 for menu; 400 for invalid order schema) | `detected`, XSS-001 |
| Same input, XSS OFF | Backend baseline; detector is not called | No XSS-001; `allowed` if no other match |
| Invalid UTF-8 JSON or lone Unicode surrogate, any mode | 400 | `blocked`, PARSE-001; mandatory input integrity |
| Ordinary Unicode/emoji, literal comparisons and incomplete comments | Normal baseline | No incidental XSS match in tested benign cases |

The central pipeline contains expected inspection-input errors in the same
sanitized parsing response. Helper calls with unsupported internal types reject
them through `InvalidInspectionInput`; valid JSON numeric/null/list values are
not coerced into HTML. Logs retain safe route, HTTP status and policy revision,
without rejected payloads or stack traces. Existing detector normalization,
independent SQLi/traversal/command modules and mandatory login safeguards remain.

### Numeric processing

- `_integer` bounds text to 32 characters before conversion, still enforces the
  field's original numeric bounds, and rejects booleans/floats/containers.
- This covers menu prices, order item IDs/quantities/optional prices and optional
  total price. Table numbers use the same ASCII integer validation, avoiding the
  previous `isdigit()` versus `int()` mismatch for characters such as `²`.
- Flask URL integer conversion is bounded before routing finishes and rejects
  IDs outside signed 64-bit database binding range. Invalid URL IDs receive a
  controlled 404/405 router response, never the tested integer overflow 500.
- Ordinary integer strings and reasonable zero padding still work. Invalid
  payloads return 400 without committing menu, staff or order changes. No Python
  safety limit was disabled and no database schema/record migration was added.

### Stored and DOM XSS

The owner reported execution from a stored description in production. The audit
baseline already escaped descriptions in some paths, but still used HTML template
construction and executable ID interpolation. The installed production revision
and its exact vulnerable path were not inspected. This change removes those
dynamic parsing paths across the actual repository pages and verifies the reported
storage-to-render scenario locally; it does not claim a production rollout.

- Menu cards, descriptions, names, weights, cart controls, search results,
  kitchen cards and archive rows use DOM creation/textContent rather than
  innerHTML/insertAdjacentHTML. Dynamic buttons use closures/event listeners,
  never JavaScript constructed from API IDs.
- `restaurant-dom.js` shares safe text/image assignment and response contracts.
  Menu/action IDs and prices must be positive safe integers. Invalid ID/price
  records cannot create executable attributes or action targets. Images accept
  absolute HTTP(S) URLs without credentials/control bytes; executable schemes
  are omitted. Arbitrary objects are not string-coerced.
- Existing and newly submitted HTML-shaped text remains unchanged in storage
  and is displayed literally. This also applies when request XSS inspection is
  OFF. Output safety has no WAF switch and is not a duplicate request firewall.
- Customer order items contain only IDs/quantities; the backend still calculates
  actual names, prices and totals. Stored malicious names are not copied into a
  new order request where the optional detector could unnecessarily block them.
- Safe form `.value`/text assignments, authentication, category navigation,
  ordering, staff transitions, timers, editing, deletion and archive behavior
  are retained. Static inline code/handlers remain; CSP is a separate next stage.

## Files changed

| File | Change |
| --- | --- |
| `waf/rules.py` | Contain HTML parser assertion; validate inspection text/types/Unicode |
| `waf/app.py` | Include inspection-input errors in centralized sanitized 400/log path |
| `backend/server.py` | Bounded payload/route integer conversion; table and invalid-Unicode validation |
| `restaurant-dom.js` | Shared DOM, text, image URL and API response helpers |
| `index.html` | Safe menu/cart/details nodes and listeners; minimal order item payload |
| `admin.html` | Safe list/search/actions; helper loading and safe rejection feedback |
| `kitchen.html` | Safe order/archive/actions; robust date handling |
| `waf/tests/test_input_regressions.py` | Real WSGI input, policy, logging, independence and data-preservation regressions |
| `waf/tests/test_restaurant_dom.mjs` | Node response/type/URL/text contract tests |
| `waf/tests/browser_restaurant.mjs` | Real Chrome + real local WSGI stored-XSS and workflow tests |
| `waf/tests/browser_wsgi_fixture.py` | Optional disposable restaurant staff/legacy payload seed; TESTING=False |
| `SECURITY_AUDIT.md` | Historical findings linked to this implementation status |
| `WAF_COVERAGE.md` | Current input/rendering responsibilities |
| `WAF_VERIFICATION.md` | Link current results while preserving earlier verification history |
| `XSS_FIX_VERIFICATION.md` | This report and manual release procedure |

No changes to database schema/migrations, PolicyStore schema, stored production
records, staff accounts, secrets, requirements, live settings or WSGI export.
The index file's line endings/trailing whitespace were normalized while changing
the renderer; the restaurant's stylesheet and static copy are otherwise retained.

## Actual local checks

| Check | Result |
| --- | --- |
| Full Python regression suite, including real WSGI, roles/orders and new input tests | 300 passed, 0 failures/errors/skips; 540.57 s |
| Node management + restaurant helper tests | 9 passed, 0 failed |
| Chrome stored-XSS/restaurant workflow test | 8 grouped checks passed; 79 requests intercepted/local, none forwarded to production |
| Existing Chrome Settings suite | 8 grouped checks passed; all eleven controls, reload, rejected changes and expired session behavior |
| JavaScript syntax | Helper, new browser harness and all three restaurant inline scripts passed |
| `git diff --check` | Passed after line-ending/whitespace cleanup |

The targeted numeric regression also passed independently. The original audit
probe script intentionally asserts old defects and is not part of the maintained
suite; use the committed regressions for current acceptance.

Commands from repository root, with production DB/policy/proxy environment values
cleared in the local test process:

```powershell
$env:DATABASE_URL=''; $env:WAF_POLICY_PATH=''; $env:WAF_TRUSTED_PROXY_IPS=''
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/xss-regressions.xml
node --test waf/tests/test_management_routes.mjs waf/tests/test_restaurant_dom.mjs
node --check restaurant-dom.js
node --check waf/tests/browser_restaurant.mjs
```

For browser checks, start:

```powershell
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture --restaurant
```

Run a dedicated headless Chrome with port 9222 and a unique temporary profile.
Run `node waf/tests/browser_restaurant.mjs`, then start another dedicated Chrome
and run `node waf/tests/browser_settings.mjs`. The first harness intercepts every
browser request, fulfills the real frontend files locally, forwards API calls
only to `127.0.0.1:8765`, and blocks unexpected destinations. The second uses only
the fixture's management interface. Stop the fixture after testing. Restart it
before repeating the restaurant test, since it asserts a fresh temporary dataset.

Browser cases cover: legacy stored description/name and unsafe image URL; six
payload variants submitted through Admin with XSS OFF; search/edit; menu/details
with XSS ON; cart/order creation using a malicious stored name; waiter approval,
chef readiness, waiter completion/archive; invalid API IDs/prices; deletion/logout.
Sentinels and unexpected-request checks detect injected execution/exfiltration.
The frontend document has **no CSP in this test**, so success is due to safe DOM
rendering. No public test route or production credential is used.

## Remaining risks and limits

- No new CSP policy or CSP control was implemented. Static inline code/handlers
  remain, and the public document's deployed headers are unverified. Existing
  backend management/API headers remain unchanged.
- WAF detection is heuristic, not a general browser sanitizer or proof that every
  XSS syntax is detected. Ingress matching and safe output have separate roles.
- Admin-selected HTTP(S) images can contact third-party origins; image origin,
  privacy and future CSP decisions remain separate. Invalid/executable legacy
  image URLs are suppressed in the browser, without rewriting their records.
- These tests cover representative payloads and actual workflows, not every
  browser/parser combination. Production is not fixed until reviewed code/assets
  are actually deployed. Do not substitute a staging pass for live version proof.
- Manual-hold precedence (A03), server-side session revocation (A04), HPP,
  resource/telemetry concerns and other audit items remain outside this change.
- No container build, production PostgreSQL run, flood test or production scan
  was performed. Runtime test databases/logs and browser profiles are disposable.

## Manual deployment and frontend publication

**Nothing was deployed by this task.** Work and push are restricted to `dev`.
Publishing `main` is a separate reviewed frontend release if it is the configured
GitHub Pages publishing source. Verify that account setting rather than assuming
that a `dev` push changes the public site.

1. Record the verified dev commit from the final report. Stage that exact commit
   against a disposable database, using the existing protected WSGI entrypoint.
   Run the commands and browser flows above. Verify existing compatible API
   behavior, image URLs, role transitions and numeric-ID assumptions.
2. Before any later authorized backend rollout, take consistent backups of the
   existing restaurant database, policy/audit store, configuration and WSGI file.
   Retain existing paths and secret keys. Do not run schema imports, table cleanup,
   password reset or attack loops against production. Startup can seed an empty
   database, so verify the configured path is the populated existing database.
3. After explicit deployment authorization, install the reviewed backend changes
   (`backend/server.py`, `waf/rules.py`, `waf/app.py`) in the compatible checkout
   and reload the managed app manually. Keep the existing protect_wsgi export,
   production login guard, CORS and all other live settings. No migration is
   required by these fixes. Do not enable staging/TESTING in production.
4. Prepare a reviewed frontend release containing **all four files together**:
   `index.html`, `admin.html`, `kitchen.html`, `restaurant-dom.js`. If Pages serves
   `main`, these files must be published to `main` through the normal review flow;
   that publication has not occurred here. Do not blindly merge unrelated dev
   history. The shared script must be present alongside the new HTML.
5. After the separately authorized frontend publication, verify the served version
   and helper availability, then perform normal, small menu/login/workflow smoke
   checks. Keep malicious-payload and repeated-failure tests on disposable staging.
   Do not delete production malicious-looking descriptions automatically: the
   new renderer displays them as inert text.
6. Roll back code and the four frontend assets coherently if required, preserving
   database, policy and secrets. Data restoration is a separate reviewed recovery
   action. Recheck security behavior after any rollback before declaring resolution.
