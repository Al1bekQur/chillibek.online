# CSP development verification

Date: 2026-11-03. Branch: `dev`. Prior verified development commit:
`e99669a657a500da464cf4dbf56abeb64aec76f5` (earlier XSS/input fix included).
This is local evidence, not a statement about production headers or publication.
Deployment, coverage matrix, configuration, migration and rollback are in
[CSP_DEPLOYMENT.md](CSP_DEPLOYMENT.md).

## Results

Final complete Python run: **338 passed in 1422.90 seconds**, zero failures or
skips (`backend/tests` and `waf/tests`, including real WSGI integration and all
earlier XSS/numeric regressions). Targeted CSP/Dashboard run: **44 passed**.
Node suite: **15 passed**. Browser suites: **33 checks passed** in total.
Environment: Python 3.11.9, Node v24.21.0, Windows and isolated headless Chrome.
Settings JS/browser harness syntax checks and Git whitespace check also passed.

| Browser suite, real Chrome via CDP | Actual completed result |
| --- | --- |
| `browser_csp.mjs`, true HTTP WSGI-served probe documents | **5 checks passed** |
| `browser_restaurant.mjs --hosted`, actual server documents/headers and real Flask APIs | **8 checks passed**, 80 requests intercepted |
| `browser_restaurant.mjs`, static split-origin compatibility without document CSP | **8 checks passed**, 89 requests intercepted |
| `browser_settings.mjs`, authenticated WSGI Settings | **8 checks passed**, all 11 earlier switches remain independent; desktop/mobile layout and offline/session-expiry states |
| `browser_static_settings.mjs`, local static Pages gateway | **4 checks passed**, no API/PythonAnywhere requests |

Every browser request was either loopback or fulfilled/aborted by test interception;
**none was sent to production**. The CSP suite explicitly aborted six known
antivirus-injected script requests from this workstation; these were not app
resources or CSP probes, and their execution was not allowed. No antivirus or
browser security settings were changed. Chrome speculative idle connections
required a threaded test-only WSGI server to avoid starving real browser requests.
Each stateful restaurant suite must start with a fresh disposable fixture.

Development runs exposed JSON array/tuple differences in policy snapshots and
object-identity comparisons in the old browser test. Snapshots now use stable
JSON-compatible values and browser comparisons use value equality. Initial failed
runs are not counted as successful final verification.

## Evidence and acceptance cases

| Requirement | Test evidence |
| --- | --- |
| One policy engine/store | `waf/policy.py` embeds `CSPPolicy`; `waf/app.py:62` captures a snapshot shared with proxy enforcement and HTML finalization at line 93; no new middleware firewall |
| Enforce / OFF / Report-Only | `test_csp_modes_all_served_documents` checks all restaurant HTML and authenticated Dashboard/Settings through ProtectedWSGI; includes master Monitor/Disabled combinations |
| No misleading Pages claim | `test_csp_disabled_frontend_coverage_and_request_rules_are_independent`; browser reads NOT COVERED status from actual Settings |
| Existing auth/RBAC/CSRF/WAF | Full original regressions retained; CSP write requires WAF operator session and CSRF; restaurant admin token grants no WAF administration |
| Real injected JavaScript blocked | Test-only fixture appends inline script, literal onclick, unapproved external script and a same-origin eval/HTML-sink probe to the actual HTTP response; Chrome enforces delivered headers |
| Real ON/OFF difference | Same five probe types: execution absent under Enforce; controlled execution succeeds under Report-Only/OFF; approved script and 15-item menu work in all modes |
| Trusted Types | Supporting Chrome rejects string HTML sink under Enforce; accepts it in Report-Only/OFF; no permissive default policy; safe production rendering needs no trust exceptions |
| Safe DOM independent of policy | Both restaurant browser suites store six payload variants through admin with request XSS OFF; existing legacy payload remains inert; XSS ON then blocks request probes while stored text stays inert |
| Real restaurant workflows | Admin login/add/search/edit/delete, menu/details/cart/table/order, waiter confirmation, chef ready, waiter completion, archive, timers and logout pass with enforced document CSP and without it |
| No raw menu data in order request | Browser asserts order body contains IDs/quantities only; stored names remain text in kitchen/archive |
| CSP persistence and legacy upgrade | `test_csp_auth_csrf_validation_persistence_and_schema_upgrade` recreates ProtectedWSGI/PolicyStore, tests exact prior schema preservation and one revision upgrade |
| Safe source configuration | Invalid inline/eval/wildcard/control/header injection/path/credential/Unicode/malformed-origin sources rejected; self retained for script/style/connect management operation |
| Report validation / abuse / privacy | WSGI tests exercise legacy and Reporting API formats, invalid structures/URLs/directives/dispositions, foreign origin, 8 KiB ceiling, MIME validation, mandatory quotas while optional rules OFF, bounded retention and redaction |
| Useful Dashboard reports | Real Chrome reports include enforce/report dispositions, event directive and Trusted Types violation; authenticated table uses textContent and retains receipt timestamp/revision |
| Static migration safety | Six Node checks compile the three external scripts, match all static control bindings and verify three fixed, script-free migration gateway destinations |

The probe code is defined only in `waf/tests/browser_wsgi_fixture.py` behind
`--csp-probes --csp`; it is not a production route, page or Demo Lab. CDP automates
clicks, reads sentinels and fills forms. It does **not** execute the alleged attack
payloads itself; those arrive as document/script HTTP bytes. DevTools execution
would not establish CSP effectiveness. Existing defensive DOM tests additionally
inject malformed API objects directly as data, which is a separate rendering test.

## Reproduction (local only)

Use the repository virtual environment; global Python on this workstation does
not have pytest. Clear inherited production overrides in the local test process:

```powershell
$env:DATABASE_URL=''
$env:WAF_POLICY_PATH=''
$env:WAF_TRUSTED_PROXY_IPS=''
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/csp-regressions.xml
node --test waf/tests/test_management_routes.mjs waf/tests/test_restaurant_dom.mjs waf/tests/test_csp_frontend.mjs
```

Start a **new fixture for each browser suite** in a separate terminal:

```powershell
# CSP probes
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture --restaurant --csp --csp-probes
node waf/tests/browser_csp.mjs

# Restart fixture: full protected frontend workflow
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture --restaurant --csp
node waf/tests/browser_restaurant.mjs --hosted

# Restart fixture: static frontend compatibility, no document CSP
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture --restaurant
node waf/tests/browser_restaurant.mjs

# Restart fixture: Settings suite
.\.venv\Scripts\python.exe -m waf.tests.browser_wsgi_fixture
node waf/tests/browser_settings.mjs

# Separate loopback static server, not a WSGI fixture
.\.venv\Scripts\python.exe -m http.server 8766 --bind 127.0.0.1
node waf/tests/browser_static_settings.mjs
```

Before **each** browser command, launch dedicated headless Chrome with an isolated
temporary profile and CDP on 9222; each suite closes its own browser:

```powershell
$cspChromeProfile = Join-Path ([IO.Path]::GetTempPath()) ('chillibek-csp-chrome-'+[guid]::NewGuid().ToString('N'))
Start-Process -FilePath 'C:\Program Files\Google\Chrome\Application\chrome.exe' -ArgumentList @('--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-port=9222',('--user-data-dir='+$cspChromeProfile),'about:blank') -WindowStyle Hidden
```

Fixtures create only temporary DBs, synthetic menu records, synthetic staff and
operator credentials, set Flask TESTING false for browser workflows and use the
real protected WSGI pipeline. They do not read or edit live restaurant state.
JUnit files/screenshots stay under ignored `waf/local/`.

## Changed-file manifest

| Files | Purpose |
| --- | --- |
| `waf/csp_policy.py`, `waf/csp_reporting.py`, `waf/frontend.py` | Validated CSP model/header/coverage, secure reporting, opt-in fixed frontend serving |
| `waf/app.py`, `waf/config.py`, `waf/policy.py`, `waf/protocol.py`, `waf/settings_api.py` | Shared snapshot, hosting opt-in, policy upgrade/report storage, early report-size ceiling, Settings coverage/defaults |
| `waf/dashboard.py`, `waf/templates/settings.html`, `settings/settings.js` | External management assets, existing Dashboard report table, CSP settings/modes/coverage |
| `index.html`, `admin.html`, `kitchen.html`; `restaurant-index.js/.css`, `restaurant-admin.js/.css`, `restaurant-kitchen.js/.css` | External restaurant assets, authored event listeners, origin-correct API base; safe DOM helper retained unchanged |
| `deploy/pages-gateway/index.html`, `admin.html`, `kitchen.html` | Opt-in manual Pages migration artifacts; not installed over restaurant sources |
| `deploy/pythonanywhere_wsgi.py.example` | Reviewed environment opt-in guidance |
| `waf/tests/test_csp.py`, `test_csp_frontend.mjs`, `browser_csp.mjs` | New WSGI, source/gateway and actual-browser CSP verification |
| `waf/tests/browser_wsgi_fixture.py`, `browser_restaurant.mjs`, `browser_settings.mjs` | Disposable HTTP probes, fixed-asset compatibility, hosted workflow verification, nested-value comparisons |
| `waf/tests/test_advanced_security.py`, `test_settings.py`, `test_wsgi.py` | External management asset assertion and JSON-compatible policy expectations |
| `CSP_DEPLOYMENT.md`, `CSP_VERIFICATION.md`, `WAF_COVERAGE.md`, `WAF_VERIFICATION.md`, `SECURITY_AUDIT.md`, `SECURITY_IMPLEMENTATION_PLAN.md`, `PYTHONANYWHERE_WAF.md` | Configuration, current coverage, evidence, limits and exact manual release/rollback order; old audit references remain historical |

## Remaining limits

Live Pages coverage requires migration; no header claim is made for production.
Old open/cached documents need reload. Browser report delivery is best-effort,
deprecated report-uri is the advertised transport, reports can be forged and
bounded quotas can drop observations. Only Chrome was exercised, not every
browser/version; Trusted Types support varies. Approved scripts/origins and
browser extensions remain trusted execution contexts. Saved image hosts outside
defaults require review. CSP does not replace safe DOM, auth, CSRF or a host/edge
DDoS layer. No restaurant record cleanup or credential guessing was performed.
