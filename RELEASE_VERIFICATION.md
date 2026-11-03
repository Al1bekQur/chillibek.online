# Combined release verification

Prepared on `dev`, 2026-11-03, from
`c430b07a167fc9f9665aecd4ff115a1d5ea0fe95`. That commit already includes the
Stored XSS/input fixes from `e99669a`. Release status: **locally verified and
prepared; production activation remains conditional** on the account-side gates
in [RELEASE_PROCEDURE.md](RELEASE_PROCEDURE.md). No new attack module, second
WAF, public attack endpoint or independent policy system was introduced.

## Actual results for this preparation

| Check | Result |
| --- | --- |
| Complete Python suite: `backend/tests waf/tests` | **354 passed**, 0 failures/errors/skips; **214.67 s** |
| Node management, DOM and CSP/frontend suites | **15 passed**, 0 failures |
| Release-specific backup/artifact/path-guard tests, included in the full suite | **16 passed** |
| Browser CSP modes and HTTP-delivered inline/event/external/eval/Trusted Types probes | **5 checks passed** |
| Browser hosted restaurant workflow, CSP enforced | **9 checks passed**, 86 intercepted requests |
| Browser static restaurant compatibility/fallback, no document CSP | **9 checks passed**, 95 intercepted requests |
| Browser authenticated Settings, eleven original controls, persistence/rejection/offline states and layouts | **8 checks passed** |
| Browser static Settings gateway from extracted Pages artifact | **4 checks passed** |
| New browser actual Pages release artifact navigation | **5 checks passed**, 17 destination requests fulfilled from the local protected stack |
| Benign `deploy.release verify-http`, actual loopback WSGI | Passed: five documents, seven restaurant assets, menu/health, protected API rejection and Settings redirect |
| `pip check` | No broken requirements found |

Total: **40 browser checks** across six suites. Every browser request either
stayed on loopback or was fulfilled/aborted by interception; none went to the
production frontend/backend, image host or antivirus server. The CSP suite
aborted six known workstation antivirus injections without changing antivirus
settings. Probe execution comes from actual test fixture HTML/scripts delivered
over HTTP, not DevTools executing an alleged attack. CDP automates UI/readouts.

Workflow evidence covers real Flask through ProtectedWSGI: menu, details, cart,
server-priced order creation, staff login, waiter approval, chef readiness, waiter
completion/archive, Admin add/search/edit/delete and logout. The expanded image
case assigns an approved URL, edits it, verifies stored/menu URL equality and
waits for a successfully decoded browser image. Image fixtures now use a valid
minimal PNG; a first development run exposed the old fixture's inability to
satisfy the new decoding assertion. The corrected final suites passed. There is
no upload endpoint; the supported image workflow is URL assignment, not file upload.

Existing/new malicious menu text remains inert, including with request XSS OFF;
the request XSS ON probe still blocks and logs. Actual CSP Enforce blocks matching
injected execution; Report-Only/OFF permit controlled probes. Legitimate code
works in all three modes. Only Chrome was exercised, not all browser versions.

All databases/accounts/orders used in validation were disposable synthetic state.
No password verification, record mutation, setting update or HTTP check was run
against production. Existing tests for parser/numeric HTTP 500 regressions, route
coverage, RBAC, centralized toggles, logging and persistent settings also passed.

## Release-specific checks

`waf/tests/test_release.py` adds **16 tests**:

- Consistent SQLite backup; full menu/staff/order row equality; exclusive new
  destinations; unchanged source file digests.
- Policy upgrade rehearsal on a throwaway copy, preserving all old flags and
  thresholds without migrating its source.
- Refusal/stop on missing DB, corrupt policy, empty menu or incompatible staff
  shape; no repair/seed/password migration in the preflight tool.
- Legacy credential warning without verification or rehashing.
- Deterministic immutable Git artifacts; required assets/modules; public Pages
  allowlist and compatible fallback; rejection of missing assets/tracked secrets.
- WSGI example checks existing policy before backend import and uses configured
  paths instead of guessing a runtime policy directory. Four additional path
  cases cover DATABASE_PATH, SQLite URL, missing URL target and a log path pointing
  at the policy DB, without importing or initializing the restaurant app.
- Benign deployment HTTP verifier exercises the real WSGI stack, detects a wrong
  expected CSP mode and rejects non-origin URLs.

Artifact rehearsal used the immutable CSP source commit. Its Pages and fallback
source bytes match the unchanged restaurant runtime in this preparation:

```text
pages-site.zip     SHA256 6e0bdb83afe5ead3d892ae08d26d0439ff5272c43f979762af34f63a16fae6b0
pages-fallback.zip SHA256 42a21d720bd3f3651b90d7279682bb3305e4cc671c9fb09ae4f2c88aa68869a0
```

Build again from the final prep SHA to include the tools, constraints, tests and
runbook in `backend-source.zip`; its source SHA/hash will differ from the CSP-only
baseline. Generated artifacts/manifest stay under ignored `waf/local/`.
Do not deploy a baseline archive and claim it contains this preparation's tools.

## Reproduction

Windows/Python 3.11.9, Node v24.21.0, isolated headless Chrome. From repo root:

```powershell
$env:DATABASE_URL=''
$env:WAF_POLICY_PATH=''
$env:WAF_TRUSTED_PROXY_IPS=''
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/release-final.xml
node --test waf/tests/test_management_routes.mjs waf/tests/test_restaurant_dom.mjs waf/tests/test_csp_frontend.mjs
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m deploy.release build --ref HEAD --output waf/local/release-final-artifacts
```

Restart the disposable fixture before each stateful restaurant suite. Launch a new
isolated headless Chrome/CDP on 9222 before each browser command, as described in
[CSP_VERIFICATION.md](CSP_VERIFICATION.md). Run these fixture/test pairs:

| Fixture flags for `python -m waf.tests.browser_wsgi_fixture` | Browser command |
| --- | --- |
| `--restaurant --csp --csp-probes` | `node waf/tests/browser_csp.mjs` |
| `--restaurant --csp` | `node waf/tests/browser_restaurant.mjs --hosted` |
| `--restaurant` | `node waf/tests/browser_restaurant.mjs` |
| none (or fresh default policy) | `node waf/tests/browser_settings.mjs` |

For artifact browser checks extract trusted `pages-site.zip` into a new local
directory and serve **that** directory, not the full backend archive:

```powershell
.\.venv\Scripts\python.exe -m zipfile -e waf/local/release-final-artifacts/pages-site.zip waf/local/release-final-pages
.\.venv\Scripts\python.exe -m http.server 8766 --bind 127.0.0.1 --directory waf/local/release-final-pages
```

With a fresh `--restaurant --csp` fixture on 8765 and isolated Chrome, run
`node waf/tests/browser_pages_release.mjs`. It proves fixed index/Admin/Kitchen
destinations with CSP/working assets, query/fragment removal, Settings as a static
gateway to the single authenticated interface and Dashboard sign-in. It intercepts
the apparent production URLs and fulfills them exclusively from `127.0.0.1:8765`.
Then start a fresh Chrome and run `node waf/tests/browser_static_settings.mjs`.
That command uses its default local URL; do not supply its optional live URL.

## Remaining gates and risks

- Live installed code, headers, path/configuration, populated DB schema, passwords,
  image hosts, Pages source and account settings are unverified; no deployment
  was authorized or performed here. Local readiness is not live coverage.
- PythonAnywhere Free limitations and SQLite/network filesystem reliability must
  pass staging. A new paid service/DB/domain migration is not silently assumed.
- Existing order/staff records may need a separate reviewed compatibility plan;
  do not initialize a new DB, bulk migrate credentials or restore backups as a
  deployment convenience. Legacy first-login hashing preserves the password but
  updates its stored representation in normal operation.
- CSP and safe DOM do not resolve historical A03 manual-hold race, A04 token
  revocation, public-order authenticity, log growth or other deferred audit items.
  No additional security module was implemented in this release preparation.
- Report delivery is best-effort/untrusted; Trusted Types support varies; approved
  script origins/extensions remain trusted. Reload old tabs after policy changes.
- Pages fallback intentionally loses dynamic document CSP. Preserving the public
  hostname while moving its execution origin requires a separate hosting decision.
