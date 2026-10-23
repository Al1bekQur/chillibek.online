# CHILLIBEK security engine review

Scope: development source and isolated synthetic tests on Windows/Python 3.11.
No public attack traffic, production login, database modification, deployment,
DNS change or `main` release was performed. Production protection remains unverified.
Measured results are in [security-results.json](security/reports/security-results.json).

Final local run: **212 Python tests passed, 0 failed/errors/skipped**, **6 Node
routing tests passed**, **8 grouped Chrome checks passed**. The 55-case corpus
yielded **35 true positives, 20 true negatives, 0 false positives, 0 false negatives**:
100% detection and 0% false-positive rate on this small labeled set only.
Detector mean latency was 0.0557 ms. Mean WSGI request latency was 50.9213 ms with
all modules ON, 37.5933 ms with optional modules OFF, versus 0.1699 ms for raw
minimal Flask. The measured ON overhead was +50.7514 ms (+29,871.34% relative to
that tiny baseline), with ON p95 86.0555 ms. This is material I/O/adapter overhead,
not a claim of high throughput; reruns vary with local disk/load. pip-audit checked
46 installed packages with no known advisory records. Bandit reported three medium
SQL-construction findings and one low empty-string finding, reviewed below.

## Verified findings and changes

| Severity | Finding | Resolution / evidence |
| --- | --- | --- |
| High | JSON escapes, multipart fields, HTML entities and comment-obfuscated SQL bypassed opaque-text inspection. | Parse fields first, bounded recursive decoding/NFKC, SQL token/structure checks, HTML tag/attribute parsing; attack-wire regression matrix. |
| High | Turning off size protection or using Monitor allowed unlimited WAF body buffering. | Mandatory 4 MiB ceiling, 5 s body deadline, 128 total / 32 per-IP transport admissions; policy size limits remain independently adjustable. |
| High | IP-only in-memory login limits could be bypassed with distributed IPs or worker restarts. | Atomic persistent Flask per-IP/account admission and temporary escalating lockouts, plus optional shared WAF failure-based detection; mandatory operator account/IP limits. |
| High, parser-dependent | Ambiguous framing and header controls were optional. | Mandatory raw ASGI header/framing checks, header bounds, actual body-length validation, compressed-body rejection. This does not establish that an upstream HTTP parser is smuggling-safe. |
| Medium | Fixed time buckets permitted boundary bursts; no route/concurrency admission. | Shared sliding windows, per-route quotas, expiring concurrency leases; tests cover time boundaries and held-open work. |
| Medium | Timeout settings did not bound custom/in-process transports; cancelled Flask threads could continue consuming capacity. | Enforce elapsed upstream timeout; independent bounded WSGI thread admission remains held until actual thread exit. |
| Medium | Order authorization read and mutation could race with another state change. | Conditional status updates/deletes reject stale writes with 409; regression commits a competing state change between read and write. |
| Medium | Dashboard logout lacked CSRF; validation errors echoed rejected values; arbitrary request paths could enter logs. | Signed session-bound logout token; sanitized validation responses; only known route templates logged. |
| Medium | HTTPX-decoded upstream responses retained stale encoding/length headers. | Remove decoded-response encoding/length metadata and connection-nominated hop headers; preserve Flask cookies only in the intended WSGI adapter. |
| Medium | Missing durable policy row could silently restore defaults on restart. | Reject missing/incomplete/corrupt policies without replacement. Exact previous policy schema upgrades atomically with audit and preserves disabled rules. |
| Dependency | Installed certifi and setuptools had nine advisory records (including duplicates). | Updated installed environment and requirement floors; rerun pip-audit reports no known advisories for the inspected environment. |
| Low / accuracy | Standalone comments and menu prose generated SQLi false positives. | Require SQL structural context; benign menu text and image URL cases are regression-tested. |

No verified critical application exploit was established. This is a scoped review,
not evidence that undiscovered critical vulnerabilities do not exist.

## Protection controls

The existing controls remain, with three additions: Command Injection, Login Abuse,
and Scanner Behavior. All eleven controls (including mode and event logging) use
the authenticated settings API, revision checks, the same durable policy and audit
as the proxy/WSGI adapter. Updates apply on the next request; the browser waits for
confirmation and reloads the saved state. Existing eight-field policies receive an
audited schema upgrade; the new controls default ON. Back up policy storage before
any separately approved installation.

Block rejects configured detections; Monitor forwards and records them. Mandatory
backend authentication/roles, login admission, management authentication/CSRF,
configuration audit, parser rejection, hard resource ceilings and timeouts cannot
be disabled. The suspicious-header switch controls method-override heuristics;
framing ambiguity remains a mandatory transport error. Rate Limiting groups IP,
route and optional concurrency protections. Scanner detection uses actual 404
sequences, not User-Agent reputation. These behavioral heuristics can temporarily
limit legitimate probing or shared-NAT clients; thresholds require workload tuning.

The backend has no server-side fetch-from-user-URL route and no request-driven
shell/subprocess sink. Menu image URLs are browser resources, not SSRF fetches.
Reject credentials and literal local/private/metadata image destinations; no DNS
resolution or URL-fetching feature was added. This validator is not a reusable
SSRF fetch guard: a future fetch feature must also validate resolved IPs, redirects,
alternate numeric address forms and DNS rebinding at connection time.

Existing SQL parameter binding, server-side totals, role checks, signed expiring
tokens and frontend output escaping remain the application defenses. Staff share
restaurant-wide order access by role; this is not a per-waiter ownership model.
HTTPS responses add HSTS; APIs use a restrictive CSP and management uses exact
inline script/style hashes. CORS origins and restaurant API URLs are unchanged.

## Scans and reproducibility

Bandit Community and pip-audit were installed into an ignored tools virtualenv and
executed. Raw results remain in ignored `waf/local/`; the public JSON report contains
only aggregate findings. Bandit's remaining SQL findings use a generated sequence
of bound placeholders or a fixed local table-name tuple in an offline import tool;
no attacker-controlled SQL identifier reaches them. Its empty-string password
finding is local memory clearing, not a credential. These are reviewed false positives,
not a clean zero-finding Bandit claim.

Semgrep CE, Trivy, Docker and OWASP ZAP were not installed/available. No results from
those tools or a container/image scan are claimed. ZAP was not pointed at production.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/security-tests.xml
node --test waf/tests/test_management_routes.mjs
.\waf\local\security-tools\Scripts\python.exe -m bandit -r backend waf -x backend/tests,waf/tests,waf/local,waf/logs -f json -o waf/local/bandit.json
.\waf\local\security-tools\Scripts\python.exe -m pip_audit --path .venv/Lib/site-packages --format json --output waf/local/pip-audit.json --progress-spinner off
.\.venv\Scripts\python.exe -m waf.scripts.security_report --junit waf/local/security-tests.xml
```

Create the tools environment with `python -m venv waf/local/security-tools` and
install `bandit pip-audit` there before running the scan commands. The browser
fixture remains loopback-only: `python -m waf.tests.browser_wsgi_fixture`; run
`node waf/tests/browser_settings.mjs` with a dedicated isolated Chrome on CDP 9222.
Eight grouped browser checks exercise all eleven switches, reloads, rejected
updates, login expiry and unavailable API behavior. Stop the fixture afterward.

Corpus detection/false-positive rates describe only 55 labeled synthetic examples,
not unseen attacks or production traffic. Wire tests additionally transform malicious
cases into double-encoded and JSON-unicode forms and exercise Block, Monitor,
disabled rules, logging and restart behavior. The latency benchmark makes 40 measured
requests per configuration after warmup to a private harmless Flask callable, with
no network listener. It includes durable SQLite operations and adapter overhead;
raw Flask has none of that security work. It does not measure concurrent capacity,
network latency or PythonAnywhere filesystem behavior.

## Open-source engine assessment

The custom engine adopts field parsing, canonicalization, rule IDs and anomaly
scoring concepts, but implements original code; no third-party SecLang rules were
copied or translated to Python regexes. [OWASP CRS](https://owasp.org/projects/crs)
requires a compatible rule engine; its [installation guide](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/)
does not make it a drop-in Python rules module.

[Coraza](https://github.com/corazawaf/coraza) is a Go library supporting SecLang and
CRS v4; ModSecurity v3 is a separate native engine with web-server connectors.
Either requires a real connector/edge process and testing, rather than importing
CRS into this ASGI/WSGI detector. PythonAnywhere Free does not grant us control of
its front HTTP parser or permission to install a server connector. Docker is absent
locally, so neither integration was executed. The custom WAF remains independent.
CRS, Coraza and ModSecurity v3 publish Apache-2.0 licenses: [CRS license](https://github.com/coreruleset/coreruleset/blob/main/LICENSE),
[Coraza license](https://github.com/corazawaf/coraza/blob/main/LICENSE),
[ModSecurity license](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/LICENSE).
Any future redistribution must retain their applicable notices/licenses.

## Remaining limitations

- Signature/behavior coverage is bounded and evadable; it is not a full SQL parser,
  browser or CRS engine. Binary/unsupported compressed bodies are not decoded.
- HTTP framing follows [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html), but
  WSGI cannot reveal duplicate headers or framing removed by a hosting proxy.
- Timeouts do not undo a completed database write or forcibly stop synchronous
  Flask work; the adapter retains capacity until those threads exit. Host/server
  timeouts and network DDoS mitigation remain necessary.
- SQLite counters/audits add I/O and grow with traffic; storage quota, retention,
  backup, locking and PythonAnywhere network-filesystem reliability remain rollout
  gates. Multi-host global limits require a shared external datastore.
- PostgreSQL SQL is supported by the new login guard and migration, but a live
  PostgreSQL instance/container was not available for integration testing.
- Existing legacy plaintext-password upgrade support still requires credential
  migration/rotation. Staff bearer sessions are expiring but have no logout revocation
  registry. Public anonymous ordering remains a business requirement, not proof that
  every submitted order is a real customer. Existing Docker images still need
  independent hardening and scanning; the Flask Docker command is a development server.
- The backend schema adds only `login_attempts` through migration `0002_login_attempts`.
  No production migration ran. New protection remains inactive in production until
  the separately approved protected WSGI/compatible backend rollout is verified.

## Changed source/artifact inventory (29 files)

- Application: `backend/db.py`, `backend/server.py`, `backend/login_guard.py`,
  `backend/migrations/versions/0002_login_attempts.py`.
- WAF: `waf/app.py`, `waf/config.py`, `waf/dashboard.py`, `waf/parsing.py`,
  `waf/policy.py`, `waf/protocol.py`, `waf/rules.py`, `waf/wsgi.py`.
- Settings: `settings/index.html`, `settings/settings.js`.
- Tests: `backend/tests/test_security.py`, `backend/tests/test_backend_advanced_security.py`,
  `waf/tests/conftest.py`, `waf/tests/security_corpus.json`,
  `waf/tests/test_advanced_security.py`, `waf/tests/test_settings.py`,
  `waf/tests/test_wsgi.py`, `waf/tests/browser_settings.mjs`,
  `waf/tests/browser_wsgi_fixture.py`.
- Verification/reporting: `requirements.txt`, `requirements-dev.txt`, `waf/README.md`,
  `waf/scripts/security_report.py`, `security/reports/security-results.json`,
  `SECURITY_REPORT.md`.

Restaurant `index.html`, `admin.html`, `kitchen.html`, API URLs, CNAME, production
data and `main` remain unchanged. Runtime databases, raw logs, tools virtualenvs,
browser profiles and credentials are excluded from the commit.
