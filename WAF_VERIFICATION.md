# Centralized WAF verification

Verified locally on 2026-11-03 on branch `dev`. No production request, production
credential guessing, deployment, database migration, data import or live staff
modification was performed.

Environment: Windows, Python 3.11.9, Node v24.21.0, Flask 3.1.3, FastAPI 0.143.0,
httpx 0.28.1 and a2wsgi 1.10.10.

## Final results

| Check | Actual result |
| --- | --- |
| Full Python backend/WAF suite | 278 passed; 0 failures/errors/skips (300.79 s) |
| Node management routing tests | 4 passed, 0 failed |
| Chrome against synthetic WSGI fixture | 8 grouped checks passed, no uncaught JavaScript exceptions |
| Settings/browser harness and restaurant inline JavaScript syntax | Passed |
| Python source syntax | 37 files parsed successfully |
| Compose YAML and single WSGI service topology | Passed static validation |
| `git diff --check` | Passed |

Python command:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q --junitxml=waf/local/centralized-tests.xml
```

The JUnit artifact is local/ignored. The final summary above is derived from it.
Both CLI smoke tests launch the real protected HTTP application on ephemeral
loopback ports with temporary restaurant/policy/log files. They verify health,
menu, blocked SQLi and retained order authentication. No standalone raw Flask
service or network WAF hop is involved.

The route suite runs with Flask's TESTING bypass disabled and uses disposable
admin/chef accounts. It checks each backend method against each content module
in Block/OFF/Monitor, plus rate, bot, size and header controls; shared login
lockouts, expiry, escalation, operator-authenticated unblock, policy revision
handoff, metadata trust, log decisions/redaction and preserved fixture data.
Existing suites additionally verify parser variants, mandatory transport safety,
cross-worker policy state, auth/CSRF, real order workflow and backend integrity.

JavaScript commands:

```text
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
node --check waf/tests/browser_settings.mjs
node waf/tests/browser_settings.mjs
```

The Chrome run used `python -m waf.tests.browser_wsgi_fixture` and a dedicated
headless Chrome profile on loopback. All eleven controls were changed, persisted,
reloaded and restored; the test also covers rejected writes, expired sessions,
unavailable APIs, and desktop/mobile layout. Screenshots remain local/ignored.
Inline scripts in index/admin/kitchen were parsed with Node's `vm.Script`; those
restaurant files have no source changes.

## Practical limits

- Docker is not installed here: no container build/run or production PostgreSQL
  rollout was performed. Compose was parsed and checked for exactly postgres,
  migrate and one protected WSGI application. CLI/WSGI runtime tests cover that
  application's Python startup; container integration still requires staging.
- These are controlled fixtures and regression tests, not production penetration
  testing, capacity measurements or evidence of live deployment status.
- The one SQLite policy store supports same-host workers. Multi-host policy
  replication is outside this change.
- Production deliberately rejects unrestricted staff-guessing configurations.
  Monitor retains mandatory staff admission; OFF experiments are isolated.
- Hosting parser/header/body/time/capacity limits and application auth/input
  constraints remain active independently of optional WAF switches.

The restaurant schema/migrations and index/admin/kitchen files have no diff.
Runtime databases/logs/secrets are excluded from the commit. For route-by-route
evidence see [WAF_COVERAGE.md](WAF_COVERAGE.md); for manual deployment and rollback
see [SETTINGS_DEPLOYMENT.md](SETTINGS_DEPLOYMENT.md).
