# Chillibek centralized WAF

The existing FastAPI WAF and restaurant Flask application run inside one protected
WSGI pipeline. Export `backend.wsgi:application`, or use `protect_wsgi(restaurant,
settings, ...)` in the managed host's WSGI file. Local development uses
`python -m backend.run` (port 5000) or `python -m waf.run` (port 8080); both run the
same protected application. Raw production Flask API access fails closed.

- [Route matrix, pipeline audit and logging](../WAF_COVERAGE.md)
- [Configuration and manual deployment](../SETTINGS_DEPLOYMENT.md)
- [Actual verification results](../WAF_VERIFICATION.md)
- [PythonAnywhere WSGI template](../deploy/pythonanywhere_wsgi.py.example)

One durable `WAF_POLICY_PATH` store holds policy, revision history, account/IP
login counters and audited blocks. Each restaurant request uses one snapshot
through inspection and authentication. The authenticated `/settings/` panel
controls the real routes used by index, admin and kitchen. There is no Demo policy
or alternate firewall.

Content rules, rate limiting and bot detection obey their individual switches on
all backend routes. Production staff login protection remains required, including
Monitor mode. OFF/Disabled login experiments use temporary staging data and
explicit `allow_disabled_mode=True`; password verification always stays active.

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests waf/tests -q
node --test waf/tests/test_management_routes.mjs
node --check settings/settings.js
```

The tests include the real WSGI -> WAF -> Flask stack and disposable staff.
Browser verification instructions are in the deployment guide. Nothing in these
commands deploys the site or probes the live staff login.
