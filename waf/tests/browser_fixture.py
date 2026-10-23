"""Optional browser QA server; ephemeral synthetic state, never a production upstream.

Run: python -m uvicorn waf.tests.browser_fixture:create_test_app --factory --host 127.0.0.1 --port 8765
"""
import tempfile
from pathlib import Path

import httpx
from werkzeug.security import generate_password_hash

from waf.app import create_app
from waf.config import WAFSettings


def create_test_app():
    temporary = tempfile.TemporaryDirectory(prefix='chillibek-browser-')
    app = create_app(WAFSettings(
        log_path=Path(temporary.name) / 'events.log',
        upstream_transport=httpx.MockTransport(lambda request: httpx.Response(200, json={'synthetic': True})),
        dashboard_username='synthetic-operator',
        dashboard_password_hash=generate_password_hash('synthetic-browser-password'),
        dashboard_session_secret='synthetic-browser-session-secret-at-least-32-characters',
        dashboard_secure_cookies=False,
    ))
    app.state.temporary_directory = temporary
    return app
