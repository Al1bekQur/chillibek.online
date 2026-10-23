"""Local browser staging of the real protected Flask app with synthetic state only.

Run: python -m waf.tests.browser_wsgi_fixture
Then run the existing browser_settings.mjs against port 8765.
This is not a PythonAnywhere entry point and must never be deployed.
"""
import os
import tempfile
from pathlib import Path
from wsgiref.simple_server import make_server

from werkzeug.security import generate_password_hash

from waf.config import WAFSettings
from waf.wsgi import protect_wsgi


def main():
    with tempfile.TemporaryDirectory(prefix='chillibek-wsgi-staging-') as directory:
        root = Path(directory)
        # Override inherited environment before importing the Flask module so its
        # import-time application cannot touch any configured real database.
        os.environ['FLASK_SECRET_KEY'] = 'synthetic-browser-flask-secret-at-least-32-characters'
        os.environ['DATABASE_PATH'] = str(root / 'import.sqlite3')
        os.environ['DATABASE_URL'] = ''
        from backend.server import app as import_only_app, create_app
        # The module's unused import-time app holds a pooled SQLite connection on
        # Windows. Release it so the synthetic directory can be removed on shutdown.
        import_only_app.config['DB_ENGINE'].dispose()
        restaurant = create_app({
            'TESTING': True, 'SECRET_KEY': os.environ['FLASK_SECRET_KEY'],
            'DATABASE_URL': None, 'DATABASE_PATH': str(root / 'restaurant.sqlite3'),
            'CORS_ALLOWED_ORIGINS': ['https://chillibek.online'], 'RATELIMIT_STORAGE_URI': 'memory://',
        })
        application = protect_wsgi(restaurant, WAFSettings(
            log_path=root / 'events.log', policy_path=root / 'policy.sqlite3',
            dashboard_username='synthetic-operator',
            dashboard_password_hash=generate_password_hash('synthetic-browser-password'),
            dashboard_session_secret='synthetic-browser-waf-session-secret-at-least-32-characters',
            dashboard_secure_cookies=False,  # HTTP loopback only.
        ))
        with make_server('127.0.0.1', 8765, application) as server:
            print('Synthetic WSGI staging: http://127.0.0.1:8765/settings/', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        restaurant.config['DB_ENGINE'].dispose()


if __name__ == '__main__':
    main()
