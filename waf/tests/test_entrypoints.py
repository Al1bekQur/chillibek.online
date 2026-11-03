"""Real CLI smoke tests with disposable databases and loopback HTTP only."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest


@pytest.mark.parametrize('module', ['backend.run', 'waf.run'])
def test_local_entrypoint_uses_one_protected_application(tmp_path, module):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    environment = {**os.environ,
        'FLASK_SECRET_KEY': 'synthetic-entrypoint-secret-at-least-32-characters',
        'DATABASE_URL': '', 'DATABASE_PATH': str(tmp_path / 'restaurant.sqlite3'),
        'WAF_POLICY_PATH': str(tmp_path / 'policy.sqlite3'),
        'FLASK_RUN_HOST': '127.0.0.1', 'FLASK_RUN_PORT': str(port),
        'WAF_LISTEN_HOST': '127.0.0.1', 'WAF_LISTEN_PORT': str(port),
        'WAF_TRUSTED_PROXY_IPS': '',
    }
    # CLI settings use the default log path; isolate it without altering sources.
    script = '''
import runpy
import sys
from dataclasses import dataclass
from pathlib import Path
import waf.config
original = waf.config.WAFSettings
@dataclass(frozen=True)
class Settings(original):
    log_path: Path = Path(sys.argv[2])
waf.config.WAFSettings = Settings
runpy.run_module(sys.argv[1], run_name='__main__')
'''
    process = subprocess.Popen([sys.executable, '-c', script, module, str(tmp_path / 'events.log')],
        cwd=Path(__file__).resolve().parents[2], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', trust_env=False, timeout=1) as client:
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, process.stdout.read()
                try:
                    health = client.get('/health')
                    break
                except httpx.TransportError:
                    if time.monotonic() >= deadline:
                        pytest.fail('Synthetic entrypoint did not start')
                    time.sleep(.05)
            assert health.status_code == 200
            assert client.get('/api/menu').status_code == 200
            assert client.get('/api/menu', params={'q': "' OR 1=1 --"}).status_code == 403
            assert client.get('/api/orders').status_code == 401
            assert not (tmp_path / 'policy-demo.sqlite3').exists()
    finally:
        process.terminate()
        process.communicate(timeout=10)
