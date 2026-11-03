"""Release/backup rehearsals use disposable databases and immutable Git content."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import zipfile

import pytest

from deploy import release
from waf.policy import Policy, PolicyStore
from waf.tests.test_wsgi import staging
from waf.tests.test_wsgi import StagingClient
from werkzeug.wrappers import Response
from dataclasses import replace
from waf.wsgi import protect_wsgi


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_schema_preflight_and_backup_preserve_all_rows_and_source_bytes(staging, tmp_path):
    client, _, settings, restaurant = staging
    assert client.post('/api/orders', json={'table_number': '1', 'items': [{'id': 1, 'qty': 2}]}).status_code == 200
    PolicyStore(settings.policy_path).read()
    path = restaurant.config['DATABASE_PATH']
    before = digest(path), digest(settings.policy_path)
    result = release.check_sqlite(path, settings.policy_path)
    assert result['compatible'] is True
    assert result['row_counts'] == {'menu_items': 14, 'staff': 3, 'orders': 1}
    assert result['policy_revision_before'] == result['policy_revision_after_rehearsal']
    destination = tmp_path / 'restaurant-backup.sqlite3'
    assert release.backup_sqlite(path, destination)['backup_created']
    with release.readonly(path) as original, release.readonly(destination) as backup:
        for table in ['menu_items', 'staff', 'orders']:
            assert original.execute(f'SELECT * FROM {table}').fetchall() == backup.execute(f'SELECT * FROM {table}').fetchall()
    assert (digest(path), digest(settings.policy_path)) == before
    with pytest.raises(FileExistsError):
        release.backup_sqlite(path, destination)
    with pytest.raises(release.ReleaseError):
        release.backup_sqlite(path, path)


def test_policy_upgrade_rehearsal_never_migrates_source(staging):
    _, _, settings, restaurant = staging
    state = PolicyStore(settings.policy_path).read()
    legacy = {**state['policy'], 'xss': False, 'login_max_attempts': 19}
    del legacy['csp']
    with sqlite3.connect(settings.policy_path) as connection:
        connection.execute('UPDATE policy SET value=? WHERE id=1', (json.dumps(legacy),))
    before = digest(settings.policy_path)
    result = release.check_sqlite(restaurant.config['DATABASE_PATH'], settings.policy_path)
    assert result['compatible']
    assert result['policy_revision_after_rehearsal'] == result['policy_revision_before'] + 1
    assert digest(settings.policy_path) == before


@pytest.mark.parametrize('mutation,reason', [
    ('DELETE FROM menu_items', 'Empty menu'),
    ("UPDATE staff SET username='UPPERCASE' WHERE id=1", 'usernames'),
    ("UPDATE staff SET role='manager' WHERE id=1", 'roles'),
])
def test_preflight_blocks_incompatible_restaurant_without_repair(staging, mutation, reason):
    _, _, settings, restaurant = staging
    PolicyStore(settings.policy_path).read()
    path = restaurant.config['DATABASE_PATH']
    with sqlite3.connect(path) as connection:
        if "role='manager'" in mutation:
            connection.execute('PRAGMA ignore_check_constraints=ON')
        connection.execute(mutation)
    before = digest(path)
    result = release.check_sqlite(path, settings.policy_path)
    assert not result['compatible'] and any(reason in item for item in result['issues'])
    assert digest(path) == before


def test_missing_database_and_corrupt_policy_do_not_create_or_repair(staging, tmp_path):
    _, _, settings, restaurant = staging
    missing = tmp_path / 'absent.sqlite3'
    with pytest.raises(FileNotFoundError):
        release.check_sqlite(missing, settings.policy_path)
    assert not missing.exists()
    PolicyStore(settings.policy_path).read()
    with sqlite3.connect(settings.policy_path) as connection:
        connection.execute("UPDATE policy SET value='{}'")
    before = digest(settings.policy_path)
    with pytest.raises(sqlite3.DatabaseError):
        release.check_sqlite(restaurant.config['DATABASE_PATH'], settings.policy_path)
    assert digest(settings.policy_path) == before


def test_release_artifacts_are_immutable_complete_and_pages_is_allowlisted(tmp_path):
    first = release.build('HEAD', tmp_path / 'one')
    second = release.build('HEAD', tmp_path / 'two')
    assert first['artifacts'] == second['artifacts']
    with zipfile.ZipFile(tmp_path / 'one/backend-source.zip') as archive:
        assert release.REQUIRED <= set(archive.namelist())
        assert not any(release.unsafe_file(name) for name in archive.namelist())
        assert b'data-api-base=' in archive.read('index.html')
    with zipfile.ZipFile(tmp_path / 'one/pages-site.zip') as archive:
        assert all(info.create_system == 3 for info in archive.infolist())
        assert set(archive.namelist()) == set(release.PAGES) | {'.nojekyll'}
        assert not any(name.startswith(('backend/', 'waf/')) for name in archive.namelist())
        assert b'https://kali.pythonanywhere.com/index.html' in archive.read('index.html')
        assert archive.read('CNAME').strip() == b'chillibek.online'
    with zipfile.ZipFile(tmp_path / 'one/pages-fallback.zip') as archive:
        assert 'restaurant-dom.js' in archive.namelist() and 'restaurant-index.js' in archive.namelist()
        assert b'data-api-base="https://kali.pythonanywhere.com/api"' in archive.read('index.html')
        assert b'http-equiv="refresh"' not in archive.read('index.html')
    with pytest.raises(FileExistsError):
        release.build('HEAD', tmp_path / 'one')


def test_artifact_builder_refuses_missing_asset_and_tracked_secrets(monkeypatch, tmp_path):
    commit = 'a' * 40
    def archived(files):
        def fake_git(*args):
            return (commit+'\n').encode() if args[0] == 'rev-parse' else release.zip_bytes(files)
        monkeypatch.setattr(release, 'git', fake_git)
    archived({'index.html': b'broken'})
    with pytest.raises(release.ReleaseError, match='missing'):
        release.build('HEAD', tmp_path / 'missing')
    archived({'.env': b'synthetic-secret'})
    with pytest.raises(release.ReleaseError, match='Unsafe'):
        release.build('HEAD', tmp_path / 'secret')
    assert not (tmp_path / 'missing').exists() and not (tmp_path / 'secret').exists()


def test_backup_is_private_and_does_not_replace_an_existing_file(tmp_path):
    source, target = tmp_path / 'source.sqlite3', tmp_path / 'keep.txt'
    with sqlite3.connect(source) as connection:
        connection.execute('CREATE TABLE synthetic(value TEXT)')
    target.write_text('do not replace', encoding='utf-8')
    with pytest.raises(FileExistsError):
        release.backup_sqlite(source, target)
    assert target.read_text(encoding='utf-8') == 'do not replace'


def test_wsgi_example_checks_existing_policy_before_importing_backend():
    source = (release.ROOT / 'deploy/pythonanywhere_wsgi.py.example').read_text(encoding='utf-8')
    compile(source, 'pythonanywhere_wsgi.py.example', 'exec')
    assert source.index('policy_path.is_file()') < source.index('from backend.server import')
    assert "Path(os.environ['WAF_POLICY_PATH'])" in source
    assert "Path(os.environ['WAF_EVENT_LOG_PATH'])" in source
    assert 'runtime / "policy.sqlite3"' not in source


@pytest.mark.parametrize('selection', ['path', 'sqlite_url', 'missing_url', 'log_is_policy'])
def test_wsgi_preimport_path_guards_do_not_initialize_database(tmp_path, monkeypatch, selection):
    restaurant, policy = tmp_path / 'restaurant.sqlite3', tmp_path / 'policy.sqlite3'
    for path in [restaurant, policy]:
        with sqlite3.connect(path) as connection:
            connection.execute('CREATE TABLE synthetic(value TEXT)')
    selected = tmp_path / 'absent.sqlite3' if selection == 'missing_url' else restaurant
    monkeypatch.setenv('DATABASE_URL', 'sqlite:///' + str(selected) if 'url' in selection else '')
    monkeypatch.setenv('DATABASE_PATH', str(selected))
    monkeypatch.setenv('WAF_POLICY_PATH', str(policy))
    monkeypatch.setenv('WAF_EVENT_LOG_PATH', str(policy if selection == 'log_is_policy' else tmp_path / 'events.log'))
    monkeypatch.setattr('dotenv.load_dotenv', lambda *args, **kwargs: None)
    monkeypatch.setattr(sys, 'path', list(sys.path))
    prefix = (release.ROOT / 'deploy/pythonanywhere_wsgi.py.example').read_text(encoding='utf-8').split('# Keep the account')[0]
    before = digest(restaurant), digest(policy)
    if selection in {'missing_url', 'log_is_policy'}:
        with pytest.raises(RuntimeError):
            exec(compile(prefix, 'wsgi-prefix', 'exec'), {})
    else:
        exec(compile(prefix, 'wsgi-prefix', 'exec'), {})
    assert not (tmp_path / 'absent.sqlite3').exists()
    assert before == (digest(restaurant), digest(policy))


def test_benign_deployment_http_checks_use_real_wsgi_and_detect_wrong_mode(staging):
    _, _, settings, restaurant = staging
    wrapper = protect_wsgi(restaurant, replace(settings, serve_frontend=True))
    client = StagingClient(wrapper, Response)
    class Result:
        def __init__(self, response):
            self.status_code, self.headers, self.text, self.content = response.status_code, response.headers, response.text, response.data
            self.json = lambda: response.json
    def get(path):
        return Result(client.get(path, base_url='https://staging.test'))
    assert release.verify_http('https://staging.test', 'enforce', get)['checks_passed']
    with pytest.raises(release.ReleaseError, match='CSP mode'):
        release.verify_http('https://staging.test', 'off', get)
    with pytest.raises(release.ReleaseError, match='exact HTTPS'):
        release.verify_http('https://staging.test/unexpected', 'enforce', get)


def test_preflight_warns_without_verifying_or_rehashing_legacy_credentials(staging):
    _, _, settings, restaurant = staging
    PolicyStore(settings.policy_path).read()
    with sqlite3.connect(restaurant.config['DATABASE_PATH']) as connection:
        connection.execute("UPDATE staff SET password='synthetic-legacy-value' WHERE id=1")
    before = digest(restaurant.config['DATABASE_PATH'])
    result = release.check_sqlite(restaurant.config['DATABASE_PATH'], settings.policy_path)
    assert result['compatible'] and any('Legacy credential' in item for item in result['warnings'])
    assert digest(restaurant.config['DATABASE_PATH']) == before
