"""Release preparation; never deploys or imports Flask.

Build, backup and preflight stay offline. verify-http makes explicit-origin GETs.

Run from the repository root: python -m deploy.release --help
"""
import argparse
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import subprocess
import tempfile
import zipfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PAGES = {
    **{name + '.html': 'deploy/pages-gateway/' + name + '.html' for name in ('index', 'admin', 'kitchen')},
    'settings/index.html': 'settings/index.html', 'settings/settings.css': 'settings/settings.css',
    'dashboard/index.html': 'dashboard/index.html', 'CNAME': 'CNAME',
}
REQUIRED = {
    'backend/server.py', 'backend/db.py', 'backend/login_guard.py',
    'waf/app.py', 'waf/wsgi.py', 'waf/policy.py', 'waf/rules.py', 'waf/protocol.py',
    'waf/enforcement.py', 'waf/parsing.py', 'waf/dashboard.py', 'waf/settings_api.py',
    'waf/csp_policy.py', 'waf/csp_reporting.py', 'waf/frontend.py', 'waf/config.py',
    'waf/templates/settings.html', 'settings/settings.js', 'settings/settings.css',
    'requirements.txt', 'requirements-dev.txt', 'restaurant-dom.js',
    'deploy/pythonanywhere_wsgi.py.example',
} | {name + '.html' for name in ('index', 'admin', 'kitchen')} | {
    f'restaurant-{name}.{ext}' for name in ('index', 'admin', 'kitchen') for ext in ('js', 'css')
}
SCHEMA = {
    'menu_items': {'id', 'category', 'name', 'description', 'weight', 'price', 'image_url'},
    'staff': {'id', 'username', 'password', 'role'},
    'orders': {'id', 'table_number', 'items_json', 'total_price', 'status', 'created_at', 'approved_at', 'ready_at'},
}


class ReleaseError(ValueError):
    pass


def readonly(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ReleaseError('Expected an existing SQLite file.')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)
    connection.execute('PRAGMA query_only=ON')
    return connection


def backup_sqlite(source, destination):
    """Consistent backup, refusing to overwrite anything; no restore operation."""
    source = Path(source).resolve(strict=True)
    destination = Path(destination).absolute()
    if source == destination.resolve():
        raise ReleaseError('Backup must have a different, new destination.')
    with closing(readonly(source)) as incoming:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(destination)) as outgoing:
            incoming.backup(outgoing, pages=256)
            if outgoing.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise ReleaseError('Backup integrity check failed; retain it for investigation.')
    digest = hashlib.sha256()
    with destination.open('rb') as snapshot:
        for chunk in iter(lambda: snapshot.read(1024 * 1024), b''):
            digest.update(chunk)
    return {'backup_created': True, 'sha256': digest.hexdigest()}


def check_sqlite(restaurant_path, policy_path):
    """Inspect source read-only; rehearse actual PolicyStore migration on a copy."""
    from waf.policy import Policy, PolicyStore
    issues, warnings, counts = [], [], {}
    with closing(readonly(restaurant_path)) as connection:
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ReleaseError('Restaurant integrity check failed.')
        for table, columns in SCHEMA.items():
            actual = {row[1] for row in connection.execute(f'PRAGMA table_info({table})')}
            if not columns <= actual:
                issues.append('Missing required restaurant columns: ' + table)
        if issues:
            return {'compatible': False, 'issues': issues, 'warnings': warnings}
        for table in SCHEMA:
            counts[table] = connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
        if not counts['menu_items']:
            issues.append('Empty menu: startup would seed sample restaurant records.')
        if not counts['staff']:
            issues.append('No existing staff: resolve account compatibility before activation.')
        invalid_roles = connection.execute("SELECT COUNT(*) FROM staff WHERE role IS NULL OR role NOT IN ('admin','waiter','chef')").fetchone()[0]
        invalid_names = connection.execute("SELECT COUNT(*) FROM staff WHERE username IS NULL OR username != lower(trim(username)) OR length(username)=0").fetchone()[0]
        if invalid_roles or invalid_names:
            issues.append('Staff roles/usernames require a separately reviewed compatibility plan.')
        if connection.execute("SELECT COUNT(*) FROM orders WHERE status IS NULL OR status NOT IN ('pending','cooking','ready','completed')").fetchone()[0]:
            issues.append('Order states require a separately reviewed compatibility plan.')
        legacy = 0
        for (password,) in connection.execute('SELECT password FROM staff'):
            if not isinstance(password, str) or not password:
                issues.append('Empty or invalid staff credential storage.')
                break
            legacy += not password.startswith(('scrypt:', 'pbkdf2:'))
        if legacy:
            warnings.append('Legacy credential storage present: normal successful login may rehash it; no passwords were verified or changed.')
        for (items,) in connection.execute('SELECT items_json FROM orders'):
            try:
                if not isinstance(json.loads(items), list):
                    raise ValueError()
            except (ValueError, TypeError, RecursionError):
                issues.append('Order item JSON is not compatible; review without modifying originals.')
                break
        warnings.append('Schema/summary checks do not prove every legacy record or database engine is compatible; staging workflows remain required.')

    # No PolicyStore is constructed against the supplied source file: read()
    # can create/migrate schema. Only the private throwaway copy is initialized.
    with closing(readonly(policy_path)) as connection:
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ReleaseError('Policy integrity check failed.')
        row = connection.execute('SELECT value, revision FROM policy WHERE id=1').fetchone()
        if row is None:
            raise ReleaseError('Policy row is missing.')
        original = json.loads(row[0])
    with tempfile.TemporaryDirectory(prefix='chillibek-policy-preflight-') as directory:
        copy = Path(directory) / 'policy.sqlite3'
        backup_sqlite(policy_path, copy)
        store = PolicyStore(copy)
        migrated = store.read()
        if not isinstance(original, dict) or any(migrated['policy'].get(key) != value for key, value in original.items()):
            raise ReleaseError('Policy migration did not preserve prior settings.')
        policy = Policy.model_validate(migrated['policy'])
        if policy.mode == 'disabled' or not policy.brute_force:
            issues.append('Stored policy violates mandatory production login protection.')
        if store.read() != migrated:
            raise ReleaseError('Policy migration is not stable across reads.')
    return {'compatible': not issues, 'issues': issues, 'warnings': warnings, 'row_counts': counts,
            'policy_revision_before': row[1], 'policy_revision_after_rehearsal': migrated['revision'],
            'effective_configured_csp': policy.csp.mode,
            'production_data_modified': False}


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def unsafe_file(name):
    parts = PurePosixPath(name).parts
    return (name.startswith('/') or '..' in parts or '\\' in name or
            any(part in {'.git', '.venv', '__pycache__', 'logs', 'local', 'instance'} for part in parts) or
            any(part == '.env' or part.startswith('.env.') and part != '.env.example' for part in parts) or
            name.endswith(('.db', '.sqlite', '.sqlite3', '.log', '.pem', '.key', '.pyc')))


def zip_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3  # Fixed Unix metadata, including on Windows.
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, value)
    return buffer.getvalue()


def build(ref, output):
    # Git resolves the ref into an immutable full SHA before archive. No working
    # tree files, ignored runtime files or uncommitted changes enter artifacts.
    commit = git('rev-parse', '--verify', ref + '^{commit}').decode().strip()
    source = {}
    with zipfile.ZipFile(io.BytesIO(git('archive', '--format=zip', commit))) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if unsafe_file(info.filename) or (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ReleaseError('Unsafe tracked release path: ' + info.filename)
            source[info.filename] = archive.read(info)
    missing = REQUIRED - source.keys()
    if missing:
        raise ReleaseError('Required release files missing: ' + ', '.join(sorted(missing)))
    for page in ('index', 'admin', 'kitchen'):
        html = source[page + '.html'].decode('utf-8')
        if 'data-api-base="https://kali.pythonanywhere.com/api"' not in html or f'restaurant-{page}.js' not in html or f'restaurant-{page}.css' not in html:
            raise ReleaseError('Restaurant HTML/asset contract failed: ' + page)
    pages = {target: source[path] for target, path in PAGES.items()}
    if pages['CNAME'].strip() != b'chillibek.online':
        raise ReleaseError('Unexpected CNAME: domain changes are not part of this release.')
    for name in ('index', 'admin', 'kitchen'):
        if f'content="0;url=https://kali.pythonanywhere.com/{name}.html"'.encode() not in pages[name + '.html']:
            raise ReleaseError('Unexpected Pages gateway target.')
    pages['.nojekyll'] = b''
    fallback = {**pages, **{name + '.html': source[name + '.html'] for name in ('index', 'admin', 'kitchen')},
                **{path: value for path, value in source.items() if path.startswith('restaurant-') and path.endswith(('.js', '.css'))}}
    manifest = {'source_commit': commit, 'backend_files': {
        path: hashlib.sha256(value).hexdigest() for path, value in sorted(source.items())},
        'pages_files': {path: hashlib.sha256(value).hexdigest() for path, value in sorted(pages.items())},
        'fallback_pages_files': {path: hashlib.sha256(value).hexdigest() for path, value in sorted(fallback.items())},
        'coverage': 'Pages gateways navigate to protected hostname; Pages itself is not dynamically protected.'}
    payloads = {'backend-source.zip': zip_bytes(source), 'pages-site.zip': zip_bytes(pages),
                'pages-fallback.zip': zip_bytes(fallback)}
    manifest['artifacts'] = {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()}
    payloads['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for name, value in payloads.items():
        (output / name).write_bytes(value)
    return {'source_commit': commit, 'output': str(output), 'artifacts': manifest['artifacts'],
            'backend_file_count': len(source), 'pages_file_count': len(pages)}


def verify_http(origin, mode, get):
    """Benign GETs only; caller supplies exact-origin transport, no redirects."""
    from waf.frontend import ASSETS
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in {'127.0.0.1', 'localhost'})) or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ReleaseError('Use an exact HTTPS origin, or HTTP loopback for local tests.')
    checked = []
    for path in ['/', '/index.html', '/admin.html', '/kitchen.html', '/dashboard/login']:
        response = get(path)
        if response.status_code != 200 or 'text/html' not in response.headers.get('content-type', ''):
            raise ReleaseError('Document response check failed: ' + path)
        enforced = response.headers.get('content-security-policy', '')
        reporting = response.headers.get('content-security-policy-report-only', '')
        if bool(enforced) != (mode == 'enforce') or bool(reporting) != (mode == 'report-only'):
            raise ReleaseError('Unexpected effective CSP mode: ' + path)
        if mode != 'off' and 'report-uri /csp-report' not in (enforced or reporting):
            raise ReleaseError('Missing CSP report destination: ' + path)
        if response.headers.get('x-content-type-options') != 'nosniff':
            raise ReleaseError('Required response safeguard missing: ' + path)
        if path != '/dashboard/login' and ('data-api-base="/api"' not in response.text or 'restaurant-dom.js' not in response.text):
            raise ReleaseError('Restaurant is not served by the protected frontend: ' + path)
        checked.append(path)
    for asset in sorted(ASSETS):
        response = get('/' + asset)
        mime = response.headers.get('content-type', '')
        if response.status_code != 200 or not response.content or ('javascript' not in mime if asset.endswith('.js') else 'text/css' not in mime):
            raise ReleaseError('Required frontend asset unavailable: ' + asset)
        checked.append('/' + asset)
    health = get('/health')
    if health.status_code != 200 or health.json() != {'status': 'ok', 'component': 'chillibek-waf'}:
        raise ReleaseError('Protected application health check failed.')
    if get('/api/menu').status_code != 200:
        raise ReleaseError('Public menu API is not available.')
    for path in ['/api/orders', '/waf-api/settings', '/dashboard/api/csp']:
        if get(path).status_code != 401:
            raise ReleaseError('Anonymous protected API access did not fail as expected.')
    if get('/settings/').status_code != 303:
        raise ReleaseError('Settings did not require operator sign-in.')
    return {'checks_passed': True, 'effective_csp': mode, 'documents_and_assets': checked,
            'coverage': 'Verified origin only; GitHub Pages traffic was not inspected or inferred.',
            'business_mutations': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    artifact = sub.add_parser('build', help='Create immutable backend and Pages artifacts; no deployment.')
    artifact.add_argument('--ref', default='HEAD')
    artifact.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('check-sqlite', help='Read-only schema checks and policy migration on a temporary copy.')
    check.add_argument('--restaurant', type=Path, required=True)
    check.add_argument('--policy', type=Path, required=True)
    backup = sub.add_parser('backup-sqlite', help='Consistent new private backup; never overwrites/restores.')
    backup.add_argument('--source', type=Path, required=True)
    backup.add_argument('--destination', type=Path, required=True)
    http = sub.add_parser('verify-http', help='Benign document/header/API GET checks; never follows redirects or logs in.')
    http.add_argument('--origin', required=True)
    http.add_argument('--csp', choices=['enforce', 'report-only', 'off'], required=True)
    args = parser.parse_args()
    try:
        if args.command == 'build':
            result = build(args.ref, args.output)
        elif args.command == 'check-sqlite':
            result = check_sqlite(args.restaurant, args.policy)
        elif args.command == 'backup-sqlite':
            result = backup_sqlite(args.source, args.destination)
        else:
            import httpx
            try:
                with httpx.Client(base_url=args.origin, timeout=10, follow_redirects=False, trust_env=False) as client:
                    result = verify_http(args.origin, args.csp, client.get)
            except httpx.HTTPError:
                raise ReleaseError('HTTP check failed; verify origin, certificate and connectivity.') from None
    except (ValueError, OSError, sqlite3.Error, subprocess.CalledProcessError):
        # Do not print raw rows, policy/credentials, DSNs or driver exceptions.
        parser.exit(2, 'Release check failed. Verify paths, schema and private configuration; no deployment was performed.\n')
    print(json.dumps(result, indent=2))
    return 0 if result.get('compatible', True) else 2


if __name__ == '__main__':
    raise SystemExit(main())
