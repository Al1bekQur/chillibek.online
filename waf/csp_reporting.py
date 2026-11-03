"""Bounded CSP report ingestion; no raw URLs, samples, cookies or bodies retained."""
import json
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request, Response

from .dashboard import require_dashboard_auth
from .csp_policy import coverage
from .policy import Policy

PATHS = {'/', '/index.html', '/admin.html', '/kitchen.html', '/dashboard', '/dashboard/login', '/settings', '/settings/'}
DIRECTIVES = {'default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src', 'style-src-elem',
              'style-src-attr', 'img-src', 'connect-src', 'object-src', 'base-uri', 'frame-ancestors',
              'form-action', 'require-trusted-types-for', 'trusted-types', 'font-src'}


def sanitize_report(raw, origin, policy):
    if not isinstance(raw, dict):
        raise ValueError()
    document = raw.get('document-uri', raw.get('documentURL'))
    directive = raw.get('effective-directive', raw.get('effectiveDirective', raw.get('violated-directive')))
    disposition = raw.get('disposition')
    blocked = raw.get('blocked-uri', raw.get('blockedURL', ''))
    if (not isinstance(document, str) or len(document) > 2048 or not isinstance(directive, str) or
            len(directive) > 200 or disposition not in {'enforce', 'report'} or not isinstance(blocked, str) or len(blocked) > 2048):
        raise ValueError()
    url = urlsplit(document)
    if url.scheme + '://' + url.netloc != origin or url.path not in PATHS or url.username or url.password:
        raise ValueError()
    directive = directive.split(' ', 1)[0]
    if directive not in DIRECTIVES:
        raise ValueError()
    if blocked in {'inline', 'eval', 'wasm-eval', 'trusted-types-sink', 'trusted-types-policy', ''}:
        resource = blocked or 'unspecified'
    else:
        target = urlsplit(blocked)
        approved = {source for key in ['script_src', 'style_src', 'img_src', 'connect_src'] for source in getattr(policy.csp, key)}
        resource_origin = target.scheme + '://' + target.netloc
        resource = 'same-origin resource' if resource_origin == origin else resource_origin if resource_origin in approved else 'external resource'
    return {'directive': directive, 'document_path': url.path, 'blocked_resource': resource,
            'disposition': disposition}


def csp_router(settings, store):
    router = APIRouter()

    @router.post('/csp-report')
    async def report(request: Request):
        # Mandatory report quotas do not depend on optional traffic switches.
        ip = request.client.host if request.client else 'unknown'
        limited_all = store.over_limit('csp-report-global', 'all', 200, 60)
        if limited_all or store.over_limit('csp-report-ip', ip, 30, 60):
            raise HTTPException(429, 'CSP report limit.', headers={'Retry-After': '60'})
        origin = str(request.base_url).rstrip('/')
        if request.headers.get('origin', origin) != origin or request.headers.get('sec-fetch-site', 'same-origin') not in {'same-origin', 'none'}:
            raise HTTPException(403, 'Same-origin reports only.')
        kind = request.headers.get('content-type', '').split(';')[0].strip().lower()
        if kind not in {'application/csp-report', 'application/reports+json'}:
            raise HTTPException(415, 'Unsupported report type.')
        body = await request.body()
        if len(body) > settings.csp_report_max_bytes:
            raise HTTPException(413, 'Report too large.')
        try:
            parsed = json.loads(body)
            policy = Policy.model_validate(request.state.policy_snapshot['policy'])
            if kind == 'application/csp-report':
                records = [parsed['csp-report']]
            else:
                if not isinstance(parsed, list) or not 1 <= len(parsed) <= 10:
                    raise ValueError()
                records = []
                for item in parsed:
                    if not isinstance(item, dict) or item.get('type') != 'csp-violation':
                        raise ValueError()
                    records.append(item['body'])
            sanitized = [sanitize_report(item, origin, policy) for item in records]
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            raise HTTPException(400, 'Invalid CSP report.') from None
        store.record_csp_reports(sanitized, request.state.policy_snapshot['revision'])
        return Response(status_code=204, headers={'Cache-Control': 'no-store'})

    @router.get('/dashboard/api/csp')
    async def reports(request: Request):
        require_dashboard_auth(request, settings)
        policy = Policy.model_validate(store.read()['policy'])
        return {'reports': store.csp_reports(), 'coverage': coverage(policy, settings),
                'notice': 'Untrusted browser observations; timestamp and revision describe receipt. URLs/samples are redacted.'}

    return router
