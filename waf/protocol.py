"""Mandatory transport safety before management or proxy routing.

ASGI/WSGI expose only what the hosting HTTP parser retained. Wire-level smuggling
must also be rejected by that parser; WSGI cannot recover discarded duplicates.
"""
import asyncio
import re
import secrets
import sqlite3
import json
from datetime import datetime, timezone

from starlette.responses import JSONResponse


def framing_error(scope, settings):
    headers = scope.get('headers', [])
    if len(headers) > settings.max_header_count or sum(len(k) + len(v) + 4 for k, v in headers) > settings.max_header_bytes:
        return 431
    seen = {}
    for key, value in headers:
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any(c < 32 and c != 9 or c == 127 for c in value):
            return 400
        seen.setdefault(key.lower(), []).append(value)
    if any(len(seen.get(key, [])) > 1 for key in (b'host', b'content-length', b'transfer-encoding', b'content-type', b'authorization', b'cookie')):
        return 400
    if b'transfer-encoding' in seen:
        if b'content-length' in seen or seen[b'transfer-encoding'][0].strip().lower() != b'chunked':
            return 400
    if b'content-length' in seen:
        length = seen[b'content-length'][0]
        if not re.fullmatch(rb'[0-9]{1,12}', length):
            return 400
        if int(length) > settings.hard_max_request_bytes:
            return 413
    if b'content-encoding' in seen and seen[b'content-encoding'] != [b'identity']:
        return 415  # No decompression bomb or opaque compressed-body inspection bypass.
    return None


class ProtocolGuard:
    def __init__(self, app, settings, store):
        self.app, self.settings, self.store = app, settings, store

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        token = 'protocol:' + secrets.token_hex(16)
        try:
            admitted = self.store.acquire(token, (scope.get('client') or ('unknown',))[0], 128, 32,
                                          self.settings.body_timeout_seconds + self.settings.request_timeout_seconds + 60)
        except (sqlite3.Error, OSError):
            return await JSONResponse({'detail': 'Security storage unavailable.'}, status_code=503)(scope, receive, send)
        if not admitted:
            return await JSONResponse({'detail': 'Request capacity exceeded.'}, status_code=429)(scope, receive, send)
        try:
            async def secure_send(message):
                if message['type'] == 'http.response.start':
                    headers = list(message.get('headers', []))
                    existing = {key.lower() for key, _ in headers}
                    for key, value in [(b'x-content-type-options', b'nosniff'), (b'x-frame-options', b'DENY'),
                                       (b'referrer-policy', b'no-referrer')]:
                        if key not in existing:
                            headers.append((key, value))
                    if scope.get('scheme') == 'https' and b'strict-transport-security' not in existing:
                        headers.append((b'strict-transport-security', b'max-age=31536000'))
                    message = {**message, 'headers': headers}
                await send(message)
            await self.handle(scope, receive, secure_send)
        finally:
            self.store.release(token)

    async def handle(self, scope, receive, send):
        error = framing_error(scope, self.settings)
        body = bytearray()
        if not error:
            try:
                async def read_body():
                    nonlocal error
                    while True:
                        event = await receive()
                        if event['type'] == 'http.disconnect':
                            return
                        body.extend(event.get('body', b''))
                        if len(body) > self.settings.hard_max_request_bytes:
                            error = 413
                            break
                        if not event.get('more_body', False):
                            break
                await asyncio.wait_for(read_body(), self.settings.body_timeout_seconds)
            except asyncio.TimeoutError:
                error = 408
        if not error:
            lengths = [value for key, value in scope.get('headers', []) if key.lower() == b'content-length']
            if lengths and int(lengths[0]) != len(body):
                error = 400
        if error:
            # No request values or raw URI are returned or written on parser errors.
            if self.store.read()['policy']['event_logging']:
                self.settings.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.settings.log_path.open('a', encoding='utf-8') as output:
                    output.write(json.dumps({'timestamp':datetime.now(timezone.utc).isoformat(), 'method':scope.get('method','')[:12],
                        'path':'/[protocol]', 'matched_rules':['HTTP-001'], 'decision':'blocked', 'status_code':error,
                        'risk_score':0, 'query_present':bool(scope.get('query_string'))}) + '\n')
            return await JSONResponse({'detail': 'Unsafe HTTP request.'}, status_code=error,
                headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})(scope, receive, send)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()
        await self.app(scope, replay, send)
