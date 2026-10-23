"""Run the existing WAF and a Flask application inside one managed WSGI worker.

No loopback HTTP, second web app, listening socket, or remote upstream is used.
The exported wrapper, rather than the raw Flask application, must be the public
WSGI entry point. See PYTHONANYWHERE_WAF.md before changing a live entry point.
"""
import asyncio
import ipaddress
import os
import threading
from dataclasses import replace

import httpx
from a2wsgi import ASGIMiddleware
from werkzeug.wrappers import Response

from .app import create_app
from .config import WAFSettings


class InProcessTransport(httpx.AsyncBaseTransport):
    """Forward only to the supplied WSGI callable, using the WAF's sanitized metadata."""

    def __init__(self, application):
        self.application = application
        self.capacity = threading.BoundedSemaphore(32)
        self.pending = set()

    async def handle_async_request(self, request):
        body = await request.aread()

        def invoke():
            # These headers are synthesized by the existing proxy, which strips
            # client-supplied X-Forwarded-* headers before setting them.
            headers = request.headers.copy()
            headers["host"] = headers["x-forwarded-host"]
            scheme = headers["x-forwarded-proto"]
            if scheme not in {"http", "https"}:
                raise httpx.RequestError("Invalid internal scheme.", request=request)
            forwarded = httpx.Request(request.method, request.url.copy_with(scheme=scheme),
                                      headers=headers, content=body)
            with httpx.WSGITransport(app=self.application, remote_addr=headers["x-forwarded-for"]) as transport:
                response = transport.handle_request(forwarded)
                try:
                    return httpx.Response(response.status_code, headers=response.headers,
                                          content=response.read(), request=request)
                finally:
                    response.close()

        # Flask's synchronous request processing runs locally, never over HTTP.
        # Cancelling an await cannot stop synchronous Flask code. Hold this
        # independent hard capacity until the real thread exits, including after
        # the proxy returns a timeout. Never queue unbounded abandoned work.
        if not self.capacity.acquire(blocking=False):
            raise httpx.PoolTimeout('Local WSGI capacity exceeded.', request=request)
        def bounded_invoke():
            try:
                return invoke()
            finally:
                self.capacity.release()
        task = asyncio.create_task(asyncio.to_thread(bounded_invoke))
        self.pending.add(task)
        def done(future):
            self.pending.discard(future)
            if not future.cancelled():
                future.exception()  # Retrieve late errors without logging request data.
        task.add_done_callback(done)
        return await asyncio.shield(task)


class ProtectedWSGI:
    def __init__(self, application, settings=None, *, trust_pythonanywhere_proxy=False):
        settings = settings or WAFSettings()
        # Ignore any remote upstream/transport supplied in environment or settings.
        # This adapter always inspects the actual application it was given.
        settings = replace(settings, upstream_base_url="http://wsgi.internal",
                           upstream_transport=InProcessTransport(application),
                           forward_upstream_cookies=True)
        self.waf = create_app(settings)
        self._adapter = None
        self._adapter_pid = None
        self._loop_thread = None
        self._adapter_lock = threading.Lock()
        self.trust_pythonanywhere_proxy = trust_pythonanywhere_proxy

    @property
    def adapter(self):
        # Managed WSGI servers may fork after importing their configuration file.
        # Start the event-loop thread inside the actual worker, on its first request.
        with self._adapter_lock:
            if self._adapter is None or self._adapter_pid != os.getpid():
                loop = asyncio.new_event_loop()
                self._loop_thread = threading.Thread(target=loop.run_forever, daemon=True)
                self._loop_thread.start()
                self._adapter = ASGIMiddleware(self.waf, wait_time=5.0, loop=loop)
                self._adapter_pid = os.getpid()
            return self._adapter

    def __call__(self, environ, start_response):
        environ = environ.copy()
        # PEP 3333 permits an empty CONTENT_LENGTH for an absent request length.
        # a2wsgi would turn that WSGI sentinel into an invalid HTTP header.
        if environ.get('CONTENT_LENGTH') == '':
            environ.pop('CONTENT_LENGTH')
        # a2wsgi only constructs an ASGI client tuple when REMOTE_PORT is present.
        environ.setdefault("REMOTE_PORT", "0")
        if self.trust_pythonanywhere_proxy:
            # Only enable on PythonAnywhere, whose load balancer overwrites X-Real-IP.
            # Never trust arbitrary X-Forwarded-For values from public clients.
            try:
                client = str(ipaddress.ip_address(environ.get("HTTP_X_REAL_IP", "")))
            except ValueError:
                response = Response('{"detail":"Trusted client metadata unavailable."}',
                                    status=503, content_type="application/json")
                return response(environ, start_response)
            environ["REMOTE_ADDR"] = client
            # Scheme comes from the managed WSGI server, not an arbitrary proxy
            # header whose overwrite behavior has not been established here.
            scheme = environ.get("wsgi.url_scheme", "")
            if scheme not in {"http", "https"}:
                return Response(status=400)(environ, start_response)
            environ["wsgi.url_scheme"] = scheme
        return self.adapter(environ, start_response)

    def close(self):
        """Release local staging/reload resources after all requests have drained."""
        if self._adapter is None or self._adapter_pid != os.getpid():
            return
        loop = self._adapter.loop
        async def drain():
            pending = self.waf.state.settings.upstream_transport.pending
            if pending:
                await asyncio.gather(*list(pending), return_exceptions=True)
            await loop.shutdown_asyncgens()
            await loop.shutdown_default_executor()
        asyncio.run_coroutine_threadsafe(drain(), loop).result(timeout=30)
        loop.call_soon_threadsafe(loop.stop)
        self._loop_thread.join(timeout=5)
        if not self._loop_thread.is_alive():
            loop.close()
        self._adapter = None


def protect_wsgi(application, settings=None, *, trust_pythonanywhere_proxy=False):
    """Wrap an existing Flask/WSGI application without altering routes or its database."""
    return ProtectedWSGI(application, settings, trust_pythonanywhere_proxy=trust_pythonanywhere_proxy)
