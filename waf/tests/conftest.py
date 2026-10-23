"""Dispose each synthetic WSGI loop/executor instead of leaking workers between tests."""
import pytest
from waf.wsgi import ProtectedWSGI


@pytest.fixture(autouse=True)
def close_staging_workers(monkeypatch):
    wrappers = []
    original = ProtectedWSGI.__init__
    def remember(self, *args, **kwargs):
        original(self, *args, **kwargs)
        wrappers.append(self)
    monkeypatch.setattr(ProtectedWSGI, '__init__', remember)
    yield
    for wrapper in wrappers:
        wrapper.close()
