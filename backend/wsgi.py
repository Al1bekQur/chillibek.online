"""Public WSGI export. Configure existing database and durable WAF paths first."""
from backend.server import app
from waf.wsgi import protect_wsgi

application = protect_wsgi(app)
