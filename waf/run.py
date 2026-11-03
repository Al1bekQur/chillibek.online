"""Compatibility CLI for the same centralized, protected WSGI application."""
from werkzeug.serving import run_simple

def main():
    from backend.wsgi import application
    from .config import WAFSettings
    settings = WAFSettings()
    run_simple(settings.listen_host, settings.listen_port, application)


if __name__ == "__main__":
    main()
