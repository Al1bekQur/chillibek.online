import os

from backend.wsgi import application
from werkzeug.serving import run_simple


def main():
    run_simple(
        os.getenv("FLASK_RUN_HOST", "127.0.0.1"),
        int(os.getenv("FLASK_RUN_PORT", "5000")),
        application,
    )


if __name__ == '__main__':
    main()
