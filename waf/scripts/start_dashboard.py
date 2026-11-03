import getpass
import os
import secrets

from werkzeug.security import generate_password_hash


def main():
    username = input("Dashboard username [analyst]: ").strip() or "analyst"
    password = getpass.getpass("Dashboard password: ")
    confirmation = getpass.getpass("Confirm dashboard password: ")
    if not password or password != confirmation:
        raise SystemExit("Password was empty or did not match confirmation.")

    os.environ["WAF_DASHBOARD_USERNAME"] = username
    os.environ["WAF_DASHBOARD_PASSWORD_HASH"] = generate_password_hash(password)
    os.environ["WAF_DASHBOARD_SESSION_SECRET"] = secrets.token_urlsafe(48)
    # This helper listens only on HTTP loopback. Public HTTPS startup keeps Secure cookies.
    os.environ.setdefault("WAF_SECURE_COOKIES", "false")

    password = ""
    confirmation = ""

    # Import after configuring operator credentials; run the same WSGI pipeline.
    os.environ['WAF_LISTEN_HOST'] = '127.0.0.1'
    os.environ['WAF_LISTEN_PORT'] = '8080'
    from waf.run import main as run_protected
    run_protected()


if __name__ == "__main__":
    main()
