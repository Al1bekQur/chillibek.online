import getpass
import os
import secrets

import uvicorn
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

    password = ""
    confirmation = ""

    uvicorn.run("waf.app:app", host="127.0.0.1", port=8080, reload=False)


if __name__ == "__main__":
    main()
