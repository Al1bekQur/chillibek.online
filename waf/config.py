from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WAFSettings:
    upstream_base_url: str = os.getenv("WAF_UPSTREAM_BASE_URL", "http://127.0.0.1:5000")
    listen_host: str = os.getenv("WAF_LISTEN_HOST", "127.0.0.1")
    listen_port: int = int(os.getenv("WAF_LISTEN_PORT", "8080"))
    max_request_bytes: int = 1 * 1024 * 1024
    upstream_timeout_seconds: float = 5.0
    block_threshold: int = 5
    log_path: Path = Path(__file__).resolve().parent / "logs" / "waf.log"
    upstream_transport: Any | None = None
    forward_upstream_cookies: bool = False
    dashboard_username: str | None = os.getenv("WAF_DASHBOARD_USERNAME")
    dashboard_password_hash: str | None = os.getenv("WAF_DASHBOARD_PASSWORD_HASH")
    dashboard_session_secret: str | None = os.getenv("WAF_DASHBOARD_SESSION_SECRET")
    dashboard_session_max_age: int = 8 * 60 * 60
    dashboard_log_read_limit: int = 5000
    policy_path: Path | None = Path(os.environ["WAF_POLICY_PATH"]) if os.getenv("WAF_POLICY_PATH") else None
    dashboard_secure_cookies: bool = os.getenv("WAF_SECURE_COOKIES", "true").lower() == "true"
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
