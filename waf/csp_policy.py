"""CSP configuration schema and response policy, owned by the existing PolicyStore."""
from urllib.parse import urlsplit
import ipaddress
import re

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr, field_validator
from typing import Literal


class CSPPolicy(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    mode: Literal['enforce', 'off', 'report-only'] = 'enforce'
    script_src: tuple[StrictStr, ...] = ("'self'",)
    style_src: tuple[StrictStr, ...] = ("'self'",)
    img_src: tuple[StrictStr, ...] = ("'self'", 'https://images.unsplash.com', 'data:')
    connect_src: tuple[StrictStr, ...] = ("'self'",)
    object_src: tuple[StrictStr, ...] = ("'none'",)
    base_uri: tuple[StrictStr, ...] = ("'none'",)
    frame_ancestors: tuple[StrictStr, ...] = ("'none'",)
    form_action: tuple[StrictStr, ...] = ("'self'",)
    trusted_types: StrictBool = True

    @field_validator('script_src', 'style_src', 'img_src', 'connect_src', 'object_src',
                     'base_uri', 'frame_ancestors', 'form_action')
    @classmethod
    def sources(cls, values, info):
        if not 1 <= len(values) <= 10 or len(set(values)) != len(values):
            raise ValueError('Use 1–10 unique CSP sources.')
        if "'none'" in values and len(values) != 1:
            raise ValueError('none must be the only source.')
        if info.field_name in {'script_src', 'style_src', 'connect_src'} and "'self'" not in values:
            raise ValueError('self is required for management assets.')
        for value in values:
            if value in {"'self'", "'none'"} or value == 'data:' and info.field_name == 'img_src':
                continue
            if len(value) > 200 or any(c.isspace() or not 33 <= ord(c) <= 126 for c in value) or any(c in value for c in ";,*\\'\""):
                raise ValueError('Use exact HTTPS origins, self or none; no inline/eval/wildcards.')
            try:
                parsed = urlsplit(value)
                valid_scheme = parsed.scheme == 'https' or parsed.scheme == 'http' and parsed.hostname in {'127.0.0.1', 'localhost', '::1'}
                if (not valid_scheme or not parsed.hostname or parsed.username or parsed.password or
                        parsed.path or parsed.query or parsed.fragment or not parsed.port and value.endswith(':')):
                    raise ValueError()
                parsed.port  # Validate malformed or overflowing ports.
                try:
                    ipaddress.ip_address(parsed.hostname)
                except ValueError:
                    if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', parsed.hostname) or any(
                        not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                        for label in parsed.hostname.split('.')
                    ):
                        raise ValueError()
            except ValueError:
                raise ValueError('CSP origins must be valid HTTPS origins (HTTP loopback is test-only).') from None
        return values


def effective_mode(policy):
    if policy.mode == 'disabled' or policy.csp.mode == 'off':
        return 'off'
    return 'report-only' if policy.mode == 'monitor' or policy.csp.mode == 'report-only' else 'enforce'


def response_headers(policy):
    mode = effective_mode(policy)
    if mode == 'off':
        return {}
    csp = policy.csp
    directives = ["default-src 'none'", "script-src-attr 'none'", "style-src-attr 'none'"]
    for field in ['script_src', 'style_src', 'img_src', 'connect_src', 'object_src', 'base_uri', 'frame_ancestors', 'form_action']:
        directives.append(field.replace('_', '-') + ' ' + ' '.join(getattr(csp, field)))
    if csp.trusted_types:
        directives.extend(["require-trusted-types-for 'script'", "trusted-types 'none'"])
    directives.append('report-uri /csp-report')
    name = 'Content-Security-Policy' if mode == 'enforce' else 'Content-Security-Policy-Report-Only'
    return {name: '; '.join(directives)}


def coverage(policy, settings):
    return {'configured_mode': policy.csp.mode, 'effective_mode': effective_mode(policy),
            'management': 'served HTML responses only',
            'restaurant': 'served HTML responses' if settings.serve_frontend else 'not served (opt-in required)',
            'github_pages': 'NOT COVERED: publish migration gateways or use a verified header-capable origin',
            'live_deployment_verified': False,
            'reporting': 'bounded, redacted, client-reported telemetry; not proof of an attack'}
