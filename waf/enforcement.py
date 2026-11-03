"""Trusted per-request handoff from the WAF to authentication, never HTTP headers."""
from dataclasses import dataclass, field

from .policy import Policy


CONTEXT_KEY = 'chillibek.waf_context'


def staff_policy(policy: Policy, allow_disabled_mode: bool) -> Policy:
    # Production can monitor request detectors without permitting unlimited
    # password guesses. The UI reports this mandatory admission explicitly.
    if not allow_disabled_mode:
        return policy.model_copy(update={'mode': 'block', 'brute_force': True})
    return policy


@dataclass
class RequestPolicy:
    policy: Policy
    revision: int
    store: object
    allow_disabled_mode: bool
    rules: list[str] = field(default_factory=list)
    blocked: bool = False

    @property
    def login_policy(self):
        return staff_policy(self.policy, self.allow_disabled_mode)
