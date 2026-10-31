"""Staff-login admission backed by the WAF's shared persistent policy store."""


def admit(policy_store, ip, username, policy):
    return policy_store.login_admission(ip, username, policy)


def failure(policy_store, ip, username, policy):
    return policy_store.record_login_failure(ip, username, policy)


def success(policy_store, username):
    policy_store.record_login_success(username)
