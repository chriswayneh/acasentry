"""Built-in mock data. No Azure access required.

The literal values for API_TOKEN and SMTP_PASSWORD are fake demo values used to
exercise the secrets check, not real credentials. Env entries are built with
_env() so bandit no longer misreads every "secret_ref": None as a password,
which is why no `# nosec` markers are needed.
"""

SUB = "00000000-0000-0000-0000-000000000000"
RG = "rg-demo"


def _env(name, value=None, ref=None, container="app"):
    # Same shape as live data: only whether a literal value exists, never the value.
    return {"name": name, "has_value": bool(value), "secret_ref": ref, "container": container}


def _id(kind, name):
    return f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.App/{kind}/{name}"


ENVIRONMENTS = [{"name": "cae-prod", "id": _id("managedEnvironments", "cae-prod")}]

APPS = [
    {
        "name": "orders-api", "id": _id("containerApps", "orders-api"), "resource_group": RG, "environment": "cae-prod",
        "ingress": {"external": True, "ip_rules": []}, "auth_enabled": False,
        "identity": "None",
        "secrets": [{"name": "db-password", "key_vault_url": None},
                    {"name": "stripe-key", "key_vault_url": "https://kv-demo.vault.azure.net/secrets/stripe-key"}],
        "env": [_env("API_TOKEN", "abc123", None),  # fake demo value
                _env("DB_PASSWORD", None, "db-password"),
                _env("LOG_LEVEL", "info", None)],
    },
    {
        "name": "web-frontend", "id": _id("containerApps", "web-frontend"), "resource_group": RG, "environment": "cae-prod",
        "ingress": {"external": True, "ip_rules": ["203.0.113.0/24"]}, "auth_enabled": True,
        "identity": "SystemAssigned",
        "secrets": [{"name": "session-key", "key_vault_url": "https://kv-demo.vault.azure.net/secrets/session-key"}],
        "env": [_env("LOG_LEVEL", "warn", None)],
    },
    {
        "name": "billing-worker", "id": _id("containerApps", "billing-worker"), "resource_group": RG, "environment": "cae-prod",
        "ingress": {"external": False, "ip_rules": []}, "auth_enabled": False,
        "identity": "UserAssigned",
        "secrets": [{"name": "smtp-pass", "key_vault_url": None}],
        "env": [_env("SMTP_PASSWORD", "hunter2", None)],  # fake demo value
    },
]

ROLE_ASSIGNMENTS = [
    {"scope_name": "cae-prod", "principal": "alice@contoso.com", "type": "User", "role": "Owner"},
    {"scope_name": "cae-prod", "principal": "ops-team", "type": "Group", "role": "Reader"},
    {"scope_name": "orders-api", "principal": "bob_partner.com#EXT#@contoso.onmicrosoft.com", "type": "User", "role": "Contributor"},
    {"scope_name": "orders-api", "principal": "ci-deployer", "type": "ServicePrincipal", "role": "Contributor"},
    {"scope_name": "web-frontend", "principal": "carol@contoso.com", "type": "User", "role": "Reader"},
    {"scope_name": "billing-worker", "principal": "dave@contoso.com", "type": "User", "role": "ContainerApp Reader"},
]
