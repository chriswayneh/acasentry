"""Built-in mock data. No Azure access required."""

SUB = "00000000-0000-0000-0000-000000000000"
RG = "rg-demo"


def _id(kind, name):
    return f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.App/{kind}/{name}"


ENVIRONMENTS = [{"name": "cae-prod", "id": _id("managedEnvironments", "cae-prod")}]

APPS = [
    {
        "name": "orders-api", "id": _id("containerApps", "orders-api"), "environment": "cae-prod",
        "ingress": {"external": True, "ip_rules": []}, "auth_enabled": False,
        "identity": "None",
        "secrets": [{"name": "db-password", "key_vault_url": None},
                    {"name": "stripe-key", "key_vault_url": "https://kv-demo.vault.azure.net/secrets/stripe-key"}],
        "env": [{"name": "API_TOKEN", "value": "abc123", "secret_ref": None},
                {"name": "DB_PASSWORD", "value": None, "secret_ref": "db-password"},
                {"name": "LOG_LEVEL", "value": "info", "secret_ref": None}],
    },
    {
        "name": "web-frontend", "id": _id("containerApps", "web-frontend"), "environment": "cae-prod",
        "ingress": {"external": True, "ip_rules": ["203.0.113.0/24"]}, "auth_enabled": True,
        "identity": "SystemAssigned",
        "secrets": [{"name": "session-key", "key_vault_url": "https://kv-demo.vault.azure.net/secrets/session-key"}],
        "env": [{"name": "LOG_LEVEL", "value": "warn", "secret_ref": None}],
    },
    {
        "name": "billing-worker", "id": _id("containerApps", "billing-worker"), "environment": "cae-prod",
        "ingress": {"external": False, "ip_rules": []}, "auth_enabled": False,
        "identity": "UserAssigned",
        "secrets": [{"name": "smtp-pass", "key_vault_url": None}],
        "env": [{"name": "SMTP_PASSWORD", "value": "hunter2", "secret_ref": None}],
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
