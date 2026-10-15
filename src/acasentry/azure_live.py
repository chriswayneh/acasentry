"""Live Azure access. Azure SDKs are imported lazily."""


def _cred():
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def _aca(sub):
    from azure.mgmt.appcontainers import ContainerAppsAPIClient
    return ContainerAppsAPIClient(_cred(), sub)


def _rg(resource_id):
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1]


def _normalize(app):
    cfg = app.configuration
    ing = cfg.ingress if cfg else None
    secrets = [{"name": s.name, "key_vault_url": getattr(s, "key_vault_url", None)}
               for s in ((cfg.secrets or []) if cfg else [])]
    env = []
    for c in (app.template.containers or []) if app.template else []:
        for e in c.env or []:
            env.append({"name": e.name, "value": e.value, "secret_ref": e.secret_ref})
    return {
        "name": app.name, "id": app.id, "resource_group": _rg(app.id),
        "environment": (app.managed_environment_id or "").split("/")[-1],
        "ingress": {"external": bool(ing and ing.external),
                    "ip_rules": [r.ip_address_range for r in ((ing.ip_security_restrictions or []) if ing else [])]},
        "auth_enabled": None, "identity": str(app.identity.type) if app.identity else "None",
        "secrets": secrets, "env": env,
    }


def load_apps(sub, check_auth=False):
    client = _aca(sub)
    apps = [_normalize(a) for a in client.container_apps.list_by_subscription()]
    if check_auth:
        for a in apps:
            try:
                cfgs = list(client.container_apps_auth_configs.list_by_container_app(a["resource_group"], a["name"]))
                a["auth_enabled"] = any(c.platform and c.platform.enabled for c in cfgs)
            except Exception:
                a["auth_enabled"] = False
    return apps


def load_role_assignments(sub):
    from azure.mgmt.authorization import AuthorizationManagementClient
    auth = AuthorizationManagementClient(_cred(), sub)
    client = _aca(sub)
    role_names = {}
    scopes = [(e.name, e.id) for e in client.managed_environments.list_by_subscription()]
    scopes += [(a.name, a.id) for a in client.container_apps.list_by_subscription()]
    out = []
    for name, scope in scopes:
        for ra in auth.role_assignments.list_for_scope(scope):
            rd = ra.role_definition_id
            if rd not in role_names:
                role_names[rd] = auth.role_definitions.get_by_id(rd).role_name
            out.append({"scope_name": name, "principal": ra.principal_id,
                        "type": str(ra.principal_type), "role": role_names[rd]})
    return out


def enable_system_identity(sub, app):
    from azure.mgmt.appcontainers.models import ManagedServiceIdentity
    client = _aca(sub)
    cur = client.container_apps.get(app["resource_group"], app["name"])
    new_type = "SystemAssigned" if app["identity"] == "None" else "SystemAssigned,UserAssigned"
    cur.identity = ManagedServiceIdentity(type=new_type,
                                          user_assigned_identities=cur.identity.user_assigned_identities if cur.identity else None)
    client.container_apps.begin_update(app["resource_group"], app["name"], cur).result()


def apply_lockdown(sub, app, allow_ips):
    from azure.mgmt.appcontainers.models import IpSecurityRestrictionRule
    client = _aca(sub)
    cur = client.container_apps.get(app["resource_group"], app["name"])
    if allow_ips:
        cur.configuration.ingress.ip_security_restrictions = [
            IpSecurityRestrictionRule(name=f"allow-{i}", ip_address_range=ip, action="Allow")
            for i, ip in enumerate(allow_ips)]
    else:
        cur.configuration.ingress.external = False
    client.container_apps.begin_update(app["resource_group"], app["name"], cur).result()
