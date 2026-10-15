"""Live Azure access. Azure SDKs are imported lazily."""
from .resilience import AcasentryError, call_with_retry, list_all


def _import_error(exc):
    return AcasentryError(
        f"Azure SDK packages are missing ({exc.name}). Reinstall with `pip install -e .`.")


def _cred():
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        raise _import_error(exc)
    return DefaultAzureCredential()


def _aca(sub):
    try:
        from azure.mgmt.appcontainers import ContainerAppsAPIClient
    except ImportError as exc:
        raise _import_error(exc)
    return ContainerAppsAPIClient(_cred(), sub)


def _rg(resource_id):
    parts = resource_id.split("/")
    lower = [p.lower() for p in parts]
    return parts[lower.index("resourcegroups") + 1]


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


def _auth_enabled(client, app):
    cfgs = list_all(lambda: client.container_apps_auth_configs.list_by_container_app(
        app["resource_group"], app["name"]))
    return any(c.platform and c.platform.enabled for c in cfgs)


def load_apps(sub, check_auth=False, client=None):
    client = client or _aca(sub)
    apps = [_normalize(a) for a in list_all(client.container_apps.list_by_subscription)]
    if check_auth:
        for a in apps:
            a["auth_enabled"] = _auth_enabled(client, a)
    return apps


def load_role_assignments(sub, client=None, auth=None):
    if auth is None:
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError as exc:
            raise _import_error(exc)
        auth = AuthorizationManagementClient(_cred(), sub)
    client = client or _aca(sub)
    role_names = {}
    scopes = [(e.name, e.id) for e in list_all(client.managed_environments.list_by_subscription)]
    scopes += [(a.name, a.id) for a in list_all(client.container_apps.list_by_subscription)]
    out = []
    for name, scope in scopes:
        for ra in list_all(lambda s=scope: auth.role_assignments.list_for_scope(s)):
            rd = ra.role_definition_id
            if rd not in role_names:
                role_names[rd] = call_with_retry(lambda: auth.role_definitions.get_by_id(rd)).role_name
            out.append({"scope_name": name, "principal": ra.principal_id,
                        "type": str(ra.principal_type), "role": role_names[rd]})
    return out


def _update(client, app, cur):
    call_with_retry(lambda: client.container_apps.begin_update(
        app["resource_group"], app["name"], cur).result())


def enable_system_identity(sub, app, client=None):
    from azure.mgmt.appcontainers.models import ManagedServiceIdentity
    client = client or _aca(sub)
    cur = call_with_retry(lambda: client.container_apps.get(app["resource_group"], app["name"]))
    new_type = "SystemAssigned" if app["identity"] == "None" else "SystemAssigned,UserAssigned"
    cur.identity = ManagedServiceIdentity(
        type=new_type, user_assigned_identities=cur.identity.user_assigned_identities if cur.identity else None)
    _update(client, app, cur)


def apply_lockdown(sub, app, allow_ips, client=None):
    from azure.mgmt.appcontainers.models import IpSecurityRestrictionRule
    client = client or _aca(sub)
    cur = call_with_retry(lambda: client.container_apps.get(app["resource_group"], app["name"]))
    if not cur.configuration or not cur.configuration.ingress:
        raise AcasentryError(f"App '{app['name']}' has no ingress configured; nothing to lock down.")
    if allow_ips:
        cur.configuration.ingress.ip_security_restrictions = [
            IpSecurityRestrictionRule(name=f"acasentry-allow-{i}", ip_address_range=ip, action="Allow")
            for i, ip in enumerate(allow_ips)]
    else:
        cur.configuration.ingress.external = False
    _update(client, app, cur)
