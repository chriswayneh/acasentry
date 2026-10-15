"""Live Azure access. Azure SDKs are imported lazily."""

from .resilience import AcasentryError, call_with_retry, list_all, status_of


def _import_error(exc):
    return AcasentryError(
        f"Azure SDK packages are missing ({exc.name}). Reinstall with `pip install -e .`."
    )


def _cred():
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        raise _import_error(exc)
    return DefaultAzureCredential()


# acasentry's own call_with_retry owns throttling/backoff, so the SDK pipeline
# retry is disabled to avoid stacking two retry loops (up to 10 x 5 attempts).
SDK_KWARGS = {"retry_total": 0}


def _aca(sub):
    try:
        from azure.mgmt.appcontainers import ContainerAppsAPIClient
    except ImportError as exc:
        raise _import_error(exc)
    return ContainerAppsAPIClient(_cred(), sub, **SDK_KWARGS)


def _rg(resource_id):
    parts = (resource_id or "").split("/")
    lower = [p.lower() for p in parts]
    try:
        rg = parts[lower.index("resourcegroups") + 1]
    except (ValueError, IndexError):
        rg = ""
    if not rg:
        raise AcasentryError(
            f"Malformed Azure resource ID (no resource group segment): '{resource_id}'"
        )
    return rg


def _normalize(app):
    cfg = app.configuration
    ing = cfg.ingress if cfg else None
    secrets = [
        {"name": s.name, "key_vault_url": getattr(s, "key_vault_url", None)}
        for s in ((cfg.secrets or []) if cfg else [])
    ]
    env = []
    tmpl = app.template
    containers = list((getattr(tmpl, "containers", None) or []) if tmpl else [])
    containers += list((getattr(tmpl, "init_containers", None) or []) if tmpl else [])
    for c in containers:
        for e in getattr(c, "env", None) or []:
            # Never keep the raw value: only whether a literal value is set.
            env.append(
                {
                    "name": e.name,
                    "has_value": bool(e.value),
                    "secret_ref": e.secret_ref,
                    "container": getattr(c, "name", None) or "-",
                }
            )
    return {
        "name": app.name,
        "id": app.id,
        "resource_group": _rg(app.id),
        "environment": (app.managed_environment_id or "").split("/")[-1],
        "environment_id": app.managed_environment_id,
        "ingress": None
        if ing is None
        else {
            "enabled": True,
            "external": bool(ing.external),
            "ip_rules": [
                r.ip_address_range
                for r in ((ing.ip_security_restrictions or []) if ing else [])
            ],
        },
        "auth_enabled": None,
        "identity": identity_type(app.identity),
        "secrets": secrets,
        "env": env,
    }


def identity_type(identity):
    """Normalize an identity type (enum or string) to e.g. 'SystemAssigned,UserAssigned'.

    str() of the SDK enum gives 'ManagedServiceIdentityType.SYSTEM_ASSIGNED' on newer
    Pythons, so always use .value when present.
    """
    if identity is None or identity.type is None:
        return "None"
    t = getattr(identity.type, "value", identity.type)
    return ",".join(p.strip() for p in str(t).split(",")) or "None"


def _enum(v):
    return getattr(v, "value", v)


def auth_state(cfgs):
    """Return (state, excluded_paths) where state is 'required', 'optional' or 'off'.

    Enabled auth with unauthenticatedClientAction AllowAnonymous does not require
    sign-in, so it is 'optional'.
    """
    state, excluded = "off", False
    for c in cfgs:
        if not (c.platform and c.platform.enabled):
            continue
        gv = getattr(c, "global_validation", None)
        action = (
            _enum(getattr(gv, "unauthenticated_client_action", None)) if gv else None
        )
        cur = (
            "optional"
            if (action is None or str(action) == "AllowAnonymous")
            else "required"
        )
        if cur == "required" or state == "off":
            state = cur
        if gv is not None and getattr(gv, "excluded_paths", None):
            excluded = True
    return state, excluded


def _env_internal(env):
    vnet = getattr(env, "vnet_configuration", None)
    if vnet is not None and getattr(vnet, "internal", False):
        return True
    return str(_enum(getattr(env, "public_network_access", None))) == "Disabled"


def load_apps(sub, check_auth=False, client=None):
    client = client or _aca(sub)
    apps = [_normalize(a) for a in list_all(client.container_apps.list_by_subscription)]
    if check_auth:
        internal = {
            (e.id or "").lower(): _env_internal(e)
            for e in list_all(client.managed_environments.list_by_subscription)
        }
        for a in apps:
            cfgs = list_all(
                lambda a=a: client.container_apps_auth_configs.list_by_container_app(
                    a["resource_group"], a["name"]
                )
            )
            a["auth_enabled"], a["auth_excluded_paths"] = auth_state(cfgs)
            a["env_internal"] = internal.get(
                (a.get("environment_id") or "").lower(), False
            )
    return apps


def load_role_assignments(sub, client=None, auth=None, graph=None):
    if auth is None:
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError as exc:
            raise _import_error(exc)
        auth = AuthorizationManagementClient(_cred(), sub, **SDK_KWARGS)
    client = client or _aca(sub)
    role_names = {}
    scopes = [
        (e.name, e.id)
        for e in list_all(client.managed_environments.list_by_subscription)
    ]
    scopes += [
        (a.name, a.id) for a in list_all(client.container_apps.list_by_subscription)
    ]
    out = []
    for name, scope in scopes:
        for ra in list_all(lambda s=scope: auth.role_assignments.list_for_scope(s)):
            rd = ra.role_definition_id
            if rd not in role_names:
                role_names[rd] = call_with_retry(
                    lambda rd=rd: auth.role_definitions.get_by_id(rd)
                ).role_name
            ptype = getattr(ra.principal_type, "value", ra.principal_type)
            out.append(
                {
                    "scope_name": name,
                    "principal": ra.principal_id,
                    "type": str(ptype),
                    "role": role_names[rd],
                }
            )
    names = resolve_principals({r["principal"] for r in out}, graph)
    for r in out:
        r["principal"] = names.get(r["principal"], r["principal"])
    return out


GRAPH_URL = "https://graph.microsoft.com/v1.0/directoryObjects/getByIds"


GRAPH_SCOPE = "https://graph.microsoft.com/.default"
TOKEN_SKEW_SECONDS = 300


class GraphSession:
    """Calls Microsoft Graph with a cached token that is refreshed when it is
    expired or within TOKEN_SKEW_SECONDS of expiring.

    It also calls Graph once more on a 401; azure-identity cannot force a refresh,
    so this usually reuses the cached token. A CAE claims challenge is not handled
    yet. Proper CAE (Continuous Access Evaluation) handling is planned.
    """

    def __init__(self, cred, clock=None, opener=None, skew=TOKEN_SKEW_SECONDS):
        import time
        import urllib.request

        self.cred, self.skew = cred, skew
        self.clock = clock or time.time
        self.opener = opener or urllib.request.urlopen
        self._token = None

    def token(self, force=False):
        if (
            force
            or self._token is None
            or self._token.expires_on - self.skew <= self.clock()
        ):
            self._token = self.cred.get_token(GRAPH_SCOPE)
        return self._token.token

    def _send(self, body, token):
        import json
        import urllib.request

        req = urllib.request.Request(
            GRAPH_URL,
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        # GRAPH_URL is a fixed https constant, so the bandit B310 scheme warning does not apply.
        with self.opener(req, timeout=30) as resp:  # nosec B310
            return json.loads(resp.read())

    def __call__(self, body):
        import urllib.error

        try:
            return self._send(body, self.token())
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            return self._send(body, self.token(force=True))


def _graph_post(cred):
    return GraphSession(cred)


def resolve_principals(ids, graph=None):
    """Map principal object IDs to UPN (users) or display name via Microsoft Graph.

    Degrades gracefully: if Graph is unavailable or denied, IDs are kept and a
    warning is printed once to stderr.
    """
    import sys

    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

    ids = sorted(i for i in ids if i)
    if not ids:
        return {}
    try:
        post = graph or _graph_post(_cred())
        names = {}
        for i in range(0, len(ids), 1000):
            body = {
                "ids": ids[i : i + 1000],
                "types": ["user", "group", "servicePrincipal"],
            }
            for obj in call_with_retry(lambda body=body: post(body)).get("value", []):
                name = (
                    obj.get("userPrincipalName") or obj.get("displayName") or obj["id"]
                )
                if obj.get("userType") == "Guest" and "#EXT#" not in name.upper():
                    name += " [guest]"
                names[obj["id"]] = name
        return names
    except AcasentryError:
        raise
    except (
        OSError,
        ValueError,
        KeyError,
        ClientAuthenticationError,
        HttpResponseError,
    ) as exc:
        if isinstance(exc, ClientAuthenticationError):
            print(
                "warning: could not get a Microsoft Graph sign-in token (sign-in missing or expired). "
                "Run `az login` again, then re-run. Showing object IDs for now; guest detection "
                "may be incomplete.",
                file=sys.stderr,
            )
            return {}
        if getattr(exc, "code", None) == 401 or status_of(exc) == 401:
            print(
                "warning: Microsoft Graph rejected the sign-in token (401). Run `az login` again, "
                "then re-run. Showing object IDs for now; guest detection may be incomplete.",
                file=sys.stderr,
            )
            return {}
        print(
            "warning: could not resolve principal names via Microsoft Graph "
            f"({type(exc).__name__}); showing object IDs, guest detection may be incomplete. "
            "Grant Directory.Read.All or User.Read.All to fix.",
            file=sys.stderr,
        )
        return {}


def _update(client, app, cur):
    call_with_retry(
        lambda: client.container_apps.begin_update(
            app["resource_group"], app["name"], cur
        ).result()
    )


def enable_system_identity(sub, app, client=None):
    from azure.mgmt.appcontainers.models import ManagedServiceIdentity

    client = client or _aca(sub)
    cur = call_with_retry(
        lambda: client.container_apps.get(app["resource_group"], app["name"])
    )
    new_type = (
        "SystemAssigned" if app["identity"] == "None" else "SystemAssigned,UserAssigned"
    )
    cur.identity = ManagedServiceIdentity(
        type=new_type,
        user_assigned_identities=cur.identity.user_assigned_identities
        if cur.identity
        else None,
    )
    _update(client, app, cur)


def apply_lockdown(sub, app, allow_ips, client=None):
    from azure.mgmt.appcontainers.models import IpSecurityRestrictionRule

    client = client or _aca(sub)
    cur = call_with_retry(
        lambda: client.container_apps.get(app["resource_group"], app["name"])
    )
    if not cur.configuration or not cur.configuration.ingress:
        raise AcasentryError(
            f"App '{app['name']}' has no ingress configured; nothing to lock down."
        )
    if allow_ips:
        ing = cur.configuration.ingress
        ing.ip_security_restrictions = merge_ip_rules(
            ing.ip_security_restrictions, allow_ips, IpSecurityRestrictionRule
        )
    else:
        cur.configuration.ingress.external = False
    _update(client, app, cur)


def merge_ip_rules(existing, allow_ips, rule_cls):
    """Keep existing rules and append Allow rules for CIDRs not already present."""
    existing = list(existing or [])
    if any((getattr(r, "action", "") or "").lower() == "deny" for r in existing):
        raise AcasentryError(
            "This app has Deny IP rules; Azure does not allow mixing Allow and Deny rules. "
            "Review its ingress rules manually."
        )
    have = {r.ip_address_range for r in existing}
    for ip in allow_ips:
        if ip not in have:
            existing.append(
                rule_cls(
                    name=f"acasentry-allow-{len(existing)}",
                    ip_address_range=ip,
                    action="Allow",
                )
            )
            have.add(ip)
    return existing
