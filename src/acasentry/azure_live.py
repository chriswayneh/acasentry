"""Live Azure access. Azure SDKs are imported lazily."""

import urllib.request

from .resilience import (
    AcasentryError,
    call_with_retry,
    is_transient,
    list_all,
    status_of,
)


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
            "deny_rules": [
                r.ip_address_range
                for r in ((ing.ip_security_restrictions or []) if ing else [])
                if str(_enum(getattr(r, "action", "")) or "").lower() == "deny"
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
                    "scope_id": scope,
                    "principal_id": ra.principal_id,
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


def _redirect_error(code, location=None):
    where = f" to {location}" if location else ""
    return AcasentryError(
        f"Microsoft Graph answered with an HTTP {code} redirect{where}; refusing to follow "
        "it so the sign-in token is not sent to another host."
    )


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect from Graph, so the Bearer token is not sent elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _redirect_error(code, headers.get("Location") or newurl)


def graph_urlopen(req, timeout):
    """urlopen for Graph calls that treats any 3xx redirect as an error."""
    import urllib.error

    opener = urllib.request.build_opener(_RefuseRedirect())
    try:
        # GRAPH_URL is a fixed https constant, so the bandit B310 scheme warning does not apply.
        return opener.open(req, timeout=timeout)  # nosec B310
    except urllib.error.HTTPError as exc:
        # 3xx codes the redirect handler does not cover (300, 304, 305, 308 on Python 3.10)
        # arrive here; they are refused the same way.
        if 300 <= exc.code < 400:
            raise _redirect_error(exc.code, exc.headers.get("Location")) from None
        raise


class GraphSession:
    """Calls Microsoft Graph with a cached token that is refreshed when it is
    expired or within TOKEN_SKEW_SECONDS of expiring.

    It also calls Graph once more on a 401; azure-identity cannot force a refresh,
    so this usually reuses the cached token. A CAE claims challenge is not handled
    yet. Proper CAE (Continuous Access Evaluation) handling is planned.
    """

    def __init__(self, cred, clock=None, opener=None, skew=TOKEN_SKEW_SECONDS):
        import time

        self.cred, self.skew = cred, skew
        self.clock = clock or time.time
        self.opener = opener or graph_urlopen
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


def _patch(client, app, body):
    """Send a narrow JSON merge-patch body and wait for it to finish.

    The Container Apps SDK has no ETag / If-Match support, so concurrency safety
    comes from sending only the fields acasentry changes (computed from a fresh
    read just before the call). Submission is retried on transient errors (the
    narrow body makes a repeat idempotent). If polling fails, polling is resumed
    from the continuation token; the change is never resubmitted.
    """
    rg, name = app["resource_group"], app["name"]
    poller = call_with_retry(lambda: client.container_apps.begin_update(rg, name, body))
    try:
        return poller.result()
    except Exception as exc:
        if not is_transient(exc):
            raise
    token = poller.continuation_token()
    return call_with_retry(
        lambda: client.container_apps.begin_update(
            rg, name, body, continuation_token=token
        ).result()
    )


def _fresh(client, app):
    return call_with_retry(
        lambda: client.container_apps.get(app["resource_group"], app["name"])
    )


def enable_system_identity(sub, app, client=None):
    """Add a system-assigned identity, keeping any user-assigned identities.

    The current identity is taken from a fresh read, not from the earlier listing.
    """
    client = client or _aca(sub)
    cur = _fresh(client, app)
    current = identity_type(cur.identity)
    if "SystemAssigned" in current:
        return
    uai = (
        getattr(cur.identity, "user_assigned_identities", None)
        if cur.identity
        else None
    )
    identity = {"type": "SystemAssigned" if not uai else "SystemAssigned,UserAssigned"}
    if uai:
        identity["userAssignedIdentities"] = {k: {} for k in uai}
    _patch(client, app, {"identity": identity})


def apply_lockdown(sub, app, allow_ips, client=None):
    client = client or _aca(sub)
    cur = _fresh(client, app)
    if not cur.configuration or not cur.configuration.ingress:
        raise AcasentryError(
            f"App '{app['name']}' has no ingress configured; nothing to lock down."
        )
    ing = cur.configuration.ingress
    if allow_ips:
        rules = merge_ip_rules(ing.ip_security_restrictions, allow_ips)
        ingress = {"ipSecurityRestrictions": rules}
    else:
        ingress = {"external": False}
    _patch(client, app, {"properties": {"configuration": {"ingress": ingress}}})


def _rule_dict(r):
    d = {
        "name": r.name,
        "ipAddressRange": r.ip_address_range,
        "action": str(_enum(r.action)),
    }
    if getattr(r, "description", None):
        d["description"] = r.description
    return d


def merge_ip_rules(existing, allow_ips):
    """Keep existing rules and append Allow rules for CIDRs not already present.

    Returns JSON-ready dicts. New rule names never collide with existing ones.
    """
    existing = list(existing or [])
    if any(
        str(_enum(getattr(r, "action", "")) or "").lower() == "deny" for r in existing
    ):
        raise AcasentryError(
            "This app has Deny IP rules; Azure does not allow mixing Allow and Deny rules. "
            "Review its ingress rules manually."
        )
    out = [_rule_dict(r) for r in existing]
    have = {r["ipAddressRange"] for r in out}
    names = {r["name"] for r in out}
    n = 0
    for ip in allow_ips:
        if ip in have:
            continue
        while f"acasentry-allow-{n}" in names:
            n += 1
        name = f"acasentry-allow-{n}"
        out.append({"name": name, "ipAddressRange": ip, "action": "Allow"})
        have.add(ip)
        names.add(name)
    return out
