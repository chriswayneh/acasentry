"""Pure analysis functions over normalized data."""

PRIVILEGED = {"Owner", "Contributor"}


def is_guest(principal):
    return "#EXT#" in principal.upper() or principal.endswith(" [guest]")


def rbac_rows(assignments):
    rows = []
    for a in assignments:
        flags = []
        if a["role"] in PRIVILEGED:
            flags.append(a["role"].upper())
        if is_guest(a["principal"]):
            flags.append("GUEST")
        rows.append([a["scope_name"], a["principal"], a["type"], a["role"], ",".join(flags) or "ok"])
    return rows


def _auth_state(app):
    """'required', 'optional' (enabled but anonymous allowed), or 'off'. Accepts legacy bools."""
    val = app.get("auth_enabled")
    if val is True:
        return "required"
    if not val:
        return "off"
    return val


def exposure_rows(apps):
    rows = []
    for app in apps:
        ing = app.get("ingress") or {}
        if not ing.get("external"):
            continue
        reach = "vnet-only" if app.get("env_internal") else "public"
        auth = _auth_state(app)
        flags = []
        if reach == "public":
            if not ing.get("ip_rules"):
                flags.append("NO_IP_RULES")
            if auth == "off":
                flags.append("NO_AUTH")
            elif auth == "optional":
                flags.append("AUTH_NOT_ENFORCED")
            if app.get("auth_excluded_paths"):
                flags.append("AUTH_EXCLUDED_PATHS")
        rows.append([app["name"], reach, str(len(ing.get("ip_rules") or [])), auth, ",".join(flags) or "ok"])
    return rows


SENSITIVE = ("PASSWORD", "SECRET", "TOKEN", "KEY", "CONN")


VALUE_MASK = "********"


def has_literal(env):
    """True when the env var has a literal value. Values themselves are never shown:
    the VALUE column is always the fixed mask VALUE_MASK."""
    return bool(env.get("has_value", env.get("value")))


def secrets_rows(apps):
    """INLINE_SECRET: a Container Apps secret not backed by a Key Vault reference
    (stored encrypted by Container Apps, but not centrally managed or rotated).
    PLAINTEXT_ENV: an env var whose literal value is in the app template and whose
    name looks sensitive."""
    rows = []
    for app in apps:
        for s in app.get("secrets", []):
            if not s.get("key_vault_url"):
                rows.append([app["name"], "secret", "-", s["name"], "-", "INLINE_SECRET"])
        for e in app.get("env", []):
            if has_literal(e) and not e.get("secret_ref") and any(k in e["name"].upper() for k in SENSITIVE):
                rows.append([app["name"], "env", e.get("container") or "-", e["name"], VALUE_MASK, "PLAINTEXT_ENV"])
    return rows


def needs_identity(app):
    return "SystemAssigned" not in (app.get("identity") or "None")


def identity_rows(apps):
    rows = []
    for app in apps:
        if not needs_identity(app):
            continue
        cur = app.get("identity") or "None"
        new = "SystemAssigned" if cur == "None" else "SystemAssigned,UserAssigned"
        rows.append([app["name"], app.get("resource_group", "-"), cur, new])
    return rows


def has_ingress(app):
    ing = app.get("ingress")
    return bool(ing) and ing.get("enabled", True)


def lockdown_plan(app, allow_ips):
    """Return plan rows; an empty list means nothing to change."""
    rg = app.get("resource_group", "-")
    if not has_ingress(app):
        if allow_ips:
            raise ValueError(f"App '{app['name']}' has ingress disabled; IP restrictions cannot be added. "
                             "It is not reachable over HTTP, so there is nothing to lock down.")
        return []
    ing = app["ingress"]
    if allow_ips:
        current = list(ing.get("ip_rules") or [])
        planned = current + [ip for ip in dict.fromkeys(allow_ips) if ip not in current]
        if planned == current:
            return []
        return [[app["name"], rg, "ip_rules", ",".join(current) or "(none)", ",".join(planned)]]
    if not ing.get("external"):
        return []
    return [[app["name"], rg, "external", "True", "False"]]


def select_app(apps, ref, resource_group=None):
    """Find exactly one app by name (optionally within a resource group) or by full resource ID."""
    if ref.lower().startswith("/subscriptions/"):
        matches = [a for a in apps if (a.get("id") or "").lower() == ref.lower()]
    else:
        matches = [a for a in apps if a["name"] == ref and (
            resource_group is None or (a.get("resource_group") or "").lower() == resource_group.lower())]
    if not matches:
        where = f" in resource group '{resource_group}'" if resource_group else ""
        raise LookupError(f"App '{ref}' not found{where}.")
    if len(matches) > 1:
        ids = "\n  ".join(a.get("id") or a["name"] for a in matches)
        raise LookupError(f"App name '{ref}' matches {len(matches)} apps. Re-run with --resource-group "
                          f"or pass the full resource ID. Candidates:\n  {ids}")
    return matches[0]
