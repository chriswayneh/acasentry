"""Pure analysis functions over normalized data."""

PRIVILEGED = {"Owner", "Contributor"}


def is_guest(principal):
    return "#EXT#" in principal.upper()


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


def exposure_rows(apps):
    rows = []
    for app in apps:
        ing = app.get("ingress") or {}
        if not ing.get("external"):
            continue
        flags = []
        if not ing.get("ip_rules"):
            flags.append("NO_IP_RULES")
        if not app.get("auth_enabled"):
            flags.append("NO_AUTH")
        rows.append([app["name"], "external", str(len(ing.get("ip_rules") or [])),
                     "yes" if app.get("auth_enabled") else "no", ",".join(flags) or "ok"])
    return rows


SENSITIVE = ("PASSWORD", "SECRET", "TOKEN", "KEY", "CONN")


def secrets_rows(apps):
    rows = []
    for app in apps:
        for s in app.get("secrets", []):
            if not s.get("key_vault_url"):
                rows.append([app["name"], "secret", s["name"], "PLAINTEXT_SECRET"])
        for e in app.get("env", []):
            if e.get("value") and not e.get("secret_ref") and any(k in e["name"].upper() for k in SENSITIVE):
                rows.append([app["name"], "env", e["name"], "PLAINTEXT_ENV"])
    return rows


def identity_rows(apps):
    rows = []
    for app in apps:
        cur = app.get("identity") or "None"
        if "SystemAssigned" in cur:
            continue
        new = "SystemAssigned" if cur == "None" else "SystemAssigned,UserAssigned"
        rows.append([app["name"], cur, new])
    return rows


def lockdown_plan(app, allow_ips):
    ing = app.get("ingress") or {}
    if allow_ips:
        current = list(ing.get("ip_rules") or [])
        planned = current + [ip for ip in dict.fromkeys(allow_ips) if ip not in current]
        return [[app["name"], "ip_rules", ",".join(current) or "(none)", ",".join(planned)]]
    return [[app["name"], "external", str(bool(ing.get("external"))), "False"]]
