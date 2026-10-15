"""Tests for the codex review findings (mocked Azure only)."""
import csv
import io
from types import SimpleNamespace as NS
from unittest import mock

import pytest

from acasentry import azure_live, checks, cli, demo
from acasentry.output import csv_safe, write_csv
from acasentry.resilience import AcasentryError

SUB = "11111111-2222-3333-4444-555555555555"


def rid(rg, name):
    return f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.App/containerApps/{name}"


def napp(name, rg, identity="None", external=True):
    return {"name": name, "id": rid(rg, name), "resource_group": rg, "environment": "env",
            "ingress": {"enabled": True, "external": external, "ip_rules": []},
            "auth_enabled": "off", "identity": identity, "secrets": [], "env": []}


DUPES = [napp("api", "rg-a"), napp("api", "rg-b", identity="SystemAssigned")]


@pytest.fixture
def live(monkeypatch):
    calls = []
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: [dict(a) for a in DUPES])
    monkeypatch.setattr(azure_live, "enable_system_identity", lambda sub, a: calls.append(("id", a["id"])))
    monkeypatch.setattr(azure_live, "apply_lockdown", lambda sub, a, ips: calls.append(("lock", a["id"])))
    return calls


# 1. duplicate names
def test_identity_apply_targets_exact_resource(live, capsys):
    assert cli.main(["identity", "--subscription", SUB, "--apply"]) == 0
    assert live == [("id", rid("rg-a", "api"))]


def test_lockdown_ambiguous_name_refused_with_candidates(live, capsys):
    assert cli.main(["lockdown", "api", "--subscription", SUB, "--apply"]) == 2
    err = capsys.readouterr().err
    assert rid("rg-a", "api") in err and rid("rg-b", "api") in err and live == []


def test_lockdown_by_resource_group(live):
    assert cli.main(["lockdown", "api", "--resource-group", "RG-B", "--subscription", SUB, "--apply"]) == 0
    assert live == [("lock", rid("rg-b", "api"))]


def test_lockdown_by_resource_id(live):
    assert cli.main(["lockdown", rid("rg-a", "api").upper(), "--subscription", SUB, "--apply"]) == 0
    assert live == [("lock", rid("rg-a", "api"))]


def test_identity_resource_group_filter(live):
    assert cli.main(["identity", "--resource-group", "rg-b", "--subscription", SUB, "--apply"]) == 0
    assert live == []


# 4. AllowAnonymous / excluded paths
def _cfg(action=None, excluded=None, enabled=True):
    gv = NS(unauthenticated_client_action=action, excluded_paths=excluded)
    return NS(platform=NS(enabled=enabled), global_validation=gv)


def test_auth_state_allow_anonymous_is_optional():
    assert azure_live.auth_state([_cfg("AllowAnonymous")]) == ("optional", False)
    assert azure_live.auth_state([_cfg("RedirectToLoginPage")]) == ("required", False)
    assert azure_live.auth_state([_cfg("Return401", ["/health"])]) == ("required", True)
    assert azure_live.auth_state([_cfg("Return401", enabled=False)]) == ("off", False)
    assert azure_live.auth_state([]) == ("off", False)


def test_exposure_flags_auth_not_enforced():
    a = napp("x", "rg"); a["auth_enabled"] = "optional"; a["auth_excluded_paths"] = True
    assert checks.exposure_rows([a])[0][4] == "NO_IP_RULES,AUTH_NOT_ENFORCED,AUTH_EXCLUDED_PATHS"


# 5. internal environment
def test_env_internal_detection():
    assert azure_live._env_internal(NS(vnet_configuration=NS(internal=True), public_network_access=None))
    assert azure_live._env_internal(NS(vnet_configuration=None, public_network_access="Disabled"))
    assert not azure_live._env_internal(NS(vnet_configuration=NS(internal=False), public_network_access="Enabled"))


def test_exposure_vnet_only_not_flagged_as_internet():
    a = napp("x", "rg"); a["env_internal"] = True
    assert checks.exposure_rows([a])[0][1:] == ["vnet-only", "0", "off", "ok"]


def test_load_apps_marks_env_internal():
    env_id = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/e1"
    app = NS(name="a", id=rid("rg", "a"), managed_environment_id=env_id.upper(), identity=None,
             configuration=NS(ingress=NS(external=True, ip_security_restrictions=None), secrets=[]),
             template=None)
    client = NS(container_apps=NS(list_by_subscription=lambda: iter([app])),
                managed_environments=NS(list_by_subscription=lambda: iter([
                    NS(id=env_id, vnet_configuration=NS(internal=True), public_network_access=None)])),
                container_apps_auth_configs=NS(list_by_container_app=lambda rg, n: iter([])))
    out = azure_live.load_apps(SUB, check_auth=True, client=client)
    assert out[0]["env_internal"] is True


# 6. init containers
def test_init_container_literal_secret_found():
    e = NS(name="SMTP_PASSWORD", value="x", secret_ref=None)
    app = NS(name="a", id=rid("rg", "a"), managed_environment_id=None, identity=None, configuration=None,
             template=NS(containers=[NS(name="main", env=[])], init_containers=[NS(name="migrate", env=[e])]))
    rows = checks.secrets_rows([azure_live._normalize(app)])
    assert rows == [["a", "env", "migrate", "SMTP_PASSWORD", "PLAINTEXT_ENV"]]


# 7. resource ID casing / malformed
def test_rg_case_insensitive_and_malformed():
    assert azure_live._rg("/subscriptions/s/resourcegroups/My-RG/providers/x") == "My-RG"
    with pytest.raises(AcasentryError, match="Malformed"):
        azure_live._rg("/subscriptions/s/providers/x")


# 8. lockdown plan for apps without ingress
def test_lockdown_plan_no_ingress():
    a = napp("w", "rg"); a["ingress"] = None
    assert checks.lockdown_plan(a, []) == []
    with pytest.raises(ValueError, match="ingress disabled"):
        checks.lockdown_plan(a, ["10.0.0.0/8"])


def test_lockdown_no_ingress_cli_is_noop(monkeypatch, capsys):
    a = napp("w", "rg"); a["ingress"] = None
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: [a])
    apply = mock.Mock()
    monkeypatch.setattr(azure_live, "apply_lockdown", apply)
    assert cli.main(["lockdown", "w", "--subscription", SUB, "--apply"]) == 0
    assert "Nothing to change" in capsys.readouterr().out and not apply.called


# 9. partial failure reporting
def test_partial_failure_reported_nonzero(monkeypatch, capsys):
    apps = [napp("a", "rg"), napp("b", "rg")]
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: apps)

    def enable(sub, app):
        if app["name"] == "b":
            raise RuntimeError("boom")
    monkeypatch.setattr(azure_live, "enable_system_identity", enable)
    assert cli.main(["identity", "--subscription", SUB, "--apply"]) == 1
    cap = capsys.readouterr()
    out = cap.out
    assert out.index("PLANNED") < out.index("OK      " + rid("rg", "a"))
    assert "FAILED  " + rid("rg", "b") in out and "1 of 2 change(s) applied" in cap.err


# 10. CSV formula injection
@pytest.mark.parametrize("bad", ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx"])
def test_csv_formula_neutralized(bad):
    assert csv_safe(bad) == "'" + bad


def test_csv_malicious_role_name(tmp_path):
    f = tmp_path / "o.csv"
    write_csv(str(f), ["ROLE"], [["=HYPERLINK(\"http://x\")"], ["Reader"]])
    rows = list(csv.reader(io.StringIO(f.read_text())))
    assert rows[1][0].startswith("'=") and rows[2][0] == "Reader"


# 12. flag rename
def test_secret_flag_renamed():
    flags = {r[-1] for r in checks.secrets_rows(demo.APPS)}
    assert flags == {"INLINE_SECRET", "PLAINTEXT_ENV"}


# review fix: interrupted apply reports progress
def test_interrupted_apply_reports_progress(monkeypatch, capsys):
    apps = [napp("a", "rg"), napp("b", "rg")]
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: apps)

    def enable(sub, app):
        if app["name"] == "b":
            raise KeyboardInterrupt
    monkeypatch.setattr(azure_live, "enable_system_identity", enable)
    assert cli.main(["identity", "--subscription", SUB, "--apply"]) == 130
    assert "1 of 2 change(s) applied" in capsys.readouterr().err
