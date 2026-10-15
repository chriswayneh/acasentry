"""Codex runner 2026-10-15 findings. Mocked Azure only."""

from types import SimpleNamespace as NS
from unittest import mock

from azure.core.exceptions import HttpResponseError, ServiceResponseError

from acasentry import azure_live, checks, cli, demo
from acasentry.resilience import is_transient

SUB = "11111111-2222-3333-4444-555555555555"
RID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.App/containerApps/a"
APP = {"name": "a", "id": RID, "resource_group": "rg", "identity": "None"}


class Poller:
    def __init__(self, fail_polls=0):
        self.fail_polls = fail_polls

    def result(self):
        if self.fail_polls:
            self.fail_polls -= 1
            raise ServiceResponseError("connection dropped while polling")

    def continuation_token(self):
        return "tok"


def fake_client(cur, poller=None):
    calls = []

    def begin_update(rg, name, body, **kw):
        calls.append((body, kw))
        return poller or Poller()

    client = NS(
        container_apps=NS(get=mock.Mock(return_value=cur), begin_update=begin_update)
    )
    return client, calls


def sdk_app(identity=None, ingress=None, template_marker="T1"):
    return NS(
        name="a",
        id=RID,
        managed_environment_id=None,
        identity=identity,
        configuration=NS(ingress=ingress, secrets=[]),
        template=NS(marker=template_marker),
    )


def rule(ip, action="Allow", name=None):
    return NS(
        name=name or f"r-{ip}", ip_address_range=ip, action=action, description=None
    )


# 1. narrow patch bodies, fresh read
def test_identity_update_sends_only_identity():
    cur = sdk_app(identity=None)
    client, calls = fake_client(cur)
    azure_live.enable_system_identity(SUB, APP, client=client)
    body = calls[0][0]
    assert body == {"identity": {"type": "SystemAssigned"}}
    client.container_apps.get.assert_called_once_with("rg", "a")


def test_lockdown_internal_sends_only_external_flag():
    cur = sdk_app(ingress=NS(external=True, ip_security_restrictions=None))
    client, calls = fake_client(cur)
    azure_live.apply_lockdown(SUB, APP, [], client=client)
    assert calls[0][0] == {
        "properties": {"configuration": {"ingress": {"external": False}}}
    }


def test_lockdown_allow_ip_sends_only_rules_from_fresh_read():
    cur = sdk_app(
        ingress=NS(
            external=True, ip_security_restrictions=[rule("9.9.9.9/32", name="dns")]
        )
    )
    client, calls = fake_client(cur)
    azure_live.apply_lockdown(SUB, APP, ["10.0.0.0/8"], client=client)
    rules = calls[0][0]["properties"]["configuration"]["ingress"][
        "ipSecurityRestrictions"
    ]
    assert [r["ipAddressRange"] for r in rules] == ["9.9.9.9/32", "10.0.0.0/8"]
    assert rules[0]["name"] == "dns" and set(calls[0][0]) == {"properties"}


def test_412_prints_clean_error_exit_2_nothing_applied(monkeypatch, capsys):
    e = HttpResponseError(message="(PreconditionFailed) etag mismatch")
    e.status_code = 412
    monkeypatch.setattr(
        azure_live,
        "load_apps",
        lambda sub, check_auth=False: [
            dict(APP, ingress={"enabled": True, "external": True, "ip_rules": []})
        ],
    )
    monkeypatch.setattr(azure_live, "apply_lockdown", mock.Mock(side_effect=e))
    assert cli.main(["lockdown", "a", "--subscription", SUB, "--apply"]) == 2
    cap = capsys.readouterr()
    assert "changed while" in cap.out and "nothing applied" in cap.err.lower()
    assert "Traceback" not in cap.err


# 2. polling failure resumes, never resubmits
def test_poll_failure_resumes_without_resubmitting():
    cur = sdk_app(identity=None)
    client, calls = fake_client(cur, poller=Poller(fail_polls=1))
    with mock.patch("acasentry.resilience.time.sleep"):
        azure_live.enable_system_identity(SUB, APP, client=client)
    submissions = [c for c in calls if "continuation_token" not in c[1]]
    resumes = [c for c in calls if c[1].get("continuation_token") == "tok"]
    assert len(submissions) == 1 and len(resumes) == 1


# 3. identity derived from fresh read
def test_identity_type_from_fresh_read_not_listing():
    uai = {"/subs/x/ua1": NS()}
    cur = sdk_app(identity=NS(type="UserAssigned", user_assigned_identities=uai))
    client, calls = fake_client(cur)
    azure_live.enable_system_identity(SUB, dict(APP, identity="None"), client=client)
    assert calls[0][0] == {
        "identity": {
            "type": "SystemAssigned,UserAssigned",
            "userAssignedIdentities": {"/subs/x/ua1": {}},
        }
    }


def test_identity_already_system_assigned_is_noop():
    cur = sdk_app(identity=NS(type="SystemAssigned", user_assigned_identities=None))
    client, calls = fake_client(cur)
    azure_live.enable_system_identity(SUB, APP, client=client)
    assert calls == []


# 4. Deny rule refused at planning
def test_deny_rule_refused_in_plan(monkeypatch, capsys):
    a = sdk_app(
        ingress=NS(external=True, ip_security_restrictions=[rule("10.0.0.0/8", "Deny")])
    )
    n = azure_live._normalize(a)
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: [n])
    apply = mock.Mock()
    monkeypatch.setattr(azure_live, "apply_lockdown", apply)
    assert (
        cli.main(
            [
                "lockdown",
                "a",
                "--subscription",
                SUB,
                "--allow-ip",
                "10.0.0.0/8",
                "--apply",
            ]
        )
        == 2
    )
    err = capsys.readouterr().err
    assert "Deny" in err and not apply.called


# 5. empty exception message
def test_empty_exception_message_does_not_crash(monkeypatch, capsys):
    apps = [dict(APP, id=RID + str(i), name=f"a{i}") for i in range(2)]
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: apps)
    monkeypatch.setattr(
        azure_live, "enable_system_identity", mock.Mock(side_effect=RuntimeError())
    )
    assert cli.main(["identity", "--subscription", SUB, "--apply"]) == 2
    out = capsys.readouterr().out
    assert out.count("FAILED") == 2 and "RuntimeError" in out


# 6. unique rule names
def test_rule_names_do_not_collide():
    existing = [rule("1.1.1.1/32", name="acasentry-allow-1")]
    out = azure_live.merge_ip_rules(existing, ["2.2.2.2/32", "3.3.3.3/32"])
    names = [r["name"] for r in out]
    assert len(names) == len(set(names))


# 7. RBAC rows keep IDs
def test_rbac_rows_keep_scope_and_principal_ids():
    env = NS(name="env", id="/env-id")
    client = NS(
        managed_environments=NS(list_by_subscription=lambda: iter([env])),
        container_apps=NS(list_by_subscription=lambda: iter([])),
    )
    ras = [
        NS(role_definition_id="r", principal_id="p1", principal_type="User"),
        NS(role_definition_id="r", principal_id="p2", principal_type="User"),
    ]
    auth = NS(
        role_assignments=NS(list_for_scope=lambda s: iter(ras)),
        role_definitions=NS(get_by_id=lambda rd: NS(role_name="Reader")),
    )
    graph = lambda body: {
        "value": [
            {"id": "p1", "displayName": "Sam"},
            {"id": "p2", "displayName": "Sam"},
        ]
    }
    rows = checks.rbac_rows(
        azure_live.load_role_assignments(SUB, client=client, auth=auth, graph=graph)
    )
    assert rows[0] != rows[1]
    assert rows[0][-2:] == ["/env-id", "p1"]


def test_rbac_demo_has_id_columns():
    assert cli.HEADERS["rbac"][-2:] == ["SCOPE_ID", "PRINCIPAL_ID"]
    assert all(len(r) == 7 for r in checks.rbac_rows(demo.ROLE_ASSIGNMENTS))


# 8. transient detection by type
def test_url_error_and_connection_subclasses_are_transient():
    import urllib.error

    assert is_transient(urllib.error.URLError("dns"))
    assert is_transient(ConnectionResetError())
    assert not is_transient(urllib.error.HTTPError("u", 404, "nf", {}, None))


# QE: non-transient polling failure re-raises, never resumes
def test_non_transient_poll_failure_reraises_without_resume():
    import pytest

    err = HttpResponseError(message="(BadRequest) invalid ingress")
    err.status_code = 400

    class BadPoller(Poller):
        def result(self):
            raise err

    cur = sdk_app(identity=None)
    client, calls = fake_client(cur, poller=BadPoller())
    with pytest.raises(HttpResponseError):
        azure_live.enable_system_identity(SUB, APP, client=client)
    assert len(calls) == 1 and "continuation_token" not in calls[0][1]


# QE: existing rule descriptions survive the full-list patch
def test_lockdown_keeps_existing_rule_description():
    existing = rule("9.9.9.9/32", name="dns")
    existing.description = "corp DNS"
    cur = sdk_app(ingress=NS(external=True, ip_security_restrictions=[existing]))
    client, calls = fake_client(cur)
    azure_live.apply_lockdown(SUB, APP, ["10.0.0.0/8"], client=client)
    rules = calls[0][0]["properties"]["configuration"]["ingress"][
        "ipSecurityRestrictions"
    ]
    assert rules[0]["description"] == "corp DNS"
