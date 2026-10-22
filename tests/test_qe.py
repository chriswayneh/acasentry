"""QE fix list tests. Mocked Azure only."""

import json
from types import SimpleNamespace as NS
from unittest import mock

import pytest
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.mgmt.appcontainers.models import (
    IpSecurityRestrictionRule,
    ManagedServiceIdentity,
    ManagedServiceIdentityType,
)

from acasentry import azure_live, checks, cli
from acasentry.resilience import AcasentryError

SUB = "11111111-2222-3333-4444-555555555555"
RID = f"/subscriptions/{SUB}/resourceGroups/rg1/providers/Microsoft.App/containerApps/"


def sdk_app(name, identity=None, ingress="default", secrets=(), env=()):
    if ingress == "default":
        ingress = NS(external=True, ip_security_restrictions=None)
    return NS(
        name=name,
        id=RID + name,
        managed_environment_id="/x/env1",
        identity=identity,
        configuration=NS(ingress=ingress, secrets=list(secrets)),
        template=NS(containers=[NS(env=list(env))]),
    )


def aca_client(apps, auth_cfgs=None):
    auth_cfgs = auth_cfgs or {}
    return NS(
        container_apps=NS(list_by_subscription=lambda: iter(apps)),
        container_apps_auth_configs=NS(
            list_by_container_app=lambda rg, n: iter(auth_cfgs.get(n, []))
        ),
        managed_environments=NS(list_by_subscription=lambda: iter([])),
    )


# 1. enum identity type
def test_identity_enum_not_flagged_as_missing():
    apps = [
        sdk_app(
            "has-sys",
            ManagedServiceIdentity(type=ManagedServiceIdentityType.SYSTEM_ASSIGNED),
        ),
        sdk_app(
            "has-both",
            ManagedServiceIdentity(
                type=ManagedServiceIdentityType.SYSTEM_ASSIGNED_USER_ASSIGNED
            ),
        ),
        sdk_app(
            "user-only",
            ManagedServiceIdentity(type=ManagedServiceIdentityType.USER_ASSIGNED),
        ),
        sdk_app("none", None),
    ]
    normalized = azure_live.load_apps(SUB, client=aca_client(apps))
    rows = checks.identity_rows(normalized)
    assert [r[0] for r in rows] == ["user-only", "none"]
    assert normalized[1]["identity"] == "SystemAssigned,UserAssigned"


# 2. principal name resolution
def _ra_client():
    env = NS(name="env1", id="/env1")
    client = NS(
        managed_environments=NS(list_by_subscription=lambda: iter([env])),
        container_apps=NS(list_by_subscription=lambda: iter([])),
    )
    ras = [
        NS(role_definition_id="r1", principal_id="oid-guest", principal_type="User"),
        NS(
            role_definition_id="r1",
            principal_id="oid-sp",
            principal_type="ServicePrincipal",
        ),
    ]
    auth = NS(
        role_assignments=NS(list_for_scope=lambda s: iter(ras)),
        role_definitions=NS(get_by_id=lambda rd: NS(role_name="Contributor")),
    )
    return client, auth


def test_rbac_resolves_names_and_flags_guest():
    client, auth = _ra_client()
    graph = mock.Mock(
        return_value={
            "value": [
                {
                    "id": "oid-guest",
                    "userPrincipalName": "bob_partner.com#EXT#@contoso.onmicrosoft.com",
                },
                {"id": "oid-sp", "displayName": "ci-deployer"},
            ]
        }
    )
    out = azure_live.load_role_assignments(SUB, client=client, auth=auth, graph=graph)
    assert [r["principal"] for r in out] == [
        "bob_partner.com#EXT#@contoso.onmicrosoft.com",
        "ci-deployer",
    ]
    assert "GUEST" in checks.rbac_rows(out)[0][4]


def test_rbac_degrades_when_graph_denied(capsys):
    client, auth = _ra_client()
    denied = HttpResponseError(message="Insufficient privileges")
    out = azure_live.load_role_assignments(
        SUB, client=client, auth=auth, graph=mock.Mock(side_effect=denied)
    )
    assert [r["principal"] for r in out] == ["oid-guest", "oid-sp"]
    assert "could not resolve principal names" in capsys.readouterr().err


def test_resolve_principals_empty():
    assert azure_live.resolve_principals(set(), graph=mock.Mock()) == {}


def test_graph_post_builds_request():
    cred = NS(get_token=lambda scope: NS(token="t0k"))
    resp = mock.MagicMock()
    resp.__enter__.return_value.read.return_value = json.dumps({"value": []}).encode()
    with mock.patch.object(azure_live, "graph_urlopen", return_value=resp) as uo:
        assert azure_live._graph_post(cred)({"ids": ["a"]}) == {"value": []}
    req = uo.call_args[0][0]
    assert (
        req.full_url == azure_live.GRAPH_URL
        and req.get_header("Authorization") == "Bearer t0k"
    )


# 3. auth errors surface (no catch-all)
def test_auth_config_auth_error_surfaces(monkeypatch, capsys):
    def boom(rg, n):
        raise ClientAuthenticationError("token expired")

    client = aca_client([sdk_app("a")])
    client.container_apps_auth_configs.list_by_container_app = boom
    with pytest.raises(ClientAuthenticationError):
        azure_live.load_apps(SUB, check_auth=True, client=client)
    monkeypatch.setattr(azure_live, "_aca", lambda sub: client)
    assert cli.main(["exposure", "--subscription", SUB]) == 2
    assert "az login" in capsys.readouterr().err


# 4. CIDR parsing
@pytest.mark.parametrize("bad", ["0", "10", "10.0", "1.2.3", "abc", "0.0.0.0/0"])
def test_allow_ip_rejects(bad):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["lockdown", "x", "--allow-ip", bad])


@pytest.mark.parametrize(
    "good,norm",
    [
        ("203.0.113.7", "203.0.113.7/32"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("2001:db8::/32", "2001:db8::/32"),
    ],
)
def test_allow_ip_accepts(good, norm):
    assert cli.build_parser().parse_args(
        ["lockdown", "x", "--allow-ip", good]
    ).allow_ip == [norm]


# 5. existing rule kept
def test_lockdown_keeps_existing_9999_rule():
    existing = IpSecurityRestrictionRule(
        name="dns", ip_address_range="9.9.9.9/32", action="Allow"
    )
    cur = sdk_app("a", ingress=NS(external=True, ip_security_restrictions=[existing]))
    client = NS(
        container_apps=NS(
            get=lambda rg, n: cur,
            begin_update=mock.Mock(return_value=NS(result=lambda: None)),
        )
    )
    azure_live.apply_lockdown(
        SUB, {"name": "a", "resource_group": "rg1"}, ["10.0.0.0/8"], client=client
    )
    sent = client.container_apps.begin_update.call_args[0][2]
    rules = sent["properties"]["configuration"]["ingress"]["ipSecurityRestrictions"]
    assert [r["ipAddressRange"] for r in rules] == ["9.9.9.9/32", "10.0.0.0/8"]


# 6. missing ingress
@pytest.mark.parametrize("cur", [sdk_app("a", ingress=None), NS(configuration=None)])
def test_lockdown_missing_ingress_clean_error(cur):
    client = NS(container_apps=NS(get=lambda rg, n: cur, begin_update=mock.Mock()))
    with pytest.raises(AcasentryError, match="no ingress"):
        azure_live.apply_lockdown(
            SUB, {"name": "a", "resource_group": "rg1"}, [], client=client
        )
    client.container_apps.begin_update.assert_not_called()


def test_normalize_handles_missing_ingress_and_config():
    app = sdk_app("a", ingress=None)
    assert azure_live._normalize(app)["ingress"] is None
    bare = NS(
        name="b",
        id=RID + "b",
        managed_environment_id=None,
        identity=None,
        configuration=None,
        template=None,
    )
    n = azure_live._normalize(bare)
    assert n["secrets"] == [] and n["env"] == [] and n["identity"] == "None"


# 9. coverage of the remaining live paths
def test_identity_apply_live_paths():
    cur = sdk_app(
        "a",
        ManagedServiceIdentity(
            type="UserAssigned", user_assigned_identities={"/id/u": {}}
        ),
    )
    client = NS(
        container_apps=NS(
            get=lambda rg, n: cur,
            begin_update=mock.Mock(return_value=NS(result=lambda: None)),
        )
    )
    azure_live.enable_system_identity(
        SUB,
        {"name": "a", "resource_group": "rg1", "identity": "UserAssigned"},
        client=client,
    )
    sent = client.container_apps.begin_update.call_args[0][2]
    assert sent["identity"]["type"] == "SystemAssigned,UserAssigned"
    assert "/id/u" in sent["identity"]["userAssignedIdentities"]


def test_lockdown_internal_live_path():
    cur = sdk_app("a")
    client = NS(
        container_apps=NS(
            get=lambda rg, n: cur,
            begin_update=mock.Mock(return_value=NS(result=lambda: None)),
        )
    )
    azure_live.apply_lockdown(
        SUB, {"name": "a", "resource_group": "rg1"}, [], client=client
    )
    sent = client.container_apps.begin_update.call_args[0][2]
    assert sent == {"properties": {"configuration": {"ingress": {"external": False}}}}


def test_cli_apply_live_end_to_end(monkeypatch, capsys):
    apps = [sdk_app("a", None)]
    client = aca_client(apps)
    client.container_apps.get = lambda rg, n: apps[0]
    client.container_apps.begin_update = mock.Mock(return_value=NS(result=lambda: None))
    monkeypatch.setattr(azure_live, "_aca", lambda sub: client)
    assert cli.main(["identity", "--subscription", SUB, "--apply"]) == 0
    assert "Applied 1 change(s)" in capsys.readouterr().out


def test_client_factories_use_credential_and_disable_sdk_retry():
    with (
        mock.patch("azure.identity.DefaultAzureCredential") as cred,
        mock.patch("azure.mgmt.appcontainers.ContainerAppsAPIClient") as aca,
    ):
        azure_live._aca(SUB)
    aca.assert_called_once_with(cred.return_value, SUB, retry_total=0)


def test_load_role_assignments_builds_auth_client(monkeypatch):
    monkeypatch.setattr(azure_live, "_cred", lambda: "cred")
    monkeypatch.setattr(
        azure_live,
        "_aca",
        lambda sub: NS(
            managed_environments=NS(list_by_subscription=lambda: iter([])),
            container_apps=NS(list_by_subscription=lambda: iter([])),
        ),
    )
    with mock.patch("azure.mgmt.authorization.AuthorizationManagementClient") as amc:
        assert azure_live.load_role_assignments(SUB) == []
    amc.assert_called_once_with("cred", SUB, retry_total=0)


def test_missing_sdk_gives_clean_error(monkeypatch):
    import builtins

    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("azure.identity"):
            raise ImportError("nope", name="azure.identity")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(AcasentryError, match="pip install"):
        azure_live._cred()


# review fixes
def test_graph_http_429_is_retried():
    import urllib.error

    calls = []

    def post(body):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                azure_live.GRAPH_URL, 429, "busy", {"Retry-After": "0"}, None
            )
        return {"value": [{"id": "x", "displayName": "X"}]}

    assert azure_live.resolve_principals({"x"}, graph=post) == {"x": "X"}
    assert len(calls) == 2


def test_guest_by_usertype_without_ext():
    names = azure_live.resolve_principals(
        {"g"},
        graph=lambda b: {
            "value": [
                {"id": "g", "userPrincipalName": "guest@other.com", "userType": "Guest"}
            ]
        },
    )
    assert checks.is_guest(names["g"])
