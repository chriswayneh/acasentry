"""Live-mode hardening tests using fakes. No real Azure calls."""
from types import SimpleNamespace as NS

import pytest
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import CredentialUnavailableError

from acasentry import azure_live, cli
from acasentry.resilience import (AcasentryError, call_with_retry, list_all,
                                  retry_after_seconds, translate, validate_subscription)

SUB = "11111111-2222-3333-4444-555555555555"


class FakeHttpError(Exception):
    def __init__(self, status, headers=None, code=None, msg="boom"):
        super().__init__(msg)
        self.status_code = status
        self.response = NS(status_code=status, headers=headers or {})
        self.error = NS(code=code) if code else None


# ---- retry helper ----

def test_retry_honors_retry_after_then_succeeds():
    calls, sleeps = [], []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise FakeHttpError(429, {"Retry-After": "7"})
        return "ok"
    assert call_with_retry(fn, sleep=sleeps.append) == "ok"
    assert sleeps == [7.0, 7.0]


def test_retry_exponential_backoff_bounded():
    sleeps = []

    def fn():
        raise FakeHttpError(503)
    with pytest.raises(FakeHttpError):
        call_with_retry(fn, max_attempts=6, base_delay=1, max_delay=5, sleep=sleeps.append, jitter=lambda: 0)
    assert sleeps == [1, 2, 4, 5, 5]


def test_retry_after_capped():
    sleeps = []
    with pytest.raises(FakeHttpError):
        call_with_retry(lambda: (_ for _ in ()).throw(FakeHttpError(429, {"retry-after": "3600"})),
                        max_attempts=2, max_delay=30, sleep=sleeps.append)
    assert sleeps == [30]


def test_retry_after_ms_header():
    assert retry_after_seconds(FakeHttpError(429, {"x-ms-retry-after-ms": "1500"})) == 1.5
    assert retry_after_seconds(FakeHttpError(429, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})) is None


@pytest.mark.parametrize("status", [400, 403, 404])
def test_no_retry_on_non_transient(status):
    sleeps = []
    with pytest.raises(FakeHttpError):
        call_with_retry(lambda: (_ for _ in ()).throw(FakeHttpError(status)), sleep=sleeps.append)
    assert sleeps == []


# ---- pagination ----

class Pager:
    """Mimics ItemPaged: iterating yields items across several pages."""
    def __init__(self, pages, fail_once_at=None):
        self.pages, self.fail_once_at, self.page_fetches = pages, fail_once_at, 0

    def __call__(self):
        return self._iter()

    def _iter(self):
        for i, page in enumerate(self.pages):
            self.page_fetches += 1
            if self.fail_once_at == i:
                self.fail_once_at = None
                raise FakeHttpError(503)
            yield from page


def test_list_all_reads_every_page():
    pager = Pager([[1, 2], [3], [4, 5]])
    assert list_all(pager) == [1, 2, 3, 4, 5]


def test_list_all_restarts_after_mid_page_error():
    pager = Pager([[1], [2], [3]], fail_once_at=1)
    assert list_all(pager, sleep=lambda s: None) == [1, 2, 3]


def _app(name):
    rid = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.App/containerApps/{name}"
    return NS(name=name, id=rid, managed_environment_id=".../env1", identity=None,
              configuration=NS(ingress=NS(external=True, ip_security_restrictions=None), secrets=[]),
              template=NS(containers=[]))


def test_load_apps_paginates_apps_and_auth_configs():
    apps = Pager([[_app("a"), _app("b")], [_app("c")]])
    auth_pages = {"a": [[NS(platform=NS(enabled=False))], [NS(platform=NS(enabled=True))]],
                  "b": [[]], "c": [[NS(platform=None)]]}
    client = NS(container_apps=NS(list_by_subscription=apps),
                container_apps_auth_configs=NS(
                    list_by_container_app=lambda rg, n: iter(x for p in auth_pages[n] for x in p)))
    out = azure_live.load_apps(SUB, check_auth=True, client=client)
    assert [a["name"] for a in out] == ["a", "b", "c"]
    assert [a["auth_enabled"] for a in out] == [True, False, False]


def test_load_role_assignments_paginates():
    env = NS(name="env1", id="/env1")
    client = NS(managed_environments=NS(list_by_subscription=Pager([[env]])),
                container_apps=NS(list_by_subscription=Pager([[_app("a")]])))
    ras = {"/env1": [[NS(role_definition_id="r1", principal_id="p1", principal_type="User")],
                     [NS(role_definition_id="r1", principal_id="p2", principal_type="Group")]]}
    lookups = []
    auth = NS(role_assignments=NS(list_for_scope=lambda s: iter(x for p in ras.get(s, [[]]) for x in p)),
              role_definitions=NS(get_by_id=lambda rd: lookups.append(rd) or NS(role_name="Owner")))
    out = azure_live.load_role_assignments(SUB, client=client, auth=auth)
    assert [r["principal"] for r in out] == ["p1", "p2"]
    assert lookups == ["r1"]


# ---- error translation and CLI messages ----

def test_translate_not_logged_in():
    err = translate(CredentialUnavailableError("no creds"))
    assert "az login" in str(err)
    assert "az login" in str(translate(ClientAuthenticationError("nope")))


def test_translate_permission_denied():
    assert "Permission denied" in str(translate(FakeHttpError(403, code="AuthorizationFailed")))


def test_translate_subscription_not_found():
    assert "not found" in str(translate(FakeHttpError(404, code="SubscriptionNotFound"), SUB))


def test_translate_real_http_response_error():
    e = HttpResponseError(message="forbidden")
    e.status_code = 403
    assert "Permission denied" in str(translate(e))


def test_translate_unknown_returns_none():
    assert translate(ValueError("x")) is None


def test_validate_subscription():
    assert validate_subscription(SUB) == SUB
    for bad in (None, "", "my-sub"):
        with pytest.raises(AcasentryError):
            validate_subscription(bad)


@pytest.mark.parametrize("exc,needle", [
    (CredentialUnavailableError("no creds"), "az login"),
    (FakeHttpError(403, code="AuthorizationFailed"), "Permission denied"),
    (FakeHttpError(404, code="SubscriptionNotFound"), "was not found"),
    (FakeHttpError(503), "after retries"),
])
def test_cli_prints_clean_error(monkeypatch, capsys, exc, needle):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(azure_live, "load_apps", boom)
    assert cli.main(["secrets", "--subscription", SUB]) == 2
    err = capsys.readouterr().err
    assert needle in err and "Traceback" not in err


def test_cli_bad_subscription_format(capsys):
    assert cli.main(["exposure", "--subscription", "not-a-guid"]) == 2
    assert "valid subscription ID" in capsys.readouterr().err


def test_cli_rejects_bad_or_open_cidr():
    with pytest.raises(SystemExit):
        cli.main(["lockdown", "orders-api", "--demo", "--allow-ip", "nope"])
    with pytest.raises(SystemExit):
        cli.main(["lockdown", "orders-api", "--demo", "--allow-ip", "0.0.0.0/0"])
