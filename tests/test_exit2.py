"""Every Azure/HTTP/connection error reaching the CLI exits 2 with one clean line."""

import urllib.error

import pytest
from azure.core.exceptions import (
    HttpResponseError,
    ResourceNotFoundError,
    ServiceRequestError,
)

from acasentry import azure_live, cli

SUB = "11111111-2222-3333-4444-555555555555"
TOKENISH = "Bearer eyJhbGciOiJSUzI1NiJ9.secretpayload"  # gitleaks:allow (fake token used to prove error bodies are not printed)


def _http(status, cls=HttpResponseError, msg="(SomeCode) Something failed"):
    e = cls(message=msg + "\nFull body line 2 " + TOKENISH)
    e.status_code = status
    return e


@pytest.mark.parametrize(
    "exc,needle",
    [
        (_http(400, msg="(InvalidParameter) bad value"), "400 Bad Request"),
        (
            _http(404, ResourceNotFoundError, "(ResourceNotFound) app gone"),
            "--resource-group",
        ),
        (_http(418, msg="(Teapot) odd"), "Azure returned HTTP 418"),
        (_http(409, msg="(Conflict) busy"), "conflict (409)"),
        (ServiceRequestError("Failed to establish a new connection"), "proxy"),
        (ConnectionResetError("reset by peer"), "Could not reach Azure"),
        (urllib.error.URLError("Name or service not known"), "Could not reach Azure"),
    ],
)
def test_azure_errors_exit_2_one_line(monkeypatch, capsys, exc, needle):
    def boom(*a, **k):
        raise exc

    monkeypatch.setattr(azure_live, "load_apps", boom)
    assert cli.main(["secrets", "--subscription", SUB]) == 2
    err = capsys.readouterr().err
    assert needle in err
    assert err.startswith("error: ") and err.count("\n") == 1
    assert "Traceback" not in err and "secretpayload" not in err and "line 2" not in err


def test_plain_value_error_still_propagates(monkeypatch):
    def bug(*a, **k):
        raise ValueError("programming bug")

    monkeypatch.setattr(azure_live, "load_apps", bug)
    with pytest.raises(ValueError, match="programming bug"):
        cli.main(["secrets", "--subscription", SUB])


def test_non_azure_key_error_still_propagates(monkeypatch):
    def bug(*a, **k):
        raise KeyError("x")

    monkeypatch.setattr(azure_live, "load_apps", bug)
    with pytest.raises(KeyError):
        cli.main(["secrets", "--subscription", SUB])
