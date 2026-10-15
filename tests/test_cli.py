import csv
import sys

import pytest

from acasentry.cli import main


def out(capsys, *argv):
    assert main(list(argv)) == 0
    return capsys.readouterr().out


def test_rbac(capsys):
    o = out(capsys, "rbac", "--demo")
    assert "OWNER" in o and "CONTRIBUTOR,GUEST" in o and "6 row(s)" in o


def test_exposure(capsys):
    o = out(capsys, "exposure", "--demo")
    assert "orders-api" in o and "NO_IP_RULES,NO_AUTH" in o
    assert "billing-worker" not in o


def test_secrets(capsys):
    o = out(capsys, "secrets", "--demo")
    for s in ("db-password", "API_TOKEN", "smtp-pass", "SMTP_PASSWORD"):
        assert s in o
    assert "stripe-key" not in o and "LOG_LEVEL" not in o


def test_identity_dry_run_and_apply(capsys):
    o = out(capsys, "identity", "--demo")
    assert "orders-api" in o and "billing-worker" in o and "web-frontend" not in o and "DRY RUN" in o
    o = out(capsys, "identity", "--demo", "--apply")
    assert "Azure was not touched" in o


def test_lockdown(capsys):
    o = out(capsys, "lockdown", "orders-api", "--demo")
    assert "external" in o and "DRY RUN" in o
    o = out(capsys, "lockdown", "orders-api", "--demo", "--allow-ip", "10.0.0.0/8", "--apply")
    assert "10.0.0.0/8" in o and "Azure was not touched" in o


def test_lockdown_unknown_app():
    with pytest.raises(SystemExit):
        main(["lockdown", "nope", "--demo"])


def test_demo_does_not_import_azure(capsys):
    out(capsys, "identity", "--demo", "--apply")
    assert "acasentry.azure_live" not in sys.modules


@pytest.mark.parametrize("cmd", [["rbac"], ["exposure"], ["secrets"], ["identity"], ["lockdown", "orders-api"]])
def test_csv(tmp_path, capsys, cmd):
    f = tmp_path / "out.csv"
    out(capsys, *cmd, "--demo", "--csv", str(f))
    rows = list(csv.reader(f.open()))
    assert len(rows) >= 2


def test_live_requires_subscription():
    with pytest.raises(SystemExit):
        main(["secrets"])
