"""--csv write failures: one clean error line, exit 2, and nothing applied."""

import builtins
import errno
from unittest import mock

import pytest

from acasentry import azure_live, cli

SUB = "11111111-2222-3333-4444-555555555555"


def _assert_clean(capsys, path, reason):
    cap = capsys.readouterr()
    assert cap.err.startswith(f"error: cannot write CSV to {path}: ")
    assert reason in cap.err and cap.err.count("\n") == 1 and "Traceback" not in cap.err


def test_csv_missing_folder_exits_2(tmp_path, capsys):
    path = str(tmp_path / "no-such-dir" / "out.csv")
    assert cli.main(["secrets", "--demo", "--csv", path]) == 2
    _assert_clean(capsys, path, "No such file or directory")


def test_csv_permission_denied_exits_2(tmp_path, capsys):
    path = str(tmp_path / "out.csv")
    real_open = builtins.open

    def deny(file, *a, **k):
        if str(file) == path:
            raise PermissionError(errno.EACCES, "Permission denied", path)
        return real_open(file, *a, **k)

    with mock.patch("builtins.open", deny):
        assert cli.main(["rbac", "--demo", "--csv", path]) == 2
    _assert_clean(capsys, path, "Permission denied")


def test_csv_failure_with_apply_changes_nothing(tmp_path, monkeypatch, capsys):
    path = str(tmp_path / "missing" / "plan.csv")
    app = {
        "name": "a",
        "id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.App/containerApps/a",
        "resource_group": "rg",
        "identity": "None",
        "ingress": None,
        "secrets": [],
        "env": [],
    }
    monkeypatch.setattr(azure_live, "load_apps", lambda sub, check_auth=False: [app])
    enable = mock.Mock()
    monkeypatch.setattr(azure_live, "enable_system_identity", enable)
    assert cli.main(["identity", "--subscription", SUB, "--apply", "--csv", path]) == 2
    enable.assert_not_called()
    _assert_clean(capsys, path, "No such file or directory")


def test_csv_other_bug_still_raises(tmp_path, monkeypatch):
    from acasentry import output

    monkeypatch.setattr(output.csv, "writer", mock.Mock(side_effect=TypeError("bug")))
    monkeypatch.setattr(cli, "write_csv", output.write_csv)
    with pytest.raises(TypeError):
        cli.main(["secrets", "--demo", "--csv", str(tmp_path / "o.csv")])
