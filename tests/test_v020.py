"""QE round for 0.2.0."""

import importlib.metadata

import pytest

import acasentry
from acasentry import cli
from acasentry.output import csv_safe


def test_version_is_single_source():
    assert acasentry.__version__ == "0.2.3"
    assert importlib.metadata.version("acasentry") == acasentry.__version__


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "0.2.3" in capsys.readouterr().out


@pytest.mark.parametrize(
    "cidr", ["10.0.0.0/8", "128.0.0.0/1", "2001:db8::/32", "8000::/1"]
)
def test_broad_allow_ip_warns(cidr, capsys):
    assert cli.main(["lockdown", "orders-api", "--demo", "--allow-ip", cidr]) == 0
    assert "very broad" in capsys.readouterr().err


@pytest.mark.parametrize("cidr", ["10.0.0.0/9", "203.0.113.7", "2001:db8::/33"])
def test_normal_allow_ip_no_warning(cidr, capsys):
    assert cli.main(["lockdown", "orders-api", "--demo", "--allow-ip", cidr]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "argv",
    [
        [
            "lockdown",
            "orders-api",
            "--demo",
            "--allow-ip",
            "10.0.0.0/8",
            "--allow-ip",
            "nope",
        ],
        ["lockdown", "no-such-app", "--demo", "--allow-ip", "10.0.0.0/8"],
    ],
)
def test_broad_warning_only_after_validation(argv, capsys, monkeypatch):
    from acasentry import demo

    dup = dict(
        demo.APPS[0],
        resource_group="rg-other",
        id=demo.APPS[0]["id"].replace("rg-demo", "rg-other"),
    )
    monkeypatch.setattr(demo, "APPS", demo.APPS + [dup])
    try:
        rc = cli.main(argv)
    except SystemExit as exc:
        rc = exc.code
    assert rc == 2
    assert "very broad" not in capsys.readouterr().err
    # ambiguous name also fails without warning
    assert (
        cli.main(["lockdown", "orders-api", "--demo", "--allow-ip", "10.0.0.0/8"]) == 2
    )
    err = capsys.readouterr().err
    assert "matches 2 apps" in err and "very broad" not in err
    # and succeeds with the warning once the target is unambiguous
    assert (
        cli.main(
            [
                "lockdown",
                "orders-api",
                "--resource-group",
                "rg-demo",
                "--demo",
                "--allow-ip",
                "10.0.0.0/8",
            ]
        )
        == 0
    )
    assert "very broad" in capsys.readouterr().err


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_zero_prefix_still_refused(cidr):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["lockdown", "x", "--allow-ip", cidr])


def test_csv_dash_placeholder_not_escaped():
    assert csv_safe("-") == "-"
    assert csv_safe("-1") == "'-1"


def test_no_plain_text_wording_left():
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    for path in list((root / "src").rglob("*.py")) + [root / "README.md"]:
        text = path.read_text().lower()
        assert "plain-text" not in text and "plain text" not in text, path


def test_version_matches_changelog_and_roadmap():
    """__version__, the newest dated CHANGELOG heading and the ROADMAP latest release agree."""
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    v = acasentry.__version__
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    dated = re.findall(
        r"^## \[(\d+\.\d+\.\d+)\] \(\d{4}-\d{2}-\d{2}\)$", changelog, re.MULTILINE
    )
    assert dated and dated[0] == v
    roadmap = (root / "ROADMAP.md").read_text(encoding="utf-8")
    m = re.search(r"\*\*Latest release\*\* \| \[`v([\d.]+)`\]\(([^)]+)\)", roadmap)
    assert m and m.group(1) == v
    assert m.group(2).endswith(f"/releases/tag/v{v}")
    security = (root / "SECURITY.md").read_text(encoding="utf-8")
    assert f"| {v} | Yes |" in security
    assert f"| < {v} | No |" in security
