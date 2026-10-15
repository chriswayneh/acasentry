"""QE round for 0.2.0."""
import importlib.metadata

import pytest

import acasentry
from acasentry import cli
from acasentry.output import csv_safe


def test_version_is_020_single_source():
    assert acasentry.__version__ == "0.2.0"
    assert importlib.metadata.version("acasentry") == acasentry.__version__


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "0.2.0" in capsys.readouterr().out


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "128.0.0.0/1", "2001:db8::/32", "8000::/1"])
def test_broad_allow_ip_warns(cidr, capsys):
    cli.build_parser().parse_args(["lockdown", "x", "--allow-ip", cidr])
    assert "very broad" in capsys.readouterr().err


@pytest.mark.parametrize("cidr", ["10.0.0.0/9", "203.0.113.7", "2001:db8::/33"])
def test_normal_allow_ip_no_warning(cidr, capsys):
    cli.build_parser().parse_args(["lockdown", "x", "--allow-ip", cidr])
    assert capsys.readouterr().err == ""


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
