"""Red Team findings on 06706d6: terminal escaping, csv_safe, Graph redirects."""

import http.server
import threading

import pytest
from azure.core.exceptions import HttpResponseError

from acasentry import azure_live, cli
from acasentry.output import csv_safe, table
from acasentry.resilience import AcasentryError

OSC8 = "\x1b]8;;http://evil\x07click\x1b]8;;\x07"
NASTY = "Eve" + OSC8 + "\x1b[2K\r" + "\x9b31m" + "\u202egpj.exe" + "\x7f\u200b"
RAW = ("\x1b", "\x07", "\r", "\x9b", "\u202e", "\x7f", "\u200b")


def _clean(text):
    for c in RAW:
        assert c not in text, repr(c)


def test_table_escapes_display_name():
    out = table(["PRINCIPAL"], [[NASTY]])
    _clean(out)
    assert "\\x1b]8;;http://evil\\x07" in out
    assert "\\x1b[2K\\x0d" in out
    assert "\\x9b31m" in out
    assert "\\u202egpj.exe" in out
    assert "\\x7f\\u200b" in out


def test_table_escape_backslash_and_alignment():
    out = table(["A", "B"], [["\\x1b", "y"], ["\x1b", "z"]])
    assert "\\\\x1b" in out
    lines = out.splitlines()
    # widths are measured on the escaped text, so columns stay aligned
    assert lines[2].index("y") == lines[3].index("z")


def test_cli_table_escapes_rows(monkeypatch, capsys):
    monkeypatch.setattr(cli.checks, "rbac_rows", lambda data: [[NASTY] * 7])
    assert cli.main(["rbac", "--demo"]) == 0
    out = capsys.readouterr().out
    _clean(out)
    assert "\\u202e" in out


def test_csv_keeps_raw_text(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli.checks, "rbac_rows", lambda data: [[NASTY] * 7])
    p = tmp_path / "o.csv"
    assert cli.main(["rbac", "--demo", "--csv", str(p)]) == 0
    assert "\u202egpj.exe" in p.read_text(encoding="utf-8")


def test_acasentry_error_message_escaped(monkeypatch, capsys):
    def boom(args):
        raise AcasentryError("app " + NASTY + " not found")

    monkeypatch.setattr(cli, "run", boom)
    assert cli.main(["rbac", "--demo"]) == 2
    err = capsys.readouterr().err
    _clean(err)
    assert "\\x1b[2K" in err and "\\u202e" in err


def test_translated_azure_error_escaped(monkeypatch, capsys):
    def boom(args):
        e = HttpResponseError(message="(Bad) " + NASTY)
        e.status_code = 400
        raise e

    monkeypatch.setattr(cli, "run", boom)
    assert cli.main(["rbac", "--demo"]) == 2
    err = capsys.readouterr().err
    _clean(err)
    assert "\\x1b[2K" in err


def test_apply_failed_line_escaped(monkeypatch, capsys):
    import argparse

    args = argparse.Namespace(
        demo=False, csv=None, command="identity", apply=True, yes=True
    )

    def action(app):
        raise AcasentryError("denied " + NASTY)

    monkeypatch.setattr(cli, "_emit", lambda *a, **k: None)
    cli._plan_and_apply(args, [], [{"id": "/x/" + NASTY}], action)
    cap = capsys.readouterr()
    _clean(cap.out + cap.err)


@pytest.mark.parametrize(
    "value,expected",
    [
        (" =1+1", "' =1+1"),
        ("  @SUM(A1)", "'  @SUM(A1)"),
        ("\n=cmd", "'\n=cmd"),
        ("\nplain", "'\nplain"),
        (" \t-2", "' \t-2"),
        ("-", "-"),
        ("plain", "plain"),
        ("=1", "'=1"),
    ],
)
def test_csv_safe_lstripped_and_newline(value, expected):
    assert csv_safe(value) == expected


@pytest.mark.parametrize("code", [300, 301, 302, 303, 305, 307, 308])
def test_graph_refuses_redirects(monkeypatch, code):
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if self.path == "/graph":
                self.send_response(code)
                self.send_header(
                    "Location", f"http://127.0.0.1:{self.server.server_port}/steal"
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        do_GET = do_POST

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setattr(
            azure_live, "GRAPH_URL", f"http://127.0.0.1:{srv.server_port}/graph"
        )
        s = azure_live.GraphSession(cred=None)
        with pytest.raises(AcasentryError, match="redirect"):
            s._send({}, "secret-token")
        assert seen == []
    finally:
        srv.shutdown()


def _redirect_server(code, seen):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if self.path == "/graph":
                port = self.server.server_port
                self.send_response(code)
                # http.server writes headers as latin-1; ESC is allowed there.
                self.send_header("Location", f"http://127.0.0.1:{port}/steal\x1b[2Kx")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                seen.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        do_GET = do_POST

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.mark.parametrize("code", [301, 307, 308])
def test_cli_rbac_graph_redirect_exits_2(monkeypatch, capsys, code):
    """End to end through cli.main: a Graph redirect is refused, exits 2, one escaped line."""
    import types

    import azure.mgmt.authorization as authz
    from test_qe import SUB, _ra_client

    client, auth = _ra_client()
    seen = []
    srv = _redirect_server(code, seen)
    try:
        monkeypatch.setattr(
            azure_live, "GRAPH_URL", f"http://127.0.0.1:{srv.server_port}/graph"
        )
        tok = types.SimpleNamespace(token="secret-token", expires_on=10**12)
        monkeypatch.setattr(
            azure_live, "_cred", lambda: types.SimpleNamespace(get_token=lambda s: tok)
        )
        monkeypatch.setattr(azure_live, "_aca", lambda sub: client)
        monkeypatch.setattr(
            authz, "AuthorizationManagementClient", lambda *a, **k: auth
        )
        rc = cli.main(["rbac", "--subscription", SUB])
    finally:
        srv.shutdown()
    cap = capsys.readouterr()
    assert rc == 2
    lines = [l for l in cap.err.splitlines() if l.strip()]
    assert len(lines) == 1 and lines[0].startswith("error: ")
    assert f"HTTP {code} redirect" in lines[0]
    assert "/steal\\x1b[2Kx" in lines[0]
    _clean(cap.err)
    assert "secret-token" not in cap.out + cap.err
    assert seen == []
