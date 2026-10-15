"""Red Team findings: Graph token refresh and secret value handling."""
import io
import json
import urllib.error
from types import SimpleNamespace as NS

from acasentry import azure_live, checks, cli, demo

SUB = "11111111-2222-3333-4444-555555555555"
SECRET = "s3cr3t-Value-XYZ"


class FakeCred:
    def __init__(self, clock, lifetime=3600):
        self.clock, self.lifetime, self.issued = clock, lifetime, 0

    def get_token(self, scope):
        self.issued += 1
        return NS(token=f"tok{self.issued}", expires_on=self.clock.now + self.lifetime)


class Clock:
    def __init__(self):
        self.now = 1_000_000

    def __call__(self):
        return self.now


class Opener:
    """Fake urlopen: records Authorization headers, optionally fails with given statuses."""
    def __init__(self, fail=()):
        self.auth, self.fail = [], list(fail)

    def __call__(self, req, timeout=None):
        self.auth.append(req.get_header("Authorization"))
        if self.fail:
            code = self.fail.pop(0)
            raise urllib.error.HTTPError(req.full_url, code, "err", {}, None)
        return _Resp(json.dumps({"value": []}).encode())


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _session(fail=()):
    clock = Clock()
    cred = FakeCred(clock)
    op = Opener(fail)
    return azure_live.GraphSession(cred, clock=clock, opener=op), cred, clock, op


# 1. token refresh
def test_graph_token_cached_while_valid():
    s, cred, clock, op = _session()
    s({"ids": []})
    clock.now += 600
    s({"ids": []})
    assert cred.issued == 1 and op.auth == ["Bearer tok1", "Bearer tok1"]


def test_graph_token_refreshed_near_expiry():
    s, cred, clock, op = _session()
    s({"ids": []})
    clock.now += 3600 - azure_live.TOKEN_SKEW_SECONDS + 1  # inside the skew window
    s({"ids": []})
    assert cred.issued == 2 and op.auth[-1] == "Bearer tok2"


def test_graph_token_refreshed_after_expiry():
    s, _cred, clock, op = _session()
    s({"ids": []})
    clock.now += 7200
    s({"ids": []})
    assert op.auth == ["Bearer tok1", "Bearer tok2"]


def test_graph_401_retries_once_with_fresh_token():
    s, _cred, _clock, op = _session(fail=[401])
    assert s({"ids": []}) == {"value": []}
    assert op.auth == ["Bearer tok1", "Bearer tok2"]


def test_graph_second_401_is_raised_not_looped():
    s, _cred, _clock, op = _session(fail=[401, 401])
    try:
        s({"ids": []})
        raise AssertionError("expected HTTPError")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    assert len(op.auth) == 2


def test_graph_403_not_retried_with_new_token():
    s, cred, _clock, op = _session(fail=[403])
    try:
        s({"ids": []})
    except urllib.error.HTTPError:
        pass
    assert cred.issued == 1 and len(op.auth) == 1


# 2. secret values never retained or printed
def _live_app():
    env = [NS(name="API_TOKEN", value=SECRET, secret_ref=None)]
    return NS(name="a", id=f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.App/containerApps/a",
              managed_environment_id=None, identity=None, configuration=None,
              template=NS(containers=[NS(name="main", env=env)], init_containers=None))


def test_normalize_does_not_retain_secret_value():
    n = azure_live._normalize(_live_app())
    assert SECRET not in repr(n)
    assert n["env"][0]["has_value"] is True


def test_secrets_output_masks_values(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(azure_live, "load_apps",
                        lambda sub, check_auth=False: [azure_live._normalize(_live_app())])
    f = tmp_path / "o.csv"
    assert cli.main(["secrets", "--subscription", SUB, "--csv", str(f)]) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and SECRET[:2] + "*" not in out
    assert checks.VALUE_MASK in out and "PLAINTEXT_ENV" in out
    assert SECRET not in f.read_text() and checks.VALUE_MASK in f.read_text()


def test_demo_data_holds_no_values():
    assert "hunter2" not in repr(demo.APPS) and "abc123" not in repr(demo.APPS)


def test_persistent_graph_401_says_sign_in_again(capsys):
    def post(body):
        raise urllib.error.HTTPError(azure_live.GRAPH_URL, 401, "Unauthorized", {}, None)
    assert azure_live.resolve_principals({"x"}, graph=post) == {}
    err = capsys.readouterr().err
    assert "rejected the sign-in token" in err and "az login" in err
    assert "Directory.Read.All" not in err


def test_graph_token_auth_error_says_az_login(capsys):
    from azure.core.exceptions import ClientAuthenticationError

    class ExpiredCred:
        def get_token(self, scope):
            raise ClientAuthenticationError("AADSTS700082: The refresh token has expired")
    s = azure_live.GraphSession(ExpiredCred(), opener=Opener())
    assert azure_live.resolve_principals({"x"}, graph=s) == {}
    err = capsys.readouterr().err
    assert "az login" in err and "Directory.Read.All" not in err
