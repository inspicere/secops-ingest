# tests/secrets/test_onboard.py
from __future__ import annotations

import io
import json
from urllib.parse import parse_qs

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.secrets import onboard as ob  # noqa: E402
from secops_ingest.secrets.base import SecretError  # noqa: E402

URL = "https://pam.example.com/SecretServer"
KEY = "onboarding-key-value"
SECRET = "new-client-secret-value"


def _server(calls, onboard_status=200, token_status=200, body=None):
    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/api/v1/sdk-client-accounts"):
            return httpx.Response(
                onboard_status,
                json=body if body is not None else {"clientId": "abc-123", "clientSecret": SECRET},
            )
        if request.url.path.endswith("/oauth2/token"):
            return httpx.Response(token_status, json={"access_token": "t", "expires_in": 60})
        raise AssertionError(request.url)

    return httpx.MockTransport(handler)


@pytest.fixture
def transport(monkeypatch):
    """Route every httpx.Client the module builds through one fake server."""
    state = {"calls": [], "kwargs": {}}
    real = httpx.Client

    class Client(real):
        def __init__(self, *a, transport=None, **k):
            super().__init__(*a, transport=_server(state["calls"], **state["kwargs"]), **k)

    monkeypatch.setattr(httpx, "Client", Client)
    return state


class Stdin(io.StringIO):
    def isatty(self):
        return False


def _run(tmp_path, argv_extra=()):
    out = io.StringIO()
    id_file = tmp_path / "client-id"
    code = ob.main(["--url", URL, "--rule", "secops-ingest", "--name", "worker-01",
                    "--client-id-file", str(id_file), *argv_extra],
                   stdin=Stdin(KEY + "\n"), stdout=out)
    return code, out.getvalue(), id_file


def test_registers_once_then_proves_the_client(transport, tmp_path):
    code, out, id_file = _run(tmp_path)
    assert code == 0
    assert out == SECRET
    assert id_file.read_text() == "sdk-client-abc-123\n"
    onboarding, token = transport["calls"]
    sent = json.loads(onboarding.content)
    assert sent["OnboardingKey"] == KEY and sent["RuleName"] == "secops-ingest"
    assert sent["Name"] == "worker-01"
    form = parse_qs(token.content.decode())
    assert form["client_id"] == ["sdk-client-abc-123"]
    assert form["grant_type"] == ["client_credentials"]


def test_the_secret_goes_to_stdout_and_nowhere_else(transport, tmp_path, capsys):
    code, out, id_file = _run(tmp_path)
    assert code == 0
    err = capsys.readouterr().err
    assert SECRET not in err and KEY not in err
    assert SECRET not in id_file.read_text()


def test_a_refused_onboarding_names_neither_secret(transport, tmp_path, capsys):
    transport["kwargs"] = {"onboard_status": 400, "body": {"message": KEY}}
    code, out, id_file = _run(tmp_path)
    assert code == 1 and out == ""
    err = capsys.readouterr().err
    assert "400" in err and KEY not in err
    assert not id_file.exists()
    assert len(transport["calls"]) == 1  # never retried


def test_a_client_that_cannot_get_a_token_keeps_its_id_and_no_secret(transport, tmp_path, capsys):
    transport["kwargs"] = {"token_status": 403}
    code, out, id_file = _run(tmp_path)
    assert code == 1 and out == ""
    assert id_file.read_text() == "sdk-client-abc-123\n"
    assert "403" in capsys.readouterr().err


def test_no_verify_makes_one_call(transport, tmp_path):
    code, out, _ = _run(tmp_path, ["--no-verify"])
    assert code == 0 and out == SECRET
    assert len(transport["calls"]) == 1


@pytest.mark.parametrize("body", [{}, {"clientId": "x"}, {"clientSecret": "y"}, []])
def test_an_incomplete_answer_is_refused(transport, tmp_path, body):
    transport["kwargs"] = {"body": body}
    code, out, _ = _run(tmp_path)
    assert code == 1 and out == ""


def test_an_id_that_already_carries_the_prefix_is_kept():
    def handler(request):
        return httpx.Response(200, json={"clientId": "sdk-client-9", "clientSecret": "s"})

    cid, _ = ob.onboard(URL, "r", KEY, "n", transport=httpx.MockTransport(handler))
    assert cid == "sdk-client-9"


def test_http_and_an_empty_key_are_refused_before_any_request():
    def handler(request):  # pragma: no cover - must not be reached
        raise AssertionError

    with pytest.raises(SecretError, match="https"):
        ob.onboard("http://pam.example.com", "r", KEY, "n",
                   transport=httpx.MockTransport(handler))
    with pytest.raises(SecretError, match="onboarding key"):
        ob.onboard(URL, "r", "", "n", transport=httpx.MockTransport(handler))


def test_a_terminal_on_stdin_is_a_usage_error(tmp_path):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert ob.main(["--url", URL, "--rule", "r", "--client-id-file",
                    str(tmp_path / "id")], stdin=Tty(), stdout=io.StringIO()) == 2
