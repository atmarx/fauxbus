"""fauxbus.testing, held to what its docstring says.

Each test here checks a claim the harness makes to a test author.  The
SDK-driven half lives in test_sdk_conformance.py, with the rest of the
tests that need globus-sdk.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import textwrap
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

import pytest
from conftest import (
    ALICE_GLOBUSID,
    BOB_GLOBUSID,
    CAMPUS_CLIENT,
    CAMPUS_REDIRECT,
    LOGIN_CLIENT,
    LOGIN_REDIRECT,
    NATIVE_CLIENT,
    PINS,
    Client,
    oidc_seed,
)

import fauxbus.testing
from fauxbus.testing import Fauxbus, FauxbusError, Login, running_fauxbus

ENV_NAMES = [f"GLOBUS_SDK_SERVICE_URL_{s}" for s in ("AUTH", "GROUPS", "TRANSFER")]


def login_seed() -> dict:
    """The conftest world, minus its issuer: the harness supplies that."""
    doc = oidc_seed("placeholder")
    del doc["oidc"]
    return doc


def authorize_url(fb: Fauxbus, client: str = LOGIN_CLIENT, redirect: str = LOGIN_REDIRECT, **extra) -> str:
    query = {
        "client_id": client,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": "openid",
        "state": "the-apps-own-state",
        **extra,
    }
    return f"{fb.url}/v2/oauth2/authorize?{urlencode(query)}"


# --- starting, seeding, and coming home ------------------------------------


def test_two_harnesses_run_side_by_side_on_their_own_ports():
    with running_fauxbus(point_env=False) as one, running_fauxbus(point_env=False) as two:
        assert one.url != two.url
        one.seed({"identities": PINS})
        assert one.state()["identities"] and not two.state()["identities"]


def test_the_seed_is_canonical_so_reset_comes_home():
    with running_fauxbus(seed={"identities": PINS}) as fb:
        before = fb.state()
        fb.tick(5)
        assert fb.state() != before
        fb.reset()
        assert fb.state() == before
        fb.reset(to="empty")
        assert not fb.state()["identities"]


def test_a_seed_can_be_a_path(tmp_path: Path):
    path = tmp_path / "seed.json"
    path.write_text(json.dumps({"identities": PINS}))
    with running_fauxbus(seed=path) as fb:
        assert fb.state()["identities"]


def test_the_issuer_defaults_to_the_servers_own_address():
    # And survives a reset to empty, because it is boot configuration
    # rather than part of the world.  Without this default every seed
    # would have to know a port that does not exist until after the bind.
    with running_fauxbus() as fb:
        fb.reset(to="empty")
        client = Client(fb.url)
        _, doc, _ = client.get("/.well-known/openid-configuration")
        assert doc["issuer"] == fb.url


def test_a_seeded_issuer_outranks_the_default():
    seed = {"oidc": {"issuer": "http://named-in-the-seed.test"}}
    with running_fauxbus(seed=seed) as fb:
        _, doc, _ = Client(fb.url).get("/.well-known/openid-configuration")
        assert doc["issuer"] == "http://named-in-the-seed.test"


def test_a_seed_this_version_refuses_fails_at_the_with_line_and_leaves_nothing_behind():
    before = {name: os.environ.get(name) for name in ENV_NAMES}
    with pytest.raises(FauxbusError) as caught, running_fauxbus(seed={"no_such_section": {}}):
        pass  # pragma: no cover
    assert caught.value.status == 422
    assert "no_such_section" in str(caught.value)
    assert {name: os.environ.get(name) for name in ENV_NAMES} == before


# --- the environment -------------------------------------------------------


def test_the_environment_is_pointed_inside_and_restored_after(monkeypatch):
    monkeypatch.setenv("GLOBUS_SDK_SERVICE_URL_AUTH", "http://was-here-first.test/")
    monkeypatch.delenv("GLOBUS_SDK_SERVICE_URL_GROUPS", raising=False)
    with running_fauxbus() as fb:
        for name in ENV_NAMES:
            assert os.environ[name] == fb.url + "/"
    assert os.environ["GLOBUS_SDK_SERVICE_URL_AUTH"] == "http://was-here-first.test/"
    assert "GLOBUS_SDK_SERVICE_URL_GROUPS" not in os.environ


def test_the_environment_comes_back_when_the_test_body_raises(monkeypatch):
    monkeypatch.delenv("GLOBUS_SDK_SERVICE_URL_AUTH", raising=False)
    with pytest.raises(RuntimeError), running_fauxbus():
        raise RuntimeError("the test failed")
    assert "GLOBUS_SDK_SERVICE_URL_AUTH" not in os.environ


def test_point_env_false_leaves_the_environment_alone(monkeypatch):
    monkeypatch.delenv("GLOBUS_SDK_SERVICE_URL_AUTH", raising=False)
    with running_fauxbus(point_env=False) as fb:
        assert "GLOBUS_SDK_SERVICE_URL_AUTH" not in os.environ
        assert fb.env["GLOBUS_SDK_SERVICE_URL_AUTH"] == fb.url + "/"


def test_the_servers_are_gone_after_the_block():
    with running_fauxbus() as fb:
        url = fb.url
    with pytest.raises(OSError):
        urllib.request.urlopen(url + "/_fauxbus/", timeout=2)


def test_a_developers_proxy_does_not_capture_the_harness():
    # In a fresh process, because urllib reads proxy settings when an
    # opener is built, and the harness builds its opener at import: a
    # monkeypatch here would arrive too late and this test would pass with
    # the fix removed.  It did, the first time it was written.  The proxy
    # address has nothing listening, so reaching for it fails the run.
    env = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}
    env.update(http_proxy="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
    program = """
        import fauxbus.testing as t
        with t.running_fauxbus() as fb:
            assert fb.tick() == 1
    """
    subprocess.run([sys.executable, "-c", textwrap.dedent(program)], check=True, env=env, timeout=30)


# --- the control verbs -----------------------------------------------------


def test_tick_returns_the_new_time():
    with running_fauxbus() as fb:
        assert fb.tick(10) == 10
        assert fb.tick() == 11
        assert fb.state()["clock"] == 11


def test_fail_arms_counts_down_and_clears():
    with running_fauxbus() as fb:
        client = Client(fb.url)
        fb.fail("/v2/groups*", 418, times=2)
        statuses = [client.get("/v2/groups/my_groups", token="t")[0] for _ in range(3)]
        assert statuses == [418, 418, 200]

        rule = fb.fail("/v2/groups*", 503, method="POST", body={"code": "DOWN"})
        assert client.post("/v2/groups", {"name": "x"}, token="t")[:2] == (503, {"code": "DOWN"})
        assert client.get("/v2/groups/my_groups", token="t")[0] == 200
        assert fb.clear_failures(rule) == 1
        assert client.post("/v2/groups", {"name": "x"}, token="t")[0] != 503

        fb.fail("/a", 500)
        fb.fail("/b", 500)
        assert fb.clear_failures() == 2


def test_a_control_plane_refusal_raises_at_the_call_that_caused_it():
    with running_fauxbus() as fb:
        with pytest.raises(FauxbusError) as caught:
            fb.tick(-1)
        assert caught.value.status == 400
        assert "seconds" in str(caught.value)


def test_control_reaches_what_has_no_method_of_its_own():
    with running_fauxbus() as fb:
        assert fb.control("GET", "/_fauxbus/")["fauxbus"] == fauxbus.__version__


def test_control_refuses_the_imitated_surface():
    with running_fauxbus() as fb, pytest.raises(ValueError, match="control-plane"):
        fb.control("GET", "/v2/groups/my_groups")


# --- the person ------------------------------------------------------------


def test_login_walks_the_picker_to_the_callback():
    with running_fauxbus(seed=login_seed()) as fb:
        login = fb.login(authorize_url(fb), ALICE_GLOBUSID)
        assert login.location.startswith(LOGIN_REDIRECT + "?")
        assert login.state == "the-apps-own-state"
        assert login.error is None
        (code,) = fb.state()["authorization_codes"]
        assert login.code == code


def test_login_covers_prompt_login_which_ignores_an_open_session():
    with running_fauxbus(seed=login_seed()) as fb:
        fb.sign_in(BOB_GLOBUSID)
        login = fb.login(authorize_url(fb, prompt="login"), ALICE_GLOBUSID)
        (code,) = fb.state()["authorization_codes"].values()
        assert code["identity_id"] == ALICE_GLOBUSID
        assert login.code


def test_an_error_for_the_client_to_handle_is_a_login_with_error_set():
    # Testing the app's own error route is a thing a test does, so this
    # is an ordinary ending, not an exception.
    with running_fauxbus(seed=login_seed()) as fb:
        login = fb.login(authorize_url(fb, response_type="token"), ALICE_GLOBUSID)
        assert login.error == "unsupported_response_type"
        assert login.error_description
        assert login.state == "the-apps-own-state"
        with pytest.raises(FauxbusError, match="without a code"):
            login.code  # noqa: B018 — the property is what raises


def test_an_account_the_client_refuses_raises_with_the_refusal():
    with running_fauxbus(seed=login_seed()) as fb:
        url = authorize_url(fb, client=CAMPUS_CLIENT, redirect=CAMPUS_REDIRECT)
        with pytest.raises(FauxbusError) as caught:
            fb.login(url, BOB_GLOBUSID)
        assert caught.value.status == 403
        assert fb.login(url, ALICE_GLOBUSID).code


def test_an_unseeded_account_raises():
    with running_fauxbus(seed=login_seed()) as fb:
        with pytest.raises(FauxbusError) as caught:
            fb.login(authorize_url(fb), "00000000-0000-4000-8000-00000000dead")
        assert caught.value.status == 400


def test_an_untrusted_redirect_uri_raises_because_there_is_no_callback():
    with running_fauxbus(seed=login_seed()) as fb:
        with pytest.raises(FauxbusError) as caught:
            fb.login(authorize_url(fb, redirect="https://evil.example/cb"), ALICE_GLOBUSID)
        assert caught.value.status >= 400


def test_a_loud_501_stays_loud():
    with running_fauxbus(seed=login_seed()) as fb:
        with pytest.raises(FauxbusError) as caught:
            fb.login(authorize_url(fb, prompt="none"), ALICE_GLOBUSID)
        assert caught.value.status == 501


def test_sign_ins_cookie_makes_authorize_skip_the_picker():
    with running_fauxbus(seed=login_seed()) as fb:
        cookie = fb.sign_in(ALICE_GLOBUSID)
        status, headers, _ = Client(fb.url).browse(authorize_url(fb), cookie=cookie)
        assert status == 302
        assert Login(headers["Location"]).code


def test_sign_in_of_an_unseeded_account_raises():
    with running_fauxbus(seed=login_seed()) as fb:
        with pytest.raises(FauxbusError):
            fb.sign_in("00000000-0000-4000-8000-00000000dead")


def test_a_native_clients_login_ends_at_the_auth_code_page():
    with running_fauxbus(seed=login_seed()) as fb:
        url = authorize_url(
            fb,
            client=NATIVE_CLIENT,
            redirect=fb.url + "/v2/web/auth-code",
            code_challenge="x" * 43,
            code_challenge_method="S256",
        )
        assert fb.login(url, ALICE_GLOBUSID).code


# --- the design claims -----------------------------------------------------


def test_the_harness_has_no_backdoor_into_the_world():
    """The module docstring's promise, as a check on the source itself.

    The roadmap says "thin wrappers over the HTTP control plane, never a
    backdoor into World."  A sentence like that is true on the day it is
    written and quietly not true the day somebody is in a hurry.
    """
    tree = ast.parse(Path(fauxbus.testing.__file__).read_text())
    touched = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not touched & {"world", "failures", "canonical_seed"}
    internal = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level > 0
    ]
    assert internal == ["server"]


def test_the_client_drives_a_server_it_did_not_start(fx):
    # The same methods against a server someone else booted: what a
    # compose stack's test suite gets.  conftest's server stands in for it.
    fb = Fauxbus(fx.base_url + "/")
    assert fb.url == fx.base_url
    fb.seed({"identities": PINS})
    assert fb.state()["identities"]
    assert fb.tick(3) == 3


def run_pytest_on(tmp_path: Path, conftest: str, test: str) -> subprocess.CompletedProcess:
    (tmp_path / "conftest.py").write_text(textwrap.dedent(conftest))
    (tmp_path / "test_consumer.py").write_text(textwrap.dedent(test))
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_the_pytest_fixture_works_the_way_the_readme_says(tmp_path: Path):
    """A consumer's suite, run for real: the plugin line, an override, a fresh world per test."""
    result = run_pytest_on(
        tmp_path,
        """
        import pytest

        pytest_plugins = ["fauxbus.testing"]

        @pytest.fixture
        def fauxbus_options():
            return {"seed": {"oidc": {"issuer": "http://seeded.test"}}}
        """,
        """
        def test_seeded_and_pointed(fauxbus):
            import os
            assert fauxbus.state()["oidc"]["issuer"] == "http://seeded.test"
            assert os.environ["GLOBUS_SDK_SERVICE_URL_AUTH"] == fauxbus.url + "/"
            fauxbus.tick(5)

        def test_a_later_test_sees_a_new_world(fauxbus):
            assert fauxbus.state()["clock"] == 0
        """,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout


def test_the_harness_needs_neither_pytest_nor_the_sdk():
    # The zero-dependency claim, checked in a process where neither can
    # be imported, rather than repeated.  None in sys.modules is Python's
    # own way of making an import fail.
    program = """
        import sys
        sys.modules["pytest"] = None
        sys.modules["globus_sdk"] = None
        import fauxbus.testing as t
        assert t.pytest is None and not hasattr(t, "fauxbus")
        with t.running_fauxbus() as fb:
            assert fb.tick(2) == 2
    """
    subprocess.run([sys.executable, "-c", textwrap.dedent(program)], check=True, timeout=30)
