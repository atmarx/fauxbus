"""The harness: a Fauxbus in your test, driven from your test.

Everything a test does to Fauxbus already has an HTTP route under
``/_fauxbus/``, so this module adds no powers.  It adds convenience, in
one small client, and the discipline is the part worth reading:

    with running_fauxbus(seed=my_seed) as fb:
        app = globus_sdk.NativeAppAuthClient(CLIENT_ID)
        app.oauth2_start_flow("openid")
        code = fb.login(app.oauth2_get_authorize_url(), ALICE).code
        tokens = app.oauth2_exchange_code_for_tokens(code)

**Why ``Fauxbus`` is only an HTTP client, even though the server is
sitting in the same process.**  ``server.world`` is one attribute away,
and reaching for it would be faster and easier to write.  It would also
mean a test passing here said nothing about the server a consumer runs
in a container, because it would have skipped the routes, the parsing,
and the lock that server goes through.  Principle 4 says the harness
stays out of band, and that holds in-process too.  The payoff is that
``Fauxbus("http://fauxbus:9800")`` drives a compose stack's server with
the same methods.

Stdlib only, like the rest of the package.  A fake that consumers add to
their dev environments should not bring a supply chain with it, and
pytest and globus-sdk are only touched if they are already there.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .server import make_server

try:
    import pytest
except ImportError:
    pytest = None  # the fixtures at the bottom simply do not exist

# The three services the SDK can be pointed at that Fauxbus imitates.
# SPEC's login-shim plan first gave Groups a /v2/ suffix; all three are
# the bare root, because the SDK's own paths already start with /v2/.
SERVICES = ("AUTH", "GROUPS", "TRANSFER")


class FauxbusError(Exception):
    """The control plane, or the browser leg of a login, said no.

    Raised at the harness call that caused it, so the traceback points
    at the line in the test that asked for something impossible rather
    than at some later assertion puzzling over a world that never
    changed.  ``status`` and ``body`` are there for a test that expects
    the refusal and wants to read it.
    """

    def __init__(self, message: str, status: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # surface the 3xx as an HTTPError instead of following it


# Two decisions in one opener.  Redirects stay unfollowed because a login
# is a chain of 302s and the Location of each hop is the evidence: the
# last one points at the client's callback, which may be a host that does
# not exist.  And proxies are ignored because this client only ever talks
# to a fake it was handed the address of: a developer's HTTP_PROXY would
# otherwise send a loopback URL to a corporate proxy, and the failure
# would read like Fauxbus being down.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _send(
    method: str, url: str, data: bytes | None, content_type: str
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", content_type)
    try:
        with _OPENER.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        with err:
            return err.code, dict(err.headers), err.read()


@dataclass(frozen=True)
class Login:
    """Where the browser ended up: the client's callback, code or error attached.

    ``location`` is what to hand a web app's callback route, and it is
    kept whole because that app reads its own ``state`` from it.  A
    native app wants ``code``.  An authorize refusal that the client is
    supposed to handle itself is not an exception here: it is a normal
    ending with ``error`` set, because testing that handler is a thing a
    test does.
    """

    location: str

    def _param(self, name: str) -> str | None:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.location).query)
        return query[name][0] if name in query else None

    @property
    def code(self) -> str:
        # Raises rather than returning None.  Passing None on to
        # oauth2_exchange_code_for_tokens fails three frames away with a
        # complaint about the SDK's arguments, and the real story (the
        # authorize step refused, and why) is gone by then.
        code = self._param("code")
        if code is None:
            raise FauxbusError(f"this login ended without a code: {self.location}")
        return code

    @property
    def state(self) -> str | None:
        return self._param("state")

    @property
    def error(self) -> str | None:
        return self._param("error")

    @property
    def error_description(self) -> str | None:
        return self._param("error_description")


class Fauxbus:
    """A client for one Fauxbus's control plane.  Holds a URL and nothing else."""

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")

    @property
    def env(self) -> dict[str, str]:
        """The environment that points an unmodified app here.

        For a subprocess: ``subprocess.run(cmd, env={**os.environ, **fb.env})``.
        """
        return {f"GLOBUS_SDK_SERVICE_URL_{service}": self.url + "/" for service in SERVICES}

    def control(self, method: str, path: str, body: Any = None) -> Any:
        """Any control-plane route, for what has no method of its own.

        Transfer tasks are the main customer: the methods below are the
        four every login test needs, and the rest of the surface stays a
        line of its own rather than a second API to keep in step with
        SPEC.  Refuses anything outside ``/_fauxbus/``.  The imitated
        surface is the app's to call, and a harness that called it would
        be the app's test double instead of the app.
        """
        if not path.startswith("/_fauxbus/"):
            raise ValueError(f"not a control-plane path: {path!r}")
        data = json.dumps(body).encode() if body is not None else None
        status, _, raw = _send(method, self.url + path, data, "application/json")
        doc = json.loads(raw) if raw else None
        if status >= 400:
            raise FauxbusError(f"{method} {path} answered {status}: {raw.decode()}", status, doc)
        return doc

    def state(self) -> dict[str, Any]:
        """Everything in the world: what is there, not what your code claims it did."""
        return self.control("GET", "/_fauxbus/state")

    def seed(self, doc: dict[str, Any], *, canonical: bool = False) -> None:
        """Replace the whole world.  ``canonical=True`` also makes it what ``reset`` restores."""
        self.control("POST", "/_fauxbus/seed" + ("?canonical=true" if canonical else ""), doc)

    def reset(self, *, to: str = "seed") -> None:
        """Back to the canonical seed (``to="empty"`` for blank), with failures disarmed."""
        self.control("POST", "/_fauxbus/reset", {"to": to})

    def tick(self, seconds: int = 1) -> int:
        """Move the logical clock; returns the new time.

        Tokens only *die* of this on a server with
        ``require_issued_tokens=True``.  Without it any bearer string is
        accepted, an expired one included, and that is the standing
        behaviour of every Fauxbus and not a special case here.
        """
        return self.control("POST", "/_fauxbus/tick", {"seconds": seconds})["clock"]

    def fail(
        self,
        path: str,
        status: int,
        *,
        method: str = "*",
        times: int | None = None,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """Arm a failure on the imitated surface; returns the rule's id for ``clear_failures``.

        ``path`` is a glob.  ``times=None`` means until cleared, the
        same default as the route, and for a reason a test author should
        know: the SDK retries a 429 or 5xx by itself, so ``times=1`` is
        usually a test of the retry, and the app never sees the failure.
        """
        rule: dict[str, Any] = {"path": path, "status": status, "method": method}
        if times is not None:
            rule["times"] = times
        if body is not None:
            rule["body"] = body
        if headers is not None:
            rule["headers"] = headers
        return self.control("POST", "/_fauxbus/failures", rule)["id"]

    def clear_failures(self, rule_id: str | None = None) -> int:
        """Disarm one rule or all of them; returns how many went."""
        query = "?" + urllib.parse.urlencode({"id": rule_id}) if rule_id is not None else ""
        return self.control("DELETE", "/_fauxbus/failures" + query)["cleared"]

    def sign_in(self, account: str) -> str:
        """Open a browser session; returns the ``Cookie`` header value for it.

        For a test driving a real browser or a web app's own HTTP client:
        with this cookie, authorize skips the account picker.  A test
        holding only an authorize URL wants ``login`` instead.
        """
        return self.control("POST", "/_fauxbus/auth/session", {"account": account})["cookie"]

    def login(self, authorize_url: str, account: str) -> Login:
        """Be the browser: follow an authorize URL, pick ``account``, stop at the callback.

        It goes through the picker rather than through ``sign_in`` because
        the picker is the one path that works for every login, including
        ``prompt=login``, which ignores an existing session on purpose.
        Anything that does not end in a redirect to the client (an
        unregistered redirect URI, an account the client's ``required_idp``
        refuses, a loud 501) raises, because no callback exists to hand back.
        """
        status, headers, raw = _send("GET", authorize_url, None, "text/plain")
        if status != 302:
            raise FauxbusError(f"authorize answered {status}: {raw.decode()}", status, raw.decode())
        location = headers["Location"]
        # The picker's Location is relative, by design (see
        # oidc_api.picker_redirect).  Anything absolute is the client's own
        # callback already: an authorize error, sent back with `error=`.
        if not location.startswith("/_fauxbus/auth/login"):
            return Login(location)
        request_id = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["request"][0]
        status, headers, raw = _send(
            "POST",
            self.url + "/_fauxbus/auth/login",
            urllib.parse.urlencode({"request": request_id, "account": account}).encode(),
            "application/x-www-form-urlencoded",
        )
        if status != 302:
            raise FauxbusError(
                f"signing in as {account} answered {status}: {raw.decode()}", status, raw.decode()
            )
        return Login(headers["Location"])

    def login_flow_manager(self, account: str) -> type:
        """A ``login_flow_manager`` for the SDK's ``UserApp``, with ``account`` at the keyboard.

        ``GlobusAppConfig(login_flow_manager=fb.login_flow_manager(ALICE))``
        and the app logs in with nobody at a terminal.  It replaces the
        person and nothing else: scope resolution, PKCE, the exchange and
        the ID-token check all run as shipped.  globus-sdk is imported
        here and not at the top, so that the harness keeps working without
        it, and this is the one method that needs it.
        """
        from globus_sdk.login_flows import CommandLineLoginFlowManager

        harness = self

        class HarnessBrowser(CommandLineLoginFlowManager):
            def print_authorize_url(self, authorize_url: str) -> None:
                self.authorize_url = authorize_url

            def prompt_for_code(self) -> str:
                return harness.login(self.authorize_url, account).code

        return HarnessBrowser


@contextmanager
def running_fauxbus(
    seed: dict[str, Any] | str | Path | None = None,
    *,
    require_issued_tokens: bool = False,
    allow_anonymous: bool = False,
    signed_token_clock: str = "wall",
    point_env: bool = True,
) -> Iterator[Fauxbus]:
    """A server on a free port, seeded, with the SDK pointed at it, for one ``with`` block.

    ``seed`` is a state document or a path to one, loaded as canonical,
    so ``reset`` comes home to it.

    **``point_env`` defaults on, because the failure of forgetting it
    is the worst one available:** an unmodified app built inside this
    block would talk to the real Globus.  The variables go back as they
    were on exit.  They live in ``os.environ``, which is process-wide, so
    a suite running harnesses in parallel threads wants ``point_env=False``
    and ``fb.env``.

    **``signed_token_clock`` defaults to ``"wall"``, which is not the
    server's default,** and is the one place this harness differs from
    ``fauxbus serve``.  The SDK verifies an ID token against real time
    whenever it decodes one, ``UserApp`` included, so on the logical
    clock the first login in a test dies as "expired" in 1970.  The
    opt-in is narrow (see ``FauxbusServer.signed_now``): only an ID
    token's instants read the wall, and access tokens and codes still
    expire by ``tick``.  Pass ``"logical"`` to compare ID tokens byte for
    byte.  A seed's ``oidc`` section outranks this, as it outranks the
    boot flag.
    """
    server = make_server(
        "127.0.0.1",
        0,  # the kernel picks; two suites on one host can never collide
        require_issued_tokens=require_issued_tokens,
        allow_anonymous=allow_anonymous,
        signed_token_clock=signed_token_clock,
    )
    host, port = server.server_address[:2]
    url = f"http://{host}:{port}"
    # The issuer is the server's own address, which does not exist until
    # the socket is bound, so this cannot be a make_server argument.  It
    # is the same field --issuer sets: boot configuration, not the world.
    # It is the right default here, unlike on the command line, because
    # the only name anything in this process can reach the server by is
    # this one, so the browser-versus-broker split SPEC worries about
    # cannot arise.
    server.default_issuer = url
    # The default poll interval is half a second, and shutdown() waits out
    # the current one.  A fixture that starts a server per test would pay
    # that on every test, to save a little idle CPU nobody is short of.
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    ).start()
    previous: dict[str, str | None] = {}
    try:
        fb = Fauxbus(url)
        if seed is not None:
            doc = seed if isinstance(seed, dict) else json.loads(Path(seed).read_text())
            # Over HTTP like everything else, so a seed this version does
            # not understand is the same 422 it would be in a container.
            fb.seed(doc, canonical=True)
        if point_env:
            previous = {name: os.environ.get(name) for name in fb.env}
            os.environ.update(fb.env)
        yield fb
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        server.shutdown()
        server.server_close()


if pytest is not None:
    # Opt in with ``pytest_plugins = ["fauxbus.testing"]`` in a top-level
    # conftest.py, or by importing the fixtures.  There is deliberately no
    # pytest11 entry point: that would load this module into the test run
    # of everyone who has Fauxbus installed, asked or not.

    @pytest.fixture
    def fauxbus_options() -> dict[str, Any]:
        """``running_fauxbus`` arguments for the ``fauxbus`` fixture.  Override it to seed."""
        return {}

    @pytest.fixture
    def fauxbus(fauxbus_options: dict[str, Any]) -> Iterator[Fauxbus]:
        """A fresh server for one test.  A server per test costs milliseconds,
        and buys a world no earlier test could have touched."""
        with running_fauxbus(**fauxbus_options) as fb:
            yield fb
