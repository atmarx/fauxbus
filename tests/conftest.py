"""Shared fixtures: one live Fauxbus server, wire-level access to it.

Tests talk to a real listening socket, not handler internals — Fauxbus
is a wire-level fake, so its tests are wire-level too.
"""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

from fauxbus.server import make_server

# Fixed identities for tests that pin them via the seed document.
ALICE = "00000000-0000-4000-8000-00000000000a"
BOB = "00000000-0000-4000-8000-00000000000b"
CAROL = "00000000-0000-4000-8000-00000000000c"

PINS = {
    "t-alice": {"identity_id": ALICE, "username": "alice@example.org"},
    "t-bob": {"identity_id": BOB, "username": "bob@example.org"},
    "t-carol": {"identity_id": CAROL, "username": "carol@example.org"},
}

# A registered confidential client for the token-endpoint tests.  The id
# is a UUID because in Globus Auth a client IS an identity — the same
# UUID shows up as a group member once the client acts on its own token.
CLIENT_ID = "00000000-0000-4000-8000-0000000c11e7"
CLIENT_SECRET = "not-a-real-secret"
CLIENTS = {CLIENT_ID: {"secret": CLIENT_SECRET, "name": "Test dispatcher"}}

GROUPS_SCOPE = "urn:globus:auth:scope:groups.api.globus.org:all"
TRANSFER_SCOPE = "urn:globus:auth:scope:transfer.api.globus.org:all"


# --- slice B: a small world of people, providers, and login clients -------
#
# Globus ID's provider UUID is RECORDED (globus_sdk/testing/data/auth/
# get_identity_providers.py) — using the real one costs nothing and
# makes the identity_provider claims look like the real thing.  The
# university is invented, under an RFC 2606 name.
GLOBUSID_IDP = "41143743-f3c8-4d60-bbdb-eeecaba85bd9"
UNIVERSITY_IDP = "00000000-0000-4000-8000-0000000001d9"

# alice: primary identity at Globus ID, plus a linked university identity.
ALICE_GLOBUSID = "00000000-0000-4000-8000-00000000a11c"
ALICE_UNIVERSITY = "00000000-0000-4000-8000-00000000a11e"
# bob: Globus ID only — the account a required_idp client must refuse.
BOB_GLOBUSID = "00000000-0000-4000-8000-000000000b0b"

LOGIN_CLIENT = "00000000-0000-4000-8000-00000000c0de"
LOGIN_SECRET = "login-secret-not-a-real-one"
LOGIN_REDIRECT = "https://app.example.org/callback"
# A second login client that demands the university identity.
CAMPUS_CLIENT = "00000000-0000-4000-8000-0000000ca305"
CAMPUS_SECRET = "campus-secret-not-a-real-one"
CAMPUS_REDIRECT = "https://campus.example.edu/broker/fauxbus/endpoint"


def oidc_seed(issuer: str, **extra: Any) -> dict[str, Any]:
    """A seed document with everything a browser login needs.

    ``issuer`` is the live test server's own URL, because globus-sdk's
    ``get_jwk`` follows discovery's ``jwks_uri`` — an issuer the test
    process cannot reach would send the SDK somewhere that does not
    answer.
    """
    doc: dict[str, Any] = {
        "identities": PINS,
        "oidc": {"issuer": issuer},
        "identity_providers": {
            GLOBUSID_IDP: {"name": "Globus ID"},
            UNIVERSITY_IDP: {"name": "Example University"},
        },
        "accounts": {
            ALICE_GLOBUSID: {
                "identities": {
                    ALICE_GLOBUSID: {
                        "username": "alice@globusid.org",
                        "identity_provider": GLOBUSID_IDP,
                        "name": "Alice Example",
                        "email": "alice@example.org",
                        "organization": "Independent",
                    },
                    ALICE_UNIVERSITY: {
                        "username": "ae123@example.edu",
                        "identity_provider": UNIVERSITY_IDP,
                        "name": "Alice Example",
                        "email": "ae123@example.edu",
                        "organization": "Example University",
                    },
                }
            },
            BOB_GLOBUSID: {
                "identities": {
                    BOB_GLOBUSID: {
                        "username": "bob@globusid.org",
                        "identity_provider": GLOBUSID_IDP,
                        "name": "Bob Example",
                        "email": "bob@example.org",
                    }
                }
            },
        },
        "clients": {
            **CLIENTS,
            LOGIN_CLIENT: {
                "secret": LOGIN_SECRET,
                "name": "Example Web Login",
                "redirect_uris": [LOGIN_REDIRECT],
            },
            CAMPUS_CLIENT: {
                "secret": CAMPUS_SECRET,
                "name": "Campus Broker",
                "redirect_uris": [CAMPUS_REDIRECT],
                "required_idp": UNIVERSITY_IDP,
            },
        },
    }
    doc.update(extra)
    return doc


def basic_header(client_id: str, secret: str) -> str:
    """The header globus-sdk's BasicAuthorizer builds, byte for byte.

    Note the raw f-string join with no percent-encoding: that is what the
    SDK does, and matching it is the point (see auth.parse_basic).
    """
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
        )
        req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null"), dict(resp.headers)
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"null"), dict(err.headers)

    def get(self, path: str, **kw: Any) -> tuple[int, Any, dict[str, str]]:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> tuple[int, Any, dict[str, str]]:
        return self.request("POST", path, body, **kw)

    def put(self, path: str, body: Any = None, **kw: Any) -> tuple[int, Any, dict[str, str]]:
        return self.request("PUT", path, body, **kw)

    def delete(self, path: str, **kw: Any) -> tuple[int, Any, dict[str, str]]:
        return self.request("DELETE", path, **kw)

    def form_post(
        self,
        path: str,
        fields: dict[str, str],
        *,
        basic: tuple[str, str] | None = None,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> tuple[int, Any, dict[str, str]]:
        """POST a form body — the OAuth2 token endpoint's native shape.

        Separate from ``request`` rather than a flag on it, because the
        two differ in every part: encoding, Content-Type, and the header
        that carries the credential.  ``content_type`` is overridable so a
        test can deliberately send the wrong one.
        """
        req = urllib.request.Request(
            self.base_url + path,
            data=urllib.parse.urlencode(fields).encode(),
            method="POST",
        )
        req.add_header("Content-Type", content_type)
        if basic is not None:
            req.add_header("Authorization", basic_header(*basic))
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"null"), dict(resp.headers)
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"null"), dict(err.headers)


    def browse(
        self,
        path: str,
        *,
        method: str = "GET",
        form: dict[str, str] | None = None,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """One browser hop, *not* following redirects.

        A login is a chain of 302s, and every one of them is something a
        test wants to read — the Location, the code in it, the cookie set
        beside it.  urllib follows redirects by default, which would
        swallow exactly the evidence the test exists to inspect, so this
        uses an opener with redirect handling removed.  Returns the
        status, the headers (a plain dict; ``Set-Cookie`` included), and
        the raw body bytes, because a hop's body may be HTML or nothing.
        """
        req = urllib.request.Request(
            path if path.startswith("http") else self.base_url + path,
            data=urllib.parse.urlencode(form).encode() if form is not None else None,
            method=method,
        )
        if form is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if cookie is not None:
            req.add_header("Cookie", cookie)
        for name, value in (headers or {}).items():
            req.add_header(name, value)
        try:
            with _NO_REDIRECTS.open(req, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # surface the 3xx as an HTTPError instead of following it


_NO_REDIRECTS = urllib.request.build_opener(_NoRedirect)


@pytest.fixture(scope="session")
def live_server():
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield Client(f"http://{host}:{port}")
    server.shutdown()
    server.server_close()


@pytest.fixture
def fx(live_server: Client) -> Client:
    """A client against a freshly reset, canonical-free world."""
    # A previous test may have pinned a canonical seed on the shared
    # server; forget it first so the reset below really means empty.
    status, _, _ = live_server.delete("/_fauxbus/seed")
    assert status == 200
    status, _, _ = live_server.post("/_fauxbus/reset")
    assert status == 200
    return live_server


@pytest.fixture
def pinned(fx: Client) -> Client:
    """A client against a world where alice/bob/carol tokens are pinned."""
    status, _, _ = fx.post("/_fauxbus/seed", {"identities": PINS})
    assert status == 200
    return fx


@pytest.fixture
def registered(fx: Client) -> Client:
    """A world with alice/bob/carol pinned and one confidential client registered."""
    status, _, _ = fx.post("/_fauxbus/seed", {"identities": PINS, "clients": CLIENTS})
    assert status == 200
    return fx


@pytest.fixture
def oidc(fx: Client) -> Client:
    """A world seeded for browser logins, issuer = this server."""
    status, doc, _ = fx.post("/_fauxbus/seed", oidc_seed(fx.base_url))
    assert status == 200, doc
    return fx


@pytest.fixture
def strict():
    """A second server running --require-issued-tokens.

    Its own process-wide fixture rather than a flag on ``fx`` because the
    setting lives on the server, not the world — you cannot toggle it
    between tests through the control plane, and that is deliberate: a
    harness should not be able to talk a fake into a different auth
    posture mid-run.
    """
    server = make_server("127.0.0.1", 0, require_issued_tokens=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    yield Client(f"http://{host}:{port}")
    server.shutdown()
    server.server_close()


# --- Transfer task monitoring: collections, roles, and who may watch ------
#
# The shape of the consumer that asked for this slice: one landing
# collection, subscribed, where a service client holds activity_monitor
# and nothing stronger.  A second collection whose subscription has
# lapsed, to prove the roles there go quiet.  Sources are invented
# per-test and never seeded — a researcher's laptop is nobody's
# collection to register.
LANDING = "00000000-0000-4000-8000-000000001a4d"
LAPSED = "00000000-0000-4000-8000-000000001a95"
LAPTOP = "00000000-0000-4000-8000-00000000e4a1"
SUBSCRIPTION = "00000000-0000-4000-8000-0000005ab5c4"


def transfer_seed(**extra: Any) -> dict[str, Any]:
    """A world where CLIENT_ID watches LANDING and alice manages it.

    bob and carol hold nothing anywhere, which is what makes them useful
    for the refusals.
    """
    doc: dict[str, Any] = {
        "identities": PINS,
        "clients": CLIENTS,
        "collections": {
            LANDING: {
                "display_name": "Example Landing",
                "subscription_id": SUBSCRIPTION,
                "roles": {CLIENT_ID: "activity_monitor", ALICE: "activity_manager"},
            },
            LAPSED: {
                "display_name": "Lapsed DTN",
                "subscription_id": None,
                "roles": {CLIENT_ID: "activity_monitor", ALICE: "activity_monitor"},
            },
        },
    }
    doc.update(extra)
    return doc


def files(count: int, *, size: int = 10, root: str = "/landing/proj-a") -> list[dict[str, Any]]:
    """``count`` files, each ``size`` bytes, named so their order is visible."""
    return [
        {
            "source_path": f"/home/alice/run/f{i:04d}.dat",
            "destination_path": f"{root}/f{i:04d}.dat",
            "size": size,
            "checksum": f"{i:064x}",
            "checksum_algorithm": "sha256",
        }
        for i in range(count)
    ]


def make_task(fx: Client, **fields: Any) -> dict[str, Any]:
    """Create a transfer task through the control plane: laptop → landing by default."""
    doc = {
        "owner_id": ALICE,
        "source_endpoint_id": LAPTOP,
        "destination_endpoint_id": LANDING,
        "files": files(2),
        **fields,
    }
    status, task, _ = fx.post("/_fauxbus/transfer/tasks", doc)
    assert status == 200, task
    return task


@pytest.fixture
def transfer(fx: Client) -> Client:
    """A world seeded with the landing collection and its watchers."""
    status, doc, _ = fx.post("/_fauxbus/seed", transfer_seed())
    assert status == 200, doc
    return fx
