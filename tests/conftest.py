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
