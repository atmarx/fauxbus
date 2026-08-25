"""Regressions for the v0.1.0 security review findings.

Every test here failed before its fix.  They are grouped by the review's
own buckets so a reader can trace a test back to the finding that bought
it.  Several drop below the `fx` client to a raw socket on purpose: the
bugs live in the bytes on the wire and in how the connection is handled,
which is exactly the layer a polite HTTP client hides from you.
"""

from __future__ import annotations

import socket
import threading

import pytest
from conftest import CLIENT_ID, CLIENT_SECRET, GROUPS_SCOPE

from fauxbus.server import MAX_BODY_BYTES, make_server

G = "00000000-0000-4000-8000-0000000000aa"
ALICE = "00000000-0000-4000-8000-00000000000a"


def raw_exchange(client, request: bytes, timeout: float = 3.0) -> bytes:
    """Send literal bytes, read until close or timeout.  Returns b'' on silence."""
    host, port = client.base_url.removeprefix("http://").split(":")
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        sock.sendall(request)
        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except TimeoutError:
            pass
        return b"".join(chunks)
    finally:
        sock.close()


# ------------------------------------------------- header injection (CRLF)


@pytest.mark.parametrize(
    "bad",
    [
        "yes\r\nX-Injected: pwned",           # forge an extra header
        "yes\r\n\r\nHTTP/1.1 200 OK",         # forge a whole second response
        "yes\nX-Injected: pwned",             # bare LF: some parsers accept it
        "yes\r\nSet-Cookie: session=evil",    # the classic payload
    ],
)
def test_failure_rule_headers_reject_crlf(fx, bad):
    status, doc, _ = fx.post(
        "/_fauxbus/failures",
        {"method": "GET", "path": "/v2/*", "status": 200, "headers": {"X-Ok": bad}},
    )
    assert status == 400
    assert "CR, LF, or NUL" in doc["detail"]


def test_failure_rule_header_names_reject_crlf(fx):
    # The name half of the pair is just as good a place to smuggle a newline.
    status, _, _ = fx.post(
        "/_fauxbus/failures",
        {"path": "/v2/*", "status": 200, "headers": {"X-Bad\r\nX-Injected": "v"}},
    )
    assert status == 400


def test_no_forged_header_reaches_the_wire(fx):
    # Belt and braces: prove it at the byte level, not just via the API.
    # A rejected rule must also mean an unarmed rule.
    fx.post(
        "/_fauxbus/failures",
        {"path": "/v2/*", "status": 200, "headers": {"X-Ok": "a\r\nX-Injected: pwned"}},
    )
    raw = raw_exchange(
        fx,
        b"GET /v2/groups/my_groups HTTP/1.1\r\nHost: x\r\n"
        b"Authorization: Bearer t-alice\r\nConnection: close\r\n\r\n",
    )
    assert b"X-Injected" not in raw
    _, armed, _ = fx.get("/_fauxbus/failures")
    assert armed["failures"] == []


def test_legitimate_headers_still_pass(fx):
    # The fix must not break Retry-After, which the 429 retry story needs.
    status, rule, _ = fx.post(
        "/_fauxbus/failures",
        {"path": "/v2/*", "status": 429, "headers": {"Retry-After": "0"}, "times": 1},
    )
    assert status == 200
    assert rule["headers"] == {"Retry-After": "0"}


# --------------------------------------------------------- Content-Length


def test_negative_content_length_gets_an_answer_not_a_parked_thread(fx):
    # int("-1") succeeds and rfile.read(-1) means "until EOF" — on a
    # keep-alive connection that is forever.  The bug's signature was
    # total silence, so the assertion is simply: the server answered.
    raw = raw_exchange(
        fx, b"POST /_fauxbus/reset HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
    )
    assert raw.startswith(b"HTTP/1.1 400"), raw[:120]


def test_absurd_content_length_is_refused_before_buffering(fx):
    raw = raw_exchange(
        fx,
        b"POST /_fauxbus/seed HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999999\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 413"), raw[:120]
    assert str(MAX_BODY_BYTES).encode() in raw


def test_garbage_content_length_is_refused(fx):
    raw = raw_exchange(
        fx, b"POST /_fauxbus/reset HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"
    )
    assert raw.startswith(b"HTTP/1.1 400"), raw[:120]


def test_refused_length_closes_the_connection_no_smuggling(fx):
    """The follow-on hazard the review didn't reach, found while fixing it.

    Refusing a length means we never consumed the body, so any bytes the
    client did send are still queued.  On a reused connection those get
    parsed as the next request — and an attacker choosing the bytes is
    choosing that request.  The server must answer and hang up.
    """
    # A body IS sent, and it is a complete, valid HTTP request. If the
    # connection were reused, this smuggled GET would execute as though
    # the client had asked for it.
    smuggled = b"GET /_fauxbus/state HTTP/1.1\r\nHost: x\r\n\r\n"
    raw = raw_exchange(
        fx,
        b"POST /_fauxbus/reset HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n" + smuggled,
    )
    assert raw.startswith(b"HTTP/1.1 413"), raw[:120]
    # One response, not two: the smuggled request never ran.  (A state
    # dump would carry "counters"; the 413 body cannot.)
    assert raw.count(b"HTTP/1.1") == 1, raw
    assert b"counters" not in raw


def test_the_server_survives_a_bad_length_and_keeps_serving(fx):
    # The real damage of a parked thread is cumulative, so prove the
    # server is still healthy afterwards.
    raw_exchange(fx, b"POST /_fauxbus/reset HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\n")
    status, doc, _ = fx.get("/_fauxbus/")
    assert status == 200 and "fauxbus" in doc


# ------------------------------------------------------- X-Fauxbus-Fail


@pytest.mark.parametrize("bad", ["99999", "0", "-1"])
def test_injection_header_status_must_be_a_real_status(fx, bad):
    status, _, _ = fx.get("/v2/groups/my_groups", token="t-alice", headers={"X-Fauxbus-Fail": bad})
    assert status == 400


def test_injection_header_still_works_for_real_statuses(fx):
    status, doc, _ = fx.get(
        "/v2/groups/my_groups", token="t-alice", headers={"X-Fauxbus-Fail": "503"}
    )
    assert status == 503
    assert doc["code"] == "FAUXBUS_INJECTED_FAILURE"


# ------------------------------------------------- seed validation (bucket A)


def test_seed_refuses_unknown_policy_keys_exactly_as_the_endpoint_does(fx):
    # These two doors disagreed: PUT /policies rejected a typo, the seed
    # swallowed it and left the fixture quietly wrong.
    status, doc, _ = fx.post(
        "/_fauxbus/seed",
        {"groups": {G: {"name": "x", "policies": {"bogus_key": "evil"}}}},
    )
    assert status == 422
    assert "bogus_key" in doc["detail"]


@pytest.mark.parametrize(
    "doc",
    [
        {"groups": {G: {"name": "x", "session_limit": "abc"}}},
        {"clock": "soon"},
        {"counters": {"group": "many"}},
        {"groups": {G: {"name": "x", "memberships": "not-a-mapping"}}},
        {"groups": {G: {"name": "x", "session_timeouts": 7}}},
        {"preferences": {ALICE: "not-a-mapping"}},
        {"identities": "not-a-mapping"},
    ],
)
def test_malformed_seed_blames_the_document_not_fauxbus(fx, doc):
    # Every one of these used to raise inside load() and surface as a 500
    # FAUXBUS_INTERNAL_ERROR — "Fauxbus is broken" — when the document was
    # the broken thing.  Wrong blame sends someone to the wrong repo.
    status, body, _ = fx.post("/_fauxbus/seed", doc)
    assert status == 422, f"{doc} → {status} {body}"
    assert body["code"] == "VALIDATION_ERROR"


def test_a_rejected_seed_leaves_the_world_alone(fx):
    fx.post("/_fauxbus/seed", {"groups": {G: {"name": "keeper"}}})
    fx.post("/_fauxbus/seed", {"groups": {G: {"name": "x", "session_limit": "abc"}}})
    _, state, _ = fx.get("/_fauxbus/state")
    # load() resets before validating, so a bad seed empties the world —
    # documented here as the actual behavior rather than assumed away.
    # What matters is that it is a *clean* state, not a half-applied one.
    assert G not in state["groups"] or state["groups"][G]["name"] == "keeper"


# ------------------------------------------- control plane reachability


@pytest.fixture
def restricted():
    server = make_server("127.0.0.1", 0, control_loopback_only=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def test_loopback_still_reaches_a_restricted_control_plane(restricted):
    host, port = restricted.server_address[:2]
    raw = raw_exchange(
        type("C", (), {"base_url": f"http://{host}:{port}"}),
        b"GET /_fauxbus/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    # 127.0.0.1 is loopback, so the flag must not lock out the local
    # harness — nor the container healthcheck, which dials 127.0.0.1
    # from inside the container.
    assert raw.startswith(b"HTTP/1.1 200"), raw[:120]


def test_default_leaves_the_control_plane_open(fx):
    # The documented default: fauxbus stands in for a service that
    # answers the network, and harnesses are often sibling containers.
    assert fx.get("/_fauxbus/")[0] == 200


def test_restriction_never_touches_the_imitated_surface(restricted):
    # Principle 4 in the other direction: the flag is about /_fauxbus/,
    # and the Globus-shaped API must behave identically either way.
    host, port = restricted.server_address[:2]
    client = type("C", (), {"base_url": f"http://{host}:{port}"})
    raw = raw_exchange(
        client,
        b"GET /v2/groups/my_groups HTTP/1.1\r\nHost: x\r\n"
        b"Authorization: Bearer t-alice\r\nConnection: close\r\n\r\n",
    )
    assert raw.startswith(b"HTTP/1.1 200"), raw[:120]


def test_non_loopback_peer_is_refused(restricted):
    # No second interface is guaranteed in CI, so exercise the decision
    # function against the addresses it will actually see rather than
    # faking a network.  The peer address is read from the accepted
    # socket, which is why this check can't be spoofed by a header.
    from fauxbus.server import FauxbusHandler

    def verdict(peer: str) -> bool:
        fake = object.__new__(FauxbusHandler)
        fake.server = restricted
        fake.client_address = (peer, 12345)
        return FauxbusHandler._control_allowed(fake)

    assert verdict("127.0.0.1") is True
    assert verdict("::1") is True
    assert verdict("10.10.1.10") is False
    assert verdict("192.168.1.50") is False
    assert verdict("") is False  # unparseable peer fails closed


# ------------------------------------------- form bodies (the token endpoint)


def test_charset_parameter_does_not_defeat_the_form_parser(registered):
    """Content-Type is a media type plus parameters, and clients send both.

    ``application/x-www-form-urlencoded; charset=UTF-8`` is the same
    encoding as the bare type, and a parser that compares the whole
    header string would decide otherwise — then fall through to the JSON
    branch and answer "not valid JSON" to a perfectly good form.
    """
    status, doc, _ = registered.form_post(
        "/v2/oauth2/token",
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=(CLIENT_ID, CLIENT_SECRET),
        content_type="application/x-www-form-urlencoded; charset=UTF-8",
    )
    assert status == 200
    assert doc["resource_server"] == "groups.api.globus.org"


def test_a_form_body_that_is_not_utf8_is_blamed_not_crashed(fx):
    # Bytes that cannot be text at all: an unpaired UTF-16 surrogate's
    # worth of garbage in a body that claims to be a form.  This must be
    # a 400 naming the body, never the 500 that says Fauxbus itself broke.
    host, port = fx.base_url.removeprefix("http://").split(":")
    payload = b"\xff\xfe\x00scope=x"
    raw = raw_exchange(
        fx,
        b"POST /v2/oauth2/token HTTP/1.1\r\nHost: %s\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
        % (host.encode(), len(payload), payload),
    )
    assert b"400" in raw.split(b"\r\n")[0]
    assert b"UTF-8" in raw


def test_failure_injection_reaches_the_token_endpoint(registered):
    """The new surface is under /v2/, so the control plane owns it too.

    Worth an explicit test rather than an assumption: a consumer's whole
    reason for wanting a token endpoint in a fake is to rehearse what
    happens when Globus Auth is having a bad day.
    """
    registered.post("/_fauxbus/failures", {"method": "POST", "path": "/v2/oauth2/*", "status": 503})
    status, _, _ = registered.form_post(
        "/v2/oauth2/token",
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=(CLIENT_ID, CLIENT_SECRET),
    )
    assert status == 503
