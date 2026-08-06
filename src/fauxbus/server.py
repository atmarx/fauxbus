"""The HTTP server: routing, auth, failure injection, and the 501 wall.

Stdlib only.  The imitated surface lives under /v2/ and requires a
bearer token; the control plane lives under /_fauxbus/ and never does.
Anything unrouted gets a loud 501 pointing at the issue tracker — never
a silent wrong answer.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import ISSUES_URL, __version__
from .auth import ANONYMOUS_TOKEN, Identity, parse_bearer
from .errors import ApiError, unauthorized
from .world import World

# A seed document is the largest thing anyone legitimately sends, and a
# test world is small.  32 MiB is far above any honest seed and far below
# "buffer whatever you're told to."
MAX_BODY_BYTES = 32 * 1024 * 1024


@dataclass
class Ctx:
    """Everything a route handler gets to see."""

    world: World
    server: FauxbusServer
    identity: Identity | None
    match: re.Match[str]
    query: dict[str, str]
    body: Any


Handler = Callable[[Ctx], tuple[int, Any] | tuple[int, Any, dict[str, str]]]


@dataclass
class Route:
    method: str
    pattern: re.Pattern[str]
    handler: Handler
    requires_auth: bool


@dataclass
class FailureRule:
    id: str
    method: str  # HTTP verb or "*"
    path: str  # glob over the request path
    status: int
    body: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    times: int | None = None  # None = until cleared

    def matches(self, method: str, path: str) -> bool:
        return self.method in ("*", method) and fnmatchcase(path, self.path)

    def doc(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "body": self.body,
            "headers": self.headers,
            "times": self.times,
        }


def injected_body(source: str) -> dict[str, Any]:
    return {"code": "FAUXBUS_INJECTED_FAILURE", "detail": f"failure injected via {source}"}


# A header value is one line, by definition.  Let a CR or LF through and
# the caller stops writing a header and starts writing the response: one
# `\r\n` forges extra headers, two forge a whole second response into the
# byte stream (response splitting).  The injected *body* is arbitrary on
# purpose — that is the product — but the headers frame the message, and
# a fake that can be made to emit a message its operator didn't write is
# a fake that can lie about who said what.  Reject rather than strip, so
# a harness learns its rule was wrong instead of silently getting a
# different one than it asked for.
def checked_header(name: str, value: str) -> tuple[str, str]:
    name, value = str(name), str(value)
    for part, what in ((name, "name"), (value, "value")):
        if "\r" in part or "\n" in part or "\0" in part:
            raise ApiError(
                400,
                "BAD_REQUEST",
                f"header {what} may not contain CR, LF, or NUL: {part!r}",
            )
    if not name or not name.isascii() or not value.isascii():
        raise ApiError(400, "BAD_REQUEST", f"header {name!r} must be non-empty and ASCII")
    return name, value


class FauxbusServer(ThreadingHTTPServer):
    """One server, one World, one lock.

    Threading because real SDK clients pool connections — a
    single-threaded server can deadlock a client that opens a second
    connection mid-request.  But the world is plain dicts, so every
    handler runs under one coarse lock (taken in _dispatch): each API
    call is atomic, concurrent requests simply serialize.  For a test
    fake this is the right trade — the critical sections are
    microseconds, the "load" is one test process, and one big lock is
    a design you can audit at a glance.  Fine-grained locking earns
    its complexity on servers with throughput problems; this isn't one.
    """

    daemon_threads = True  # worker threads must never outlive Ctrl-C

    def __init__(
        self,
        address: tuple[str, int],
        *,
        world: World | None = None,
        allow_anonymous: bool = False,
        verbose: bool = False,
        canonical_seed: dict[str, Any] | None = None,
        control_loopback_only: bool = False,
    ) -> None:
        super().__init__(address, FauxbusHandler)
        self.world = world or World()
        self.lock = threading.Lock()
        self.allow_anonymous = allow_anonymous
        self.verbose = verbose
        # Off by default, deliberately.  Fauxbus stands in for a service
        # that answers the whole network, and the harness driving it is
        # routinely a sibling container rather than a process on this
        # host — a loopback-only control plane would break the shipped
        # compose pattern.  What the flag buys, for anyone who wants it:
        # the control plane is the one surface that can rewrite the world
        # and forge responses, so on a shared host it is the surface you
        # may want reachable only from the machine under test.
        self.control_loopback_only = control_loopback_only
        self.routes: list[Route] = []
        self.failures: list[FailureRule] = []
        self.fail_counter = 0
        # The document reset restores — the fixed point tests return to.
        # Set at boot (--seed) or via POST /_fauxbus/seed?canonical=true.
        self.canonical_seed = canonical_seed

    def add_route(self, method: str, pattern: str, handler: Handler, *, auth: bool) -> None:
        # Patterns are anchored ^...$ so "/v2/groups" can never match
        # "/v2/groups/anything" by prefix.  First registered match wins
        # — see groups_api.register for why its order is deliberate.
        self.routes.append(Route(method, re.compile(f"^{pattern}$"), handler, auth))

    def arm_failure(self, doc: dict[str, Any]) -> FailureRule:
        status = doc.get("status")
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise ApiError(400, "BAD_REQUEST", "failure rule requires an integer 'status' (100-599)")
        path = doc.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ApiError(400, "BAD_REQUEST", "failure rule requires a 'path' glob starting with /")
        times = doc.get("times")
        if times is not None and (not isinstance(times, int) or times < 1):
            raise ApiError(400, "BAD_REQUEST", "'times' must be a positive integer or null")
        self.fail_counter += 1
        rule = FailureRule(
            id=f"fail-{self.fail_counter}",
            method=str(doc.get("method", "*")).upper(),
            path=path,
            status=status,
            body=doc.get("body"),
            # Validated at ARM time, not send time: a bad rule should fail
            # the harness call that armed it, where the stack trace points
            # at the test that wrote it — not three requests later inside
            # some unrelated assertion.
            headers=dict(
                checked_header(k, v) for k, v in (doc.get("headers") or {}).items()
            ),
            times=times,
        )
        self.failures.append(rule)
        return rule

    def consume_failure(self, method: str, path: str) -> FailureRule | None:
        # First armed rule wins.  Counted rules burn one use per match
        # and vanish at zero — that countdown is what lets the SDK's
        # automatic retry finally break through and succeed, which is
        # exactly the arc a retry test wants to watch.
        for rule in self.failures:
            if rule.matches(method, path):
                if rule.times is not None:
                    rule.times -= 1
                    if rule.times <= 0:
                        self.failures.remove(rule)
                return rule
        return None


class FauxbusHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 turns on keep-alive, which the SDK's connection pooling
    # expects.  Keep-alive imposes a discipline: every response must
    # carry an accurate Content-Length (_send guarantees it), and every
    # request body must be consumed even on paths that never use it
    # (_drain_body) — unread bytes left on a reused connection are
    # parsed as the start of the NEXT request, and everything after
    # that failure is confusing.
    protocol_version = "HTTP/1.1"
    server: FauxbusServer  # narrowed for type checkers

    # ------------------------------------------------------------- plumbing

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _send(self, status: int, doc: Any, headers: dict[str, str] | None = None) -> None:
        # sort_keys: byte-stable responses across runs.  Principle 3
        # applies to the wire, not just the world.
        body = json.dumps(doc, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _content_length(self) -> int:
        """How many body bytes to read — trusting nothing about the number.

        `int()` on a header is where a small server gets hurt: `int("-1")`
        succeeds, and `rfile.read(-1)` means "read until EOF", which on a
        keep-alive connection is a client that simply never sends EOF.  The
        worker thread blocks there forever, and enough of those exhaust the
        pool with no error anywhere.  An absurd positive length is the same
        wound the other way — we would happily buffer it into memory.
        """
        raw = self.headers.get("Content-Length")
        if raw is None:
            return 0
        try:
            length = int(raw)
        except (TypeError, ValueError):
            self._refuse_body()
            raise ApiError(400, "BAD_REQUEST", f"Content-Length is not an integer: {raw!r}") from None
        if length < 0:
            self._refuse_body()
            raise ApiError(400, "BAD_REQUEST", f"Content-Length may not be negative: {length}")
        if length > MAX_BODY_BYTES:
            self._refuse_body()
            raise ApiError(
                413,
                "PAYLOAD_TOO_LARGE",
                f"body of {length} bytes exceeds the {MAX_BODY_BYTES}-byte limit",
            )
        return length

    def _refuse_body(self) -> None:
        """Answer, then hang up — the only safe move after refusing a length.

        Rejecting a Content-Length leaves the connection indeterminate:
        we declined to say how many body bytes were coming, so we cannot
        consume them, so whatever the client actually sent is still in
        the buffer.  On a keep-alive connection those leftovers are
        parsed as the *next* request — which is request smuggling, and
        an attacker who picks the bytes picks that request.  This is the
        same hazard `_drain_body` exists to prevent; there the cure is
        to read the body, and here, where reading it is precisely what
        we refused to do, the cure is to close.
        """
        self.close_connection = True

    def _read_body(self) -> Any:
        length = self._content_length()
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(400, "BAD_REQUEST", "request body is not valid JSON") from None

    # ------------------------------------------------------------- dispatch

    def _dispatch(self, method: str) -> None:
        # The life of a request, in order:
        #   1. Failure injection (imitated surface only) — armed rules
        #      and the X-Fauxbus-Fail header answer before any routing,
        #      the way a genuinely broken service fails before logic.
        #   2. Read and parse the JSON body.
        #   3. Route.  No such path → loud 501 (principle 2: never a
        #      silent wrong answer).  Path exists, wrong verb → 405.
        #   4. Under the world lock: authenticate, run the handler.
        #   5. Render.  Handlers return (status, doc[, headers]);
        #      raised ApiErrors render through one place below.
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            if path.startswith("/_fauxbus") and not self._control_allowed():
                raise ApiError(
                    403,
                    "CONTROL_PLANE_RESTRICTED",
                    "the control plane is restricted to loopback callers "
                    "(--control-loopback-only). The imitated surface is unaffected.",
                )
            if path.startswith("/v2/"):
                # Injection is scoped to the imitated surface.  The
                # control plane stays unbreakable: a harness that could
                # sabotage its own reset endpoint couldn't be trusted
                # to clean up after the test that did it (principle 4).
                if self._maybe_inject(method, path):
                    return
            body = self._read_body()
            route, saw_path = self._find_route(method, path)
            if route is None:
                if saw_path:
                    # PROVISIONAL: known path, wrong verb.
                    raise ApiError(405, "METHOD_NOT_ALLOWED", f"{method} is not allowed on {path}")
                raise ApiError(
                    501,
                    "NOT_IMPLEMENTED",
                    f"Fauxbus does not implement {method} {path}. Real client code "
                    f"needs it? File an issue: {ISSUES_URL}",
                )
            with self.server.lock:
                identity = self._authenticate() if route.requires_auth else None
                match = route.pattern.match(path)
                assert match is not None
                result = route.handler(
                    Ctx(self.server.world, self.server, identity, match, query, body)
                )
            if len(result) == 2:
                status, doc = result
                headers: dict[str, str] = {}
            else:
                status, doc, headers = result
            self._send(status, doc, headers)
        except ApiError as err:
            self._send(err.status, err.body())
        except Exception:
            traceback.print_exc(file=sys.stderr)
            self._send(
                500,
                {
                    "code": "FAUXBUS_INTERNAL_ERROR",
                    "detail": "Fauxbus itself broke — this is a Fauxbus bug, not a "
                    f"Globus behavior. File an issue: {ISSUES_URL}",
                },
            )

    def _maybe_inject(self, method: str, path: str) -> bool:
        # Two injection channels, and each earns its keep:
        # - X-Fauxbus-Fail header: zero-setup, one request — the test
        #   marks a single call it makes itself as doomed.
        # - Armed rules (POST /_fauxbus/failures): out-of-band and
        #   pattern-matched — "the next 2 POSTs to /v2/groups/* answer
        #   429."  This reaches where the header can't: the SDK retries
        #   *inside* one client call, re-sending the same headers every
        #   attempt, so only a rule that counts down and then clears
        #   can make retry #3 succeed while attempts #1-2 fail.
        header = self.headers.get("X-Fauxbus-Fail")
        if header is not None:
            try:
                status = int(header)
            except ValueError:
                raise ApiError(400, "BAD_REQUEST", "X-Fauxbus-Fail must be an integer status") from None
            # Same range the armed-rule path enforces.  Two doors to the
            # same behavior should not disagree about what is valid —
            # and send_response() with a nonsense code emits a status
            # line no HTTP client should be asked to parse.
            if not 100 <= status <= 599:
                raise ApiError(
                    400, "BAD_REQUEST", f"X-Fauxbus-Fail must be a status in 100-599, got {status}"
                )
            self._drain_body()
            self._send(status, injected_body("X-Fauxbus-Fail header"))
            return True
        with self.server.lock:
            rule = self.server.consume_failure(method, path)
        if rule is not None:
            self._drain_body()
            body = rule.body if rule.body is not None else injected_body(f"rule {rule.id}")
            self._send(rule.status, body, rule.headers)
            return True
        return False

    def _drain_body(self) -> None:
        # Keep-alive hygiene: consume the request body even when injecting
        # a failure, or the unread bytes corrupt the next request on the
        # connection.  Same guarded length as the real read — draining is
        # not a reason to trust a number we just refused to trust.
        length = self._content_length()
        if length:
            self.rfile.read(length)

    def _find_route(self, method: str, path: str) -> tuple[Route | None, bool]:
        # Two answers, not one: the route, and whether the PATH exists
        # under any verb at all.  Wire manners hang on the distinction
        # — wrong verb on a real path is 405; unknown path is the loud
        # 501 with a file-an-issue pointer.
        saw_path = False
        for route in self.server.routes:
            if route.pattern.match(path):
                if route.method == method:
                    return route, True
                saw_path = True
        return None, saw_path

    def _control_allowed(self) -> bool:
        """Whether this peer may speak to /_fauxbus/ at all.

        Only consulted when --control-loopback-only is set.  The check is
        on the peer address, which cannot be spoofed over a completed TCP
        handshake the way a header can — that is the whole reason to
        prefer it to a self-declared identity here.  Note that a
        container's own healthcheck dials 127.0.0.1 from inside the
        container, so it stays green under this flag.
        """
        if not self.server.control_loopback_only:
            return True
        try:
            return ip_address(self.client_address[0]).is_loopback
        except (ValueError, IndexError):
            # Unparseable peer (a Unix socket, an exotic transport) —
            # fail closed.  The flag exists to be strict; a peer we
            # cannot identify is not one we can call local.
            return False

    def _authenticate(self) -> Identity:
        token = parse_bearer(self.headers.get("Authorization"))
        if token is None:
            if not self.server.allow_anonymous:
                raise unauthorized()
            token = ANONYMOUS_TOKEN
        return self.server.world.identity_for_token(token)

    # ----------------------------------------------------------- verb hooks

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")


def make_server(
    host: str = "127.0.0.1",
    port: int = 9800,
    *,
    world: World | None = None,
    allow_anonymous: bool = False,
    verbose: bool = False,
    canonical_seed: dict[str, Any] | None = None,
    control_loopback_only: bool = False,
) -> FauxbusServer:
    from .control_api import register as register_control
    from .groups_api import register as register_groups

    server = FauxbusServer(
        (host, port),
        world=world,
        allow_anonymous=allow_anonymous,
        verbose=verbose,
        canonical_seed=canonical_seed,
        control_loopback_only=control_loopback_only,
    )
    register_groups(server)
    register_control(server)
    return server


def boot_line(server: FauxbusServer) -> str:
    from . import SDK_PIN

    host, port = server.server_address[:2]
    return (
        f"fauxbus {__version__} listening on http://{host}:{port} — "
        f"imitating: groups v2 (globus-sdk {SDK_PIN} surface); control plane at /_fauxbus/"
    )
