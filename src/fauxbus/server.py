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
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import ISSUES_URL, __version__
from .auth import ANONYMOUS_TOKEN, Identity, parse_bearer
from .errors import ApiError, unauthorized
from .world import World


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


class FauxbusServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        world: World | None = None,
        allow_anonymous: bool = False,
        verbose: bool = False,
    ) -> None:
        super().__init__(address, FauxbusHandler)
        self.world = world or World()
        self.lock = threading.Lock()
        self.allow_anonymous = allow_anonymous
        self.verbose = verbose
        self.routes: list[Route] = []
        self.failures: list[FailureRule] = []
        self.fail_counter = 0

    def add_route(self, method: str, pattern: str, handler: Handler, *, auth: bool) -> None:
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
            headers={str(k): str(v) for k, v in (doc.get("headers") or {}).items()},
            times=times,
        )
        self.failures.append(rule)
        return rule

    def consume_failure(self, method: str, path: str) -> FailureRule | None:
        for rule in self.failures:
            if rule.matches(method, path):
                if rule.times is not None:
                    rule.times -= 1
                    if rule.times <= 0:
                        self.failures.remove(rule)
                return rule
        return None


class FauxbusHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: FauxbusServer  # narrowed for type checkers

    # ------------------------------------------------------------- plumbing

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _send(self, status: int, doc: Any, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(doc, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(400, "BAD_REQUEST", "request body is not valid JSON") from None

    # ------------------------------------------------------------- dispatch

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            if path.startswith("/v2/"):
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
        header = self.headers.get("X-Fauxbus-Fail")
        if header is not None:
            try:
                status = int(header)
            except ValueError:
                raise ApiError(400, "BAD_REQUEST", "X-Fauxbus-Fail must be an integer status") from None
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
        # connection.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)

    def _find_route(self, method: str, path: str) -> tuple[Route | None, bool]:
        saw_path = False
        for route in self.server.routes:
            if route.pattern.match(path):
                if route.method == method:
                    return route, True
                saw_path = True
        return None, saw_path

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
) -> FauxbusServer:
    from .control_api import register as register_control
    from .groups_api import register as register_groups

    server = FauxbusServer(
        (host, port), world=world, allow_anonymous=allow_anonymous, verbose=verbose
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
