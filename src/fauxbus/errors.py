"""Error documents shaped the way globus-sdk parses them.

The SDK's GlobusAPIError reads ``code`` into ``.code`` and any of
``message``/``detail``/``title`` into ``.message``, whichever of its
error-format branches fires.  ``{"code": ..., "detail": ...}`` satisfies
all of them, so nearly every Fauxbus error uses exactly that shape.

"Nearly" because the OAuth2 token endpoint speaks a different error
dialect — RFC 6749 §5.2's ``{"error": ..., "error_description": ...}``
— and Globus really does send that one there.  ``OAuthError`` below
carries it, and its docstring is the argument for why the two shapes
have to coexist rather than one being normalized into the other.
Globus Auth's own resources (userinfo) speak a third, ``AuthServiceError``,
and the Transfer API a fourth, ``TransferError``.  Each one is recorded
in the SDK's fixtures; none of them is Fauxbus's invention.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import ISSUES_URL
from .ids import sequential_id


class ApiError(Exception):
    """An error to be rendered as a Globus-shaped JSON error response.

    The pattern to learn here: raise this anywhere — three calls deep
    in world.py, in a route handler, in auth — and exactly one place
    (the dispatcher's ``except ApiError`` in server.py) turns it into
    an HTTP response.  Handlers never thread error tuples back up the
    call stack; the exception IS the response, waiting to happen.
    """

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail

    def body(self) -> dict[str, Any]:
        return {"code": self.code, "detail": self.detail}


# Factories, not subclasses: the wire only ever sees (status, code,
# detail), so a function returning a pre-filled ApiError documents each
# situation without growing a class hierarchy nothing dispatches on.


def unauthorized() -> ApiError:
    return ApiError(
        401,
        "UNAUTHORIZED",
        "No bearer token. Fauxbus requires Authorization: Bearer <token> "
        "unless started with --allow-anonymous.",
    )


def group_not_found(group_id: str) -> ApiError:
    # PROVISIONAL: 404 rather than 403 for groups the caller may not see —
    # information hiding is the security-correct default until a recording
    # against the real service says otherwise.
    return ApiError(404, "NOT_FOUND", f"Group {group_id} was not found")


def validation_error(detail: str) -> ApiError:
    # PROVISIONAL: the real Groups service is FastAPI (its operation ids
    # leak into the SDK docstrings), so 422 is the likely wire truth for
    # malformed input; the body shape here is Fauxbus's own.
    return ApiError(422, "VALIDATION_ERROR", detail)


def not_implemented(what: str) -> ApiError:
    """Principle 2's loud wall, as a value.

    The dispatcher raises this for an unrouted path; anything *inside* a
    handler that hits a shape Fauxbus knows about but has not built yet
    should raise it too.  A 501 with a place to file the gap is the only
    honest answer to "the real service does this and we don't" — the
    alternative is inventing a plausible response, which is exactly the
    silent wrong answer the principle exists to forbid.
    """
    return ApiError(501, "NOT_IMPLEMENTED", f"{what} File an issue: {ISSUES_URL}")


class OAuthError(ApiError):
    """A token-endpoint error, which does not look like any other error here.

    Every other Fauxbus error renders ``{"code": ..., "detail": ...}``,
    because that is the shape globus-sdk's GlobusAPIError parses.  The
    OAuth2 token endpoint is the exception: RFC 6749 §5.2 defines its own
    body, and the SDK's own fixture confirms Globus sends that instead —
    ``globus_sdk/testing/data/auth/oauth2_exchange_code_for_tokens.py``
    answers a bad authorization code with status **401** and the body
    ``{"error": "invalid_grant"}``.

    Two things in that fixture are worth carrying forward.

    First the status.  RFC 6749 says ``invalid_grant`` is a 400; Globus
    answers 401.  The recording wins (principle 5: faithful to Globus,
    not to the document Globus was implementing), and Fauxbus uses 401
    for the credential-shaped failures to match.

    Second, what is *absent*.  There is no ``code`` and no ``detail``, so
    the SDK's error parser falls through to its "undefined format"
    branch and finds nothing it recognizes: measured against 4.8.1 on
    2026-08-24, ``GlobusAPIError.code`` and ``.message`` both come back
    as ``None``, leaving ``.http_status`` and the raw body as the only
    signal.  A consumer's error handling really is that blind at this
    endpoint.  Fauxbus reproduces the blindness rather than improving on
    it — a fake that is kinder than the service hides a rough edge the
    consumer will meet in production anyway, and the conformance suite
    pins the observation so a later SDK bump cannot change it quietly.

    ``error_description`` is the one addition, and it is free: RFC 6749
    §5.2 makes it optional, Globus sends it on other Auth endpoints
    (``globus_sdk/testing/data/auth/_common.py``), and it appears in
    *none* of the SDK's message fields (``message``/``detail``/``title``)
    — so no consumer can accidentally come to depend on it, while
    whoever is reading a raw ``curl`` gets told what actually went wrong.
    """

    def __init__(self, status: int, error: str, description: str) -> None:
        super().__init__(status, error, description)
        self.error = error

    def body(self) -> dict[str, Any]:
        return {"error": self.error, "error_description": self.detail}


# RFC 6749 §5.2 names the error codes; the statuses are as reasoned above.


def invalid_client(detail: str) -> OAuthError:
    return OAuthError(401, "invalid_client", detail)


def invalid_request(detail: str) -> OAuthError:
    return OAuthError(400, "invalid_request", detail)


def invalid_grant(detail: str) -> OAuthError:
    # RECORDED: 401, from the SDK's oauth2_exchange_code_for_tokens fixture.
    return OAuthError(401, "invalid_grant", detail)


def unsupported_grant_type(detail: str) -> OAuthError:
    return OAuthError(400, "unsupported_grant_type", detail)


def invalid_scope(detail: str) -> OAuthError:
    return OAuthError(400, "invalid_scope", detail)


class AuthServiceError(ApiError):
    """Globus Auth's *own* error document — a third shape, and also recorded.

    Two dialects turned out to be an undercount.  The userinfo endpoint
    is an Auth API resource, not an OAuth2 grant, and the SDK's fixtures
    for it (``globus_sdk/testing/data/auth/userinfo.py`` and
    ``_common.py``, 4.8.1) show a document that carries *both* families
    at once: a JSON:API-style ``errors`` list with ``code``/``detail``/
    ``title``, and RFC 6749's ``error``/``error_description`` beside it.
    The SDK parses the list, so ``.code`` comes back ``UNAUTHORIZED`` and
    ``.message`` "Call must be authenticated" — unlike the token
    endpoint, where both are ``None``.

    The ``id`` in the fixture is a fresh ``uuid1`` per process.  Fauxbus
    derives one from the code instead (principle 3: no randomness), so
    the same failure renders the same bytes on every run.
    """

    def __init__(self, status: int, code: str, detail: str, title: str) -> None:
        super().__init__(status, code, detail)
        self.title = title

    def body(self) -> dict[str, Any]:
        return {
            "errors": [
                {
                    "status": str(self.status),
                    "id": sequential_id("auth-error", self.status),
                    "code": self.code,
                    "detail": self.detail,
                    "title": self.title,
                }
            ],
            "error_description": "Unauthorized",
            "error": "unauthorized",
        }


# RECORDED, both of them, body and text: the fixtures pair the same
# "Call must be authenticated" detail with 401/UNAUTHORIZED and with
# 403/FORBIDDEN.  Which *situation* earns which status is not recorded —
# see World.userinfo_token for the mapping Fauxbus chose.


def auth_unauthorized() -> AuthServiceError:
    return AuthServiceError(401, "UNAUTHORIZED", "Call must be authenticated", "Unauthorized")


def auth_forbidden() -> AuthServiceError:
    return AuthServiceError(403, "FORBIDDEN", "Call must be authenticated", "Unauthorized")


class TransferError(ApiError):
    """Globus Transfer's error document — the fourth dialect, and recorded too.

    Transfer predates the shapes the rest of Globus settled on, and its
    errors say so.  The SDK's fixtures show one document everywhere it
    records a Transfer failure (``set_subscription_admin_verified.py``,
    ``operation_stat.py``, ``submit_transfer.py`` under
    ``globus_sdk/testing/data/transfer/``, 4.8.1)::

        {"code": "PermissionDenied", "message": "...",
         "request_id": "BHI2BHt8N", "resource": "/v0.10/..."}

    ``message``, not ``detail`` — GlobusAPIError reads either into
    ``.message``, so a consumer cannot tell, but a raw-JSON reader can,
    and the fake says what the service says.  The codes are CamelCase
    words rather than the SHOUTING_SNAKE the rest of Fauxbus uses for
    its own errors, because these are Globus's codes and those are not.

    ``resource`` is the request path, ``/v0.10`` and all, exactly as the
    recordings show it.  World methods do not know the path, so they
    raise with ``resource=None`` and the Transfer handlers fill it in on
    the way out (see transfer_api).

    ``request_id`` is nine random-looking characters in every recording.
    Fauxbus hashes the code and the resource into nine characters
    instead (principle 3), so the same failure on the same path renders
    the same bytes on every run — and still *looks* like a request id
    to a consumer that logs it.
    """

    def __init__(self, status: int, code: str, message: str, resource: str | None = None) -> None:
        super().__init__(status, code, message)
        self.resource = resource

    def body(self) -> dict[str, Any]:
        resource = self.resource or ""
        digest = hashlib.sha256(f"{self.code}:{resource}".encode()).digest()
        # Base62 over the digest, nine characters, the recorded length.
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        n = int.from_bytes(digest, "big")
        request_id = ""
        for _ in range(9):
            n, r = divmod(n, 62)
            request_id += alphabet[r]
        return {
            "code": self.code,
            "message": self.detail,
            "request_id": request_id,
            "resource": resource,
        }


# The four codes the task-monitoring slice can answer with.  The *codes*
# and statuses are DOCUMENTED — the "Common errors" table of the
# published reference (docs.globus.org/api/transfer/
# advanced_collection_management, read 2026-10-14) lists PermissionDenied
# 403, TaskNotFound 404 and EndpointNotFound 404, and BadRequest 400 is
# RECORDED in the SDK's own fixtures.  The *messages* are Fauxbus's own:
# a recording would only replace the sentence, never the shape.


def transfer_permission_denied(message: str) -> TransferError:
    return TransferError(403, "PermissionDenied", message)


def task_not_found(task_id: str) -> TransferError:
    return TransferError(404, "TaskNotFound", f"Task {task_id} not found")


def endpoint_not_found(endpoint_id: str) -> TransferError:
    return TransferError(404, "EndpointNotFound", f"Endpoint {endpoint_id} not found")


def transfer_bad_request(message: str) -> TransferError:
    return TransferError(400, "BadRequest", message)
