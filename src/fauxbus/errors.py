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
"""

from __future__ import annotations

from typing import Any

from . import ISSUES_URL


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
