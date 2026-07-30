"""Error documents shaped the way globus-sdk parses them.

The SDK's GlobusAPIError reads ``code`` into ``.code`` and any of
``message``/``detail``/``title`` into ``.message``, whichever of its
error-format branches fires.  ``{"code": ..., "detail": ...}`` satisfies
all of them, so every Fauxbus error uses exactly that shape.
"""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """An error to be rendered as a Globus-shaped JSON error response."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail

    def body(self) -> dict[str, Any]:
        return {"code": self.code, "detail": self.detail}


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
