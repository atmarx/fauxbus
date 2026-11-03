"""The imitated surface, identities half: ``GET /v2/api/identities``.

Login shim step 5.  Signing in tells an app who *the caller* is; this
endpoint tells it who *anyone else* is.  An app that lists group members
by name, or lets an admin type a colleague's username into an "add
member" box, calls it — usually through globus-sdk's ``IdentityMap``,
which batches up the ids and usernames it is handed and files every
record it gets back under both.

The shape is RECORDED (``globus_sdk/testing/data/auth/get_identities.py``,
4.8.1).  What the endpoint knows comes from the seed's ``accounts``
section, the only place Fauxbus holds a full identity record — see
World.lookup_identities for what happens to everything else.

Why its own file and not ``auth_api.py`` or ``oidc_api.py``: those two
are the login — the token endpoint and the browser half.  This is a
plain Auth *API* resource that any token-holder may call, the way
Groups and Transfer routes are, and it authenticates like them.
"""

from __future__ import annotations

from typing import Any

from .auth import ANONYMOUS_TOKEN, AUTH_RESOURCE_SERVER, parse_bearer
from .errors import ApiError, auth_forbidden, auth_unauthorized, not_implemented
from .server import Ctx, FauxbusServer

IDENTITIES_PATH = "/v2/api/identities"


def _authenticate(ctx: Ctx) -> None:
    """The same gate Groups and Transfer use, rendered in Auth's own words.

    Permissive by default: any bearer token gets an answer, exactly as
    any token gets into Groups, because consumers have been written
    against that posture since 0.1.  Under ``--require-issued-tokens``
    the token must be live and minted for auth.globus.org — the strict
    mode's resource-server check, which is the only one it makes.

    The route is registered with ``auth=False`` and does this itself for
    one reason: the shared gate raises Groups-shaped errors, and an Auth
    API endpoint answers in the Auth error document (RECORDED — it is
    the fixture's own ``unauthorized`` response).  The SDK parses that
    document into ``.code`` and ``.message``; a Groups body would parse
    into nothing, and a consumer's error handling would be tested
    against the wrong thing.
    """
    header = ctx.headers.get("Authorization")
    # The SDK can also reach this endpoint with a client's own id and
    # secret in a Basic header (an AuthClient built on BasicAuthorizer).
    # Real Globus Auth answers that; Fauxbus would have to decide which
    # identities a client may see, and nothing yet asks it to.
    if header and header.split(None, 1)[0].lower() == "basic":
        raise not_implemented(
            "The identities lookup authenticated by client id and secret (Basic). "
            "Fauxbus answers bearer tokens here; a client_credentials token works."
        )
    token = parse_bearer(header)
    if token is None:
        if not ctx.server.allow_anonymous:
            raise auth_unauthorized()
        token = ANONYMOUS_TOKEN
    if ctx.server.require_issued_tokens:
        try:
            ctx.world.require_issued(token, AUTH_RESOURCE_SERVER)
        except ApiError as refused:
            # Same split the strict gate makes — 401 for no live token,
            # 403 for a live token minted for another service — kept,
            # and re-said in the recorded Auth document.
            raise (auth_forbidden() if refused.status == 403 else auth_unauthorized()) from refused


def _comma_list(ctx: Ctx, name: str) -> list[str] | None:
    """A comma-joined query parameter, split — or None if it was not sent.

    None and [] mean different things here: "not asked by id" versus
    "asked by id, for nothing."  The SDK's ``commajoin`` sends the
    second as an empty string, and it gets an empty answer, not a 400.
    """
    raw = ctx.query.get(name)
    if raw is None:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def get_identities(ctx: Ctx) -> tuple[int, Any]:
    _authenticate(ctx)
    # The SDK sends ``provision`` only alongside usernames, spelled
    # "true" or "false" — ``str(bool).lower()``.
    provision = ctx.query.get("provision", "false").lower() == "true"
    records = ctx.world.lookup_identities(
        ids=_comma_list(ctx, "ids"),
        usernames=_comma_list(ctx, "usernames"),
        provision=provision,
    )
    return 200, {"identities": records}


def register(server: FauxbusServer) -> None:
    server.add_route("GET", IDENTITIES_PATH, get_identities, auth=False)
