"""The imitated surface: Globus Auth v2, the OAuth2 token endpoint.

One route so far — ``POST /v2/oauth2/token`` with
``grant_type=client_credentials``, the grant a service uses to act as
*itself* rather than on behalf of a person.  It is built
resource-server-generic on purpose: nothing here knows or cares that
Groups exists.  The requested scopes name the service, and the same
endpoint that hands a WordPress provisioner a Groups token hands a
Transfer poller a Transfer token.

Two things make this file look different from ``groups_api.py``, and
both are the OAuth2 spec's doing rather than ours:

- **The body is a form, not JSON.**  RFC 6749 §4.4.2 says so, and
  globus-sdk sends one.  ``server._read_body`` parses it and records the
  encoding on ``Ctx``; ``_require_form`` below is what turns a JSON body
  into a clear complaint instead of a confusing KeyError.
- **The caller is a client, not a person.**  Every other route in
  Fauxbus resolves ``Authorization: Bearer`` into an identity before the
  handler runs.  This one is registered ``auth=False`` and does its own
  thing with ``Authorization: Basic``, because the question it asks —
  "which piece of software is this?" — is not the question the bearer
  path answers.

The handler stays thin in the usual way: unpack the wire, call one World
method, render.  Who may have what lives in world.py.
"""

from __future__ import annotations

from typing import Any

from .auth import OFFLINE_ACCESS_TYPE, REFRESH_SCOPE, parse_basic, split_scopes
from .errors import (
    invalid_client,
    invalid_request,
    not_implemented,
    unsupported_grant_type,
)
from .server import Ctx, FauxbusServer
from .world import GLOBUS_GRANT_TYPES, IMPLEMENTED_GRANT_TYPES, OAuthClient

TOKEN_PATH = "/v2/oauth2/token"


def _require_form(ctx: Ctx) -> dict[str, str]:
    """The token endpoint takes a form POST, and says so when it doesn't get one.

    This check exists because the alternative is worse than useless.  A
    JSON body parses into a dict that looks exactly like a form dict, so
    without this every field lookup below would succeed and the endpoint
    would happily mint a token for a request the real Globus Auth would
    have rejected outright.  That is a fake teaching a consumer a habit
    that breaks in production — the precise failure a fake exists to
    prevent.
    """
    if ctx.body_encoding != "form":
        raise invalid_request(
            "the token endpoint takes an application/x-www-form-urlencoded body "
            f"(RFC 6749 §4.4.2); this request sent {ctx.body_encoding}. globus-sdk does "
            "this correctly — if you are hand-rolling the call, send form data."
        )
    return ctx.body if isinstance(ctx.body, dict) else {}


def _authenticate_client(ctx: Ctx, form: dict[str, str]) -> OAuthClient:
    """Work out which client is calling, from either of the two legal places.

    RFC 6749 §2.3.1 allows a confidential client to present its
    credentials two ways, and Fauxbus accepts both because its two known
    consumers split across them:

    - **HTTP Basic** — what globus-sdk sends (``ConfidentialAppAuthClient``
      installs a ``BasicAuthorizer``), and what the RFC prefers.
    - **Form fields** ``client_id``/``client_secret`` — what identity
      brokers commonly send (Keycloak calls it ``client_secret_post``),
      which matters because a broker is exactly the consumer Slice B is
      being built for.

    The RFC says a client MUST NOT use more than one method at once, and
    the reason is not pedantry: if the two disagree, the server has to
    pick, and any choice is a security decision made by accident.
    Refusing is the only answer that cannot be wrong.
    """
    basic = parse_basic(ctx.headers.get("Authorization"))
    in_body = "client_id" in form or "client_secret" in form
    if basic is not None and in_body:
        raise invalid_request(
            "client credentials arrived twice — once in an Authorization: Basic header "
            "and once in the form body. RFC 6749 §2.3.1 permits either, never both."
        )
    if basic is not None:
        client_id, secret = basic
    elif in_body:
        client_id, secret = form.get("client_id", ""), form.get("client_secret", "")
        if not client_id or not secret:
            raise invalid_request(
                "in-body client authentication requires both 'client_id' and "
                "'client_secret'."
            )
    else:
        raise invalid_client(
            "no client credentials. Send an Authorization: Basic header (what globus-sdk "
            "does) or client_id/client_secret form fields."
        )
    return ctx.world.authenticate_client(client_id, secret)


def _require_grant(form: dict[str, str]) -> str:
    """Which grant, and is it one we can actually perform.

    The three-way split here is principle 2 in miniature.  A grant Globus
    supports and Fauxbus has built runs.  A grant Globus supports and
    Fauxbus has *not* built is our gap, so it gets the loud 501 with a
    place to file it — answering ``unsupported_grant_type`` would be
    Fauxbus lying about the real service on our own behalf.  A grant
    Globus does not support at all is the client's mistake, and gets the
    RFC 6749 answer it would get from the real endpoint.
    """
    grant_type = form.get("grant_type")
    if not grant_type:
        raise invalid_request("'grant_type' is required.")
    if grant_type in IMPLEMENTED_GRANT_TYPES:
        return grant_type
    if grant_type in GLOBUS_GRANT_TYPES:
        raise not_implemented(
            f"Globus Auth supports grant_type={grant_type!r}; Fauxbus has not built it "
            f"yet. Implemented today: {', '.join(IMPLEMENTED_GRANT_TYPES)}. Real client "
            f"code needs this grant?"
        )
    raise unsupported_grant_type(
        f"Globus Auth does not offer grant_type={grant_type!r}. It supports: "
        f"{', '.join(GLOBUS_GRANT_TYPES)}."
    )


def _refuse_refresh_requests(form: dict[str, str], scopes: list[str]) -> None:
    """A request for a refresh token gets the 501, not a token without one.

    Exactly the same shape of gap as the ``openid`` check below, one
    field over.  Both scopes are promises about the *response document*:
    ``openid`` promises an ``id_token``, ``offline_access`` promises a
    ``refresh_token``, and Fauxbus can honour neither yet.  Answering 200
    without the field would move the failure into the consumer's own
    ``response["refresh_token"]`` — a KeyError wearing a traceback that
    points at the wrong repository.

    Both spellings are checked because both are in live use and they
    come from different callers.  A broker sends the scope; globus-sdk
    sends ``access_type=offline``.  Honouring neither is fine — that is
    a slice not built.  Catching only one would mean the SDK, the thing
    principle 1 calls the contract, is the caller Fauxbus fails quietly.
    """
    if REFRESH_SCOPE in scopes or form.get("access_type") == OFFLINE_ACCESS_TYPE:
        raise not_implemented(
            f"this request asks for a refresh token — {REFRESH_SCOPE!r} in 'scope', or "
            f"access_type={OFFLINE_ACCESS_TYPE!r} — and Fauxbus does not issue them yet, "
            f"so it will not answer with a token document that quietly lacks the "
            f"'refresh_token' field. Drop the request for offline access to get an access "
            f"token today. Real client code needs to refresh?"
        )


def token(ctx: Ctx) -> tuple[int, Any]:
    form = _require_form(ctx)
    client = _authenticate_client(ctx, form)
    grant_type = _require_grant(form)

    raw_scope = form.get("scope", "")
    scopes = split_scopes(raw_scope)
    if not scopes:
        # RFC 6749 makes ``scope`` optional in general, on the theory that
        # a server can fall back to a default.  Globus cannot: a token is
        # issued for exactly one resource server and the scope string is
        # the only place the request names it.  With nothing to parse
        # there is no honest default to reach for, so this is a client
        # error rather than a Fauxbus gap.
        raise invalid_request(
            "'scope' is required. A Globus access token is issued for exactly one "
            "resource server, and the scope string is what names it — e.g. "
            "urn:globus:auth:scope:groups.api.globus.org:all"
        )
    if "openid" in scopes:
        # SPEC promises that an openid response carries an ``id_token``,
        # and Fauxbus cannot sign one until Auth slice B lands.  Issuing
        # the token *without* the field would be the silent wrong answer
        # principle 2 forbids — the consumer's ``response["id_token"]``
        # would raise a KeyError pointing at their code rather than at
        # this gap.  There is also a semantic argument: an ID token
        # describes an authenticated person, and client_credentials has
        # no person in it at all.
        raise not_implemented(
            "Fauxbus does not issue ID tokens yet, so it will not answer a request "
            "carrying the 'openid' scope with a token that is missing one. Signed "
            "id_tokens arrive with Auth slice B (the authorization-code flow), where "
            "there is an authenticated person for an ID token to describe."
        )

    _refuse_refresh_requests(form, scopes)

    resource_server = ctx.world.resource_server_for_request(scopes)
    issued = ctx.world.issue_token(
        client,
        resource_server=resource_server,
        scopes=scopes,
        grant_type=grant_type,
    )
    # RECORDED: 200 with the six-field token document.  See
    # World.token_response for the field-by-field grounding, and in
    # particular why ``other_tokens`` is not optional.
    return 200, ctx.world.token_response(issued)


def register(server: FauxbusServer) -> None:
    # auth=False: this endpoint authenticates a client from a Basic
    # header, not a caller from a Bearer token — see _authenticate_client.
    # resource_server=None for the same reason the control plane has
    # none: the token endpoint is where tokens come *from*, so it cannot
    # require one.
    server.add_route("POST", TOKEN_PATH, token, auth=False)
