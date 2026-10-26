"""The imitated surface: Globus Auth v2, the OAuth2 token endpoint.

``POST /v2/oauth2/token`` with three grants.  ``client_credentials``
(slice A) is the grant a service uses to act as *itself* rather than on
behalf of a person; ``authorization_code`` (slice B) is where a browser
login that started at ``/v2/oauth2/authorize`` (see ``oidc_api.py``) is
redeemed for tokens acting as the person who signed in; and
``refresh_token`` (login shim step 3) is how that login keeps going
after its access tokens expire, with no browser in sight.  All are built
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

from . import signing
from .auth import (
    AUTH_RESOURCE_SERVER,
    OFFLINE_ACCESS_TYPE,
    REFRESH_SCOPE,
    parse_basic,
    split_scopes,
)
from .errors import (
    invalid_client,
    invalid_request,
    not_implemented,
    unauthorized_client,
    unsupported_grant_type,
)
from .oidc_api import require_issuer
from .server import Ctx, FauxbusServer
from .world import GLOBUS_GRANT_TYPES, IMPLEMENTED_GRANT_TYPES, OAuthClient

TOKEN_PATH = "/v2/oauth2/token"
INTROSPECT_PATH = "/v2/oauth2/token/introspect"
REVOKE_PATH = "/v2/oauth2/token/revoke"


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
    consumers split across them — plus the third way, which is no
    credential at all:

    - **HTTP Basic** — what globus-sdk sends (``ConfidentialAppAuthClient``
      installs a ``BasicAuthorizer``), and what the RFC prefers.
    - **Form fields** ``client_id``/``client_secret`` — what identity
      brokers commonly send (Keycloak calls it ``client_secret_post``),
      which matters because a broker is exactly the consumer Slice B is
      being built for.
    - **``client_id`` alone** in the form — a public client (RFC 6749
      §2.3), which has no secret to present.  Login shim step 2.

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
        if not client_id:
            raise invalid_request(
                "in-body client authentication requires 'client_id' (and 'client_secret', "
                "unless the client is a public native app)."
            )
        if not secret:
            # A client_id with no secret is not a malformed request — it
            # is how a *public* client (a native app; globus-sdk's
            # NativeAppAuthClient) identifies itself, with PKCE standing
            # in for the secret it cannot keep.  Whether this client may
            # do that is the registry's call, not the wire's.
            return ctx.world.identify_public_client(client_id)
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
    """Client credentials plus offline access: still the 501, for a new reason.

    Exactly the same shape of gap as the ``openid`` check below, one
    field over.  Both scopes are promises about the *response document*:
    ``openid`` promises an ``id_token``, ``offline_access`` promises a
    ``refresh_token``.  Answering 200 without the field would move the
    failure into the consumer's own ``response["refresh_token"]`` — a
    KeyError wearing a traceback that points at the wrong repository.

    Login shim step 3 built refresh tokens, and they are still refused
    here, because this grant has no person in it.  RFC 6749 §4.4.3 says
    a refresh token SHOULD NOT come back from client credentials: the
    client can simply run the grant again, so a standing right to mint
    tokens buys it nothing but a credential to leak.  Whether Globus
    follows the SHOULD or answers some other way is unrecorded, and a
    200 without the field is the one answer Fauxbus knows to be wrong.

    Both spellings are checked because both are in live use and they
    come from different callers.  A broker sends the scope; globus-sdk
    sends ``access_type=offline``.  Catching only one would mean the
    SDK, the thing principle 1 calls the contract, is the caller Fauxbus
    fails quietly.
    """
    if REFRESH_SCOPE in scopes or form.get("access_type") == OFFLINE_ACCESS_TYPE:
        raise not_implemented(
            f"this client_credentials request asks for a refresh token — {REFRESH_SCOPE!r} "
            f"in 'scope', or access_type={OFFLINE_ACCESS_TYPE!r}. Fauxbus issues refresh "
            f"tokens only to a person's login (the authorization-code grant); RFC 6749 "
            f"§4.4.3 says client credentials SHOULD NOT get one, and what Globus does here "
            f"is unrecorded. A service can run this grant again instead of refreshing. "
            f"Real client code asks for this?"
        )


def token(ctx: Ctx) -> tuple[int, Any]:
    form = _require_form(ctx)
    client = _authenticate_client(ctx, form)
    grant_type = _require_grant(form)
    if client.public_client and grant_type == "client_credentials":
        # RFC 6749 §4.4: the client-credentials grant is for confidential
        # clients only, and the reason is in the name — a client with no
        # credential cannot be granted a token on the strength of it.  A
        # native app acts for a person, so its every token starts with a
        # person signing in — and may carry on by refresh, which a
        # public client is allowed (RFC 6749 §6 asks for client
        # authentication only from clients that have credentials).
        raise unauthorized_client(
            f"client {client.client_id!r} is a public (native app) client; it gets tokens "
            f"by the authorization-code grant with PKCE (then by refresh_token), never by "
            f"grant_type={grant_type!r}."
        )
    if grant_type == "authorization_code":
        return _authorization_code(ctx, client, form)
    if grant_type == "refresh_token":
        return _refresh_token(ctx, client, form)
    return _client_credentials(ctx, client, form, grant_type)


def _client_credentials(
    ctx: Ctx, client: OAuthClient, form: dict[str, str], grant_type: str
) -> tuple[int, Any]:
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
        # Still refused after slice B, and now the reason is different.
        # Fauxbus can sign ID tokens — but an ID token describes an
        # authenticated *person*, and client_credentials has no person in
        # it at all.  Whether the real endpoint declines this request or
        # answers it somehow is unobserved (recording list #3), and
        # answering without the ``id_token`` field would be the silent
        # wrong answer principle 2 forbids: the consumer's
        # ``response["id_token"]`` would raise a KeyError pointing at
        # their code rather than at this gap.
        raise not_implemented(
            "Fauxbus issues ID tokens only from the authorization-code grant, where a "
            "person signed in for the token to describe. Whether Globus answers 'openid' "
            "under client_credentials is unrecorded, so Fauxbus will not guess."
        )

    _refuse_refresh_requests(form, scopes)

    # Parse everything first, mint second — two statements on purpose.
    # A 501 on the third scope must not leave two orphan tokens behind in
    # the world state, and keeping the parse on its own line makes that
    # ordering something you can see rather than something you have to
    # know about when Python evaluates a comprehension.
    by_server = ctx.world.scopes_by_resource_server(scopes)
    # One token per service, minted in first-named order, so the primary
    # is always the lowest-numbered token and a given request produces
    # the same strings on every run.
    issued = [
        ctx.world.issue_token(
            client,
            resource_server=resource_server,
            scopes=server_scopes,
            grant_type=grant_type,
        )
        for resource_server, server_scopes in by_server.items()
    ]
    # RECORDED: 200 with the six-field token document.  See
    # World.token_response for the field-by-field grounding, and in
    # particular why ``other_tokens`` is not optional.
    return 200, ctx.world.token_response(issued[0], issued[1:])


def _authorization_code(ctx: Ctx, client: OAuthClient, form: dict[str, str]) -> tuple[int, Any]:
    """RFC 6749 §4.1.3: trade a one-use code for tokens.

    The response is RECORDED from ``oauth2_exchange_code_for_tokens.py``
    (4.8.1), and it holds two surprises worth knowing before reading the
    code:

    - **``state`` comes back in the body.**  The fixture's default
      response carries ``"state": "_default"`` — the SDK's own default
      state value — even though the exchange request never sends one.
      So the real service remembers the authorize request's ``state``
      and echoes it here.  Fauxbus does the same, from the code's
      binding, and leaves the key off when no state was sent.  The
      fixture's ``openid`` variant has no ``state`` at all; whether that
      is the service or the fixture being terse is unknown, and Fauxbus
      echoes it there too.
    - **``openid`` puts ``auth.globus.org`` on top.**  The fixture's
      openid response names ``auth.globus.org`` as the primary
      ``resource_server`` with ``id_token`` beside it at the top level,
      which is the only place ``decode_id_token`` looks.  So when
      ``openid`` is among the scopes, the Auth token is primary whatever
      order the scopes were named in.  PROVISIONAL as a rule for
      multi-service requests (recording list #8's question, one case
      narrower): the fixture shows ``openid`` alone.

    ``scope`` in the exchange body is ignored — RFC 6749 §4.1.3 does not
    define it here, and the code already carries what was authorized.
    """
    code_value = form.get("code")
    if not code_value:
        raise invalid_request("'code' is required.")
    redirect_uri = form.get("redirect_uri")
    if not redirect_uri:
        raise invalid_request(
            "'redirect_uri' is required — the same URI the authorization request used "
            "(RFC 6749 §4.1.3)."
        )
    # Before the code is spent, not after: a missing issuer discovered
    # while signing would leave a redeemed code and minted tokens behind
    # an error response — the orphan problem the all-or-nothing scope
    # parse exists to prevent, arriving by a side door.
    issuer = require_issuer(ctx)
    code = ctx.world.redeem_code(client, code_value, redirect_uri, form.get("code_verifier"))

    by_server = ctx.world.scopes_by_resource_server(code.scopes)
    if "openid" in code.scopes:
        by_server = {AUTH_RESOURCE_SERVER: by_server.pop(AUTH_RESOURCE_SERVER), **by_server}
    issued = [
        ctx.world.issue_token(
            client,
            resource_server=resource_server,
            scopes=server_scopes,
            grant_type="authorization_code",
            login=code,
        )
        for resource_server, server_scopes in by_server.items()
    ]
    if code.offline:
        # Login shim step 3: one refresh token beside *every* token in the
        # document, primary and other_tokens alike.  A refresh token is
        # for one resource server, so a login that minted three access
        # tokens has three things to refresh — and an app that keeps its
        # Transfer token alive but not its Groups one has not got
        # offline access, it has a third of it.
        for token in issued:
            ctx.world.issue_refresh_token(token)
    doc = ctx.world.token_response(issued[0], issued[1:])
    if "openid" in code.scopes:
        claims = ctx.world.id_token_claims(
            code,
            issued[0].token,
            issuer=issuer,
            now=ctx.server.signed_now(),
        )
        doc["id_token"] = signing.sign_jwt(claims)
    if code.state is not None:
        # PROVISIONAL for the openid case: the recorded default response
        # echoes ``state``; the recorded openid response has none.  See
        # the docstring — Fauxbus echoes in both.
        doc["state"] = code.state
    return 200, doc


def _refresh_token(ctx: Ctx, client: OAuthClient, form: dict[str, str]) -> tuple[int, Any]:
    """RFC 6749 §6: a refresh token in, one fresh access token out.

    globus-sdk sends exactly ``grant_type`` and ``refresh_token``
    (``AuthLoginClient.oauth2_refresh_token``, 4.8.1), from a confidential
    client with its Basic header or a native app with ``client_id``
    alone.  ``_authenticate_client`` has already told those apart; the
    binding check below is what makes a refresh token useless in anyone
    else's hands.

    The response is the ordinary token document with one token in it,
    ``other_tokens`` empty.  Not a style choice: ``RefreshTokenAuthorizer``
    raises ``ValueError`` unless a refresh answers with exactly one
    token, so this is pinned from the reader's side.  The refresh token
    is in it too — see ``World.token_response`` on why, and on rotation.

    Two things a refresh deliberately does *not* bring back:

    - **No ``id_token``.**  An ID token says a person authenticated, and
      nobody did — that is the point of refreshing.  Whether Globus
      re-issues one for an ``openid`` refresh is unrecorded; the SDK's
      storage reads it with ``.get`` and falls back to the identity it
      already stored, so leaving it out breaks nothing that reads it.
      PROVISIONAL.
    - **No ``state``.**  ``state`` belongs to a browser round trip, and
      there was none.

    The new access token is timed from *now* on the logical clock, so a
    test that ticks past expiry, watches a call fail, and lets the SDK
    refresh gets a token that works — the whole proof this step exists
    for.
    """
    value = form.get("refresh_token")
    if not value:
        raise invalid_request("'refresh_token' is required — the refresh token being redeemed.")
    raw_scope = form.get("scope")
    refresh = ctx.world.redeem_refresh_token(
        client, value, None if raw_scope is None else split_scopes(raw_scope)
    )
    issued = ctx.world.issue_token(
        client,
        resource_server=refresh.resource_server,
        scopes=refresh.scopes,
        grant_type="refresh_token",
        login=refresh,
    )
    issued.refresh_token = refresh.token
    return 200, ctx.world.token_response(issued)


def _require_token_field(form: dict[str, str]) -> str:
    """The one field introspection and revocation both take."""
    token = form.get("token")
    if not token:
        raise invalid_request(
            "'token' is required — the access token being asked about, as a raw string."
        )
    # ``token_type_hint`` (RFC 7009 §2.1, RFC 7662 §2.1) is deliberately
    # ignored rather than validated.  Both RFCs call it a hint the server
    # MAY use to speed a lookup, and Fauxbus keeps its tokens in one
    # dict, so there is nothing to speed up.  Rejecting a hint the real
    # service tolerates would be a fake failing a call that works in
    # production — the worse direction to be wrong in.
    return token


def introspect(ctx: Ctx) -> tuple[int, Any]:
    """RFC 7662: the question a *resource server* asks about a token.

    This is the other half of the story slice A started.  The token
    endpoint is where a service gets a credential; this is where the
    service on the receiving end asks Globus Auth whether the credential
    it was just handed is real, who it belongs to, and what it is good
    for.  Fauxbus has held all three answers since slice A — in
    ``IssuedToken`` — and had no way for anyone outside to ask.

    Note who is *not* checked: whether the calling client has anything to
    do with the token.  That is deliberate and it is the difference
    between this endpoint and revocation next door.  Introspection exists
    for resource servers, which by definition did not issue the token
    they are holding; scoping it to the issuing client would make it
    useless to its only real audience.  Revocation is the opposite — the
    caller is the owner, and a stranger gets nothing.

    One more thing this endpoint quietly does, which is worth knowing
    before it surprises you: it makes ``--require-issued-tokens``
    visible from outside.  Under the permissive default the imitated
    surface accepts any bearer string at all, but introspection answers
    only about tokens this Auth *issued*, because that is what the real
    service can answer about.  So ``t-alice`` works fine against Groups
    and introspects as ``{"active": false}``, and the fake looks like it
    is contradicting itself.  It isn't: permissive bearer handling is
    how Fauxbus decides who is calling, not a claim that Globus minted
    anything.  If your consumer introspects the tokens it holds, hand it
    tokens from the token endpoint — which is what the strict flag is
    for, and this is the endpoint that makes the difference show.
    """
    form = _require_form(ctx)
    if _authenticate_client(ctx, form).public_client:
        # Introspection answers a resource server, and a resource server
        # is a service with a secret; globus-sdk gives NativeAppAuthClient
        # no introspect method at all.  An endpoint that would tell any
        # installed copy of an app about any token it found is one RFC
        # 7662 §2.1 asks servers to close.  PROVISIONAL as to the real
        # error, which is unrecorded.
        raise invalid_client(
            "a public (native app) client cannot introspect tokens; introspection is for "
            "resource servers, which authenticate with a secret."
        )
    token = _require_token_field(form)
    if form.get("include"):
        # ``include=identity_set`` asks for the token subject's linked
        # identities.  Until slice B this was refused because Fauxbus
        # could not model linking at all, and the only possible answer
        # was a list of one for everybody.  Slice B can model it — the
        # seed's ``accounts`` link identities — so the refusal now rests
        # on principle 2 alone: nobody has asked for the introspection
        # form, and its shape is as unrecorded as userinfo's.  The
        # identity set a broker needs arrives in the ID token and from
        # userinfo, which are built.
        raise not_implemented(
            f"include={form['include']!r} on introspection is not built. Linked identities "
            f"are modeled (the seed's 'accounts'), and a login's identity_set is in its ID "
            f"token and at /v2/oauth2/userinfo. Real client code needs it here too?"
        )
    return 200, ctx.world.introspect(token)


def revoke(ctx: Ctx) -> tuple[int, Any]:
    """RFC 7009: retire a token you issued.

    RECORDED response (``oauth2_revoke_token.py``, 4.8.1): ``{"active":
    false}``, and the same document comes back whether anything was
    revoked or not — see ``World.revoke`` for why "nothing happened" and
    "it's gone" deliberately look identical from out here.

    Public clients are welcome here, unlike next door: RFC 7009 §2.1
    lets a client that cannot authenticate revoke by naming itself, and
    globus-sdk's native client sends exactly that — ``client_id`` in the
    body, no header.  A CLI's ``logout`` is this call.
    """
    form = _require_form(ctx)
    client = _authenticate_client(ctx, form)
    ctx.world.revoke(client, _require_token_field(form))
    return 200, {"active": False}


def register(server: FauxbusServer) -> None:
    # auth=False: this endpoint authenticates a client from a Basic
    # header, not a caller from a Bearer token — see _authenticate_client.
    # resource_server=None for the same reason the control plane has
    # none: the token endpoint is where tokens come *from*, so it cannot
    # require one.
    server.add_route("POST", TOKEN_PATH, token, auth=False)
    # Both for the same reason as the token endpoint: these authenticate
    # a *client* from a Basic header, not a caller from a Bearer token.
    # The token in their body is the subject of the question, never the
    # credential for asking it.
    server.add_route("POST", INTROSPECT_PATH, introspect, auth=False)
    server.add_route("POST", REVOKE_PATH, revoke, auth=False)
