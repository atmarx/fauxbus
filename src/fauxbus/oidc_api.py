"""The imitated surface, OIDC half: discovery, keys, authorize, userinfo.

Auth slice B.  ``auth_api.py`` holds the token endpoint, where both
grants are redeemed; this file holds everything a browser login touches
on the way there, plus the two documents a verifier fetches to check
what it was handed.

Read this file knowing that it is **the first place the SDK is not the
whole contract.**  ``get_openid_configuration``, ``get_jwk``, and
``userinfo`` are real globus-sdk methods, and the conformance suite
drives them.  ``/v2/oauth2/authorize`` is not and cannot be: no library
performs an interactive login, because a person is in the middle of it.
There the contract is OIDC Core, the published Globus reference, and
what a real broker actually sends — which is why ``examples/`` carries a
script that runs a real Keycloak through this endpoint, and why the
grades in the comments below are mostly DOCUMENTED rather than RECORDED.

One rule shapes the whole authorize handler: **it never learns it is
fake** (principle 4).  There is no ``fauxbus_identity`` parameter and
never will be.  A browser with no Fauxbus session is redirected to an
out-of-band account picker under ``/_fauxbus/auth/`` (``account_picker.py``),
which signs it in and finishes the request.  The imitated endpoint only
ever sees what a real authorization server sees: a request, and maybe a
session cookie.
"""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

from . import signing
from .auth import OFFLINE_ACCESS_TYPE, REFRESH_SCOPE, parse_bearer, split_scopes
from .errors import ApiError, not_implemented
from .server import Ctx, FauxbusServer, redirect
from .world import AuthorizationCode, AuthorizationRequest, RequiredIdpUnsatisfied, Session

DISCOVERY_PATH = "/.well-known/openid-configuration"
# RECORDED from the live service: discovery's ``jwks_uri`` is
# https://auth.globus.org/jwk.json (captured 2026-10-12).  globus-sdk
# never hard-codes it — ``get_jwk`` follows whatever ``jwks_uri`` says —
# so the path matters to brokers configured by hand, which is exactly
# the case slice B exists for.
JWKS_PATH = "/jwk.json"
AUTHORIZE_PATH = "/v2/oauth2/authorize"
USERINFO_PATH = "/v2/oauth2/userinfo"

# The Fauxbus-only session cookie the account picker sets.  The name says
# whose it is, so nobody reading a browser's cookie jar mistakes it for
# the real service's.
SESSION_COOKIE = "fauxbus_session"
PICKER_PATH = "/_fauxbus/auth/login"


def require_issuer(ctx: Ctx) -> str:
    """The configured issuer, or a loud refusal to guess one.

    There is a tempting default — build the issuer from the request's
    ``Host`` header — and it is wrong in exactly the deployment slice B
    exists for.  In a compose network the browser reaches Fauxbus as
    ``localhost:9800`` while the broker reaches it as ``fauxbus:9800``;
    a Host-derived issuer would hand those two callers two different
    ``iss`` strings, and the broker compares ``iss`` character for
    character.  So the issuer is configuration, stated once, and every
    endpoint answers the same thing whichever name it was reached by.
    """
    issuer = ctx.server.issuer()
    if issuer is None:
        raise ApiError(
            503,
            "OIDC_ISSUER_NOT_CONFIGURED",
            "Fauxbus has no OIDC issuer, so it cannot say who signed anything. Set one with "
            "`fauxbus serve --issuer http://<the name your browser and broker both use>` "
            'or in the seed: {"oidc": {"issuer": "..."}}. It is never derived from the '
            "Host header — see oidc_api.require_issuer for why.",
        )
    return issuer


def discovery(ctx: Ctx) -> tuple[int, Any]:
    """``GET /.well-known/openid-configuration`` — where a broker learns everything else.

    The *keys* are RECORDED: this is the live service's document
    (captured 2026-10-12), key for key.  Most *values* are too, with
    every URL rebuilt on the configured issuer.  Where a value would
    claim something Fauxbus does not do, the value tells the truth about
    Fauxbus instead, because discovery is a statement about *this*
    server and a broker acts on it:

    - ``response_types_supported`` is ``["code"]``.  The live document
      also lists ``token``, ``id_token`` and ``token id_token`` — implicit
      and hybrid flows Fauxbus has not built and nobody has asked for.
    - ``id_token_signing_alg_values_supported`` is the recorded
      ``["RS512"]``, and true: see signing.py.
    - ``token_endpoint_auth_methods_supported`` is the recorded
      ``["client_secret_basic"]`` — and here the fake is *kinder* than
      its own document, because the token endpoint also accepts
      ``client_secret_post`` (SPEC slice A).  PROVISIONAL: whether the
      real endpoint accepts ``client_secret_post`` is unobserved, and
      the real service's own discovery promises only Basic.  Advertising
      only Basic keeps a broker that configures itself from this
      document on the method the real service promises — and a broker
      configured by hand should choose Basic too.

    No ``introspection_endpoint`` (the live document lists none, though
    the endpoint exists) and no ``code_challenge_methods_supported``
    (likewise absent live; Fauxbus honours S256 regardless — see
    ``authorize``).
    """
    base = require_issuer(ctx).rstrip("/")
    return 200, {
        "issuer": require_issuer(ctx),
        "authorization_endpoint": base + AUTHORIZE_PATH,
        "userinfo_endpoint": base + USERINFO_PATH,
        "token_endpoint": base + "/v2/oauth2/token",
        "revocation_endpoint": base + "/v2/oauth2/token/revoke",
        "jwks_uri": base + JWKS_PATH,
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": [signing.ALGORITHM],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "claims_supported": [
            "at_hash",
            "aud",
            "email",
            "exp",
            "name",
            "nonce",
            "preferred_username",
            "iat",
            "iss",
            "sub",
        ],
        "subject_types_supported": ["public"],
    }


def jwks(ctx: Ctx) -> tuple[int, Any]:
    # The public key only.  Served whether or not an issuer is set: a
    # key is a key, and refusing it would only move the confusion.
    return 200, signing.jwks()


def with_query(uri: str, params: dict[str, str | None]) -> str:
    """Append parameters to a redirect URI that may already carry a query.

    RFC 6749 §3.1.2 lets a registered redirect URI include a query
    component, which "MUST be retained when adding additional query
    parameters."  Gluing on ``?code=`` blindly would break any client
    that registered ``.../callback?tenant=x``.  ``None`` values are
    dropped, which is how ``state`` is left off when none was sent.
    """
    parts = urlsplit(uri)
    extra = urlencode({k: v for k, v in params.items() if v is not None})
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit(parts._replace(query=query))


def session_from(ctx: Ctx) -> Session | None:
    """The browser's Fauxbus session, if its cookie names one that exists."""
    raw = ctx.headers.get("Cookie")
    if not raw:
        return None
    try:
        jar = SimpleCookie(raw)
    except CookieError:
        return None
    morsel = jar.get(SESSION_COOKIE)
    return ctx.world.sessions.get(morsel.value) if morsel is not None else None


def code_redirect(code: AuthorizationCode) -> tuple[int, Any, dict[str, str]]:
    """The success hop: back to the client with a code and its own ``state``.

    ``state`` is echoed byte for byte (RFC 6749 §4.1.2).  It is the
    client's CSRF defence — it compares what comes back with what it
    sent — so a fake that trimmed, decoded, or "helpfully" defaulted it
    would break the one check that keeps a login from being forged.
    """
    return redirect(with_query(code.redirect_uri, {"code": code.code, "state": code.state}))


def picker_redirect(request: AuthorizationRequest) -> tuple[int, Any, dict[str, str]]:
    # A *relative* Location, on purpose.  The browser reached this
    # endpoint by some name — localhost:9800, fauxbus.test, whatever its
    # network gives it — and the picker lives at that same name.  An
    # absolute URL built from the issuer would assume the issuer is
    # browser-reachable, which is the one assumption the issuer-vs-
    # reachability split exists to avoid.
    return redirect(f"{PICKER_PATH}?{urlencode({'request': request.id})}")


def authorize(ctx: Ctx) -> tuple[int, Any] | tuple[int, Any, dict[str, str]]:
    """``GET /v2/oauth2/authorize`` — the browser leg, in RFC 6749 §4.1.1's order.

    Three kinds of failure, and the difference between them is the
    design:

    1. **The redirect URI cannot be trusted** (unknown client, missing
       or unregistered URI).  Rendered here, never redirected — sending
       an error to an unvetted URI is how an authorization server
       becomes an open redirector.  See World.login_client.
    2. **The client asked for something malformed** (wrong
       ``response_type``, no scope, a broken PKCE pair).  Redirected
       back with ``error=`` and the client's ``state``, per §4.1.2.1 —
       the client's own callback is the place it handles these.
    3. **The client asked for something Globus does and Fauxbus has not
       built** (refresh tokens, ``prompt`` values other than ``login``,
       PKCE ``plain``).  A loud 501, rendered — not redirected, because
       an OAuth ``error=`` code would tell the client *it* was wrong,
       and it was not.  Same three-way split as the token endpoint's
       grant types, for the same reason.
    """
    query = ctx.query
    # The code flow needs an issuer at the far end (the token endpoint
    # signs with it), so say so at the near end rather than after a
    # person has clicked through the picker.
    require_issuer(ctx)
    client = ctx.world.login_client(query.get("client_id", ""), query.get("redirect_uri", ""))
    redirect_uri = query["redirect_uri"]
    state = query.get("state")

    def refuse(error: str, description: str) -> tuple[int, Any, dict[str, str]]:
        return redirect(
            with_query(
                redirect_uri,
                {"error": error, "error_description": description, "state": state},
            )
        )

    # --- kind 3: Fauxbus's gaps, said before anything is parked ---------
    scopes = split_scopes(query.get("scope", ""))
    if REFRESH_SCOPE in scopes or query.get("access_type") == OFFLINE_ACCESS_TYPE:
        raise not_implemented(
            f"this authorization request asks for offline access ({REFRESH_SCOPE!r} or "
            f"access_type={OFFLINE_ACCESS_TYPE!r}), and Fauxbus does not issue refresh tokens "
            f"yet. Real client code needs to refresh?"
        )
    prompt = query.get("prompt")
    if prompt not in (None, "login"):
        # ``none`` matters most: it means "never show UI", and answering
        # it with a picker would be the silent wrong answer.  DOCUMENTED:
        # the reference describes ``prompt=login`` only.
        raise not_implemented(
            f"prompt={prompt!r} is not built; Fauxbus handles prompt=login only. Real "
            f"client code sends this?"
        )
    if query.get("response_mode") not in (None, "query"):
        raise not_implemented(
            f"response_mode={query['response_mode']!r} is not built; codes come back on the "
            f"query string. Real client code needs another mode?"
        )
    challenge = query.get("code_challenge")
    method = query.get("code_challenge_method")
    if challenge is not None and method in (None, "plain"):
        # RFC 7636 §4.3: a challenge with no method *means* plain.
        raise not_implemented(
            "PKCE code_challenge_method=plain is not built; Fauxbus verifies S256, which is "
            "what globus-sdk's NativeAppAuthClient and Keycloak both send. Real client code "
            "uses plain?"
        )

    # --- kind 2: the client's mistakes, reported to the client ----------
    if query.get("response_type") != "code":
        return refuse(
            "unsupported_response_type",
            "Fauxbus implements response_type=code (the authorization-code flow) only.",
        )
    if not scopes:
        return refuse("invalid_request", "'scope' is required.")
    if method is not None and method != "S256":
        return refuse("invalid_request", f"unknown code_challenge_method {method!r}.")
    if method == "S256" and (challenge is None or len(challenge) != 43):
        # RFC 7636 §4.2: an S256 challenge is BASE64URL(SHA256(...)),
        # which is always exactly 43 characters.
        return refuse("invalid_request", "an S256 code_challenge is 43 base64url characters.")
    # Every scope must parse before anything is parked — the same
    # all-or-nothing rule as the token endpoint, and the same 501 for a
    # scope form Fauxbus cannot attribute to a service.
    ctx.world.scopes_by_resource_server(scopes)

    request = ctx.world.park_authorization(
        client,
        redirect_uri=redirect_uri,
        scopes=scopes,
        state=state,
        nonce=query.get("nonce"),
        code_challenge=challenge,
    )
    session = session_from(ctx)
    # DOCUMENTED: prompt=login means "the user will be redirected to log
    # in before the authorization step" — so an existing session is
    # ignored and the picker comes back, even for the same browser.
    if session is not None and prompt != "login":
        try:
            return code_redirect(ctx.world.complete_authorization(request, session))
        except RequiredIdpUnsatisfied:
            # The signed-in account cannot satisfy this client.  Globus
            # would keep the user and ask them to sign in differently, so
            # the picker it is — the request is still parked.
            pass
    return picker_redirect(request)


def userinfo(ctx: Ctx) -> tuple[int, Any]:
    """``GET``/``POST /v2/oauth2/userinfo`` — the ID token's claims, asked for live.

    DOCUMENTED: GET or POST, authenticated with an access token "valid
    for at least the openid scope."  The claims are built by the same
    function as the ID token's (World.identity_claims), so ``sub`` and
    the identity set cannot disagree between the two — and Keycloak
    checks that userinfo's ``sub`` matches the ID token's, refusing the
    login if not.  The refusals are RECORDED bodies; see
    World.userinfo_token for which situation gets which.
    """
    issued = ctx.world.userinfo_token(parse_bearer(ctx.headers.get("Authorization")))
    return 200, ctx.world.userinfo(issued)


def register(server: FauxbusServer) -> None:
    # All auth=False: discovery and keys are public by definition,
    # authorize authenticates nobody (the person does that at the
    # picker), and userinfo checks its bearer token itself because its
    # answer depends on the *issued* record, not just on who is calling.
    server.add_route("GET", DISCOVERY_PATH, discovery, auth=False)
    server.add_route("GET", JWKS_PATH, jwks, auth=False)
    server.add_route("GET", AUTHORIZE_PATH, authorize, auth=False)
    server.add_route("GET", USERINFO_PATH, userinfo, auth=False)
    server.add_route("POST", USERINFO_PATH, userinfo, auth=False)
