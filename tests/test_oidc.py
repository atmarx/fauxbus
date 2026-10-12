"""Auth slice B on the wire: discovery, keys, the browser leg, the code exchange.

Most of this file drives HTTP by hand, and that is not a lapse from
principle 1 — it is the part of slice B the SDK cannot reach.  No
library performs an interactive login, so the authorize leg's contract
is OIDC plus the published Globus reference plus what a real broker
sends, and the honest test of it is a client that behaves like a
browser.  Everything the SDK *can* drive is driven through it in
test_sdk_conformance.py; ``examples/keycloak_broker.py`` puts a real
broker through the same doors.

Tests that verify a signature need PyJWT, which arrives with globus-sdk
(it is the SDK's own ID-token verifier).  Same switch as the conformance
file: a bare checkout skips them, CI's FAUXBUS_REQUIRE_CONFORMANCE makes
a missing verifier a hard error.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from conftest import (
    ALICE_GLOBUSID,
    ALICE_UNIVERSITY,
    BOB_GLOBUSID,
    CAMPUS_CLIENT,
    CAMPUS_REDIRECT,
    CAMPUS_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    GLOBUSID_IDP,
    GROUPS_SCOPE,
    LOGIN_CLIENT,
    LOGIN_REDIRECT,
    LOGIN_SECRET,
    Client,
    oidc_seed,
)

from fauxbus import signing
from fauxbus.cli import main as cli_main

TOKEN = "/v2/oauth2/token"
AUTHORIZE = "/v2/oauth2/authorize"
USERINFO = "/v2/oauth2/userinfo"


@pytest.fixture
def verifier():
    """PyJWT, or a skip — never a silent pass without it under CI."""
    if os.environ.get("FAUXBUS_REQUIRE_CONFORMANCE"):
        import jwt
    else:
        jwt = pytest.importorskip("jwt")
    return jwt


# ------------------------------------------------------------------ helpers


def authorize_path(
    client: str = LOGIN_CLIENT,
    redirect_uri: str = LOGIN_REDIRECT,
    scope: str = "openid profile email",
    **extra: str,
) -> str:
    params = {
        "client_id": client,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "response_type": "code",
        "state": "st-1",
        "nonce": "n-1",
        **extra,
    }
    return f"{AUTHORIZE}?{urlencode({k: v for k, v in params.items() if v is not None})}"


def query_of(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


def pick(fx: Client, location: str, account: str) -> tuple[int, dict[str, str], bytes]:
    """Follow a picker redirect and choose an account, the way a person would."""
    assert location.startswith("/_fauxbus/auth/login?request=")
    request_id = query_of(location)["request"]
    status, _, page = fx.browse(location)
    assert status == 200 and b"<form" in page
    return fx.browse(
        "/_fauxbus/auth/login", method="POST", form={"request": request_id, "account": account}
    )


def login(
    fx: Client, account: str = ALICE_GLOBUSID, **authorize_kw: str
) -> tuple[str, dict[str, str], str]:
    """The whole browser leg: authorize → picker → back to the client with a code.

    Returns the code, the callback's query parameters, and the session
    cookie the picker set.
    """
    status, headers, _ = fx.browse(authorize_path(**authorize_kw))
    assert status == 302, headers
    status, headers, _ = pick(fx, headers["Location"], account)
    assert status == 302, headers
    callback = query_of(headers["Location"])
    cookie = headers["Set-Cookie"].split(";")[0]
    return callback["code"], callback, cookie


def exchange(
    fx: Client,
    code: str,
    *,
    client: tuple[str, str] = (LOGIN_CLIENT, LOGIN_SECRET),
    redirect_uri: str = LOGIN_REDIRECT,
    post: bool = False,
    **extra: str,
) -> tuple[int, Any]:
    fields = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, **extra}
    if post:
        # client_secret_post: what Keycloak's broker can be set to send.
        fields.update(client_id=client[0], client_secret=client[1])
        status, doc, _ = fx.form_post(TOKEN, fields)
    else:
        status, doc, _ = fx.form_post(TOKEN, fields, basic=client)
    return status, doc


def claims_of(id_token: str) -> dict[str, Any]:
    """The payload, decoded *without* verification — for shape assertions only.

    Signature checks live in the tests that take the ``verifier``
    fixture; this is just base64 so a claim test does not need PyJWT.
    """
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


# ---------------------------------------------------------------- discovery


def test_discovery_derives_every_url_from_the_one_issuer(oidc):
    status, doc, _ = oidc.get("/.well-known/openid-configuration")
    assert status == 200
    base = oidc.base_url
    assert doc["issuer"] == base
    assert doc["authorization_endpoint"] == base + "/v2/oauth2/authorize"
    assert doc["token_endpoint"] == base + "/v2/oauth2/token"
    assert doc["userinfo_endpoint"] == base + "/v2/oauth2/userinfo"
    assert doc["revocation_endpoint"] == base + "/v2/oauth2/token/revoke"
    assert doc["jwks_uri"] == base + "/jwk.json"


def test_discovery_has_the_live_documents_keys_exactly(oidc):
    """RECORDED: the key set of https://auth.globus.org/.well-known/openid-configuration,
    captured 2026-10-12.  Values differ where Fauxbus does less (response
    types); keys do not, so a broker reading this meets the same document."""
    _, doc, _ = oidc.get("/.well-known/openid-configuration")
    assert sorted(doc) == sorted(
        [
            "issuer",
            "authorization_endpoint",
            "userinfo_endpoint",
            "token_endpoint",
            "revocation_endpoint",
            "jwks_uri",
            "response_types_supported",
            "id_token_signing_alg_values_supported",
            "scopes_supported",
            "token_endpoint_auth_methods_supported",
            "claims_supported",
            "subject_types_supported",
        ]
    )
    assert doc["id_token_signing_alg_values_supported"] == ["RS512"]
    assert doc["token_endpoint_auth_methods_supported"] == ["client_secret_basic"]
    assert doc["response_types_supported"] == ["code"]


def test_the_issuer_ignores_the_host_header(oidc):
    """The compose trap: browser and broker reach Fauxbus by different names.

    The issuer must be the same string for both, so it is configuration,
    never a function of the Host header the request happened to carry.
    """
    status, doc, _ = oidc.get(
        "/.well-known/openid-configuration", headers={"Host": "fauxbus:9800"}
    )
    assert status == 200
    assert doc["issuer"] == oidc.base_url
    assert doc["jwks_uri"].startswith(oidc.base_url)


def test_no_issuer_is_a_loud_refusal_not_a_guess(fx):
    status, doc, _ = fx.get("/.well-known/openid-configuration")
    assert status == 503
    assert doc["code"] == "OIDC_ISSUER_NOT_CONFIGURED"
    status, _, _ = fx.browse(authorize_path())
    assert status == 503


def test_a_real_globus_issuer_is_refused_at_the_seed_door(fx):
    for bad in ("https://auth.globus.org", "https://globus.org", "https://x.globusid.org/"):
        status, doc, _ = fx.post("/_fauxbus/seed", {"oidc": {"issuer": bad}})
        assert status == 422, bad
        assert "real Globus" in doc["detail"]


def test_a_real_globus_issuer_is_refused_at_boot(capsys):
    assert cli_main(["serve", "--issuer", "https://auth.globus.org", "--port", "0"]) == 2
    assert "refusing issuer" in capsys.readouterr().err


def test_failure_injection_reaches_discovery_and_keys(oidc):
    """The imitated surface now extends past /v2/, and so does injection."""
    oidc.post("/_fauxbus/failures", {"path": "/jwk.json", "status": 503, "times": 1})
    status, _, _ = oidc.get("/jwk.json")
    assert status == 503
    status, _, _ = oidc.get("/jwk.json")
    assert status == 200


# --------------------------------------------------------------------- keys


def test_jwks_publishes_one_public_key_with_a_kid(oidc):
    status, doc, _ = oidc.get("/jwk.json")
    assert status == 200
    (key,) = doc["keys"]
    # RECORDED key set: the live /jwk.json entry's keys, captured 2026-10-12.
    assert sorted(key) == ["alg", "e", "kid", "kty", "n", "use"]
    assert key["alg"] == "RS512" and key["use"] == "sig" and key["kty"] == "RSA"
    assert key["kid"] == signing.KID
    assert "d" not in key  # the private exponent is published in the source, never served


def test_the_fixture_key_is_a_working_rsa_pair():
    # m^(e*d) ≡ m (mod n) — if the transcribed hex were off by a digit,
    # every token would fail to verify and the failure would point here.
    assert pow(pow(42, signing.E, signing.N), signing.D, signing.N) == 42


# ---------------------------------------------------------- the browser leg


def test_no_session_redirects_to_the_out_of_band_picker(oidc):
    status, headers, body = oidc.browse(authorize_path())
    assert status == 302
    # Relative, so the browser stays on whatever name it reached us by.
    assert headers["Location"] == "/_fauxbus/auth/login?request=fauxbus-request-0"
    assert body == b""


def test_the_picker_lists_seeded_accounts_and_asks_no_password(oidc):
    _, headers, _ = oidc.browse(authorize_path())
    status, page_headers, page = oidc.browse(headers["Location"])
    assert status == 200
    assert page_headers["Content-Type"].startswith("text/html")
    assert b"alice@globusid.org" in page and b"bob@globusid.org" in page
    assert b'type="password"' not in page


def test_picking_an_account_returns_a_code_with_state_unchanged(oidc):
    code, callback, cookie = login(oidc, state="a b/c?d=e&f")
    assert code == "fauxbus-code-0"
    assert callback["state"] == "a b/c?d=e&f"  # byte for byte, through encoding
    assert cookie == "fauxbus_session=fauxbus-session-0"


def test_a_redirect_uri_with_its_own_query_keeps_it(fx):
    seed = oidc_seed(fx.base_url)
    seed["clients"][LOGIN_CLIENT]["redirect_uris"] = ["https://app.example.org/cb?tenant=t1"]
    fx.post("/_fauxbus/seed", seed)
    _, headers, _ = fx.browse(authorize_path(redirect_uri="https://app.example.org/cb?tenant=t1"))
    _, headers, _ = pick(fx, headers["Location"], ALICE_GLOBUSID)
    location = headers["Location"]
    assert location.startswith("https://app.example.org/cb?tenant=t1&")
    assert query_of(location)["code"] == "fauxbus-code-0"


def test_a_session_skips_the_picker(oidc):
    _, _, cookie = login(oidc)
    status, headers, _ = oidc.browse(authorize_path(), cookie=cookie)
    assert status == 302
    assert headers["Location"].startswith(LOGIN_REDIRECT + "?code=fauxbus-code-1")


def test_prompt_login_ignores_the_session(oidc):
    _, _, cookie = login(oidc)
    status, headers, _ = oidc.browse(authorize_path(prompt="login"), cookie=cookie)
    assert status == 302
    assert headers["Location"].startswith("/_fauxbus/auth/login?request=")


def test_the_headless_session_route_signs_a_test_in_without_a_page(oidc):
    status, doc, headers = oidc.post("/_fauxbus/auth/session", {"account": ALICE_GLOBUSID})
    assert status == 200
    assert headers["Set-Cookie"].startswith(doc["cookie"] + ";")
    status, headers, _ = oidc.browse(authorize_path(), cookie=doc["cookie"])
    assert status == 302 and "?code=" in headers["Location"]


def test_an_unknown_account_cannot_get_a_session(oidc):
    status, _, _ = oidc.post("/_fauxbus/auth/session", {"account": BOB_GLOBUSID[:-1] + "f"})
    assert status == 422


# ------------------------------------------------- authorize: the three refusals


def test_an_unregistered_redirect_uri_is_rendered_never_redirected(oidc):
    for uri in (LOGIN_REDIRECT + "/", LOGIN_REDIRECT.upper(), "https://evil.example/cb"):
        status, headers, body = oidc.browse(authorize_path(redirect_uri=uri))
        assert status == 400, uri
        assert "Location" not in headers
        assert json.loads(body)["error"] == "invalid_request"


def test_an_unknown_client_is_rendered_never_redirected(oidc):
    status, headers, _ = oidc.browse(authorize_path(client=CLIENT_ID[:-1] + "0"))
    assert status == 400 and "Location" not in headers


def test_a_client_mistake_goes_back_to_the_client_with_its_state(oidc):
    status, headers, _ = oidc.browse(authorize_path(response_type="token"))
    assert status == 302
    back = query_of(headers["Location"])
    assert headers["Location"].startswith(LOGIN_REDIRECT + "?")
    assert back["error"] == "unsupported_response_type"
    assert back["state"] == "st-1"

    _, headers, _ = oidc.browse(authorize_path(scope=""))
    assert query_of(headers["Location"])["error"] == "invalid_request"


def test_fauxbus_gaps_at_authorize_are_501s_not_oauth_errors(oidc):
    for extra in (
        {"prompt": "none"},
        {"access_type": "offline"},
        {"scope": "openid offline_access"},
        {"code_challenge": "x" * 43, "code_challenge_method": "plain"},
        {"code_challenge": "x" * 43},  # no method means plain (RFC 7636 §4.3)
    ):
        status, headers, body = oidc.browse(authorize_path(**extra))
        assert status == 501, extra
        assert "Location" not in headers
        assert json.loads(body)["code"] == "NOT_IMPLEMENTED"


# --------------------------------------------------------------- the exchange


def test_the_exchange_returns_the_recorded_document_plus_an_id_token(oidc):
    code, _, _ = login(oidc)
    status, doc = exchange(oidc, code)
    assert status == 200
    # RECORDED shape (oauth2_exchange_code_for_tokens.py, openid variant),
    # with ``state`` echoed as the default variant shows.
    assert sorted(doc) == sorted(
        [
            "access_token",
            "expires_in",
            "id_token",
            "other_tokens",
            "resource_server",
            "scope",
            "state",
            "token_type",
        ]
    )
    assert doc["resource_server"] == "auth.globus.org"
    assert doc["other_tokens"] == []
    assert doc["state"] == "st-1"
    assert doc["expires_in"] == 172800


def test_the_access_token_acts_as_the_person_not_the_client(oidc):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    status, info, _ = oidc.form_post(
        TOKEN + "/introspect", {"token": doc["access_token"]}, basic=(CLIENT_ID, CLIENT_SECRET)
    )
    assert status == 200
    # sub and client_id come apart here, as slice A.2 predicted.
    assert info["sub"] == ALICE_GLOBUSID
    assert info["client_id"] == LOGIN_CLIENT
    assert info["username"] == "alice@globusid.org"
    assert info["name"] == "Alice Example"
    assert info["email"] == "alice@example.org"


def test_client_secret_post_works_for_the_exchange(oidc):
    code, _, _ = login(oidc)
    status, doc = exchange(oidc, code, post=True)
    assert status == 200 and "id_token" in doc


def test_a_code_is_one_use(oidc):
    code, _, _ = login(oidc)
    assert exchange(oidc, code)[0] == 200
    status, doc = exchange(oidc, code)
    assert status == 401
    assert doc["error"] == "invalid_grant"


def test_a_code_expires_on_the_logical_clock(oidc):
    code, _, _ = login(oidc)
    oidc.post("/_fauxbus/tick", {"seconds": 601})
    status, doc = exchange(oidc, code)
    assert status == 401 and doc["error"] == "invalid_grant"
    assert "expired" in doc["error_description"]


def test_a_code_survives_until_its_last_second(oidc):
    code, _, _ = login(oidc)
    oidc.post("/_fauxbus/tick", {"seconds": 599})
    assert exchange(oidc, code)[0] == 200


def test_a_code_belongs_to_its_client(oidc):
    code, _, _ = login(oidc)
    status, doc = exchange(oidc, code, client=(CAMPUS_CLIENT, CAMPUS_SECRET))
    assert status == 401 and doc["error"] == "invalid_grant"
    # and a failed attempt does not spend it
    assert exchange(oidc, code)[0] == 200


def test_a_code_belongs_to_its_redirect_uri(oidc):
    code, _, _ = login(oidc)
    status, doc = exchange(oidc, code, redirect_uri=LOGIN_REDIRECT + "/")
    assert status == 401 and doc["error"] == "invalid_grant"


def test_pkce_right_verifier_passes(oidc):
    verifier = "v" * 50
    code, _, _ = login(oidc, code_challenge=s256(verifier), code_challenge_method="S256")
    status, _ = exchange(oidc, code, code_verifier=verifier)
    assert status == 200


def test_pkce_wrong_or_missing_verifier_is_invalid_grant(oidc):
    code, _, _ = login(oidc, code_challenge=s256("v" * 50), code_challenge_method="S256")
    assert exchange(oidc, code, code_verifier="w" * 50)[1]["error"] == "invalid_grant"
    assert exchange(oidc, code)[1]["error"] == "invalid_grant"
    # neither attempt spent the code
    assert exchange(oidc, code, code_verifier="v" * 50)[0] == 200


def test_a_verifier_for_a_code_with_no_challenge_is_refused(oidc):
    code, _, _ = login(oidc)
    assert exchange(oidc, code, code_verifier="v" * 50)[1]["error"] == "invalid_grant"


def test_a_public_client_exchange_is_fauxbus_gap(oidc):
    code, _, _ = login(oidc)
    status, doc, _ = oidc.form_post(
        TOKEN,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": LOGIN_REDIRECT,
            "client_id": LOGIN_CLIENT,
            "code_verifier": "v" * 50,
        },
    )
    assert status == 501


# ------------------------------------------------------------------ id token


def test_the_id_token_verifies_by_kid_through_the_published_jwks(oidc, verifier):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    header = verifier.get_unverified_header(doc["id_token"])
    assert header["alg"] == "RS512"
    _, keyset, _ = oidc.get("/jwk.json")
    (jwk,) = [k for k in keyset["keys"] if k["kid"] == header["kid"]]
    key = verifier.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    claims = verifier.decode(
        doc["id_token"],
        key,
        algorithms=["RS512"],
        audience=LOGIN_CLIENT,
        issuer=oidc.base_url,
        # a fresh world's logical clock is 0, so iat/exp are 1970; this
        # test is about the signature — the clock has its own tests.
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims["sub"] == ALICE_GLOBUSID
    assert claims["nonce"] == "n-1"


def test_a_tampered_id_token_fails_verification(oidc, verifier):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    head, payload, sig = doc["id_token"].split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged["sub"] = BOB_GLOBUSID
    forged_payload = signing.b64url(json.dumps(forged).encode())
    key = verifier.algorithms.RSAAlgorithm.from_jwk(json.dumps(signing.jwks()["keys"][0]))
    with pytest.raises(verifier.InvalidSignatureError):
        verifier.decode(
            f"{head}.{forged_payload}.{sig}",
            key,
            algorithms=["RS512"],
            audience=LOGIN_CLIENT,
            options={"verify_exp": False},
        )


def test_at_hash_binds_the_id_token_to_its_access_token(oidc):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    digest = hashlib.sha512(doc["access_token"].encode()).digest()
    expected = base64.urlsafe_b64encode(digest[:32]).rstrip(b"=").decode()
    assert claims_of(doc["id_token"])["at_hash"] == expected


def test_nonce_is_omitted_when_none_was_sent(oidc):
    code, _, _ = login(oidc, nonce=None)
    _, doc = exchange(oidc, code)
    assert "nonce" not in claims_of(doc["id_token"])


def test_openid_alone_says_who_but_not_their_name_or_mail(oidc):
    """DOCUMENTED scope gating: openid → sub, last_authentication, identity_set."""
    code, _, _ = login(oidc, scope="openid")
    _, doc = exchange(oidc, code)
    claims = claims_of(doc["id_token"])
    for absent in ("email", "name", "preferred_username", "organization", "identity_provider"):
        assert absent not in claims, absent
    assert claims["sub"] == ALICE_GLOBUSID
    assert [i["sub"] for i in claims["identity_set"]] == [ALICE_GLOBUSID, ALICE_UNIVERSITY]
    assert sorted(claims) == sorted(
        ["aud", "at_hash", "exp", "iat", "identity_set", "iss", "last_authentication", "nonce", "sub"]
    )


def test_profile_and_email_add_only_their_documented_claims(oidc):
    code, _, _ = login(oidc, scope="openid email")
    _, doc = exchange(oidc, code)
    claims = claims_of(doc["id_token"])
    assert claims["email"] == "alice@example.org"
    assert "name" not in claims

    code, _, _ = login(oidc, scope="openid profile")
    _, doc = exchange(oidc, code)
    claims = claims_of(doc["id_token"])
    assert "email" not in claims
    assert claims["name"] == "Alice Example"
    assert claims["preferred_username"] == "alice@globusid.org"
    assert claims["identity_provider"] == GLOBUSID_IDP
    assert claims["identity_provider_display_name"] == "Globus ID"
    assert claims["organization"] == "Independent"


def test_iss_and_aud_name_the_configured_issuer_and_the_client(oidc):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    claims = claims_of(doc["id_token"])
    assert claims["iss"] == oidc.base_url
    assert claims["aud"] == LOGIN_CLIENT


# ------------------------------------------------------------- required_idp


def test_required_idp_signs_in_as_the_linked_identity(oidc):
    """DOCUMENTED: sub is the effective identity — the linked one from the required IdP."""
    code, _, _ = login(oidc, client=CAMPUS_CLIENT, redirect_uri=CAMPUS_REDIRECT)
    _, doc = exchange(oidc, code, client=(CAMPUS_CLIENT, CAMPUS_SECRET), redirect_uri=CAMPUS_REDIRECT)
    claims = claims_of(doc["id_token"])
    assert claims["sub"] == ALICE_UNIVERSITY
    assert claims["preferred_username"] == "ae123@example.edu"
    # the whole set is still there, primary first
    assert [i["sub"] for i in claims["identity_set"]] == [ALICE_GLOBUSID, ALICE_UNIVERSITY]


def test_an_unsatisfied_required_idp_never_calls_the_client_back(oidc):
    _, headers, _ = oidc.browse(authorize_path(client=CAMPUS_CLIENT, redirect_uri=CAMPUS_REDIRECT))
    location = headers["Location"]
    _, _, page = oidc.browse(location)
    assert b"No identity from the provider this client requires" in page
    status, headers, page = pick(oidc, location, BOB_GLOBUSID)
    assert status == 403
    assert "Location" not in headers and "Set-Cookie" not in headers
    assert b"Example University" in page
    # The request is still parked: alice can finish it.
    status, headers, _ = pick(oidc, location, ALICE_GLOBUSID)
    assert status == 302 and headers["Location"].startswith(CAMPUS_REDIRECT + "?code=")


def test_a_session_that_cannot_satisfy_required_idp_goes_to_the_picker(oidc):
    _, doc, _ = oidc.post("/_fauxbus/auth/session", {"account": BOB_GLOBUSID})
    status, headers, _ = oidc.browse(
        authorize_path(client=CAMPUS_CLIENT, redirect_uri=CAMPUS_REDIRECT), cookie=doc["cookie"]
    )
    assert status == 302 and headers["Location"].startswith("/_fauxbus/auth/login")


def test_a_required_idp_must_name_a_seeded_provider(fx):
    seed = oidc_seed(fx.base_url)
    seed["clients"][CAMPUS_CLIENT]["required_idp"] = "00000000-0000-4000-8000-0000000000ff"
    status, doc, _ = fx.post("/_fauxbus/seed", seed)
    assert status == 422 and "identity_providers" in doc["detail"]


# ------------------------------------------------------------------ userinfo


def test_userinfo_matches_the_id_token(oidc):
    code, _, _ = login(oidc, client=CAMPUS_CLIENT, redirect_uri=CAMPUS_REDIRECT)
    _, doc = exchange(oidc, code, client=(CAMPUS_CLIENT, CAMPUS_SECRET), redirect_uri=CAMPUS_REDIRECT)
    claims = claims_of(doc["id_token"])
    for method in ("GET", "POST"):
        status, info, _ = oidc.request(method, USERINFO, token=doc["access_token"])
        assert status == 200
        assert info["sub"] == claims["sub"] == ALICE_UNIVERSITY
        assert info["identity_set"] == claims["identity_set"]
        assert info["email"] == claims["email"]
        # userinfo carries no token-only claims
        for absent in ("iss", "aud", "exp", "iat", "at_hash", "nonce"):
            assert absent not in info


def test_userinfo_without_a_live_token_is_the_recorded_401(oidc):
    for token in (None, "t-alice", "fauxbus-at-99"):
        status, doc, _ = oidc.get(USERINFO, token=token)
        assert status == 401
        # RECORDED body (userinfo.py / _common.py), down to the text.
        assert doc["error"] == "unauthorized"
        assert doc["errors"][0]["code"] == "UNAUTHORIZED"
        assert doc["errors"][0]["detail"] == "Call must be authenticated"


def test_userinfo_for_a_token_with_no_person_is_the_recorded_403(oidc):
    _, doc, _ = oidc.form_post(
        TOKEN, {"grant_type": "client_credentials", "scope": GROUPS_SCOPE}, basic=(CLIENT_ID, CLIENT_SECRET)
    )
    status, body, _ = oidc.get(USERINFO, token=doc["access_token"])
    assert status == 403
    assert body["errors"][0]["code"] == "FORBIDDEN"


def test_userinfo_honours_revocation(oidc):
    code, _, _ = login(oidc)
    _, doc = exchange(oidc, code)
    oidc.form_post(TOKEN + "/revoke", {"token": doc["access_token"]}, basic=(LOGIN_CLIENT, LOGIN_SECRET))
    assert oidc.get(USERINFO, token=doc["access_token"])[0] == 401


# --------------------------------------------------- two services in one login


def test_openid_puts_auth_on_top_whatever_order_the_scopes_came_in(oidc):
    code, _, _ = login(oidc, scope=f"{GROUPS_SCOPE} openid email")
    status, doc = exchange(oidc, code)
    assert status == 200
    assert doc["resource_server"] == "auth.globus.org"
    assert doc["scope"] == "openid email"
    (groups,) = doc["other_tokens"]
    assert groups["resource_server"] == "groups.api.globus.org"
    # and the Groups token acts as alice, at Groups
    status, created, _ = oidc.post(
        "/v2/groups", {"name": "Alice's lab", "description": ""}, token=groups["access_token"]
    )
    assert status == 200
    assert created["my_memberships"][0]["identity_id"] == ALICE_GLOBUSID


# ---------------------------------------------------------------- the clocks


def test_logical_clock_stamps_id_tokens_with_the_world_clock(fx):
    fx.post("/_fauxbus/seed", oidc_seed(fx.base_url, clock=1767225600))
    code, _, _ = login(fx)
    _, doc = exchange(fx, code)
    claims = claims_of(doc["id_token"])
    assert claims["iat"] == 1767225600
    assert claims["exp"] == 1767225600 + 172800
    assert claims["last_authentication"] == 1767225600


def test_logical_id_tokens_are_byte_identical_across_a_reset(oidc):
    """Principle 3 reaches all the way into the signature under the logical clock."""
    seed = oidc_seed(oidc.base_url)
    code, _, _ = login(oidc)
    first = exchange(oidc, code)[1]["id_token"]
    oidc.post("/_fauxbus/reset", {"to": "empty"})
    oidc.post("/_fauxbus/seed", seed)
    code, _, _ = login(oidc)
    assert exchange(oidc, code)[1]["id_token"] == first


def test_wall_clock_is_an_opt_in_and_reads_the_injected_clock():
    """The one wall-clock read in Fauxbus, frozen here so the test is still deterministic."""
    import threading

    from fauxbus.server import make_server

    server = make_server("127.0.0.1", 0, wall_clock=lambda: 1791000000.75)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        host, port = server.server_address[:2]
        client = Client(f"http://{host}:{port}")
        seed = oidc_seed(client.base_url, oidc={"issuer": client.base_url, "signed_token_clock": "wall"})
        client.post("/_fauxbus/seed", seed)
        client.post("/_fauxbus/tick", {"seconds": 5000})  # tick moves codes, not wall time
        code, _, _ = login(client)
        _, doc = exchange(client, code)
        claims = claims_of(doc["id_token"])
        assert claims["iat"] == 1791000000
        assert claims["exp"] == 1791000000 + 172800
        assert claims["last_authentication"] == 1791000000
        _, index, _ = client.get("/_fauxbus/")
        assert index["oidc"]["signed_token_clock"] == "wall"
    finally:
        server.shutdown()
        server.server_close()


def test_boot_flags_are_defaults_the_seed_overrides():
    import threading

    from fauxbus.server import make_server

    server = make_server(
        "127.0.0.1", 0, issuer="http://fauxbus.test:9800", signed_token_clock="wall"
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        host, port = server.server_address[:2]
        client = Client(f"http://{host}:{port}")
        _, doc, _ = client.get("/.well-known/openid-configuration")
        assert doc["issuer"] == "http://fauxbus.test:9800"
        client.post("/_fauxbus/seed", {"oidc": {"issuer": "http://seeded.test"}})
        _, doc, _ = client.get("/.well-known/openid-configuration")
        assert doc["issuer"] == "http://seeded.test"
        _, state, _ = client.get("/_fauxbus/state")
        # the dump describes the world, not the command line
        assert state["oidc"] == {"issuer": "http://seeded.test", "signed_token_clock": None}
        client.post("/_fauxbus/reset", {"to": "empty"})
        _, doc, _ = client.get("/.well-known/openid-configuration")
        assert doc["issuer"] == "http://fauxbus.test:9800"
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------- reset and round trip


def test_reset_clears_codes_sessions_and_parked_requests(oidc):
    code, _, cookie = login(oidc)
    oidc.browse(authorize_path(prompt="login"), cookie=cookie)  # parks one
    _, state, _ = oidc.get("/_fauxbus/state")
    assert state["authorization_codes"] and state["sessions"] and state["authorization_requests"]

    oidc.post("/_fauxbus/reset", {"to": "empty"})
    _, state, _ = oidc.get("/_fauxbus/state")
    assert state["authorization_codes"] == {}
    assert state["sessions"] == {}
    assert state["authorization_requests"] == {}
    # and the cookie names nothing any more
    oidc.post("/_fauxbus/seed", oidc_seed(oidc.base_url))
    status, headers, _ = oidc.browse(authorize_path(), cookie=cookie)
    assert headers["Location"].startswith("/_fauxbus/auth/login")


def test_a_half_finished_login_survives_dump_and_restore(oidc):
    """Ephemeral auth state joins the round-trip invariant: capture mid-login, replay."""
    _, headers, _ = oidc.browse(authorize_path())  # parked at the picker
    picker = headers["Location"]
    code, _, _ = login(oidc)  # and a second login with an unredeemed code
    _, state, _ = oidc.get("/_fauxbus/state")

    oidc.post("/_fauxbus/reset", {"to": "empty"})
    oidc.post("/_fauxbus/seed", state)
    _, replayed, _ = oidc.get("/_fauxbus/state")
    assert replayed == state  # dump, seed, dump: identical

    # Both logins finish in the restored world.
    status, headers, _ = pick(oidc, picker, ALICE_GLOBUSID)
    assert status == 302 and "?code=" in headers["Location"]
    assert exchange(oidc, code)[0] == 200


def test_a_seeded_code_may_not_wear_a_name_the_mint_has_not_reached(fx):
    seed = oidc_seed(fx.base_url)
    seed["authorization_codes"] = {
        "fauxbus-code-0": {
            "client_id": LOGIN_CLIENT,
            "redirect_uri": LOGIN_REDIRECT,
            "scopes": ["openid"],
            "account": ALICE_GLOBUSID,
        }
    }
    status, doc, _ = fx.post("/_fauxbus/seed", seed)
    assert status == 422 and "counters.authorization_code to 1" in doc["detail"]
    # a name outside the minted space is the harness's to use
    seed["authorization_codes"] = {"handmade-code": seed["authorization_codes"]["fauxbus-code-0"]}
    assert fx.post("/_fauxbus/seed", seed)[0] == 200
    assert exchange(fx, "handmade-code", scope="ignored")[0] == 200


def test_an_identity_belongs_to_one_account(fx):
    seed = oidc_seed(fx.base_url)
    seed["accounts"][BOB_GLOBUSID]["identities"][ALICE_UNIVERSITY] = seed["accounts"][
        ALICE_GLOBUSID
    ]["identities"][ALICE_UNIVERSITY]
    status, doc, _ = fx.post("/_fauxbus/seed", seed)
    assert status == 422 and "one account" in doc["detail"]
