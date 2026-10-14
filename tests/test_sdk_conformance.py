"""The conformance seed: real globus-sdk client code against Fauxbus.

This file is the embryo of the two-backend conformance tether from
SPEC.md.  Today it runs against Fauxbus on every CI run; the env-gated
real-service backend arrives with the first recording session.  Nothing
in here monkeypatches anything — the SDK is pointed at Fauxbus by
base_url alone, which is the whole point.
"""

from __future__ import annotations

import ast
import datetime as dt
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

# The tether's weak point, and the reason for the switch below: with
# globus-sdk absent, `importorskip` deletes this entire file and the run
# still reports green — a suite whose founding claim is "the SDK is the
# contract" quietly testing no SDK at all.  A bare checkout should still
# be runnable, so the skip stays the local default; CI sets
# FAUXBUS_REQUIRE_CONFORMANCE=1 and the missing import becomes a
# collection error instead of a shrug.
if os.environ.get("FAUXBUS_REQUIRE_CONFORMANCE"):
    import globus_sdk
else:
    globus_sdk = pytest.importorskip("globus_sdk")

from conftest import (  # noqa: E402
    ALICE,
    ALICE_GLOBUSID,
    CLIENT_ID,
    CLIENT_SECRET,
    GROUPS_SCOPE,
    LANDING,
    LAPSED,
    LAPTOP,
    LOGIN_CLIENT,
    LOGIN_REDIRECT,
    LOGIN_SECRET,
    TRANSFER_SCOPE,
    files,
    make_task,
    oidc_seed,
    transfer_seed,
)
from globus_sdk import (  # noqa: E402
    AccessTokenAuthorizer,
    AuthAPIError,
    AuthClient,
    BatchMembershipActions,
    ClientCredentialsAuthorizer,
    ConfidentialAppAuthClient,
    GroupPolicies,
    GroupsAPIError,
    GroupsClient,
    GroupsManager,
    TransferAPIError,
    TransferClient,
)

from fauxbus import signing  # noqa: E402
from fauxbus.ids import identity_id_for_token  # noqa: E402

# The stated SDK contract version, as one literal.  SPEC.md and README
# both say Fauxbus imitates globus-sdk 4.8.1; pyproject pins it exactly.
# This is the third copy of that fact, and the only one a test can check
# — which is the point.  Keep all three in step when bumping.
CONTRACT_SDK_VERSION = "4.8.1"


def test_installed_sdk_is_the_stated_contract_version():
    """The tether is only honest if the SDK under it is the stated one.

    This is the assertion that was missing on 2026-08-16, when the pin
    read `globus-sdk>=4.8.1,<5` and resolved to 4.9.0.  The suite was
    green, the SPEC said 4.8.1, and CI had been conforming against an
    SDK nobody had named for however long 4.9.0 had been on PyPI.  A
    conformance suite that does not check *which* SDK it conformed to is
    describing a contract it cannot prove it tested.
    """
    assert globus_sdk.__version__ == CONTRACT_SDK_VERSION, (
        f"conformance ran against globus-sdk {globus_sdk.__version__}, but the "
        f"stated contract in SPEC.md and pyproject is {CONTRACT_SDK_VERSION}.  "
        f"Remedy: either reinstall the pinned SDK "
        f"(pip install -e '.[conformance]'), or — if this is a deliberate bump "
        f"— change the pin in pyproject.toml, CONTRACT_SDK_VERSION here, and "
        f"the version named in SPEC.md and README.md, together, in one commit."
    )


def sdk_client(base_url: str, token: str = "t-alice") -> GroupsClient:
    return GroupsClient(base_url=base_url, authorizer=AccessTokenAuthorizer(token))


@pytest.fixture
def client(fx) -> GroupsClient:
    return sdk_client(fx.base_url)


def test_create_get_update_delete_round_trip(client):
    created = client.create_group({"name": "Route 9800", "description": "same stops every run"})
    gid = created["id"]
    assert created["my_memberships"][0]["role"] == "admin"

    fetched = client.get_group(gid, include=["memberships", "child_ids"])
    assert fetched["name"] == "Route 9800"
    assert fetched["child_ids"] == []

    updated = client.update_group(gid, {"name": "Renamed Riders"})
    assert updated["name"] == "Renamed Riders"

    deleted = client.delete_group(gid)
    assert deleted["id"] == gid

    with pytest.raises(GroupsAPIError) as exc:
        client.get_group(gid)
    assert exc.value.http_status == 404
    assert exc.value.code == "NOT_FOUND"


def test_get_my_groups_parses_as_array_response(client):
    client.create_group({"name": "one", "description": ""})
    client.create_group({"name": "two", "description": ""})
    listing = client.get_my_groups()
    assert [g["name"] for g in listing] == ["one", "two"]
    # And the statuses filter goes over the wire as the SDK sends it:
    assert list(client.get_my_groups(statuses="invited")) == []


def test_groups_manager_membership_flow(fx):
    alice = GroupsManager(sdk_client(fx.base_url))
    dave_token = "t-dave"
    dave_id = identity_id_for_token(dave_token)

    gid = alice.create_group("Managed", "via GroupsManager")["id"]
    added = alice.add_member(gid, identity_id_for_token("t-bob"), role="manager")
    assert added["add"][0]["role"] == "manager"

    invited = alice.invite_member(gid, dave_id)
    assert invited["invite"][0]["status"] == "invited"

    dave = GroupsManager(sdk_client(fx.base_url, dave_token))
    accepted = dave.accept_invite(gid, dave_id)
    assert accepted["accept"][0]["status"] == "active"


def test_batch_membership_actions_payload(client):
    gid = client.create_group({"name": "Batchers", "description": ""})["id"]
    batch = BatchMembershipActions()
    batch.add_members([identity_id_for_token("t-bob")])
    batch.invite_members([identity_id_for_token("t-carol")], role="manager")

    result = client.batch_membership_action(gid, batch)
    assert result["add"][0]["status"] == "active"
    assert result["invite"][0]["role"] == "manager"


def test_group_policies_payload(client):
    gid = client.create_group({"name": "Policied", "description": ""})["id"]
    result = client.set_group_policies(
        gid,
        GroupPolicies(
            is_high_assurance=False,
            group_visibility="authenticated",
            group_members_visibility="members",
            join_requests=True,
            signup_fields=["address1"],
            authentication_assurance_timeout=28800,
        ),
    )
    assert result["group_visibility"] == "authenticated"
    assert result["join_requests"] is True

    fetched = client.get_group_policies(gid)
    assert fetched["signup_fields"] == ["address1"]


def test_preferences_round_trip(client):
    client.set_identity_preferences({"allow_add": False})
    assert client.get_identity_preferences()["allow_add"] is False


def test_membership_fields_round_trip_via_sdk(client):
    # Wire-level coverage existed for this path; what was missing until
    # the pre-v0.1 audit was the SDK's own spelling of it.  Four of the
    # fourteen GroupsClient methods had never been driven through the
    # real SDK — this test and the two below close that gap.
    gid = client.create_group({"name": "Fielded", "description": ""})["id"]
    fields = {"institution": "Drexel", "current_project_name": "root-cellar"}
    # PROVISIONAL downstream: fields are stored and returned as sent.
    assert client.set_membership_fields(gid, fields).data == fields
    assert client.get_membership_fields(gid).data == fields


def test_subscription_admin_verified_via_sdk(fx, client):
    gid = client.create_group({"name": "Verified", "description": ""})["id"]
    sid = "11111111-2222-4333-8444-555555555555"
    doc = client.set_subscription_admin_verified(gid, sid)
    assert doc["id"] == gid
    # The group document doesn't carry the verified id (RECORDED shape
    # omits it), so the state dump is where a test proves it stuck.
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"][gid]["subscription_admin_verified_id"] == sid
    # Clearing is spelled None on the SDK side, null on the wire.
    client.set_subscription_admin_verified(gid, None)
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"][gid]["subscription_admin_verified_id"] is None


def test_get_group_by_subscription_id_via_sdk(fx, client):
    # subscription_id has no write endpoint (true of the real service
    # too — subscriptions come from Globus operations, not the API), so
    # the seed is how a test world gets one.
    sid = "99999999-8888-4777-8666-555555555444"
    gid = "00000000-0000-4000-8000-0000000000aa"
    alice = identity_id_for_token("t-alice")
    fx.post(
        "/_fauxbus/seed",
        {
            "groups": {
                gid: {
                    "name": "Subscribed",
                    "memberships": {alice: {"role": "admin", "status": "active"}},
                    "subscription_id": sid,
                    "subscription_info": {
                        "is_high_assurance": True,
                        "is_baa": False,
                        "connectors": {},
                        "internal_bookkeeping": "must not leak",
                    },
                }
            }
        },
    )
    found = client.get_group_by_subscription_id(sid)
    assert found["group_id"] == gid
    # RECORDED: the endpoint returns the restricted projection only.
    assert found["subscription_info"]["is_high_assurance"] is True
    assert "internal_bookkeeping" not in found["subscription_info"]

    with pytest.raises(GroupsAPIError) as exc:
        client.get_group_by_subscription_id("00000000-0000-4000-8000-00000000dead")
    assert exc.value.http_status == 404


def test_unimplemented_endpoint_raises_loud_501(client):
    with pytest.raises(GroupsAPIError) as exc:
        client.get("/v2/definitely_not_a_thing")
    assert exc.value.http_status == 501
    assert exc.value.code == "NOT_IMPLEMENTED"
    assert "file an issue" in exc.value.message.lower()


def test_sdk_retry_layer_survives_an_injected_429(fx, client):
    """The whole pitch in one test: arm a 429, and the SDK's own retry
    logic — the code you actually ship — sails through it."""
    client.create_group({"name": "Resilient", "description": ""})
    fx.post(
        "/_fauxbus/failures",
        {
            "method": "GET",
            "path": "/v2/groups/my_groups",
            "status": 429,
            "headers": {"Retry-After": "0"},
            "times": 1,
        },
    )
    listing = client.get_my_groups()  # no exception: the retry ate the 429
    assert [g["name"] for g in listing] == ["Resilient"]

    _, armed, _ = fx.get("/_fauxbus/failures")
    assert armed["failures"] == []  # the injected failure was really served


# --------------------------------------------- auth slice A: client_credentials


def confidential_client(base_url: str, secret: str = CLIENT_SECRET):
    return ConfidentialAppAuthClient(CLIENT_ID, secret, base_url=base_url)


def test_client_credentials_grant_drives_end_to_end(registered):
    """The tether's newest strand: real SDK, real grant, real token, real call.

    Nothing is monkeypatched and nothing is hand-assembled.  The SDK
    builds the form POST and the Basic header, Fauxbus mints a token, and
    the same SDK then spends that token against Groups — which is the
    only way to prove the two halves of the fake agree about who the
    caller is.  A response the SDK could parse but whose identity was
    wrong would pass every wire-level test and fail here.
    """
    client = confidential_client(registered.base_url)
    tokens = client.oauth2_client_credentials_tokens(GROUPS_SCOPE)

    # by_resource_server is the SDK's own view of the document, and
    # building it is what would have raised KeyError on a missing
    # 'other_tokens'.
    token_data = tokens.by_resource_server["groups.api.globus.org"]
    assert token_data["token_type"] == "Bearer"
    assert token_data["scope"] == GROUPS_SCOPE

    groups = GroupsClient(
        base_url=registered.base_url,
        authorizer=AccessTokenAuthorizer(token_data["access_token"]),
    )
    created = groups.create_group({"name": "SDK round trip", "description": ""})
    (membership,) = created["my_memberships"]
    assert membership["identity_id"] == CLIENT_ID
    assert membership["username"] == f"{CLIENT_ID}@clients.auth.globus.org"


def test_a_multi_service_grant_lands_in_by_resource_server(registered):
    """The SDK's view of ``other_tokens``, which is the one that matters.

    ``by_resource_server`` folds the primary and every ``other_tokens``
    entry into one dict keyed by service — which is also why the
    PROVISIONAL primary-token rule cannot reach an SDK consumer who looks
    tokens up by name, the way this test does.  Each entry must survive
    ``_convert_token_info_dict``, and the Groups token must still be good
    for a real Groups call.
    """
    tokens = confidential_client(registered.base_url).oauth2_client_credentials_tokens(
        [TRANSFER_SCOPE, GROUPS_SCOPE]
    )
    assert set(tokens.by_resource_server) == {
        "transfer.api.globus.org",
        "groups.api.globus.org",
    }
    assert tokens.by_scopes[TRANSFER_SCOPE]["resource_server"] == "transfer.api.globus.org"
    groups_token = tokens.by_resource_server["groups.api.globus.org"]["access_token"]
    groups = GroupsClient(
        base_url=registered.base_url, authorizer=AccessTokenAuthorizer(groups_token)
    )
    created = groups.create_group({"name": "Two tokens, one call", "description": ""})
    assert created["my_memberships"][0]["identity_id"] == CLIENT_ID


def test_by_scopes_indexes_the_response_too(registered):
    # The SDK offers two views of the same document; both are built from
    # fields Fauxbus has to get right, so both are worth touching.
    tokens = confidential_client(registered.base_url).oauth2_client_credentials_tokens(GROUPS_SCOPE)
    assert tokens.by_scopes[GROUPS_SCOPE]["resource_server"] == "groups.api.globus.org"


def test_client_credentials_authorizer_fetches_its_own_token(registered):
    """The way a service actually uses this grant in production.

    ClientCredentialsAuthorizer takes the confidential client and the
    scopes, then goes and gets a token when the first request needs one
    — no explicit grant call in the consumer's code at all.  If Fauxbus
    only satisfied the explicit path, this is where that would show.
    """
    authorizer = ClientCredentialsAuthorizer(confidential_client(registered.base_url), GROUPS_SCOPE)
    groups = GroupsClient(base_url=registered.base_url, authorizer=authorizer)
    groups.create_group({"name": "Self-serve", "description": ""})
    assert [g["name"] for g in groups.get_my_groups()] == ["Self-serve"]


def test_the_token_endpoints_errors_really_are_that_opaque(registered):
    """Pinning an unflattering fact so a later SDK bump cannot hide it.

    The token endpoint answers RFC 6749's ``{"error": ...}`` body, which
    carries none of the fields GlobusAPIError parses — so ``.code`` and
    ``.message`` come back as None and a consumer is left with the status
    and the raw body.  Fauxbus deliberately does not improve on this (see
    errors.OAuthError): a fake that is kinder than the service hides a
    rough edge the consumer meets in production anyway.  The assertion
    exists because that claim is written in a docstring, and a claim no
    test checks is the kind this project has already shipped three of.
    """
    client = confidential_client(registered.base_url, secret="wrong")
    with pytest.raises(globus_sdk.GlobusAPIError) as exc:
        client.oauth2_client_credentials_tokens(GROUPS_SCOPE)
    assert exc.value.http_status == 401
    assert exc.value.code is None
    assert exc.value.message is None
    assert exc.value.raw_json["error"] == "invalid_client"


# ------------------------------------- auth slice A.2: introspection, revocation


def test_introspection_round_trips_through_the_sdk(registered):
    """The tether on the endpoint whose whole job is being believed.

    A resource server introspects a token to decide whether to serve a
    request. If Fauxbus's document were shaped wrong, the consumer's
    ``data["sub"]`` would be the thing that broke — in their code, at
    runtime, against a fake that had already told them everything was
    fine. So the SDK does the asking here, not urllib.
    """
    client = confidential_client(registered.base_url)
    token = client.oauth2_client_credentials_tokens(GROUPS_SCOPE)["access_token"]

    data = client.oauth2_token_introspect(token)
    assert data["active"] is True
    assert data["sub"] == CLIENT_ID
    assert data["scope"] == GROUPS_SCOPE
    assert data["iss"] == "https://auth.globus.org"
    # The same UUID the Groups half of the fake will report for this
    # caller. Two surfaces, one answer — which is the only thing that
    # makes introspection worth having.
    groups = GroupsClient(
        base_url=registered.base_url, authorizer=AccessTokenAuthorizer(token)
    )
    (membership,) = groups.create_group({"name": "Assayed", "description": ""})[
        "my_memberships"
    ]
    assert membership["identity_id"] == data["sub"]


def test_revoke_then_introspect_is_the_loop_the_sdk_documents(registered):
    """``oauth2_revoke_token``'s own docstring describes this sequence.

    "You can check the 'active' status of the token after revocation if
    you want to confirm that it was revoked" (base_login_client.py,
    4.8.1). A consumer following that advice against Fauxbus has to get
    the same answer it would get against Globus, which means both halves
    have to agree — and they only agree because revocation is world
    state rather than a deletion.
    """
    client = confidential_client(registered.base_url)
    token = client.oauth2_client_credentials_tokens(GROUPS_SCOPE)["access_token"]
    assert client.oauth2_token_introspect(token)["active"] is True

    assert client.oauth2_revoke_token(token)["active"] is False
    assert client.oauth2_token_introspect(token)["active"] is False


def test_introspecting_a_token_the_sdk_never_got_is_not_an_error(registered):
    # RFC 7662 §2.2: inactive is an answer, not a failure. A consumer
    # that wrapped this in try/except would never see the except branch
    # against the real service either.
    data = confidential_client(registered.base_url).oauth2_token_introspect("t-alice")
    assert data["active"] is False


# ------------------------------------------- auth slice B: the OIDC code flow
#
# Every leg the pinned SDK exposes, driven through it.  The one leg it
# cannot drive — a person at the authorize page — is walked by plain
# HTTP between ``oauth2_get_authorize_url`` and
# ``oauth2_exchange_code_for_tokens``, exactly where a browser would be.


def login_client(base_url: str) -> ConfidentialAppAuthClient:
    return ConfidentialAppAuthClient(LOGIN_CLIENT, LOGIN_SECRET, base_url=base_url)


def browser_login(fx, authorize_url: str, account: str = ALICE_GLOBUSID) -> str:
    """Be the browser: follow the SDK's authorize URL to the picker, pick, return the code."""
    status, headers, _ = fx.browse(authorize_url)
    assert status == 302, headers
    request_id = parse_qs(urlsplit(headers["Location"]).query)["request"][0]
    status, headers, _ = fx.browse(
        "/_fauxbus/auth/login", method="POST", form={"request": request_id, "account": account}
    )
    assert status == 302, headers
    callback = parse_qs(urlsplit(headers["Location"]).query)
    return callback["code"][0]


def test_discovery_and_jwk_load_through_the_sdk(oidc):
    client = login_client(oidc.base_url)
    config = client.get_openid_configuration()
    assert config["issuer"] == oidc.base_url
    # get_jwk follows discovery's jwks_uri and decodes keys[0] into a
    # real ``cryptography`` public key — the SDK's own path to verifying.
    key = client.get_jwk(openid_configuration=config, as_pem=True)
    assert key.public_numbers().n == signing.N
    raw = client.get_jwk(openid_configuration=config, as_pem=False)
    assert raw["keys"][0]["kid"] == signing.KID


def test_the_sdks_own_code_flow_ends_in_an_id_token_it_verifies(fx):
    """The whole flow the SDK documents, against a wall-clock world.

    ``decode_id_token`` is the SDK's verifier: it fetches discovery and
    the JWK itself, checks the RS512 signature, the audience, and
    ``exp``/``iat`` against *real* time.  That last check is why this
    world opts into ``signed_token_clock: "wall"`` — on the logical
    clock at zero the token would be from 1970, and the SDK would be
    right to refuse it.  Exactly the trap a broker falls into.
    """
    fx.post(
        "/_fauxbus/seed",
        oidc_seed(fx.base_url, oidc={"issuer": fx.base_url, "signed_token_clock": "wall"}),
    )
    client = login_client(fx.base_url)
    client.oauth2_start_flow(LOGIN_REDIRECT, "openid profile email", state="sdk-state")
    url = client.oauth2_get_authorize_url(query_params={"nonce": "sdk-nonce"})
    assert url.startswith(fx.base_url + "/v2/oauth2/authorize?")

    tokens = client.oauth2_exchange_code_for_tokens(browser_login(fx, url))
    auth_tokens = tokens.by_resource_server["auth.globus.org"]
    assert auth_tokens["scope"] == "openid profile email"
    assert tokens["state"] == "sdk-state"  # the default fixture's echo

    claims = tokens.decode_id_token()
    assert claims["sub"] == ALICE_GLOBUSID
    assert claims["aud"] == LOGIN_CLIENT
    assert claims["nonce"] == "sdk-nonce"
    assert claims["preferred_username"] == "alice@globusid.org"


def test_userinfo_through_the_sdk_matches_the_id_token(fx):
    fx.post(
        "/_fauxbus/seed",
        oidc_seed(fx.base_url, oidc={"issuer": fx.base_url, "signed_token_clock": "wall"}),
    )
    client = login_client(fx.base_url)
    client.oauth2_start_flow(LOGIN_REDIRECT, "openid email")
    tokens = client.oauth2_exchange_code_for_tokens(
        browser_login(fx, client.oauth2_get_authorize_url())
    )
    access = tokens.by_resource_server["auth.globus.org"]["access_token"]
    info = AuthClient(base_url=fx.base_url, authorizer=AccessTokenAuthorizer(access)).userinfo()
    claims = tokens.decode_id_token()
    assert info["sub"] == claims["sub"]
    assert info["identity_set"] == claims["identity_set"]
    assert info["email"] == "alice@example.org"


def test_userinfo_refusals_parse_the_way_the_recorded_fixture_says(oidc):
    """Unlike the token endpoint, these errors DO reach ``.code`` and ``.message``.

    The fixture's metadata says so (``code: UNAUTHORIZED``, ``message:
    "Call must be authenticated"``), and this pins it — the SDK reads the
    JSON:API ``errors`` list in Globus Auth's own error document.
    """
    client = AuthClient(base_url=oidc.base_url, authorizer=AccessTokenAuthorizer("t-alice"))
    with pytest.raises(AuthAPIError) as exc:
        client.userinfo()
    assert exc.value.http_status == 401
    assert exc.value.code == "UNAUTHORIZED"
    assert exc.value.message == "Call must be authenticated"


def test_a_spent_code_fails_through_the_sdk_like_the_recorded_invalid_grant(fx):
    fx.post("/_fauxbus/seed", oidc_seed(fx.base_url))
    client = login_client(fx.base_url)
    client.oauth2_start_flow(LOGIN_REDIRECT, "openid")
    code = browser_login(fx, client.oauth2_get_authorize_url())
    client.oauth2_exchange_code_for_tokens(code)
    with pytest.raises(AuthAPIError) as exc:
        client.oauth2_exchange_code_for_tokens(code)
    assert exc.value.http_status == 401
    assert exc.value.raw_json == {
        "error": "invalid_grant",
        "error_description": "that authorization code has already been redeemed; codes are one-use.",
    }


# ------------------------------------- transfer: endpoint_manager task monitoring
#
# The consumer this slice was built for is a poller (Root Cellar's
# globus_watch), and the tests below call the SDK exactly the way it
# does: a confidential client, ClientCredentialsAuthorizer for the
# Transfer scope, one base_url for Auth and Transfer both, and the
# paginated endpoint_manager_* calls with the same arguments.  If the
# consumer's own code changes shape, these should change with it.


def watcher(base_url: str) -> TransferClient:
    """``SdkTaskSource._tc``, verbatim but for the names."""
    auth = ConfidentialAppAuthClient(CLIENT_ID, CLIENT_SECRET, base_url=base_url)
    authorizer = ClientCredentialsAuthorizer(auth, TRANSFER_SCOPE)
    return TransferClient(authorizer=authorizer, base_url=base_url)


def recorded_task_keys() -> set[str]:
    """The task document's key set, read out of the SDK's own fixture source.

    Read with ``ast`` rather than imported, because importing
    ``globus_sdk.testing`` pulls in ``responses``, which the conformance
    extra does not install and which Fauxbus has no other use for.  The
    document is the dict literal whose ``DATA_TYPE`` is ``"task"``; its
    keys are string constants even where its values are f-strings.
    """
    source = (
        Path(globus_sdk.__file__).parent
        / "testing/data/transfer/endpoint_manager_task_list.py"
    ).read_text()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            pairs = {
                k.value: v
                for k, v in zip(node.keys, node.values, strict=True)
                if isinstance(k, ast.Constant)
            }
            data_type = pairs.get("DATA_TYPE")
            if isinstance(data_type, ast.Constant) and data_type.value == "task":
                return set(pairs)
    raise AssertionError("no task document in the SDK's endpoint_manager_task_list fixture")


# A logical clock seeded to a real second, the way a consumer comparing
# against its own ``now`` has to (SPEC: introspection's "seed the clock"
# advice, which Transfer's timestamps need just as much).
NOON = dt.datetime(2026, 10, 14, 12, 0, 0, tzinfo=dt.UTC)


@pytest.fixture
def watched(fx):
    status, doc, _ = fx.post("/_fauxbus/seed", transfer_seed(clock=int(NOON.timestamp())))
    assert status == 200, doc
    return fx


def test_task_documents_carry_the_recorded_key_set(watched):
    make_task(watched, status="SUCCEEDED")
    tc = watcher(watched.base_url)
    (doc,) = tc.endpoint_manager_task_list(filter_endpoint=LANDING, filter_status="SUCCEEDED")
    assert set(doc) == recorded_task_keys()
    assert set(tc.endpoint_manager_get_task(doc["task_id"]).data) == recorded_task_keys()


def test_the_consumers_poll_runs_unmodified(watched):
    """globus_watch's three calls, with its arguments, against a world in motion.

    The window is a datetime pair, which the SDK turns into
    ``"<start>,<end>"`` with ``isoformat(timespec="seconds")``;
    filter_status is a tuple, which it comma-joins.  Fauxbus parsing both
    correctly is what this test proves, because a mismatch in either
    would return the wrong tasks rather than an error.
    """
    before = make_task(watched, status="SUCCEEDED")  # completes at NOON, outside
    watched.post("/_fauxbus/tick", {"seconds": 3600})
    done = make_task(watched, files=files(3, size=1000), duration=60)
    failed = make_task(watched, files=files(5))
    watched.post(f"/_fauxbus/transfer/tasks/{failed['task_id']}",
                 {"status": "FAILED", "files_succeeded": 2})
    running = make_task(watched, duration=10_000)
    paused = make_task(watched, status="INACTIVE")
    outbound = make_task(watched, source_endpoint_id=LANDING, destination_endpoint_id=LAPTOP,
                         status="SUCCEEDED")
    watched.post("/_fauxbus/tick", {"seconds": 120})  # `done` finishes at +3660

    tc = watcher(watched.base_url)
    now = NOON + dt.timedelta(seconds=3720)
    since = NOON + dt.timedelta(minutes=30)
    terminal = [
        dict(t)
        for t in tc.paginated.endpoint_manager_task_list(
            filter_endpoint=LANDING,
            filter_endpoint_use="destination",
            filter_status=("SUCCEEDED", "FAILED"),
            filter_completion_time=(since, now),
            query_params={"limit": 1000},
        ).items()
    ]
    active = [
        dict(t)
        for t in tc.paginated.endpoint_manager_task_list(
            filter_endpoint=LANDING,
            filter_endpoint_use="destination",
            filter_status=("ACTIVE", "INACTIVE"),
            query_params={"limit": 1000},
        ).items()
    ]
    assert [t["task_id"] for t in terminal] == [done["task_id"], failed["task_id"]]
    assert before["task_id"] not in {t["task_id"] for t in terminal}
    assert outbound["task_id"] not in {t["task_id"] for t in terminal + active}
    assert {t["task_id"] for t in active} == {running["task_id"], paused["task_id"]}

    # The fields globus_watch._sight reads, parsed the way it parses them.
    finished = terminal[0]
    assert dt.datetime.fromisoformat(finished["completion_time"]) == NOON + dt.timedelta(
        seconds=3660
    )
    assert finished["owner_id"] == ALICE
    assert (finished["files_transferred"], finished["bytes_transferred"]) == (3, 3000)
    assert finished["faults"] == 0

    rows = [dict(r) for r in tc.paginated.endpoint_manager_task_successful_transfers(
        done["task_id"]).items()]
    assert [r["destination_path"] for r in rows] == [
        "/landing/proj-a/f0000.dat", "/landing/proj-a/f0001.dat", "/landing/proj-a/f0002.dat",
    ]
    # The three fields globus_watch._read stores beside the path.
    assert {(r["size"], r["checksum_algorithm"]) for r in rows} == {(1000, "sha256")}
    assert rows[0]["checksum"] == f"{0:064x}"


def test_last_key_pagination_really_pages_through_the_sdk(watched):
    made = []
    for _ in range(5):
        made.append(make_task(watched, status="SUCCEEDED")["task_id"])
        watched.post("/_fauxbus/tick", {"seconds": 1})
    paginator = watcher(watched.base_url).paginated.endpoint_manager_task_list(
        filter_endpoint=LANDING, filter_status="SUCCEEDED", query_params={"limit": 2}
    )
    pages = list(paginator.pages())
    assert [len(p["DATA"]) for p in pages] == [2, 2, 1]
    assert [t["task_id"] for p in pages for t in p] == list(reversed(made))


def test_next_marker_pagination_really_pages_through_the_sdk(watched):
    task = make_task(watched, status="SUCCEEDED", files=files(250))
    paginator = watcher(watched.base_url).paginated.endpoint_manager_task_successful_transfers(
        task["task_id"]
    )
    pages = list(paginator.pages())
    assert [len(p["DATA"]) for p in pages] == [100, 100, 50]
    paths = [r["destination_path"] for p in pages for r in p]
    assert len(set(paths)) == 250


def test_permission_denied_parses_like_the_recorded_document(watched):
    """``.code`` and ``.message`` from Transfer's own dialect.

    The client holds activity_monitor on LAPSED, whose subscription is
    gone — the roles-go-inactive rule, met through the SDK.
    """
    tc = watcher(watched.base_url)
    with pytest.raises(TransferAPIError) as exc:
        tc.endpoint_manager_task_list(filter_endpoint=LAPSED, filter_status="SUCCEEDED")
    assert exc.value.http_status == 403
    assert exc.value.code == "PermissionDenied"
    assert "not subscribed" in exc.value.message
    assert exc.value.raw_json["resource"] == "/v0.10/endpoint_manager/task_list"
    assert exc.value.request_id == exc.value.raw_json["request_id"]


def test_an_unbuilt_transfer_route_is_a_loud_501_through_the_sdk(watched):
    task = make_task(watched)
    with pytest.raises(TransferAPIError) as exc:
        watcher(watched.base_url).endpoint_manager_task_event_list(task["task_id"])
    assert exc.value.http_status == 501
    assert exc.value.code == "NOT_IMPLEMENTED"
    assert "file an issue" in exc.value.message.lower()


def test_sdk_retries_through_an_injected_429_on_the_task_list(watched):
    make_task(watched)
    watched.post(
        "/_fauxbus/failures",
        {
            "method": "GET",
            "path": "/v0.10/endpoint_manager/task_list",
            "status": 429,
            "headers": {"Retry-After": "0"},
            "times": 1,
        },
    )
    tasks = list(watcher(watched.base_url).endpoint_manager_task_list(
        filter_endpoint=LANDING, filter_status="ACTIVE"))
    assert len(tasks) == 1
    _, armed, _ = watched.get("/_fauxbus/failures")
    assert armed["failures"] == []


def test_an_injected_failure_reaches_the_consumer_as_a_transfer_error(watched):
    """Fail on demand, in Transfer's own words, on the file-list call.

    The failure a poller must survive is the one this arms: a task whose
    successful-transfer list will not read.  The armed body is Transfer's
    recorded error shape, so the SDK parses it exactly as it would the
    real thing.
    """
    task = make_task(watched, status="SUCCEEDED")
    path = f"/v0.10/endpoint_manager/task/{task['task_id']}/successful_transfers"
    watched.post(
        "/_fauxbus/failures",
        {
            "method": "GET",
            "path": path,
            "status": 404,
            "body": {"code": "TaskNotFound", "message": "gone", "request_id": "injected1",
                     "resource": path},
            "times": 1,
        },
    )
    tc = watcher(watched.base_url)
    with pytest.raises(TransferAPIError) as exc:
        list(tc.paginated.endpoint_manager_task_successful_transfers(task["task_id"]).items())
    assert (exc.value.http_status, exc.value.code) == (404, "TaskNotFound")
    # Disarmed after one use: the next poll reads it.
    rows = list(tc.paginated.endpoint_manager_task_successful_transfers(task["task_id"]).items())
    assert len(rows) == 2
