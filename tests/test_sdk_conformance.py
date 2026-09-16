"""The conformance seed: real globus-sdk client code against Fauxbus.

This file is the embryo of the two-backend conformance tether from
SPEC.md.  Today it runs against Fauxbus on every CI run; the env-gated
real-service backend arrives with the first recording session.  Nothing
in here monkeypatches anything — the SDK is pointed at Fauxbus by
base_url alone, which is the whole point.
"""

from __future__ import annotations

import os

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

from conftest import CLIENT_ID, CLIENT_SECRET, GROUPS_SCOPE  # noqa: E402
from globus_sdk import (  # noqa: E402
    AccessTokenAuthorizer,
    BatchMembershipActions,
    ClientCredentialsAuthorizer,
    ConfidentialAppAuthClient,
    GroupPolicies,
    GroupsAPIError,
    GroupsClient,
    GroupsManager,
)

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
