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

from globus_sdk import (  # noqa: E402
    AccessTokenAuthorizer,
    BatchMembershipActions,
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
