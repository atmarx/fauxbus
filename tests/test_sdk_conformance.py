"""The conformance seed: real globus-sdk client code against Fauxbus.

This file is the embryo of the two-backend conformance tether from
SPEC.md.  Today it runs against Fauxbus on every CI run; the env-gated
real-service backend arrives with the first recording session.  Nothing
in here monkeypatches anything — the SDK is pointed at Fauxbus by
base_url alone, which is the whole point.
"""

from __future__ import annotations

import pytest

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


def sdk_client(base_url: str, token: str = "t-alice") -> GroupsClient:
    return GroupsClient(base_url=base_url, authorizer=AccessTokenAuthorizer(token))


@pytest.fixture
def client(fx) -> GroupsClient:
    return sdk_client(fx.base_url)


def test_create_get_update_delete_round_trip(client):
    created = client.create_group({"name": "Rough Riders", "description": "no stairs"})
    gid = created["id"]
    assert created["my_memberships"][0]["role"] == "admin"

    fetched = client.get_group(gid, include=["memberships", "child_ids"])
    assert fetched["name"] == "Rough Riders"
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
