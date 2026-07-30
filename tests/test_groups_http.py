"""The imitated Groups v2 surface, exercised at the wire level."""

from __future__ import annotations

from uuid import UUID

from conftest import ALICE, BOB, CAROL

from fauxbus.ids import identity_id_for_token

A, B, C = "t-alice", "t-bob", "t-carol"


def make_group(fx, name="Route 9800", token=A, **extra):
    status, doc, _ = fx.post("/v2/groups", {"name": name, "description": "d", **extra}, token=token)
    assert status == 200, doc
    return doc


def batch(fx, gid, actions, token=A):
    status, doc, _ = fx.post(f"/v2/groups/{gid}", actions, token=token)
    assert status == 200, doc
    return doc


# ----------------------------------------------------------------- lifecycle


def test_requests_without_auth_fail_in_dev_not_prod(fx):
    status, doc, _ = fx.get("/v2/groups/my_groups")
    assert status == 401
    assert doc["code"] == "UNAUTHORIZED"


def test_create_group_document_shape(pinned):
    doc = make_group(pinned)
    assert set(doc) == {
        "name",
        "description",
        "parent_id",
        "id",
        "group_type",
        "enforce_session",
        "session_limit",
        "session_timeouts",
        "my_memberships",
        "policies",
        "subscription_id",
        "subscription_info",
    }
    UUID(doc["id"])  # a real UUID, like the real service
    assert doc["group_type"] == "regular"
    assert doc["session_limit"] == 28800
    assert doc["policies"] == {
        "group_visibility": "private",
        "group_members_visibility": "managers",
    }
    # The creating identity becomes an active admin.
    assert doc["my_memberships"] == [
        {
            "group_id": doc["id"],
            "identity_id": ALICE,
            "username": "alice@example.org",
            "role": "admin",
            "status": "active",
        }
    ]


def test_create_requires_name(fx):
    status, doc, _ = fx.post("/v2/groups", {"description": "no name"}, token=A)
    assert status == 422
    assert doc["code"] == "VALIDATION_ERROR"


def test_group_ids_are_deterministic_across_runs(fx):
    first = make_group(fx)["id"]
    fx.post("/_fauxbus/reset")
    second = make_group(fx)["id"]
    assert first == second


def test_get_group_includes(pinned):
    parent = make_group(pinned)
    child = make_group(pinned, name="child", parent_id=parent["id"])

    status, doc, _ = pinned.get(
        f"/v2/groups/{parent['id']}?include=memberships,child_ids,policies,allowed_actions",
        token=A,
    )
    assert status == 200
    assert [m["identity_id"] for m in doc["memberships"]] == [ALICE]
    assert doc["child_ids"] == [child["id"]]
    assert set(doc["policies"]) == {
        "is_high_assurance",
        "group_visibility",
        "group_members_visibility",
        "join_requests",
        "signup_fields",
        "authentication_assurance_timeout",
    }
    assert "leave" in doc["allowed_actions"]

    status, doc, _ = pinned.get(f"/v2/groups/{parent['id']}?include=bogus", token=A)
    assert status == 422


def test_non_uuid_group_id_is_validation_error_not_501(fx):
    status, doc, _ = fx.get("/v2/groups/not-a-uuid", token=A)
    assert status == 422
    assert doc["code"] == "VALIDATION_ERROR"


def test_my_groups_entries_are_slim(fx):
    make_group(fx)
    status, listing, _ = fx.get("/v2/groups/my_groups", token=A)
    assert status == 200
    assert isinstance(listing, list) and len(listing) == 1
    entry = listing[0]
    # RECORDED quirk: the list view is slimmer than the single-group view.
    assert "description" not in entry
    assert "subscription_id" not in entry
    assert entry["my_memberships"][0]["role"] == "admin"


def test_my_groups_statuses_filter(pinned):
    gid = make_group(pinned)["id"]
    batch(pinned, gid, {"invite": [{"identity_id": BOB}]})

    _, all_groups, _ = pinned.get("/v2/groups/my_groups", token=B)
    assert len(all_groups) == 1

    _, active_only, _ = pinned.get("/v2/groups/my_groups?statuses=active", token=B)
    assert active_only == []

    _, invited, _ = pinned.get("/v2/groups/my_groups?statuses=invited,pending", token=B)
    assert len(invited) == 1

    status, _, _ = pinned.get("/v2/groups/my_groups?statuses=bogus", token=B)
    assert status == 422


def test_subgroup_requires_admin_on_parent(pinned):
    parent = make_group(pinned)
    status, doc, _ = pinned.post(
        "/v2/groups", {"name": "kid", "parent_id": parent["id"]}, token=B
    )
    # Bob can't even see alice's private parent group: information hiding.
    assert status == 404

    batch(pinned, parent["id"], {"add": [{"identity_id": BOB}]})
    status, doc, _ = pinned.post(
        "/v2/groups", {"name": "kid", "parent_id": parent["id"]}, token=B
    )
    assert status == 403


def test_update_group(fx):
    gid = make_group(fx)["id"]
    status, doc, _ = fx.put(f"/v2/groups/{gid}", {"name": "renamed"}, token=A)
    assert status == 200
    assert doc["name"] == "renamed"


def test_delete_returns_doc_and_cascades_to_subgroups(fx):
    parent = make_group(fx)
    child = make_group(fx, name="child", parent_id=parent["id"])

    status, doc, _ = fx.delete(f"/v2/groups/{parent['id']}", token=A)
    assert status == 200
    assert doc["id"] == parent["id"]  # RECORDED: DELETE answers with the doc

    status, _, _ = fx.get(f"/v2/groups/{child['id']}", token=A)
    assert status == 404


# ---------------------------------------------------------------- visibility


def test_private_groups_are_invisible_to_strangers(pinned):
    gid = make_group(pinned)["id"]
    status, _, _ = pinned.get(f"/v2/groups/{gid}", token=B)
    assert status == 404

    pinned.put(
        f"/v2/groups/{gid}/policies", {"group_visibility": "authenticated"}, token=A
    )
    status, _, _ = pinned.get(f"/v2/groups/{gid}", token=B)
    assert status == 200


def test_policies_get_and_set(pinned):
    gid = make_group(pinned)["id"]

    status, doc, _ = pinned.get(f"/v2/groups/{gid}/policies", token=A)
    assert status == 200
    assert doc["join_requests"] is False

    batch(pinned, gid, {"add": [{"identity_id": BOB}]})
    status, _, _ = pinned.put(f"/v2/groups/{gid}/policies", {"join_requests": True}, token=B)
    assert status == 403

    status, doc, _ = pinned.put(
        f"/v2/groups/{gid}/policies", {"join_requests": True, "signup_fields": ["address1"]}, token=A
    )
    assert status == 200
    assert doc["join_requests"] is True
    assert doc["signup_fields"] == ["address1"]

    status, _, _ = pinned.put(f"/v2/groups/{gid}/policies", {"nope": 1}, token=A)
    assert status == 422


# ------------------------------------------------------- preferences, fields


def test_identity_preferences(fx):
    status, doc, _ = fx.get("/v2/preferences", token=A)
    assert (status, doc) == (200, {"allow_add": True})

    status, doc, _ = fx.put("/v2/preferences", {"allow_add": False}, token=A)
    assert (status, doc) == (200, {"allow_add": False})

    _, doc, _ = fx.get("/v2/preferences", token=A)
    assert doc == {"allow_add": False}


def test_membership_fields_round_trip(fx):
    gid = make_group(fx)["id"]
    status, doc, _ = fx.get(f"/v2/groups/{gid}/membership_fields", token=A)
    assert (status, doc) == (200, {})

    fields = {"institution": "Drexel University"}
    status, doc, _ = fx.put(f"/v2/groups/{gid}/membership_fields", fields, token=A)
    assert (status, doc) == (200, fields)


# -------------------------------------------------------------------- batch


def test_batch_partial_success(pinned):
    gid = make_group(pinned)["id"]
    pinned.put("/v2/preferences", {"allow_add": False}, token=B)

    doc = batch(pinned, gid, {"add": [{"identity_id": BOB}, {"identity_id": CAROL}]})
    assert [m["identity_id"] for m in doc["add"]] == [CAROL]
    assert doc["errors"]["add"] == [
        {
            "identity_id": BOB,
            "code": "NOT_ALLOWED",
            "detail": "identity preferences do not allow being added to groups",
        }
    ]


def test_invite_accept_upgrades_placeholder_username(fx):
    gid = make_group(fx)["id"]
    dave = identity_id_for_token("t-dave")

    doc = batch(fx, gid, {"invite": [{"identity_id": dave, "role": "manager"}]})
    assert doc["invite"][0]["status"] == "invited"
    assert doc["invite"][0]["username"] == f"{dave}@fauxbus.example"  # placeholder

    doc = batch(fx, gid, {"accept": [{"identity_id": dave}]}, token="t-dave")
    membership = doc["accept"][0]
    assert membership["status"] == "active"
    assert membership["role"] == "manager"
    assert membership["username"] == "t-dave@fauxbus.example"  # the invitee showed up


def test_self_verbs_reject_other_identities(pinned):
    gid = make_group(pinned)["id"]
    # Carol gets her own invite so the private group is visible to her at
    # all — information hiding 404s outsiders before any verb runs.
    batch(pinned, gid, {"invite": [{"identity_id": BOB}, {"identity_id": CAROL}]})

    doc = batch(pinned, gid, {"accept": [{"identity_id": BOB}]}, token=C)
    assert doc["errors"]["accept"][0]["code"] == "FORBIDDEN"


def test_join_and_request_join_flows(pinned):
    open_gid = make_group(pinned, name="open")["id"]
    pinned.put(
        f"/v2/groups/{open_gid}/policies", {"group_visibility": "authenticated"}, token=A
    )
    doc = batch(pinned, open_gid, {"join": [{"identity_id": BOB}]}, token=B)
    assert doc["join"][0]["status"] == "active"

    gated_gid = make_group(pinned, name="gated")["id"]
    pinned.put(
        f"/v2/groups/{gated_gid}/policies",
        {"group_visibility": "authenticated", "join_requests": True},
        token=A,
    )
    doc = batch(pinned, gated_gid, {"request_join": [{"identity_id": CAROL}]}, token=C)
    assert doc["request_join"][0]["status"] == "pending"

    doc = batch(pinned, gated_gid, {"approve": [{"identity_id": CAROL}]})
    assert doc["approve"][0]["status"] == "active"

    # And the rejection branch:
    doc = batch(pinned, gated_gid, {"request_join": [{"identity_id": BOB}]}, token=B)
    doc = batch(pinned, gated_gid, {"reject": [{"identity_id": BOB}]})
    assert doc["reject"][0]["status"] == "rejected"


def test_decline_invite(pinned):
    gid = make_group(pinned)["id"]
    batch(pinned, gid, {"invite": [{"identity_id": BOB}]})
    doc = batch(pinned, gid, {"decline": [{"identity_id": BOB}]}, token=B)
    assert doc["decline"][0]["status"] == "declined"


def test_leave_and_the_last_admin_guard(pinned):
    gid = make_group(pinned)["id"]
    batch(pinned, gid, {"add": [{"identity_id": BOB}]})

    doc = batch(pinned, gid, {"leave": [{"identity_id": BOB}]}, token=B)
    assert doc["leave"][0]["status"] == "left"

    doc = batch(pinned, gid, {"leave": [{"identity_id": ALICE}]})
    assert doc["errors"]["leave"][0]["code"] == "LAST_ADMIN"


def test_role_guardrails(pinned):
    gid = make_group(pinned)["id"]
    batch(pinned, gid, {"add": [{"identity_id": BOB, "role": "manager"}, {"identity_id": CAROL}]})

    # A manager may remove a member...
    doc = batch(pinned, gid, {"remove": [{"identity_id": CAROL}]}, token=B)
    assert doc["remove"][0]["status"] == "removed"

    # ...but managers cannot touch admins.
    doc = batch(pinned, gid, {"remove": [{"identity_id": ALICE}]}, token=B)
    assert doc["errors"]["remove"][0]["code"] == "FORBIDDEN"
    doc = batch(pinned, gid, {"change_role": [{"identity_id": ALICE, "role": "member"}]}, token=B)
    assert doc["errors"]["change_role"][0]["code"] == "FORBIDDEN"
    doc = batch(
        pinned, gid, {"add": [{"identity_id": identity_id_for_token("t-eve"), "role": "admin"}]},
        token=B,
    )
    assert doc["errors"]["add"][0]["code"] == "FORBIDDEN"

    # Admins can promote, and members can be re-added after removal.
    doc = batch(pinned, gid, {"change_role": [{"identity_id": BOB, "role": "admin"}]})
    assert doc["change_role"][0]["role"] == "admin"
    doc = batch(pinned, gid, {"add": [{"identity_id": CAROL}]})
    assert doc["add"][0]["status"] == "active"

    # Demoting the only admin is refused; with two admins it works.
    doc = batch(pinned, gid, {"change_role": [{"identity_id": ALICE, "role": "member"}]})
    assert doc["change_role"][0]["role"] == "member"
    doc = batch(pinned, gid, {"change_role": [{"identity_id": BOB, "role": "member"}]}, token=B)
    assert doc["errors"]["change_role"][0]["code"] == "LAST_ADMIN"


def test_duplicate_add_is_already_member(pinned):
    gid = make_group(pinned)["id"]
    batch(pinned, gid, {"add": [{"identity_id": BOB}]})
    doc = batch(pinned, gid, {"add": [{"identity_id": BOB}]})
    assert doc["errors"]["add"][0]["code"] == "ALREADY_MEMBER"


def test_unknown_batch_verb_is_validation_error(fx):
    gid = make_group(fx)["id"]
    status, doc, _ = fx.post(f"/v2/groups/{gid}", {"promote": [{"identity_id": ALICE}]}, token=A)
    assert status == 422


# ------------------------------------------------------------- subscriptions


def test_subscription_lookup_returns_restricted_projection(fx):
    sid = "11111111-0000-4000-8000-000000000001"
    gid = "22222222-0000-4000-8000-000000000002"
    fx.post(
        "/_fauxbus/seed",
        {
            "groups": {
                gid: {
                    "name": "subscribed",
                    "policies": {"group_visibility": "authenticated"},
                    "subscription_id": sid,
                    "subscription_info": {
                        "name": "Charter Coach Co",  # not part of the projection
                        "is_high_assurance": True,
                        "is_baa": False,
                        "connectors": {},
                    },
                }
            }
        },
    )
    status, doc, _ = fx.get(f"/v2/subscription_info/{sid}", token=A)
    assert status == 200
    assert doc == {
        "group_id": gid,
        "subscription_id": sid,
        "subscription_info": {"is_high_assurance": True, "is_baa": False, "connectors": {}},
    }

    status, _, _ = fx.get("/v2/subscription_info/33333333-0000-4000-8000-000000000003", token=A)
    assert status == 404


def test_subscription_admin_verified_set_and_clear(fx):
    gid = make_group(fx)["id"]
    sid = "11111111-0000-4000-8000-000000000001"

    status, _, _ = fx.put(
        f"/v2/groups/{gid}/subscription_admin_verified",
        {"subscription_admin_verified_id": sid},
        token=A,
    )
    assert status == 200
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"][gid]["subscription_admin_verified_id"] == sid

    status, _, _ = fx.put(
        f"/v2/groups/{gid}/subscription_admin_verified",
        {"subscription_admin_verified_id": None},
        token=A,
    )
    assert status == 200
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"][gid]["subscription_admin_verified_id"] is None
