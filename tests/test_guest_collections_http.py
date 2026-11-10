"""Guest collections and their permissions, on the wire (0.6.0).

Three surfaces meet here: each seeded endpoint's GCS Manager under
``/gcs/<endpoint>/api/``, Transfer's ``/endpoint/<id>/access*``, and the
task monitoring the 0.4.0 slice built, now aware that a task can land in
a guest collection hosted on a mapped one.  The control plane's
``/_fauxbus/transfer/submit`` ties them together: a person's transfer
happens only if the permissions say so, against the same Groups world
the Groups API changes.
"""

from __future__ import annotations

import json
import threading

import pytest
from conftest import (
    ALICE,
    BOB,
    CAROL,
    CLIENT_ID,
    CLIENT_SECRET,
    CLOSED,
    DAVE,
    ENDPOINT,
    GATEWAY,
    GCS_DEPENDENT_SCOPE,
    LANDING,
    LAPTOP,
    MANAGERS,
    PLATFORM_TOKEN,
    READ,
    READERS,
    TRANSFER_SCOPE,
    UPLOAD,
    WRITERS,
    Client,
    attempt,
    gcs,
    guest_seed,
    make_guest,
    transfer_seed,
)

from fauxbus.ids import derived_id
from fauxbus.server import make_server

P = PLATFORM_TOKEN


# ------------------------------------------------------------ GCS Manager


def test_the_mapped_collection_says_what_a_guest_needs(guests):
    status, doc, _ = guests.get(f"{gcs()}/collections/{UPLOAD}", token=P)
    assert status == 200
    # RECORDED result envelope; the collection is its first data entry.
    assert (doc["DATA_TYPE"], doc["code"], doc["http_response_code"]) == ("result#1.0.0", "success", 200)
    (mapped,) = doc["data"]
    assert mapped["DATA_TYPE"] == "collection#1.0.0"
    assert mapped["collection_type"] == "mapped"
    assert mapped["storage_gateway_id"] == GATEWAY
    assert mapped["allow_guest_collections"] is True


def test_an_endpoint_nobody_seeded_is_fauxbuss_own_404(guests):
    status, err, _ = guests.get(f"{gcs(LAPTOP)}/collections/{UPLOAD}", token=P)
    assert (status, err["code"]) == (404, "NOT_FOUND")
    assert "gcs_endpoints" in err["detail"]


def test_a_collection_on_another_endpoint_is_not_found_here(guests):
    # LANDING is a plain task-monitoring collection, not this endpoint's.
    status, err, _ = guests.get(f"{gcs()}/collections/{LANDING}", token=P)
    assert (status, err["code"], err["http_response_code"]) == (404, "not_found", 404)


def test_a_mapped_identity_makes_its_credential_and_lists_it(guests):
    status, empty, _ = guests.get(f"{gcs()}/user_credentials?storage_gateway={GATEWAY}", token=P)
    assert (status, empty["data"], empty["has_next_page"]) == (200, [], False)
    status, made, _ = guests.post(
        f"{gcs()}/user_credentials",
        {"DATA_TYPE": "user_credential#1.0.0", "identity_id": CLIENT_ID,
         "connector_id": "145812c8-decc-41f1-83cf-bb2a85a2a70b", "username": "rcsvc",
         "storage_gateway_id": GATEWAY},
        token=P,
    )
    assert status == 201
    assert made["http_response_code"] == 201 and made["detail"] == "created"
    (cred,) = made["data"]
    assert (cred["identity_id"], cred["username"], cred["storage_gateway_id"]) == (
        CLIENT_ID, "rcsvc", GATEWAY,
    )
    _, listed, _ = guests.get(f"{gcs()}/user_credentials?storage_gateway={GATEWAY}", token=P)
    assert [c["id"] for c in listed["data"]] == [cred["id"]]
    # Nobody else's list shows it.
    _, theirs, _ = guests.get(f"{gcs()}/user_credentials", token="t-alice")
    assert theirs["data"] == []


def test_an_identity_the_gateway_does_not_map_gets_no_credential(guests):
    status, err, _ = guests.post(
        f"{gcs()}/user_credentials",
        {"identity_id": CAROL, "username": "carol", "storage_gateway_id": GATEWAY},
        token="t-carol",
    )
    assert (status, err["code"]) == (403, "permission_denied")
    assert "not mapped" in err["message"]


def test_creating_a_guest_makes_the_creator_its_administrator(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    _, doc, _ = guests.get(f"{gcs()}/collections/{guest}", token=P)
    (c,) = doc["data"]
    assert (c["collection_type"], c["mapped_collection_id"], c["collection_base_path"]) == (
        "guest", UPLOAD, "/c-0001/",
    )
    assert (c["identity_id"], c["storage_gateway_id"], c["allow_guest_collections"]) == (
        CLIENT_ID, GATEWAY, False,
    )
    _, state, _ = guests.get("/_fauxbus/state")
    assert state["guest_collections"][guest]["roles"] == {CLIENT_ID: "administrator"}


def test_the_guest_list_filters_by_mapped_collection_and_pages_by_marker(guests):
    made = [make_guest(guests, UPLOAD, f"/c-{i:04d}/") for i in range(3)]
    make_guest(guests, READ, "/c-0000/")
    seen, marker, pages = [], "", 0
    while True:
        q = f"mapped_collection_id={UPLOAD}&filter=guest_collections&page_size=2"
        status, page, _ = guests.get(f"{gcs()}/collections?{q}&marker={marker}", token=P)
        assert status == 200
        pages += 1
        seen += [(c["id"], c["collection_base_path"], c["display_name"], c["identity_id"])
                 for c in page["data"]]
        if not page["has_next_page"]:
            assert page["marker"] == ""
            break
        marker = page["marker"]
    assert pages == 2
    assert sorted(i for i, *_ in seen) == sorted(made)
    assert {(b, who) for _, b, _, who in seen} == {
        (f"/c-{i:04d}/", CLIENT_ID) for i in range(3)
    }


def test_a_mapped_collection_with_guests_switched_off_hosts_none(guests):
    status, err, _ = guests.post(
        f"{gcs()}/collections",
        {"collection_type": "guest", "display_name": "nope", "mapped_collection_id": CLOSED,
         "user_credential_id": "00000000-0000-4000-8000-000000000000",
         "collection_base_path": "/x/"},
        token=P,
    )
    assert (status, err["code"]) == (403, "permission_denied")
    assert "allow_guest_collections" in err["message"]


def test_an_unmapped_identity_may_not_create_a_guest(guests):
    status, err, _ = guests.post(
        f"{gcs()}/collections",
        {"collection_type": "guest", "display_name": "mine", "mapped_collection_id": UPLOAD,
         "user_credential_id": "00000000-0000-4000-8000-000000000000",
         "collection_base_path": "/bob/"},
        token="t-bob",
    )
    assert (status, err["code"]) == (403, "permission_denied")
    assert "not mapped" in err["message"]


def test_a_guest_can_be_renamed_but_never_moved(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    url = f"{gcs()}/collections/{guest}"
    status, doc, _ = guests.patch(url, {"collection_type": "guest", "display_name": "Renamed"}, token=P)
    assert status == 200 and doc["data"][0]["display_name"] == "Renamed"
    # Sending the base path unchanged is fine; changing it is not.
    status, _, _ = guests.patch(url, {"collection_base_path": "/c-0001/"}, token=P)
    assert status == 200
    status, err, _ = guests.patch(url, {"collection_base_path": "/c-0002/"}, token=P)
    assert (status, err["code"]) == (400, "bad_request")
    assert "collection_base_path may not be changed" in err["message"]
    _, doc, _ = guests.get(url, token=P)
    assert doc["data"][0]["collection_base_path"] == "/c-0001/"
    # Only an administrator renames.
    status, err, _ = guests.patch(url, {"display_name": "Mine now"}, token="t-alice")
    assert (status, err["code"]) == (403, "permission_denied")


def test_deleting_a_guest_takes_its_permissions_with_it(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    status, doc, _ = guests.delete(f"{gcs()}/collections/{guest}", token=P)
    assert (status, doc["data"]) == (200, [])
    assert guests.get(f"{gcs()}/collections/{guest}", token=P)[0] == 404
    status, err, _ = guests.get(f"/v0.10/endpoint/{guest}/access_list", token=P)
    assert (status, err["code"]) == (404, "EndpointNotFound")


def test_unbuilt_gcs_surface_is_a_loud_501(guests):
    for path in (f"{gcs()}/info", f"{gcs()}/collections?filter=managed_by_me",
                 f"{gcs()}/collections?include=private_policies"):
        status, err, _ = guests.get(path, token=P)
        assert (status, err["code"]) == (501, "NOT_IMPLEMENTED"), path


# ------------------------------------------------- Transfer permissions


def test_the_access_list_shows_role_rules_that_cannot_be_deleted(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    status, acl, _ = guests.get(f"/v0.10/endpoint/{guest}/access_list", token=P)
    assert status == 200
    assert (acl["DATA_TYPE"], acl["endpoint"]) == ("access_list", guest)
    role_rule, group_rule = acl["DATA"]
    role_id = derived_id("role", guest, CLIENT_ID, "administrator")
    assert role_rule == {
        "DATA_TYPE": "access", "create_time": None, "expiration_date": None, "id": None,
        "path": "/", "permissions": "rw", "principal": CLIENT_ID, "principal_type": "identity",
        "role_id": role_id, "role_type": "administrator",
    }
    assert (group_rule["principal_type"], group_rule["principal"], group_rule["permissions"]) == (
        "group", WRITERS, "rw",
    )
    assert group_rule["role_id"] is None and group_rule["id"] is not None
    # Undeletable: it has no id, and its role id names no permission.
    status, err, _ = guests.delete(f"/v0.10/endpoint/{guest}/access/{role_id}", token=P)
    assert (status, err["code"]) == (404, "AccessRuleNotFound")
    assert len(guests.get(f"/v0.10/endpoint/{guest}/access_list", token=P)[1]["DATA"]) == 2


def test_adding_and_deleting_a_permission_speak_transfers_documents(guests):
    guest = make_guest(guests, READ, "/c-0001/")
    status, made, _ = guests.post(
        f"/v0.10/endpoint/{guest}/access",
        {"DATA_TYPE": "access", "principal_type": "group", "principal": READERS,
         "path": "/", "permissions": "r"},
        token=P,
    )
    assert status == 201
    assert (made["DATA_TYPE"], made["code"], made["resource"]) == (
        "access_create_result", "Created", f"/endpoint/{guest}/access",
    )
    rule_id = made["access_id"]
    status, gone, _ = guests.delete(f"/v0.10/endpoint/{guest}/access/{rule_id}", token=P)
    assert status == 200
    assert (gone["DATA_TYPE"], gone["code"]) == ("result", "Deleted")
    assert gone["message"] == f"Access rule '{rule_id}' deleted successfully"
    status, err, _ = guests.delete(f"/v0.10/endpoint/{guest}/access/{rule_id}", token=P)
    assert (status, err["code"]) == (404, "AccessRuleNotFound")


def test_the_same_principal_and_path_twice_is_exists(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    status, err, _ = guests.post(
        f"/v0.10/endpoint/{guest}/access",
        {"DATA_TYPE": "access", "principal_type": "group", "principal": WRITERS,
         "path": "/", "permissions": "r"},
        token=P,
    )
    assert (status, err["code"]) == (409, "Exists")
    assert err["resource"] == f"/v0.10/endpoint/{guest}/access"


def test_a_group_nobody_has_heard_of_is_accepted_as_globus_accepts_it(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    status, _, _ = guests.post(
        f"/v0.10/endpoint/{guest}/access",
        {"principal_type": "group", "principal": "00000000-0000-4000-8000-0000000dead0",
         "path": "/", "permissions": "rw"},
        token=P,
    )
    assert status == 201


def test_the_thousand_and_first_permission_is_limit_exceeded(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    _, state, _ = guests.get("/_fauxbus/state")
    state["guest_collections"][guest]["permissions"] = {
        derived_id("planted", str(i)): {
            "principal_type": "identity", "principal": derived_id("person", str(i)),
            "path": "/", "permissions": "r", "create_time": 0,
        }
        for i in range(999)
    }
    assert guests.post("/_fauxbus/seed", state)[0] == 200

    def add(principal: str) -> tuple[int, dict]:
        status, body, _ = guests.post(
            f"/v0.10/endpoint/{guest}/access",
            {"principal_type": "group", "principal": principal, "path": "/", "permissions": "r"},
            token=P,
        )
        return status, body

    assert add(READERS)[0] == 201  # the thousandth
    status, err = add(WRITERS)
    assert (status, err["code"]) == (409, "LimitExceeded")


@pytest.mark.parametrize("path", ["c-0001/", "/c-0001", "/a/../b/", "/a/./b/", "/" + "x" * 2000 + "/"])
def test_a_path_that_does_not_begin_and_end_with_a_slash_is_invalid(guests, path):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    status, err, _ = guests.post(
        f"/v0.10/endpoint/{guest}/access",
        {"principal_type": "group", "principal": WRITERS, "path": path, "permissions": "rw"},
        token=P,
    )
    assert (status, err["code"]) == (400, "InvalidPath")


def test_permissions_live_only_on_guest_collections(guests):
    status, err, _ = guests.get(f"/v0.10/endpoint/{UPLOAD}/access_list", token=P)
    assert (status, err["code"]) == (409, "NotSupported")
    status, err, _ = guests.get(f"/v0.10/endpoint/{LAPTOP}/access_list", token=P)
    assert (status, err["code"]) == (404, "EndpointNotFound")


def test_only_an_access_manager_or_administrator_manages_permissions(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    status, err, _ = guests.get(f"/v0.10/endpoint/{guest}/access_list", token="t-alice")
    assert (status, err["code"]) == (403, "PermissionDenied")
    # access_manager on the *mapped* collection reaches the guest, and
    # shows up as a role rule of its own.
    _, state, _ = guests.get("/_fauxbus/state")
    state["mapped_collections"][UPLOAD]["roles"][ALICE] = "access_manager"
    guests.post("/_fauxbus/seed", state)
    status, acl, _ = guests.get(f"/v0.10/endpoint/{guest}/access_list", token="t-alice")
    assert status == 200
    assert {(r["principal"], r["role_type"]) for r in acl["DATA"] if r["role_id"]} == {
        (CLIENT_ID, "administrator"), (ALICE, "access_manager"),
    }


def test_unbuilt_permission_calls_are_501_not_405(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    rule = guests.get(f"/v0.10/endpoint/{guest}/access_list", token=P)[1]["DATA"][1]["id"]
    assert guests.get(f"/v0.10/endpoint/{guest}/access/{rule}", token=P)[0] == 501
    assert guests.put(f"/v0.10/endpoint/{guest}/access/{rule}", {"permissions": "r"}, token=P)[0] == 501
    status, _, _ = guests.post(
        f"/v0.10/endpoint/{guest}/access",
        {"principal_type": "all_authenticated_users", "principal": "", "path": "/",
         "permissions": "r"},
        token=P,
    )
    assert status == 501


# -------------------------------------------- the permission is the gate


@pytest.fixture
def workspace(guests):
    """One workspace: an upload guest ruled rw for writers, a read guest ruled r for readers."""
    upload = make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS, permissions="rw")
    read = make_guest(guests, READ, "/c-0001/", group=READERS, permissions="r")
    return guests, upload, read


def test_a_writer_moves_files_in(workspace):
    fx, upload, _ = workspace
    status, task = attempt(fx, ALICE, LAPTOP, upload)
    assert status == 200, task
    assert (task["status"], task["destination_endpoint_id"]) == ("SUCCEEDED", upload)


def test_a_reader_moves_files_out_and_may_not_write(workspace):
    fx, upload, read = workspace
    status, task = attempt(fx, BOB, read, LAPTOP, ("/results/r.csv", "/home/bob/r.csv"))
    assert status == 200, task
    status, err = attempt(fx, BOB, LAPTOP, read)
    assert (status, err["code"]) == (403, "PermissionDenied")
    assert "may not write" in err["message"] and "(it holds r)" in err["message"]
    status, err = attempt(fx, BOB, LAPTOP, upload)
    assert status == 403


def test_a_writer_reads_the_read_side_because_writers_are_readers(workspace):
    fx, _, read = workspace
    assert attempt(fx, ALICE, read, LAPTOP, ("/x.dat", "/home/alice/x.dat"))[0] == 200


def test_an_outsider_is_refused_both_ways_and_no_task_appears(workspace):
    fx, upload, read = workspace
    for source, destination in ((LAPTOP, upload), (read, LAPTOP), (upload, LAPTOP)):
        status, err = attempt(fx, CAROL, source, destination)
        assert (status, err["code"]) == (403, "PermissionDenied")
        assert err["resource"] == "/_fauxbus/transfer/submit"
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["transfer_tasks"] == {}


def test_a_manager_passes_through_a_subgroup_of_the_ruled_group(workspace):
    fx, upload, read = workspace
    assert attempt(fx, DAVE, LAPTOP, upload)[0] == 200
    assert attempt(fx, DAVE, read, LAPTOP)[0] == 200


def test_removing_a_writer_from_the_group_closes_the_door(workspace):
    fx, upload, _ = workspace
    assert attempt(fx, ALICE, LAPTOP, upload)[0] == 200
    status, doc, _ = fx.post(f"/v2/groups/{WRITERS}", {"remove": [{"identity_id": ALICE}]}, token=P)
    assert status == 200 and doc["remove"][0]["status"] == "removed"
    status, err = attempt(fx, ALICE, LAPTOP, upload)
    assert (status, err["code"]) == (403, "PermissionDenied")


def test_removing_the_permission_closes_the_door_too(workspace):
    fx, upload, _ = workspace
    acl = fx.get(f"/v0.10/endpoint/{upload}/access_list", token=P)[1]["DATA"]
    (rule,) = [r["id"] for r in acl if r["id"]]
    fx.delete(f"/v0.10/endpoint/{upload}/access/{rule}", token=P)
    assert attempt(fx, ALICE, LAPTOP, upload)[0] == 403


def test_a_permission_on_a_subdirectory_covers_only_that_subdirectory(guests):
    guest = make_guest(guests, UPLOAD, "/c-0001/")
    guests.post(f"/v0.10/endpoint/{guest}/access",
                {"principal_type": "identity", "principal": CAROL, "path": "/drop/",
                 "permissions": "rw"}, token=P)
    assert attempt(guests, CAROL, LAPTOP, guest, ("/a", "/drop/a.dat"))[0] == 200
    assert attempt(guests, CAROL, LAPTOP, guest, ("/a", "/elsewhere/a.dat"))[0] == 403


def test_a_mapped_collection_lets_through_only_what_its_gateway_maps(guests):
    assert attempt(guests, CLIENT_ID, LAPTOP, UPLOAD)[0] == 200
    status, err = attempt(guests, ALICE, LAPTOP, UPLOAD)
    assert status == 403 and "does not map" in err["message"]


def test_switching_guests_off_on_the_mapped_collection_closes_every_guest(workspace):
    fx, upload, _ = workspace
    _, state, _ = fx.get("/_fauxbus/state")
    state["mapped_collections"][UPLOAD]["allow_guest_collections"] = False
    fx.post("/_fauxbus/seed", state)
    status, err = attempt(fx, ALICE, LAPTOP, upload)
    assert status == 403 and "allow_guest_collections" in err["message"]


# ------------------------------------------- monitoring through the host


def test_the_mapped_collection_filter_finds_tasks_into_and_out_of_its_guests(workspace):
    fx, upload, read = workspace
    _, inbound = attempt(fx, ALICE, LAPTOP, upload, ("/home/alice/a.dat", "/run1/a.dat"))
    _, outbound = attempt(fx, BOB, read, LAPTOP, ("/run1/r.csv", "/home/bob/r.csv"))

    def listed(endpoint: str, use: str | None = None) -> list[str]:
        q = f"filter_endpoint={endpoint}&filter_status=SUCCEEDED"
        if use:
            q += f"&filter_endpoint_use={use}"
        status, page, _ = fx.get(f"/v0.10/endpoint_manager/task_list?{q}", token=P)
        assert status == 200, page
        return [t["task_id"] for t in page["DATA"]]

    assert listed(UPLOAD) == [inbound["task_id"]]
    assert listed(UPLOAD, "destination") == [inbound["task_id"]]
    assert listed(UPLOAD, "source") == []
    assert listed(READ, "source") == [outbound["task_id"]]
    assert listed(READ, "destination") == []
    # The guest's own id works too: the mapped role reaches it.
    assert listed(upload) == [inbound["task_id"]]


def test_a_guest_task_names_its_guest_and_its_host(workspace):
    fx, upload, read = workspace
    _, task = attempt(fx, ALICE, LAPTOP, upload, ("/home/alice/a.dat", "/run1/a.dat"))
    status, doc, _ = fx.get(f"/v0.10/endpoint_manager/task/{task['task_id']}", token=P)
    assert status == 200
    assert doc["destination_endpoint_id"] == upload
    assert doc["destination_endpoint_display_name"] == "ws /c-0001/"
    assert doc["destination_host_endpoint_id"] == UPLOAD
    assert doc["destination_mapped_collection_id"] == UPLOAD
    assert doc["destination_mapped_collection_display_name"] == "Upload"
    assert doc["destination_host_endpoint"] == f"Upload#{UPLOAD}"
    assert doc["destination_host_path"] == "/c-0001/"
    # The laptop is nobody's guest: its host fields stay null.
    assert doc["source_host_endpoint_id"] is None and doc["source_host_path"] is None

    _, out = attempt(fx, BOB, read, LAPTOP, ("/run1/r.csv", "/home/bob/r.csv"))
    _, doc, _ = fx.get(f"/v0.10/endpoint_manager/task/{out['task_id']}", token=P)
    assert (doc["source_endpoint_id"], doc["source_host_endpoint_id"],
            doc["source_mapped_collection_id"], doc["source_host_path"]) == (
        read, READ, READ, "/c-0001/",
    )


def test_file_paths_are_relative_to_the_guest_not_the_mapped_root(workspace):
    fx, upload, _ = workspace
    _, task = attempt(fx, ALICE, LAPTOP, upload, ("/home/alice/a.dat", "/run1/a.dat"))
    status, page, _ = fx.get(
        f"/v0.10/endpoint_manager/task/{task['task_id']}/successful_transfers", token=P
    )
    assert status == 200
    assert [(r["source_path"], r["destination_path"]) for r in page["DATA"]] == [
        ("/home/alice/a.dat", "/run1/a.dat"),
    ]


def test_host_fields_are_shown_only_to_whom_globus_shows_them(workspace):
    fx, upload, _ = workspace
    _, task = attempt(fx, ALICE, LAPTOP, upload)
    _, state, _ = fx.get("/_fauxbus/state")
    # carol may watch the guest itself, and nothing on the mapped one.
    state["guest_collections"][upload]["roles"][CAROL] = "activity_monitor"
    state["mapped_collections"][UPLOAD]["public"] = False
    fx.post("/_fauxbus/seed", state)
    status, doc, _ = fx.get(f"/v0.10/endpoint_manager/task/{task['task_id']}", token="t-carol")
    assert status == 200
    assert doc["destination_endpoint_id"] == upload
    assert doc["destination_host_endpoint_id"] is None
    assert doc["destination_mapped_collection_id"] is None
    assert doc["destination_host_path"] is None
    # A public mapped collection lends its name, still not the host path.
    state["mapped_collections"][UPLOAD]["public"] = True
    fx.post("/_fauxbus/seed", state)
    _, doc, _ = fx.get(f"/v0.10/endpoint_manager/task/{task['task_id']}", token="t-carol")
    assert doc["destination_host_endpoint_id"] == UPLOAD
    assert doc["destination_host_path"] is None


# ------------------------------------------------------------ seed & state


def test_guest_world_round_trips_byte_identically(workspace):
    fx, upload, _ = workspace
    attempt(fx, ALICE, LAPTOP, upload)
    _, first, _ = fx.get("/_fauxbus/state")
    assert first["guest_collections"][upload]["permissions"]
    fx.post("/_fauxbus/reset")
    assert fx.post("/_fauxbus/seed", first)[0] == 200
    _, second, _ = fx.get("/_fauxbus/state")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_a_planted_permission_is_one_a_consumer_can_revoke(fx):
    guest = "00000000-0000-4000-8000-00000000c0c0"
    rule = "00000000-0000-4000-8000-0000000000e1"
    doc = guest_seed(guest_collections={
        guest: {
            "mapped_collection_id": UPLOAD, "display_name": "planted", "identity_id": CLIENT_ID,
            "collection_base_path": "/c-0009/", "roles": {CLIENT_ID: "administrator"},
            "permissions": {rule: {"principal_type": "group", "principal": WRITERS,
                                   "path": "/", "permissions": "rw"}},
        }
    })
    assert fx.post("/_fauxbus/seed", doc)[0] == 200
    assert attempt(fx, ALICE, LAPTOP, guest)[0] == 200
    assert fx.delete(f"/v0.10/endpoint/{guest}/access/{rule}", token=P)[0] == 200
    assert attempt(fx, ALICE, LAPTOP, guest)[0] == 403


@pytest.mark.parametrize(
    "section, patch, typo",
    [
        ("mapped_collections", {UPLOAD: {"endpoint_id": ENDPOINT, "storage_gateway_id": GATEWAY,
                                         "alow_guest_collections": True}}, "alow_guest_collections"),
        ("gcs_endpoints", {ENDPOINT: {"storage_gateway": {}}}, "storage_gateway'"),
        ("user_credentials", {"00000000-0000-4000-8000-0000000000c1": {
            "storage_gateway_id": GATEWAY, "identity_id": CLIENT_ID, "username": "x", "uid": 5}},
         "'uid'"),
    ],
)
def test_a_seed_record_with_a_field_nobody_knows_is_refused_by_name(fx, section, patch, typo):
    doc = guest_seed()
    doc[section] = {**doc.get(section, {}), **patch}
    status, err, _ = fx.post("/_fauxbus/seed", doc)
    assert (status, err["code"]) == (422, "VALIDATION_ERROR")
    assert typo in err["detail"]


def test_a_seed_may_not_give_two_collections_one_id(fx):
    doc = guest_seed(**{"collections": transfer_seed()["collections"]})
    doc["collections"][UPLOAD] = {"display_name": "dup", "subscription_id": None}
    status, err, _ = fx.post("/_fauxbus/seed", doc)
    assert status == 422 and "reuses a collection id" in err["detail"]


def test_plain_collections_still_refuse_access_manager(fx):
    # The task-monitoring slice's rule holds: access_manager means
    # something on a guest-capable collection and nothing on a plain one.
    status, err, _ = fx.post(
        "/_fauxbus/seed", transfer_seed(collections={LANDING: {"roles": {ALICE: "access_manager"}}})
    )
    assert status == 422 and "access_manager" in err["detail"]


# --------------------------------------------- strict tokens, GCS's own


@pytest.fixture
def strict_guests():
    server = make_server("127.0.0.1", 0, require_issued_tokens=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    client = Client(f"http://{host}:{port}")
    assert client.post("/_fauxbus/seed", guest_seed())[0] == 200
    yield client
    server.shutdown()
    server.server_close()


def _token(fx: Client, scope: str) -> tuple[int, dict]:
    status, doc, _ = fx.form_post(
        "/v2/oauth2/token", {"grant_type": "client_credentials", "scope": scope},
        basic=(CLIENT_ID, CLIENT_SECRET),
    )
    return status, doc


def test_a_gcs_token_is_minted_for_the_endpoint_dependency_and_all(strict_guests):
    status, doc = _token(strict_guests, GCS_DEPENDENT_SCOPE)
    assert status == 200, doc
    assert (doc["resource_server"], doc["scope"]) == (ENDPOINT, GCS_DEPENDENT_SCOPE)
    status, _, _ = strict_guests.get(f"{gcs()}/collections/{UPLOAD}", token=doc["access_token"])
    assert status == 200


def test_a_transfer_token_is_no_good_at_a_gcs_manager(strict_guests):
    _, doc = _token(strict_guests, TRANSFER_SCOPE)
    status, err, _ = strict_guests.get(f"{gcs()}/collections/{UPLOAD}", token=doc["access_token"])
    assert (status, err["code"]) == (403, "FORBIDDEN")
    assert ENDPOINT in err["detail"]


def test_a_dependent_scope_anywhere_else_is_still_the_loud_501(strict_guests):
    status, doc = _token(
        strict_guests,
        f"{TRANSFER_SCOPE}[https://auth.globus.org/scopes/{UPLOAD}/data_access]",
    )
    assert status == 501, doc


def test_the_guest_world_is_on_the_mapped_collections_side_of_the_reset(guests):
    make_guest(guests, UPLOAD, "/c-0001/", group=WRITERS)
    guests.post("/_fauxbus/reset", {"to": "empty"})
    _, state, _ = guests.get("/_fauxbus/state")
    assert all(state[k] == {} for k in (
        "gcs_endpoints", "mapped_collections", "guest_collections", "user_credentials",
    ))


def test_group_membership_is_counted_from_the_same_groups_world(workspace):
    # dave is in MANAGERS alone; READERS ⊃ WRITERS ⊃ MANAGERS makes him
    # a reader and a writer for a permission's purposes, while the Groups
    # API still shows him one membership.
    fx, _, _ = workspace
    _, mine, _ = fx.get("/v2/groups/my_groups", token="t-dave")
    assert [g["id"] for g in mine] == [MANAGERS]
