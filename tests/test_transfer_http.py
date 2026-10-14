"""Transfer task monitoring over the wire: the endpoint_manager routes and their control plane.

Plain HTTP, the way test_groups_http.py drives Groups.  What the real
SDK makes of these answers is test_sdk_conformance.py's job; this file
pins the rules — who may watch, how filters cut, how pages turn, how a
task moves on the logical clock — where a failure points straight at
the rule that broke.
"""

from __future__ import annotations

import json
from urllib.parse import urlencode

from conftest import (
    ALICE,
    CLIENT_ID,
    CLIENT_SECRET,
    GROUPS_SCOPE,
    LANDING,
    LAPSED,
    LAPTOP,
    PINS,
    TRANSFER_SCOPE,
    files,
    make_task,
    transfer_seed,
)

ALICE_TOKEN = "t-alice"  # activity_manager on LANDING (see transfer_seed)
BOB_TOKEN = "t-bob"  # no role anywhere
LIST = "/v0.10/endpoint_manager/task_list"


def task_list(fx, token: str = ALICE_TOKEN, **params):
    return fx.get(f"{LIST}?{urlencode(params)}", token=token)


def landing(fx, token: str = ALICE_TOKEN, **params):
    """task_list as the consumer asks it: into LANDING, inbound only."""
    return task_list(
        fx, token, filter_endpoint=LANDING, filter_endpoint_use="destination", **params
    )


def ids(page) -> list[str]:
    return [t["task_id"] for t in page["DATA"]]


# ------------------------------------------------------------ the documents


def test_task_list_envelope_and_task_document(transfer):
    task = make_task(transfer, status="SUCCEEDED", label="run 7")
    status, page, _ = landing(transfer)
    assert status == 200
    # RECORDED envelope: these four keys and no others.
    assert set(page) == {"DATA", "DATA_TYPE", "has_next_page", "last_key"}
    assert page["DATA_TYPE"] == "task_list"
    assert page["has_next_page"] is False
    (doc,) = page["DATA"]
    assert doc["DATA_TYPE"] == "task"
    assert doc["task_id"] == task["task_id"]
    assert doc["owner_id"] == ALICE
    # owner_string defaults to what the world knows the owner as.
    assert doc["owner_string"] == "alice@example.org"
    assert doc["source_endpoint_id"] == LAPTOP
    assert doc["destination_endpoint_id"] == LANDING
    assert doc["destination_endpoint_display_name"] == "Example Landing"
    # A source nobody seeded has no display name, and says so.
    assert doc["source_endpoint_display_name"] is None
    assert (doc["files"], doc["files_transferred"], doc["bytes_transferred"]) == (2, 2, 20)
    assert doc["status"] == "SUCCEEDED"
    assert doc["label"] == "run 7"
    # The recorded timestamp shape, on the logical clock at zero.
    assert doc["request_time"] == "1970-01-01T00:00:00+00:00"
    assert doc["completion_time"] == "1970-01-01T00:00:00+00:00"
    assert doc["deadline"] == "1970-01-02T00:00:00+00:00"


def test_get_task_and_its_refusals(transfer):
    task = make_task(transfer)
    path = f"/v0.10/endpoint_manager/task/{task['task_id']}"
    status, doc, _ = transfer.get(path, token=ALICE_TOKEN)
    assert (status, doc["task_id"], doc["status"]) == (200, task["task_id"], "ACTIVE")

    status, err, _ = transfer.get(path, token=BOB_TOKEN)
    assert status == 403
    assert err["code"] == "PermissionDenied"

    missing = "00000000-0000-4000-8000-0000000dead0"
    status, err, _ = transfer.get(f"/v0.10/endpoint_manager/task/{missing}", token=ALICE_TOKEN)
    assert (status, err["code"]) == (404, "TaskNotFound")
    status, err, _ = transfer.get("/v0.10/endpoint_manager/task/not-a-uuid", token=ALICE_TOKEN)
    assert (status, err["code"]) == (404, "TaskNotFound")


def test_transfer_errors_speak_transfers_dialect(transfer):
    """RECORDED shape: code, message, request_id, resource — not code/detail."""
    status, err, _ = task_list(transfer, filter_status="SUCCEEDED")
    assert status == 400
    assert set(err) == {"code", "message", "request_id", "resource"}
    assert err["code"] == "BadRequest"
    assert "filter_endpoint is required" in err["message"]
    assert err["resource"] == LIST
    assert len(err["request_id"]) == 9 and err["request_id"].isalnum()
    # Deterministic: the same failure renders the same bytes every time.
    _, again, _ = task_list(transfer, filter_status="SUCCEEDED")
    assert again == err


# --------------------------------------------------------------- who may look


def test_no_role_is_permission_denied(transfer):
    status, err, _ = landing(transfer, token=BOB_TOKEN)
    assert (status, err["code"]) == (403, "PermissionDenied")
    assert "holds no activity_monitor" in err["message"]


def test_a_lapsed_subscription_silences_the_roles(transfer):
    # alice holds activity_monitor on LAPSED, and it does her no good:
    # "if the endpoint or collection is unsubscribed, activity manager
    # and monitor roles become inactive" (DOCUMENTED).
    status, err, _ = task_list(transfer, filter_endpoint=LAPSED)
    assert (status, err["code"]) == (403, "PermissionDenied")
    assert "not subscribed" in err["message"]


def test_an_unknown_collection_is_endpoint_not_found(transfer):
    status, err, _ = task_list(transfer, filter_endpoint=LAPTOP)
    assert (status, err["code"]) == (404, "EndpointNotFound")


def test_without_filter_endpoint_you_see_what_your_roles_reach(transfer):
    mine = make_task(transfer)
    # A task between two collections alice has no live role on.
    make_task(transfer, destination_endpoint_id=LAPSED)
    status, page, _ = task_list(transfer, filter_status="ACTIVE,INACTIVE")
    assert status == 200
    assert ids(page) == [mine["task_id"]]
    # And bob, with no roles at all, sees an empty list, not an error.
    status, page, _ = task_list(transfer, BOB_TOKEN, filter_status="ACTIVE")
    assert (status, page["DATA"]) == (200, [])


def test_a_role_on_the_source_is_enough(transfer):
    # PROVISIONAL rule (see World._task_visible): the reference says
    # source or destination, the SDK docstring says destination.
    outbound = make_task(transfer, source_endpoint_id=LANDING, destination_endpoint_id=LAPTOP)
    status, _, _ = transfer.get(
        f"/v0.10/endpoint_manager/task/{outbound['task_id']}", token=ALICE_TOKEN
    )
    assert status == 200


# ------------------------------------------------------------------ filters


def test_filter_endpoint_use_cuts_by_direction(transfer):
    inbound = make_task(transfer)
    outbound = make_task(transfer, source_endpoint_id=LANDING, destination_endpoint_id=LAPTOP)
    both = {inbound["task_id"], outbound["task_id"]}
    _, page, _ = task_list(transfer, filter_endpoint=LANDING, filter_status="ACTIVE")
    assert set(ids(page)) == both
    _, page, _ = landing(transfer, filter_status="ACTIVE")
    assert ids(page) == [inbound["task_id"]]
    _, page, _ = task_list(
        transfer, filter_endpoint=LANDING, filter_endpoint_use="source", filter_status="ACTIVE"
    )
    assert ids(page) == [outbound["task_id"]]


def test_filter_status_is_a_comma_list(transfer):
    active = make_task(transfer)
    done = make_task(transfer, status="SUCCEEDED")
    failed = make_task(transfer, status="FAILED")
    _, page, _ = landing(transfer, filter_status="SUCCEEDED,FAILED")
    assert set(ids(page)) == {done["task_id"], failed["task_id"]}
    _, page, _ = landing(transfer, filter_status="ACTIVE")
    assert ids(page) == [active["task_id"]]
    status, err, _ = landing(transfer, filter_status="DONE")
    assert (status, err["code"]) == (400, "BadRequest")


def test_filter_completion_time_window(transfer):
    early = make_task(transfer, status="SUCCEEDED")  # completes at 0
    transfer.post("/_fauxbus/tick", {"seconds": 100})
    late = make_task(transfer, status="FAILED")  # completes at 100
    running = make_task(transfer)

    def window(value: str) -> set[str]:
        status, page, _ = landing(transfer, filter_completion_time=value)
        assert status == 200, page
        return set(ids(page))

    # The SDK's own encoding: isoformat(timespec="seconds"), one comma.
    assert window("1970-01-01T00:00:00+00:00,1970-01-01T00:00:50+00:00") == {early["task_id"]}
    # Both edges inclusive (PROVISIONAL).
    assert window("1970-01-01T00:01:40+00:00,1970-01-01T00:01:40+00:00") == {late["task_id"]}
    # 'Z', no zone at all (UTC), and a space for the T: all DOCUMENTED.
    assert window("1970-01-01T00:00:00Z,1970-01-01 00:00:50") == {early["task_id"]}
    # An unencoded '+' from curl decodes as a space; still an offset.
    assert window("1970-01-01T00:01:00 00:00,1970-01-01T00:02:00 00:00") == {late["task_id"]}
    # A blank end includes every running task (DOCUMENTED).
    assert window("1970-01-01T00:01:00+00:00,") == {late["task_id"], running["task_id"]}
    # A blank start does not.
    assert window(",1970-01-01T00:01:00+00:00") == {early["task_id"]}

    for bad in (",", "1970-01-01T00:00:00", "yesterday,today"):
        status, err, _ = landing(transfer, filter_completion_time=bad)
        assert (status, err["code"]) == (400, "BadRequest"), bad


def test_unbuilt_filters_are_a_loud_501_never_ignored(transfer):
    status, err, _ = landing(transfer, filter_owner_id=ALICE)
    assert status == 501
    assert err["code"] == "NOT_IMPLEMENTED"
    assert "filter_owner_id" in err["detail"]


def test_event_list_is_not_built_and_says_so(transfer):
    task = make_task(transfer)
    status, err, _ = transfer.get(
        f"/v0.10/endpoint_manager/task/{task['task_id']}/event_list", token=ALICE_TOKEN
    )
    assert (status, err["code"]) == (501, "NOT_IMPLEMENTED")


# ---------------------------------------------------------- order and paging


def test_order_is_running_newest_first_then_completed_newest_first(transfer):
    a = make_task(transfer, status="SUCCEEDED")  # completed at 0
    transfer.post("/_fauxbus/tick", {"seconds": 10})
    b = make_task(transfer)  # running, requested at 10
    c = make_task(transfer, status="FAILED")  # completed at 10
    transfer.post("/_fauxbus/tick", {"seconds": 10})
    d = make_task(transfer, status="INACTIVE")  # running, requested at 20
    _, page, _ = landing(transfer, filter_status="ACTIVE,INACTIVE,SUCCEEDED,FAILED")
    assert ids(page) == [d["task_id"], b["task_id"], c["task_id"], a["task_id"]]


def test_last_key_pages_through_every_task_exactly_once(transfer):
    made = []
    for _ in range(5):
        made.append(make_task(transfer, status="SUCCEEDED")["task_id"])
        transfer.post("/_fauxbus/tick", {"seconds": 1})
    seen, last_key, pages = [], None, 0
    while True:
        params = {"filter_status": "SUCCEEDED", "limit": 2}
        if last_key:
            params["last_key"] = last_key
        status, page, _ = landing(transfer, **params)
        assert status == 200
        pages += 1
        seen += ids(page)
        last_key = page["last_key"]
        if not page["has_next_page"]:
            break
    assert pages == 3
    assert seen == list(reversed(made))  # newest completion first, no repeats


def test_paging_refusals(transfer):
    status, err, _ = landing(transfer, last_key="whatever")
    assert (status, err["code"]) == (400, "BadRequest")
    status, err, _ = landing(transfer, limit=1001)
    assert (status, err["code"]) == (400, "BadRequest")
    status, page, _ = landing(transfer, limit=1000)
    assert status == 200
    assert page["last_key"] is None  # an empty page has nothing to resume after


def test_successful_transfers_pages_by_marker(transfer):
    task = make_task(transfer, status="SUCCEEDED", files=files(250, size=7))
    path = f"/v0.10/endpoint_manager/task/{task['task_id']}/successful_transfers"
    status, first, _ = transfer.get(path, token=ALICE_TOKEN)
    assert status == 200
    assert (first["DATA_TYPE"], first["marker"], first["next_marker"]) == (
        "successful_transfers",
        0,
        100,
    )
    row = first["DATA"][0]
    assert row == {
        "DATA_TYPE": "successful_transfer",
        "source_path": "/home/alice/run/f0000.dat",
        "destination_path": "/landing/proj-a/f0000.dat",
        "size": 7,
        "checksum": f"{0:064x}",
        "checksum_algorithm": "sha256",
        "dynamic": False,
    }
    _, second, _ = transfer.get(f"{path}?marker=100", token=ALICE_TOKEN)
    _, third, _ = transfer.get(f"{path}?marker=200", token=ALICE_TOKEN)
    assert (len(second["DATA"]), second["next_marker"]) == (100, 200)
    assert (len(third["DATA"]), third["next_marker"]) == (50, None)

    status, err, _ = transfer.get(path, token=BOB_TOKEN)
    assert (status, err["code"]) == (403, "PermissionDenied")


# ----------------------------------------------- the task's life, on the clock


def test_a_duration_finishes_on_tick_with_files_arriving_on_the_way(transfer):
    task = make_task(transfer, files=files(4, size=5), duration=100)
    get = f"/v0.10/endpoint_manager/task/{task['task_id']}"

    transfer.post("/_fauxbus/tick", {"seconds": 50})
    _, doc, _ = transfer.get(get, token=ALICE_TOKEN)
    assert (doc["status"], doc["files_transferred"], doc["bytes_transferred"]) == ("ACTIVE", 2, 10)
    assert doc["is_ok"] is True
    _, rows, _ = transfer.get(f"{get}/successful_transfers", token=ALICE_TOKEN)
    assert [r["destination_path"] for r in rows["DATA"]] == [
        "/landing/proj-a/f0000.dat",
        "/landing/proj-a/f0001.dat",
    ]

    # Tick well past the due time: the task finished when it was due,
    # not when the harness looked.
    transfer.post("/_fauxbus/tick", {"seconds": 500})
    _, doc, _ = transfer.get(get, token=ALICE_TOKEN)
    assert (doc["status"], doc["files_transferred"]) == ("SUCCEEDED", 4)
    assert doc["completion_time"] == "1970-01-01T00:01:40+00:00"
    assert doc["is_ok"] is None


def test_move_pause_resume_fail(transfer):
    task = make_task(transfer, files=files(10), duration=100)
    tid = task["task_id"]
    move = f"/_fauxbus/transfer/tasks/{tid}"

    transfer.post("/_fauxbus/tick", {"seconds": 30})
    status, moved, _ = transfer.post(move, {"status": "INACTIVE"})
    assert (status, moved["status"], moved["files_done"]) == (200, "INACTIVE", 3)
    # Paused means paused: time passes, nothing arrives, nothing finishes.
    transfer.post("/_fauxbus/tick", {"seconds": 1000})
    _, doc, _ = transfer.get(f"/v0.10/endpoint_manager/task/{tid}", token=ALICE_TOKEN)
    assert (doc["status"], doc["files_transferred"], doc["is_ok"]) == ("INACTIVE", 3, False)

    # Resume with fresh time for the remaining seven.
    transfer.post(move, {"status": "ACTIVE", "duration": 70})
    transfer.post("/_fauxbus/tick", {"seconds": 10})
    _, doc, _ = transfer.get(f"/v0.10/endpoint_manager/task/{tid}", token=ALICE_TOKEN)
    assert doc["files_transferred"] == 4

    # Fail it at 60%, the way SPEC's opening paragraph promised.
    status, moved, _ = transfer.post(
        move,
        {"status": "FAILED", "files_succeeded": 6, "faults": 2,
         "fatal_error": {"code": "PERMISSION_DENIED", "description": "quota"}},
    )
    assert status == 200
    _, doc, _ = transfer.get(f"/v0.10/endpoint_manager/task/{tid}", token=ALICE_TOKEN)
    assert (doc["status"], doc["files_transferred"], doc["faults"]) == ("FAILED", 6, 2)
    assert doc["fatal_error"] == {"code": "PERMISSION_DENIED", "description": "quota"}
    assert doc["subtasks_failed"] == 4
    # A FAILED task's partial list is the part that made it (PROVISIONAL).
    _, rows, _ = transfer.get(
        f"/v0.10/endpoint_manager/task/{tid}/successful_transfers", token=ALICE_TOKEN
    )
    assert len(rows["DATA"]) == 6

    # Terminal is final.
    status, err, _ = transfer.post(move, {"status": "SUCCEEDED"})
    assert (status, err["code"]) == (409, "CONFLICT")


def test_a_failed_task_gets_a_fatal_error_even_unasked(transfer):
    task = make_task(transfer, status="FAILED")
    _, doc, _ = transfer.get(f"/v0.10/endpoint_manager/task/{task['task_id']}", token=ALICE_TOKEN)
    assert doc["fatal_error"]["code"] == "FAUXBUS_FAILED"


def test_control_plane_refuses_nonsense(transfer):
    for body in (
        {"owner_id": "nope"},
        {"owner_id": ALICE, "source_endpoint_id": LAPTOP, "destination_endpoint_id": LANDING,
         "status": "SUCCEEDED", "duration": 5},
        {"owner_id": ALICE, "source_endpoint_id": LAPTOP, "destination_endpoint_id": LANDING,
         "colour": "blue"},
    ):
        status, err, _ = transfer.post("/_fauxbus/transfer/tasks", body)
        assert (status, err["code"]) == (422, "VALIDATION_ERROR"), body
    status, _, _ = transfer.post(
        "/_fauxbus/transfer/tasks/00000000-0000-4000-8000-0000000dead0", {"status": "FAILED"}
    )
    assert status == 404


# ------------------------------------------------------------- seed and state


def test_seed_refuses_roles_and_tasks_that_cannot_be(fx):
    status, err, _ = fx.post(
        "/_fauxbus/seed",
        transfer_seed(collections={LANDING: {"roles": {ALICE: "access_manager"}}}),
    )
    assert status == 422
    assert "access_manager" in err["detail"]

    status, err, _ = fx.post(
        "/_fauxbus/seed",
        transfer_seed(
            transfer_tasks={
                "00000000-0000-4000-8000-00000000babe": {
                    "owner_id": ALICE,
                    "source_endpoint_id": LAPTOP,
                    "destination_endpoint_id": LANDING,
                    "status": "SUCCEEDED",
                }
            }
        ),
    )
    assert status == 422
    assert "completion_time" in err["detail"]


def test_transfer_state_round_trips_mid_transfer(transfer):
    """A dump taken while a task is half-way reloads to the same half-way."""
    task = make_task(transfer, files=files(4), duration=100)
    transfer.post("/_fauxbus/tick", {"seconds": 50})
    _, first, _ = transfer.get("/_fauxbus/state")
    transfer.post("/_fauxbus/reset")
    status, _, _ = transfer.post("/_fauxbus/seed", first)
    assert status == 200
    _, second, _ = transfer.get("/_fauxbus/state")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    _, doc, _ = transfer.get(f"/v0.10/endpoint_manager/task/{task['task_id']}", token=ALICE_TOKEN)
    assert doc["files_transferred"] == 2
    # And the next minted id does not collide with the reloaded one.
    assert make_task(transfer)["task_id"] != task["task_id"]


def test_a_hand_seeded_task_id_is_never_overwritten_by_the_mint(fx):
    # The id the counter will produce first, seeded by hand with no
    # counter beside it — the fauxbus-at-0 collision, in Transfer's form.
    first = make_task(fx)["task_id"]
    fx.post("/_fauxbus/reset")
    fx.post(
        "/_fauxbus/seed",
        transfer_seed(
            transfer_tasks={
                first: {
                    "owner_id": ALICE,
                    "source_endpoint_id": LAPTOP,
                    "destination_endpoint_id": LANDING,
                    "label": "seeded by hand",
                }
            }
        ),
    )
    minted = make_task(fx)["task_id"]
    assert minted != first
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["transfer_tasks"][first]["label"] == "seeded by hand"


# ------------------------------------------------- auth posture and failures


def test_strict_mode_refuses_a_groups_token_at_transfer(strict):
    strict.post("/_fauxbus/seed", transfer_seed())

    def token(scope: str) -> str:
        status, doc, _ = strict.form_post(
            "/v2/oauth2/token",
            {"grant_type": "client_credentials", "scope": scope},
            basic=(CLIENT_ID, CLIENT_SECRET),
        )
        assert status == 200, doc
        return doc["access_token"]

    status, err, _ = landing(strict, token(GROUPS_SCOPE))
    assert status == 403
    assert "transfer.api.globus.org" in err["detail"]
    # The client's own identity holds activity_monitor on LANDING.
    status, page, _ = landing(strict, token(TRANSFER_SCOPE))
    assert (status, page["DATA"]) == (200, [])


def test_failure_injection_reaches_transfer_routes(transfer):
    status, body, _ = transfer.get(
        f"{LIST}?{urlencode({'filter_endpoint': LANDING})}",
        token=ALICE_TOKEN,
        headers={"X-Fauxbus-Fail": "503"},
    )
    assert (status, body["code"]) == (503, "FAUXBUS_INJECTED_FAILURE")
    transfer.post(
        "/_fauxbus/failures",
        {"method": "GET", "path": "/v0.10/endpoint_manager/*", "status": 502, "times": 1},
    )
    status, _, _ = landing(transfer)
    assert status == 502
    status, _, _ = landing(transfer)
    assert status == 200


def test_pins_make_owner_strings_readable(fx):
    fx.post("/_fauxbus/seed", transfer_seed(identities=PINS))
    task = make_task(fx, owner_string="alice@globusid.org")
    assert task["owner_string"] == "alice@globusid.org"
