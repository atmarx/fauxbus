"""The /_fauxbus/ control plane, the 501 wall, and failure injection."""

from __future__ import annotations

import json

TOKEN = "t-alice"


def test_index_names_itself(fx):
    status, doc, _ = fx.get("/_fauxbus/")
    assert status == 200
    assert doc["imitates"] == ["groups v2"]
    assert doc["sdk_pin"] == "4.8.1"


def test_state_starts_empty(fx):
    status, doc, _ = fx.get("/_fauxbus/state")
    assert status == 200
    assert doc["groups"] == {}
    assert doc["clock"] == 0
    assert doc["version"] == 0


def test_unimplemented_is_a_loud_501(fx):
    status, doc, _ = fx.get("/v2/endpoint_manager/tasks", token=TOKEN)
    assert status == 501
    assert doc["code"] == "NOT_IMPLEMENTED"
    assert "file an issue" in doc["detail"].lower()

    status, doc, _ = fx.post("/totally/unknown", {"x": 1})
    assert status == 501
    assert doc["code"] == "NOT_IMPLEMENTED"


def test_known_path_wrong_verb_is_405(fx):
    status, doc, _ = fx.delete("/v2/preferences", token=TOKEN)
    assert status == 405
    assert doc["code"] == "METHOD_NOT_ALLOWED"


def test_one_shot_header_injection(fx):
    status, doc, _ = fx.get(
        "/v2/groups/my_groups", token=TOKEN, headers={"X-Fauxbus-Fail": "429"}
    )
    assert status == 429
    assert doc["code"] == "FAUXBUS_INJECTED_FAILURE"

    status, doc, _ = fx.get("/v2/groups/my_groups", token=TOKEN)
    assert status == 200
    assert doc == []


def test_header_injection_ignored_on_control_plane(fx):
    status, _, _ = fx.get("/_fauxbus/state", headers={"X-Fauxbus-Fail": "500"})
    assert status == 200


def test_armed_failures_count_down(fx):
    status, rule, _ = fx.post(
        "/_fauxbus/failures",
        {"method": "GET", "path": "/v2/groups/*", "status": 500, "times": 2},
    )
    assert status == 200
    assert rule["id"] == "fail-1"

    for _ in range(2):
        status, doc, _ = fx.get("/v2/groups/my_groups", token=TOKEN)
        assert status == 500
        assert doc["code"] == "FAUXBUS_INJECTED_FAILURE"

    status, _, _ = fx.get("/v2/groups/my_groups", token=TOKEN)
    assert status == 200

    _, listing, _ = fx.get("/_fauxbus/failures")
    assert listing["failures"] == []


def test_armed_failure_custom_body_and_headers(fx):
    fx.post(
        "/_fauxbus/failures",
        {
            "path": "/v2/groups/my_groups",
            "status": 429,
            "body": {"code": "RATE_LIMITED", "detail": "slow down"},
            "headers": {"Retry-After": "0"},
            "times": 1,
        },
    )
    status, doc, headers = fx.get("/v2/groups/my_groups", token=TOKEN)
    assert status == 429
    assert doc == {"code": "RATE_LIMITED", "detail": "slow down"}
    assert headers.get("Retry-After") == "0"


def test_disarm_clears_persistent_rules(fx):
    fx.post("/_fauxbus/failures", {"path": "/v2/*", "status": 503})
    status, _, _ = fx.get("/v2/groups/my_groups", token=TOKEN)
    assert status == 503

    status, doc, _ = fx.delete("/_fauxbus/failures")
    assert status == 200
    assert doc["cleared"] == 1

    status, _, _ = fx.get("/v2/groups/my_groups", token=TOKEN)
    assert status == 200


def test_reset_disarms_failures_too(fx):
    fx.post("/_fauxbus/failures", {"path": "/v2/*", "status": 503})
    fx.post("/_fauxbus/reset")
    _, listing, _ = fx.get("/_fauxbus/failures")
    assert listing["failures"] == []


def test_tick_advances_logical_clock_only(fx):
    status, doc, _ = fx.post("/_fauxbus/tick", {"seconds": 41})
    assert status == 200
    assert doc == {"clock": 41}

    _, state, _ = fx.get("/_fauxbus/state")
    assert state["clock"] == 41

    fx.post("/_fauxbus/reset")
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["clock"] == 0


def test_seed_state_round_trip_is_byte_identical(fx):
    # Build a non-trivial world through the imitated API...
    _, parent, _ = fx.post("/v2/groups", {"name": "parent", "description": "p"}, token="t-alice")
    fx.post("/v2/groups", {"name": "child", "parent_id": parent["id"]}, token="t-alice")
    fx.put("/v2/preferences", {"allow_add": False}, token="t-bob")
    fx.post("/_fauxbus/tick", {"seconds": 7})

    _, first, _ = fx.get("/_fauxbus/state")
    fx.post("/_fauxbus/reset")
    status, _, _ = fx.post("/_fauxbus/seed", first)
    assert status == 200
    _, second, _ = fx.get("/_fauxbus/state")

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_seed_rejects_garbage(fx):
    status, doc, _ = fx.post("/_fauxbus/seed", {"groups": {"not-a-uuid": {"name": "x"}}})
    assert status == 422
    assert doc["code"] == "VALIDATION_ERROR"
