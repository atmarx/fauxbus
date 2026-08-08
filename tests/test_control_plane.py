"""The /_fauxbus/ control plane, the 501 wall, and failure injection."""

from __future__ import annotations

import json

import pytest
from conftest import BOB, PINS

TOKEN = "t-alice"


def test_index_names_itself(fx):
    status, doc, _ = fx.get("/_fauxbus/")
    assert status == 200
    assert doc["imitates"] == ["groups v2"]
    assert doc["sdk_pin"] == "4.8.1"


def test_index_reports_the_version_it_was_actually_built_as(fx):
    """The wire answer must match the package pip resolved.

    This is the test that was missing.  `__version__` used to be a
    second, hand-maintained copy of the version in pyproject.toml, and
    nothing compared them — so v0.1.0 and v0.1.1 both shipped answering
    "0.1.0.dev0" here.  The test right above this one is called
    "names itself" and checked everything about itself except which one
    it is.

    Why this endpoint and this comparison: a consumer chasing a
    conformance mismatch asks GET /_fauxbus/ what it is talking to, and
    a stale answer sends them to the wrong changelog.  Comparing against
    importlib.metadata means we check what pip *installed*, not what the
    source tree says about itself — the two agreeing is the whole claim.

    If this fails in a working tree right after a version bump, the
    install is stale, not the code: re-run `pip install -e ".[dev]"`.
    That is a real finding, not test noise — it means you have been
    running your tests against a different build than you think.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("fauxbus")
    except PackageNotFoundError:  # pragma: no cover — source-tree-only run
        pytest.skip("fauxbus is not installed; nothing to compare the wire answer to")

    _, doc, _ = fx.get("/_fauxbus/")
    # Say the remedy in the failure, not just in this docstring — pytest
    # shows the assertion, and a bare `'0.2.0.dev0' == '0.1.2'` reads
    # like a broken test rather than a stale venv.  Same principle as
    # the empty-token guard in .woodpecker.yml: name the real cause.
    assert doc["fauxbus"] == installed, (
        f"the running server reports {doc['fauxbus']!r} but pip installed {installed!r}. "
        "If you just bumped __version__, your install is stale — re-run "
        'pip install -e ".[dev]". If you did not, the build is no longer '
        "reading src/fauxbus/__init__.py and the published artifact will "
        "misreport its own version, which is exactly what v0.1.0 and v0.1.1 did."
    )


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


# ------------------------------------------------------- canonical seed

def _pinned_world(fx) -> dict:
    """Seed identities, create one group via the API, return the dump."""
    fx.post("/_fauxbus/seed", {"identities": PINS})
    fx.post("/v2/groups", {"name": "Route 9800"}, token=TOKEN)
    _, state, _ = fx.get("/_fauxbus/state")
    return state


def test_reset_restores_the_canonical_seed(fx):
    # The staged-fixture workflow: canonical roster pinned once, tests
    # mutate freely as throw-aways, reset comes home — not to empty.
    canonical = _pinned_world(fx)
    status, doc, _ = fx.post("/_fauxbus/seed?canonical=true", canonical)
    assert (status, doc) == (200, {"ok": True, "groups": 1, "canonical": True})

    gid = next(iter(canonical["groups"]))
    fx.post(f"/v2/groups/{gid}", {"add": [{"identity_id": BOB}]}, token=TOKEN)
    _, mutated, _ = fx.get("/_fauxbus/state")
    assert mutated != canonical

    status, doc, _ = fx.post("/_fauxbus/reset")
    assert (status, doc["world"]) == (200, "seed")
    _, restored, _ = fx.get("/_fauxbus/state")
    assert json.dumps(restored, sort_keys=True) == json.dumps(canonical, sort_keys=True)


def test_reset_to_empty_opts_out_but_keeps_the_canonical(fx):
    fx.post("/_fauxbus/seed?canonical=true", _pinned_world(fx))

    status, doc, _ = fx.post("/_fauxbus/reset", {"to": "empty"})
    assert (status, doc) == (200, {"ok": True, "world": "empty", "groups": 0})
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"] == {}

    # ...but the pin survives: the next plain reset still comes home
    fx.post("/_fauxbus/reset")
    _, state, _ = fx.get("/_fauxbus/state")
    assert len(state["groups"]) == 1


def test_forgetting_the_seed_makes_reset_mean_empty(fx):
    fx.post("/_fauxbus/seed?canonical=true", _pinned_world(fx))

    status, doc, _ = fx.delete("/_fauxbus/seed")
    assert (status, doc) == (200, {"cleared": True})
    fx.post("/_fauxbus/reset")
    _, state, _ = fx.get("/_fauxbus/state")
    assert state["groups"] == {}


def test_reset_without_canonical_reports_empty(fx):
    status, doc, _ = fx.post("/_fauxbus/reset")
    assert (status, doc) == (200, {"ok": True, "world": "empty", "groups": 0})


def test_reset_rejects_unknown_targets(fx):
    status, doc, _ = fx.post("/_fauxbus/reset", {"to": "narnia"})
    assert status == 400
    assert doc["code"] == "BAD_REQUEST"
