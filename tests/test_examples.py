"""The shipped examples must stay true — documentation that runs.

examples/seed.json is what we tell first consumers to copy.  If the
world schema ever drifts, these tests fail before the example lies.
"""

from __future__ import annotations

import json
from pathlib import Path

EXAMPLES = Path(__file__).parent.parent / "examples"


def example_seed() -> dict:
    return json.loads((EXAMPLES / "seed.json").read_text())


def test_example_seed_loads(fx):
    status, doc, _ = fx.post("/_fauxbus/seed", example_seed())
    assert status == 200
    assert doc["groups"] == 1


def test_example_seed_is_byte_identical_to_its_own_dump(fx):
    # The SPEC round-trip invariant, applied to the shipped file: the
    # example IS a state dump (indent=2, sorted keys, trailing newline),
    # not a hand-written approximation that merely happens to load.
    fx.post("/_fauxbus/seed", example_seed())
    _, state, _ = fx.get("/_fauxbus/state")
    assert json.dumps(state, indent=2, sort_keys=True) + "\n" == (
        EXAMPLES / "seed.json"
    ).read_text()


def test_example_seed_as_canonical_comes_home_on_reset(fx):
    # The workflow the container is built for: the mounted seed is the
    # fixed point.  Pin it, mutate the world as a throw-away, reset —
    # and the state is byte-identical to the shipped file again.
    doc = example_seed()
    fx.post("/_fauxbus/seed?canonical=true", doc)

    (gid,) = doc["groups"]
    bob = "00000000-0000-4000-8000-00000000000b"
    fx.post(f"/v2/groups/{gid}", {"change_role": [{"identity_id": bob, "role": "manager"}]},
            token="t-alice")
    _, mutated, _ = fx.get("/_fauxbus/state")
    assert mutated["groups"][gid]["memberships"][bob]["role"] == "manager"

    fx.post("/_fauxbus/reset")
    _, restored, _ = fx.get("/_fauxbus/state")
    assert json.dumps(restored, indent=2, sort_keys=True) + "\n" == (
        EXAMPLES / "seed.json"
    ).read_text()


def test_example_seed_pins_work_on_the_wire(fx):
    fx.post("/_fauxbus/seed", example_seed())
    status, groups, _ = fx.get("/v2/groups/my_groups", token="t-alice")
    assert status == 200
    assert [g["name"] for g in groups] == ["Night Owl Service"]

    # bob rides too — active member, not just present in the file
    _, groups, _ = fx.get("/v2/groups/my_groups", token="t-bob")
    assert [m["role"] for g in groups for m in g["my_memberships"]] == ["member"]


def test_example_seed_lets_its_dispatcher_watch_the_landing(fx):
    # The poller pattern the Transfer slice exists for, from the shipped
    # file alone: the dispatcher client takes a Transfer token with its
    # own secret and reads the landing collection as an activity monitor.
    doc = example_seed()
    fx.post("/_fauxbus/seed", doc)
    dispatcher = "00000000-0000-4000-8000-0000000c11e7"
    status, token, _ = fx.form_post(
        "/v2/oauth2/token",
        {"grant_type": "client_credentials",
         "scope": "urn:globus:auth:scope:transfer.api.globus.org:all"},
        basic=(dispatcher, doc["clients"][dispatcher]["secret"]),
    )
    assert status == 200
    (landing,) = doc["collections"]
    status, page, _ = fx.get(
        f"/v0.10/endpoint_manager/task_list?filter_endpoint={landing}"
        f"&filter_endpoint_use=destination&filter_status=SUCCEEDED,FAILED",
        token=token["access_token"],
    )
    assert status == 200
    (task,) = page["DATA"]
    # The seeded clock is a real 2026 second, so the times read as one.
    assert task["completion_time"] == "2026-01-01T00:00:00+00:00"
    assert task["files_transferred"] == 2
