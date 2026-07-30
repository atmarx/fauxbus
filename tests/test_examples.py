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


def test_example_seed_pins_work_on_the_wire(fx):
    fx.post("/_fauxbus/seed", example_seed())
    status, groups, _ = fx.get("/v2/groups/my_groups", token="t-alice")
    assert status == 200
    assert [g["name"] for g in groups] == ["Night Owl Service"]

    # bob rides too — active member, not just present in the file
    _, groups, _ = fx.get("/v2/groups/my_groups", token="t-bob")
    assert [m["role"] for g in groups for m in g["my_memberships"]] == ["member"]
