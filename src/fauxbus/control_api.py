"""The control plane: /_fauxbus/ — out-of-band by principle 4.

No Globus API will ever claim this prefix, so the imitated surface
stays pure.  Nothing here requires auth; it is the test harness's own
back door into the world.
"""

from __future__ import annotations

from typing import Any

from . import SDK_PIN, __version__
from .errors import ApiError
from .server import Ctx, FauxbusServer


def index(ctx: Ctx) -> tuple[int, Any]:
    return 200, {
        "fauxbus": __version__,
        "sdk_pin": SDK_PIN,
        "imitates": ["groups v2"],
        "control": [
            "GET  /_fauxbus/state",
            "POST /_fauxbus/reset",
            "POST /_fauxbus/seed",
            "GET  /_fauxbus/failures",
            "POST /_fauxbus/failures",
            "DELETE /_fauxbus/failures[?id=fail-N]",
            "POST /_fauxbus/tick",
        ],
    }


def get_state(ctx: Ctx) -> tuple[int, Any]:
    return 200, ctx.world.dump()


def reset(ctx: Ctx) -> tuple[int, Any]:
    # The between-tests handshake: wipes the world AND disarms failures —
    # a reset that left tripwires armed would not be much of a reset.
    ctx.world.reset()
    ctx.server.failures.clear()
    return 200, {"ok": True}


def seed(ctx: Ctx) -> tuple[int, Any]:
    if not isinstance(ctx.body, dict):
        raise ApiError(400, "BAD_REQUEST", "seed body must be a state document")
    ctx.world.load(ctx.body)
    return 200, {"ok": True, "groups": len(ctx.world.groups)}


def list_failures(ctx: Ctx) -> tuple[int, Any]:
    return 200, {"failures": [rule.doc() for rule in ctx.server.failures]}


def arm_failure(ctx: Ctx) -> tuple[int, Any]:
    if not isinstance(ctx.body, dict):
        raise ApiError(400, "BAD_REQUEST", "failure rule body required")
    rule = ctx.server.arm_failure(ctx.body)
    return 200, rule.doc()


def disarm_failures(ctx: Ctx) -> tuple[int, Any]:
    rule_id = ctx.query.get("id")
    if rule_id is None:
        cleared = len(ctx.server.failures)
        ctx.server.failures.clear()
        return 200, {"cleared": cleared}
    for rule in ctx.server.failures:
        if rule.id == rule_id:
            ctx.server.failures.remove(rule)
            return 200, {"cleared": 1}
    raise ApiError(404, "NOT_FOUND", f"no armed failure rule with id {rule_id!r}")


def tick(ctx: Ctx) -> tuple[int, Any]:
    body = ctx.body if isinstance(ctx.body, dict) else {}
    seconds = body.get("seconds", 1)
    if not isinstance(seconds, int) or seconds < 1:
        raise ApiError(400, "BAD_REQUEST", "'seconds' must be a positive integer")
    ctx.world.clock += seconds
    # Logical time only — nothing consumes it in v0.1, but determinism is
    # load-bearing from day one, not retrofitted (SPEC principle 3).
    return 200, {"clock": ctx.world.clock}


def register(server: FauxbusServer) -> None:
    add = server.add_route
    add("GET", "/_fauxbus/?", index, auth=False)
    add("GET", "/_fauxbus/state", get_state, auth=False)
    add("POST", "/_fauxbus/reset", reset, auth=False)
    add("POST", "/_fauxbus/seed", seed, auth=False)
    add("GET", "/_fauxbus/failures", list_failures, auth=False)
    add("POST", "/_fauxbus/failures", arm_failure, auth=False)
    add("DELETE", "/_fauxbus/failures", disarm_failures, auth=False)
    add("POST", "/_fauxbus/tick", tick, auth=False)
