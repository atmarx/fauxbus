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
    # Self-describing root: curl it and learn the control surface.  It
    # answers without auth and reads no state, which is also what makes
    # it the container HEALTHCHECK and compose's service_healthy probe
    # — a liveness check must never be able to perturb the world it
    # checks.
    return 200, {
        "fauxbus": __version__,
        "sdk_pin": SDK_PIN,
        "imitates": ["groups v2", "auth v2 (client_credentials)"],
        "require_issued_tokens": ctx.server.require_issued_tokens,
        "control": [
            "GET  /_fauxbus/state",
            'POST /_fauxbus/reset (to canonical seed; body {"to": "empty"} for blank)',
            "POST /_fauxbus/seed[?canonical=true]",
            "DELETE /_fauxbus/seed (forget canonical)",
            "GET  /_fauxbus/failures",
            "POST /_fauxbus/failures",
            "DELETE /_fauxbus/failures[?id=fail-N]",
            "POST /_fauxbus/tick",
        ],
    }


def get_state(ctx: Ctx) -> tuple[int, Any]:
    return 200, ctx.world.dump()


def reset(ctx: Ctx) -> tuple[int, Any]:
    # The between-tests handshake: disarms failures always — a reset that
    # left tripwires armed would not be much of a reset — and returns the
    # world to its canonical seed if one is on record (--seed at boot, or
    # seed?canonical=true).  The canonical document is the fixed point
    # tests come home to; everything between resets was a throw-away.
    # {"to": "empty"} opts out and gives a blank world instead.
    body = ctx.body if isinstance(ctx.body, dict) else {}
    target = body.get("to", "seed")
    if target not in ("seed", "empty"):
        raise ApiError(400, "BAD_REQUEST", "'to' must be \"seed\" or \"empty\"")
    ctx.world.reset()
    ctx.server.failures.clear()
    if target == "seed" and ctx.server.canonical_seed is not None:
        ctx.world.load(ctx.server.canonical_seed)
        return 200, {"ok": True, "world": "seed", "groups": len(ctx.world.groups)}
    return 200, {"ok": True, "world": "empty", "groups": 0}


def seed(ctx: Ctx) -> tuple[int, Any]:
    if not isinstance(ctx.body, dict):
        raise ApiError(400, "BAD_REQUEST", "seed body must be a state document")
    ctx.world.load(ctx.body)
    doc: dict[str, Any] = {"ok": True, "groups": len(ctx.world.groups)}
    if ctx.query.get("canonical") in ("true", "1"):
        # Pin this document as what reset restores — the over-HTTP twin
        # of booting with --seed, for harnesses that can't mount files.
        ctx.server.canonical_seed = ctx.body
        doc["canonical"] = True
    return 200, doc


def forget_seed(ctx: Ctx) -> tuple[int, Any]:
    # Unpin the canonical seed; the current world is untouched.  After
    # this, reset means empty again.
    had = ctx.server.canonical_seed is not None
    ctx.server.canonical_seed = None
    return 200, {"cleared": had}


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
    # auth=False across the board: the harness's own tools must keep
    # working even when a test has made the imitated surface hostile
    # (401 everywhere, armed failures).  Injection skips /_fauxbus/
    # entirely — see server._dispatch — so these routes cannot be
    # broken from inside a test.
    add = server.add_route
    add("GET", "/_fauxbus/?", index, auth=False)
    add("GET", "/_fauxbus/state", get_state, auth=False)
    add("POST", "/_fauxbus/reset", reset, auth=False)
    add("POST", "/_fauxbus/seed", seed, auth=False)
    add("DELETE", "/_fauxbus/seed", forget_seed, auth=False)
    add("GET", "/_fauxbus/failures", list_failures, auth=False)
    add("POST", "/_fauxbus/failures", arm_failure, auth=False)
    add("DELETE", "/_fauxbus/failures", disarm_failures, auth=False)
    add("POST", "/_fauxbus/tick", tick, auth=False)
