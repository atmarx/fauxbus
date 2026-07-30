"""The imitated surface: Globus Groups API v2, complete GroupsClient scope.

Paths and payloads follow what globus-sdk 4.8.1 actually sends (see
SPEC.md for the recorded/documented/provisional grades of each shape).
Registration order matters: literal paths (my_groups) register before
the {group_id} patterns that would otherwise swallow them.
"""

from __future__ import annotations

from typing import Any

from .errors import validation_error
from .server import Ctx, FauxbusServer
from .world import GET_GROUP_INCLUDES, STATUSES


def _csv(value: str | None) -> list[str]:
    return [v for v in (value or "").split(",") if v]


def get_my_groups(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    statuses = _csv(ctx.query.get("statuses"))
    unknown = set(statuses) - set(STATUSES)
    if unknown:
        raise validation_error(f"unknown membership statuses: {sorted(unknown)}")
    groups = ctx.world.my_groups(ctx.identity, statuses or None)
    # RECORDED: a bare JSON array, no pagination envelope.
    return 200, [ctx.world.my_groups_doc(g, ctx.identity) for g in groups]


def create_group(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    if not isinstance(ctx.body, dict):
        raise validation_error("group document required")
    group = ctx.world.create_group(ctx.identity, ctx.body)
    return 200, ctx.world.group_doc(group, ctx.identity)


def get_group(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    include = _csv(ctx.query.get("include"))
    unknown = set(include) - set(GET_GROUP_INCLUDES)
    if unknown:
        raise validation_error(f"unknown include fields: {sorted(unknown)}")
    group = ctx.world.get_group(ctx.match.group(1), ctx.identity)
    return 200, ctx.world.group_doc(group, ctx.identity, include)


def update_group(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    group = ctx.world.update_group(ctx.identity, ctx.match.group(1), ctx.body or {})
    return 200, ctx.world.group_doc(group, ctx.identity)


def delete_group(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    group = ctx.world.get_group(ctx.match.group(1), ctx.identity)
    doc = ctx.world.group_doc(group, ctx.identity)  # render before it's gone
    ctx.world.delete_group(ctx.identity, group.id)
    # RECORDED: DELETE answers 200 with the deleted group document.
    return 200, doc


def batch_membership(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    result = ctx.world.batch_action(ctx.identity, ctx.match.group(1), ctx.body or {})
    return 200, result


def get_policies(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    group = ctx.world.get_group(ctx.match.group(1), ctx.identity)
    return 200, dict(group.policies)


def set_policies(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    group = ctx.world.set_policies(ctx.identity, ctx.match.group(1), ctx.body or {})
    # RECORDED: PUT answers with the full six-field policy document.
    return 200, dict(group.policies)


def get_preferences(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.get_preferences(ctx.identity)


def set_preferences(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.set_preferences(ctx.identity, ctx.body or {})


def get_membership_fields(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.get_membership_fields(ctx.identity, ctx.match.group(1))


def set_membership_fields(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.set_membership_fields(ctx.identity, ctx.match.group(1), ctx.body or {})


def set_subscription_admin_verified(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    body = ctx.body if isinstance(ctx.body, dict) else {}
    if "subscription_admin_verified_id" not in body:
        raise validation_error("document requires 'subscription_admin_verified_id' (id or null)")
    group = ctx.world.set_subscription_admin_verified(
        ctx.identity, ctx.match.group(1), body["subscription_admin_verified_id"]
    )
    return 200, ctx.world.group_doc(group, ctx.identity)


def get_subscription_info(ctx: Ctx) -> tuple[int, Any]:
    return 200, ctx.world.group_by_subscription(ctx.match.group(1))


SEG = r"([^/]+)"


def register(server: FauxbusServer) -> None:
    add = server.add_route
    add("GET", "/v2/groups/my_groups", get_my_groups, auth=True)
    add("POST", "/v2/groups", create_group, auth=True)
    add("GET", f"/v2/groups/{SEG}/policies", get_policies, auth=True)
    add("PUT", f"/v2/groups/{SEG}/policies", set_policies, auth=True)
    add("GET", f"/v2/groups/{SEG}/membership_fields", get_membership_fields, auth=True)
    add("PUT", f"/v2/groups/{SEG}/membership_fields", set_membership_fields, auth=True)
    add(
        "PUT",
        f"/v2/groups/{SEG}/subscription_admin_verified",
        set_subscription_admin_verified,
        auth=True,
    )
    add("GET", f"/v2/groups/{SEG}", get_group, auth=True)
    add("PUT", f"/v2/groups/{SEG}", update_group, auth=True)
    add("DELETE", f"/v2/groups/{SEG}", delete_group, auth=True)
    add("POST", f"/v2/groups/{SEG}", batch_membership, auth=True)
    add("GET", "/v2/preferences", get_preferences, auth=True)
    add("PUT", "/v2/preferences", set_preferences, auth=True)
    add("GET", f"/v2/subscription_info/{SEG}", get_subscription_info, auth=True)
