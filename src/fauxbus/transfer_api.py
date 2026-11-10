"""The imitated surface: Globus Transfer API v0.10, task monitoring and permissions.

Three routes from the ``endpoint_manager_*`` family of globus-sdk
4.8.1's ``TransferClient``, the ones a poller watching a collection
calls:

- ``endpoint_manager_task_list`` — ``GET /v0.10/endpoint_manager/task_list``
- ``endpoint_manager_get_task`` — ``GET /v0.10/endpoint_manager/task/{id}``
- ``endpoint_manager_task_successful_transfers`` —
  ``GET /v0.10/endpoint_manager/task/{id}/successful_transfers``

And since 0.6.0, three for a guest collection's permissions (ACL rules):

- ``endpoint_acl_list`` — ``GET /v0.10/endpoint/{id}/access_list``
- ``add_endpoint_acl_rule`` — ``POST /v0.10/endpoint/{id}/access``
- ``delete_endpoint_acl_rule`` — ``DELETE /v0.10/endpoint/{id}/access/{rule}``

``get_endpoint_acl_rule`` and ``update_endpoint_acl_rule`` share the
last path and are answered with the 501 by name, because the
dispatcher's rule — a known path with an unrouted verb is a 405 — would
otherwise tell a consumer that Globus has no such call.

Everything else under ``/v0.10/`` is unrouted, so it meets the
dispatcher's loud 501 — including ``endpoint_manager_task_event_list``,
which SPEC names as part of the confirmed surface and which no consumer
calls yet.  Principle 2: built when someone needs it, refused loudly
until then.

Same thin-handler rule as groups_api: unpack the wire, call one World
method, render.  The one thing these handlers add is the request path
on a Transfer error (see ``_transfer``), because Transfer's recorded
error document names the resource it failed on and World does not know
what URL it was reached by.
"""

from __future__ import annotations

from functools import wraps
from typing import Any

from .auth import TRANSFER_RESOURCE_SERVER
from .errors import TransferError, not_implemented
from .server import Ctx, FauxbusServer, Handler


def _transfer(handler: Handler) -> Handler:
    """Stamp the request path onto any Transfer error on its way out.

    World raises ``TransferError`` without a ``resource`` because it is
    plain data with no idea of URLs (see World's docstring for why that
    split is the codebase's spine).  The path is right here, as the
    string the route pattern matched.  Errors in Fauxbus's own dialect —
    a 501, a 401 for no token — pass through untouched: those are the
    fake speaking about itself, not imitating Transfer.
    """

    @wraps(handler)
    def wrapped(ctx: Ctx) -> Any:
        try:
            return handler(ctx)
        except TransferError as err:
            err.resource = ctx.match.string
            raise

    return wrapped


@_transfer
def task_list(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.endpoint_manager_task_list(ctx.identity, ctx.query)


@_transfer
def get_task(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.endpoint_manager_get_task(ctx.identity, ctx.match.group(1))


@_transfer
def successful_transfers(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.endpoint_manager_successful_transfers(
        ctx.identity, ctx.match.group(1), ctx.query
    )


@_transfer
def acl_list(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.endpoint_acl_list(ctx.identity, ctx.match.group(1))


@_transfer
def add_acl_rule(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    # DOCUMENTED: 201 Created.
    return 201, ctx.world.add_access_rule(ctx.identity, ctx.match.group(1), ctx.body)


@_transfer
def delete_acl_rule(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.delete_access_rule(
        ctx.identity, ctx.match.group(1), ctx.match.group(2)
    )


def acl_rule_unbuilt(ctx: Ctx) -> tuple[int, Any]:
    raise not_implemented(
        "Fauxbus does not implement reading or changing one access rule by id "
        "(get_endpoint_acl_rule, update_endpoint_acl_rule). Real client code needs it?"
    )


# One path segment, as in groups_api: a {task_id} slot must not swallow
# "/successful_transfers" and hand the wrong handler a task id with a
# slash in it.
SEG = r"([^/]+)"


def register(server: FauxbusServer) -> None:
    # Every route is the Transfer resource server's, so under
    # --require-issued-tokens a Groups token presented here is refused —
    # the same check, threaded the same way, that has kept Transfer
    # tokens out of Groups since slice A.  Registration order: the
    # longer successful_transfers path first is not needed (patterns are
    # anchored), but it reads in the order a poller calls them.
    def add(pattern: str, handler: Handler) -> None:
        server.add_route(
            "GET", pattern, handler, auth=True, resource_server=TRANSFER_RESOURCE_SERVER
        )

    add("/v0.10/endpoint_manager/task_list", task_list)
    add(f"/v0.10/endpoint_manager/task/{SEG}", get_task)
    add(f"/v0.10/endpoint_manager/task/{SEG}/successful_transfers", successful_transfers)

    def route(method: str, pattern: str, handler: Handler) -> None:
        server.add_route(
            method, pattern, handler, auth=True, resource_server=TRANSFER_RESOURCE_SERVER
        )

    route("GET", f"/v0.10/endpoint/{SEG}/access_list", acl_list)
    route("POST", f"/v0.10/endpoint/{SEG}/access", add_acl_rule)
    route("DELETE", f"/v0.10/endpoint/{SEG}/access/{SEG}", delete_acl_rule)
    route("GET", f"/v0.10/endpoint/{SEG}/access/{SEG}", acl_rule_unbuilt)
    route("PUT", f"/v0.10/endpoint/{SEG}/access/{SEG}", acl_rule_unbuilt)
