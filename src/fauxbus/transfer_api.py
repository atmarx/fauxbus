"""The imitated surface: Globus Transfer API v0.10, task monitoring only.

Three routes from the ``endpoint_manager_*`` family of globus-sdk
4.8.1's ``TransferClient``, the ones a poller watching a collection
calls:

- ``endpoint_manager_task_list`` — ``GET /v0.10/endpoint_manager/task_list``
- ``endpoint_manager_get_task`` — ``GET /v0.10/endpoint_manager/task/{id}``
- ``endpoint_manager_task_successful_transfers`` —
  ``GET /v0.10/endpoint_manager/task/{id}/successful_transfers``

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
from .errors import TransferError
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
