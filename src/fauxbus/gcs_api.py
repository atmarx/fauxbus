"""The imitated surface: a GCS Manager API per seeded endpoint, guest collections only.

A Globus Connect Server endpoint runs its own manager at its own host —
``https://<something>.data.globus.org/api/`` — so unlike Groups or
Transfer there is no one address to imitate.  Fauxbus serves every
seeded endpoint's manager from its one socket, under
``/gcs/<endpoint id>/api/``, and a consumer points a ``GCSClient`` there.

One wrinkle from the SDK, and it is the consumer's to know: globus-sdk
4.8.1's ``GCSClient.__init__`` turns any address not starting with
``https://`` into ``https://<address>/api/``, so a plain-HTTP Fauxbus
cannot be handed to it as a constructor argument.  Construct the client
and set ``base_url`` to ``http://<fauxbus>/gcs/<endpoint id>/api/``
after; the SDK builds every request from that attribute.

The routes, from ``GCSClient``:

- ``get_collection`` — ``GET /collections/{id}``
- ``get_collection_list`` — ``GET /collections`` (marker-paged)
- ``create_collection`` — ``POST /collections`` (guest collections)
- ``update_collection`` — ``PATCH /collections/{id}``
- ``delete_collection`` — ``DELETE /collections/{id}``
- ``get_user_credential_list`` — ``GET /user_credentials`` (marker-paged)
- ``create_user_credential`` — ``POST /user_credentials``

Everything else under ``/gcs/`` meets the dispatcher's loud 501, which
includes ``/info``: ``GCSClient`` calls it only to discover the
endpoint's client id, and a consumer handing the client an authorizer
never does.  Thin handlers, as everywhere: World holds the rules.
"""

from __future__ import annotations

import re
from typing import Any

from .server import Ctx, FauxbusServer, Handler

SEG = r"([^/]+)"
PREFIX = f"/gcs/{SEG}/api"


def _endpoint_resource_server(match: re.Match[str]) -> str:
    """A GCS token's resource server is its endpoint's id — the first path segment.

    globus-sdk 4.8.1: ``GCSClient.resource_server`` is the endpoint's
    client id, and its scopes are ``urn:globus:auth:scope:<that id>:...``.
    Under ``--require-issued-tokens`` a Transfer token, or another
    endpoint's, is refused here exactly as a Groups token is at Transfer.
    Per-operation scope (``manage_collections`` and its ``data_access``
    dependency) is not checked, for the reason SPEC's Auth posture gives.
    """
    return match.group(1)


def get_collection(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.gcs_get_collection(ctx.identity, ctx.match.group(1), ctx.match.group(2))


def list_collections(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.gcs_list_collections(ctx.identity, ctx.match.group(1), ctx.query)


def create_collection(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    guest = ctx.world.gcs_create_collection(ctx.identity, ctx.match.group(1), ctx.body)
    # PROVISIONAL: 201 and ``detail: "created"``, by analogy with the
    # recorded user-credential create, whose envelope says 201.  No
    # collection-create fixture exists.
    return 201, ctx.world.gcs_result(
        [ctx.world.gcs_collection_doc(guest)], 201, message=f"Created Collection {guest.id}"
    )


def update_collection(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    guest = ctx.world.gcs_update_collection(
        ctx.identity, ctx.match.group(1), ctx.match.group(2), ctx.body
    )
    return 200, ctx.world.gcs_result([ctx.world.gcs_collection_doc(guest)])


def delete_collection(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    ctx.world.gcs_delete_collection(ctx.identity, ctx.match.group(1), ctx.match.group(2))
    # PROVISIONAL: the reference does not show the body; an empty result
    # envelope is the shape every other answer here has.
    return 200, ctx.world.gcs_result([])


def list_user_credentials(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    return 200, ctx.world.gcs_list_user_credentials(ctx.identity, ctx.match.group(1), ctx.query)


def create_user_credential(ctx: Ctx) -> tuple[int, Any]:
    assert ctx.identity is not None
    cred = ctx.world.gcs_create_user_credential(ctx.identity, ctx.match.group(1), ctx.body)
    # RECORDED (create_user_credential.py): the envelope says
    # http_response_code 201, detail "created", and this message.  The
    # HTTP status itself is the envelope's number — the fixture registers
    # no status of its own — so 201 on the wire is PROVISIONAL.
    return 201, ctx.world.gcs_result(
        [ctx.world.gcs_user_credential_doc(cred)],
        201,
        has_next_page=False,
        message=f"Created User Credential {cred.id}",
    )


def register(server: FauxbusServer) -> None:
    def add(method: str, pattern: str, handler: Handler) -> None:
        server.add_route(
            method, PREFIX + pattern, handler, auth=True, resource_server=_endpoint_resource_server
        )

    # The SDK's get_collection_list path has no leading slash
    # ("collections"), and slash_join makes it /api/collections all the
    # same; both spellings arrive here identically.
    add("GET", "/collections", list_collections)
    add("POST", "/collections", create_collection)
    add("GET", f"/collections/{SEG}", get_collection)
    add("PATCH", f"/collections/{SEG}", update_collection)
    add("DELETE", f"/collections/{SEG}", delete_collection)
    add("GET", "/user_credentials", list_user_credentials)
    add("POST", "/user_credentials", create_user_credential)
