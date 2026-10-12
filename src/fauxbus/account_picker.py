"""The control plane's browser leg: ``/_fauxbus/auth/`` — sign in as a seeded account.

Principle 4 decides where this lives.  The real authorize endpoint
shows a person Globus's login page; Fauxbus has no passwords to check
and no business pretending to.  So ``/v2/oauth2/authorize`` redirects a
browser with no Fauxbus session *here*, to a plain page that lists the
seeded accounts.  Pick one, and this module signs the browser in with a
Fauxbus-only cookie and finishes the authorization request it was
holding — the client gets its code exactly as if Globus had shown a
login page.  The imitated endpoint never learns any of this happened.

Three routes, two audiences:

- ``GET  /_fauxbus/auth/login?request=…`` — the page, for a browser (or a
  test driving one with plain HTTP: every account is a one-field form).
- ``POST /_fauxbus/auth/login`` — the form's target.  Signs in, resumes.
- ``POST /_fauxbus/auth/session`` — for a headless test that wants to
  be signed in *before* it starts a login, so authorize skips the picker
  entirely.  JSON in, a ``Set-Cookie`` out.

No passwords, ever.  A picker that asked for one would be teaching
people to type passwords into a fake.
"""

from __future__ import annotations

from html import escape
from typing import Any

from .errors import ApiError, validation_error
from .oidc_api import SESSION_COOKIE, code_redirect
from .server import Ctx, FauxbusServer, Raw
from .world import AuthorizationRequest, RequiredIdpUnsatisfied, Session

LOGIN_PATH = "/_fauxbus/auth/login"
SESSION_PATH = "/_fauxbus/auth/session"


def session_cookie(session: Session) -> str:
    """The ``Set-Cookie`` value that signs a browser in.

    ``Path=/`` because the cookie is set here, under ``/_fauxbus/``, and
    must be sent to ``/v2/oauth2/authorize``.  ``SameSite=Lax`` because
    the request that needs it is a top-level redirect *from the broker's
    site* — Lax sends cookies on exactly that, and Strict would not.
    ``HttpOnly`` because nothing in a page should read it.  No
    ``Secure``: Fauxbus is routinely plain http on localhost, and a
    Secure cookie there is a cookie the browser silently drops.
    """
    return f"{SESSION_COOKIE}={session.id}; Path=/; HttpOnly; SameSite=Lax"


def _page(status: int, title: str, body: str) -> tuple[int, Raw]:
    html = (
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{escape(title)} — Fauxbus</title>"
        "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;"
        "padding:0 1rem}form{margin:.75rem 0}button{font:inherit;padding:.5rem 1rem;"
        "cursor:pointer}.note{color:#666;font-size:.9em}.no{color:#a33}</style></head><body>"
        f"<h1>{escape(title)}</h1>{body}"
        "<p class=\"note\">Fauxbus is a test fake, not Globus. Nothing here checks a "
        "password, and no account on this page is real.</p></body></html>\n"
    )
    return status, Raw(html.encode("utf-8"), "text/html; charset=utf-8")


def _pending(ctx: Ctx, request_id: str | None) -> AuthorizationRequest:
    request = ctx.world.authorization_requests.get(request_id or "")
    if request is None:
        # A finished, reset, or invented request id.  Not resumable, and
        # the page says so rather than guessing which login was meant.
        raise ApiError(
            404,
            "NO_SUCH_AUTHORIZATION_REQUEST",
            f"no authorization request {request_id!r} is waiting. It may have finished "
            f"already, or a reset cleared it — start the login again from the client.",
        )
    return request


def login_page(ctx: Ctx) -> tuple[int, Any]:
    try:
        request = _pending(ctx, ctx.query.get("request"))
    except ApiError as err:
        return _page(err.status, "Nothing to sign in to", f"<p>{escape(err.detail)}</p>")
    client = ctx.world.clients[request.client_id]
    rows = []
    for primary, account in sorted(ctx.world.accounts.items()):
        identity = ctx.world.effective_identity(account, client)
        first = account.identities[primary]
        linked = ", ".join(escape(i.username) for i in account.ordered()[1:])
        label = escape(first.name or first.username)
        detail = escape(first.username) + (f" · linked: {linked}" if linked else "")
        if identity is None:
            # Shown, not hidden: a tester looking for an account should
            # find it and learn why it cannot be used here.
            rows.append(
                f"<p><strong>{label}</strong> <span class=\"note\">{detail}</span><br>"
                f"<span class=\"no\">No identity from the provider this client requires.</span></p>"
            )
            continue
        rows.append(
            f"<form method=\"post\" action=\"{LOGIN_PATH}\">"
            f"<input type=\"hidden\" name=\"request\" value=\"{escape(request.id)}\">"
            f"<input type=\"hidden\" name=\"account\" value=\"{escape(primary)}\">"
            f"<button type=\"submit\">{label}</button> "
            f"<span class=\"note\">{detail} — signs in as {escape(identity.username)}</span></form>"
        )
    if not rows:
        rows.append("<p>No accounts are seeded. Add some under <code>accounts</code>.</p>")
    intro = (
        f"<p><strong>{escape(client.name)}</strong> is asking to sign you in "
        f"(scopes: <code>{escape(' '.join(request.scopes))}</code>). Pick a seeded account.</p>"
    )
    return _page(200, "Sign in to Fauxbus", intro + "".join(rows))


def login_submit(ctx: Ctx) -> tuple[int, Any] | tuple[int, Any, dict[str, str]]:
    form = ctx.body if isinstance(ctx.body, dict) else {}
    try:
        request = _pending(ctx, form.get("request"))
    except ApiError as err:
        return _page(err.status, "Nothing to sign in to", f"<p>{escape(err.detail)}</p>")
    account = ctx.world.accounts.get(form.get("account", ""))
    if account is None:
        return _page(400, "Unknown account", "<p>That account is not seeded.</p>")
    client = ctx.world.clients[request.client_id]
    if ctx.world.effective_identity(account, client) is None:
        # Checked before a session exists, so a refused pick leaves no
        # half-signed-in browser behind.  The request stays parked.
        refusal = RequiredIdpUnsatisfied(client, account, ctx.world.identity_providers)
        back = f"{LOGIN_PATH}?request={escape(request.id)}"
        return _page(
            refusal.status,
            "This account cannot sign in here",
            f"<p>{escape(refusal.detail)}</p><p><a href=\"{back}\">Choose another account</a></p>",
        )
    session = ctx.world.open_session(account.primary, ctx.server.signed_now())
    status, raw, headers = code_redirect(ctx.world.complete_authorization(request, session))
    return status, raw, {**headers, "Set-Cookie": session_cookie(session)}


def open_session(ctx: Ctx) -> tuple[int, Any, dict[str, str]]:
    """Headless sign-in: ``{"account": "<primary identity id>"}`` → a session cookie.

    The response says the cookie's name and value in the body as well as
    in ``Set-Cookie``, because a test client without a cookie jar should
    not have to parse a header to use it.
    """
    body = ctx.body if isinstance(ctx.body, dict) else {}
    account = body.get("account")
    if not isinstance(account, str):
        raise validation_error("'account' (the account's primary identity id) is required")
    session = ctx.world.open_session(account, ctx.server.signed_now())
    return (
        200,
        {"session": session.id, "cookie": f"{SESSION_COOKIE}={session.id}", "account": account},
        {"Set-Cookie": session_cookie(session)},
    )


def register(server: FauxbusServer) -> None:
    # auth=False like the rest of the control plane; under
    # --control-loopback-only these refuse non-loopback peers too, which
    # means a browser in another container cannot reach the picker.
    # That is the flag doing its job — use the headless session route
    # from the harness instead.
    server.add_route("GET", LOGIN_PATH, login_page, auth=False)
    server.add_route("POST", LOGIN_PATH, login_submit, auth=False)
    server.add_route("POST", SESSION_PATH, open_session, auth=False)
