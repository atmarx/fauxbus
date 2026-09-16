"""The vocabulary of authentication: bearer tokens, client secrets, scopes.

Three separate things live here, and the first lesson is that they are
separate:

- **Bearer** (``Authorization: Bearer <token>``) — how a caller acts on
  the imitated surface.  By default a bearer token is not validated at
  all: its identity is a pure function of the token string, so
  ``token-for-alice`` is the same caller — same UUID, same username —
  on every run.  The seed document's ``identities`` section pins
  explicit mappings when a test needs to control them.
- **Basic** (``Authorization: Basic <base64>``) — how an OAuth2
  *confidential client* proves it is itself at the token endpoint.  The
  credential is an id/secret pair belonging to a piece of software, not
  a bearer token belonging to a person.  Different header, different
  question, different answer.
- **Scopes** — the strings a client asks for when requesting a token.
  They matter here because a Globus access token is issued *for exactly
  one resource server*, and the only place that resource server is
  named is inside the scope string.  Parsing scopes is therefore how the
  token endpoint knows what it is about to issue.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from .ids import identity_id_for_token

ANONYMOUS_TOKEN = ""

# The two resource servers Fauxbus can currently issue for.  A "resource
# server" is the service a token is good at — Globus Auth mints the
# token, but Groups is what will accept it.  Presenting a Groups token
# to Transfer fails, and that is the point of the field.
AUTH_RESOURCE_SERVER = "auth.globus.org"
GROUPS_RESOURCE_SERVER = "groups.api.globus.org"

# RECORDED (globus_sdk/scopes/data/groups.py, 4.8.1): the URN form is
# what the SDK's own scope constants expand to, e.g.
# "urn:globus:auth:scope:groups.api.globus.org:all".
_URN_PREFIX = "urn:globus:auth:scope:"
# DOCUMENTED: Globus's newer URL scope form, which the SDK also accepts.
_URL_PREFIX = "https://auth.globus.org/scopes/"

# OIDC's standard scopes carry no resource-server segment to parse —
# they are plain words, and Globus Auth itself is what answers for them.
# RECORDED for ``openid`` (the SDK's own openid token fixture names
# auth.globus.org as the resource server); ``profile`` and ``email`` are
# OIDC Core §5.4.
OIDC_SCOPES = frozenset({"openid", "profile", "email"})

# ``offline_access`` (OIDC Core §11) is OIDC too, and it used to sit in
# the set above.  Taking it out is a bug fix, and the bug is worth
# keeping as a lesson: those three scopes name a *service* — Globus Auth
# is what answers for them, so mapping them to auth.globus.org is the
# same move as parsing a resource server out of a URN.  offline_access
# names no service at all.  It is a modifier on the request, meaning
# "and also give me a refresh token."
#
# Filing it with the others meant that ``offline_access <groups scope>``
# — an entirely ordinary thing for a broker to send — looked to Fauxbus
# like a request spanning two resource servers, and earned a 501 that
# named the wrong gap and pointed the reader at the wrong issue.  Asked
# on its own it was worse: a 200, for a token minted against
# auth.globus.org, carrying no refresh token and no hint that the thing
# the caller asked for had quietly not happened.
#
# The kind-confusion is the general lesson.  A scope grammar has more
# than one kind of word in it, and a parser that knows only one kind
# will answer confidently about the others.
REFRESH_SCOPE = "offline_access"

# The other way the same question gets asked.  globus-sdk does not use
# the scope at all — its flow managers and its dependent-token call send
# ``access_type=offline`` instead (globus_sdk/services/auth/
# flow_managers/authorization_code.py and native_app.py, 4.8.1), which
# is Google's OAuth2 dialect that Globus adopted.  Two spellings, one
# request, and a fake that honours neither had better say so for both —
# otherwise the SDK's own spelling is the one that fails silently.
OFFLINE_ACCESS_TYPE = "offline"


@dataclass(frozen=True)
class Identity:
    identity_id: str
    username: str


def derive_identity(token: str) -> Identity:
    """Mint an Identity from nothing but the token string.

    Two halves, both deterministic:
    - the UUID is a hash of the token (ids.py) — stable across runs;
    - the username is the token itself, sanitized into an email local
      part, so logs and state dumps stay human-readable —
      ``t-alice@fauxbus.example`` tells you who that was at a glance,
      where a bare UUID would tell you nothing.

    ``.example`` is an RFC 2606 reserved domain: obviously fake on
    sight, and mail to it can never reach anyone real.
    """
    if token == ANONYMOUS_TOKEN:
        local = "anonymous"
    else:
        # Tokens are arbitrary strings; usernames shouldn't be.
        # Lowercase, squash anything email-unsafe to '-', cap the length.
        local = re.sub(r"[^a-z0-9_.-]+", "-", token.lower()).strip("-") or "caller"
    return Identity(
        identity_id=identity_id_for_token(token),
        username=f"{local[:64]}@fauxbus.example",
    )


def parse_bearer(header_value: str | None) -> str | None:
    """Return the token from an Authorization header, or None if absent/malformed.

    Malformed is deliberately treated the same as absent: parsing
    answers "what is the token?", never "is this allowed?".  Policy —
    401 versus --allow-anonymous — belongs to the server, which is why
    this returns None instead of raising.
    """
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def parse_basic(header_value: str | None) -> tuple[str, str] | None:
    """Return (client_id, client_secret) from a Basic header, or None.

    Same contract as ``parse_bearer``: this answers "what credential was
    presented?", never "is it good?".  A malformed header is None, and
    the caller decides what that means.

    One faithfulness note worth carrying.  RFC 6749 §2.3.1 says the id
    and secret should each be form-urlencoded *before* being joined with
    a colon and base64'd — so a secret containing ``:`` or ``%`` would
    arrive percent-escaped.  globus-sdk does not do that; its
    ``BasicAuthorizer`` base64s the raw ``f"{username}:{password}"``
    (globus_sdk/authorizers/basic.py, 4.8.1).  Fauxbus matches the SDK,
    because the SDK is the contract (principle 1) — which means a secret
    with a colon in it splits at the *first* colon, exactly as it would
    against the real service when sent by this client.
    """
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    client_id, separator, secret = decoded.partition(":")
    if not separator:
        return None
    return client_id, secret


def split_scopes(raw: str) -> list[str]:
    """A scope *string* is space-delimited; a scope *list* is what we work with."""
    return raw.split()


def resource_server_for_scope(scope: str) -> str | None:
    """Which service will accept a token carrying this scope, or None if unknown.

    Returning None rather than guessing is deliberate.  A scope shape
    Fauxbus does not recognize is a gap in Fauxbus, and principle 2 says
    a gap gets a loud 501 with a place to file it — never a token issued
    for a resource server we picked because it seemed likely.  The
    caller (world.resource_server_for_request) is what turns None into
    that 501.
    """
    # A leading '*' marks an optional dependent scope in Globus's scope
    # grammar.  It does not change which service the scope belongs to,
    # so strip it before parsing rather than failing on it.
    scope = scope.removeprefix("*")
    if scope.startswith(_URN_PREFIX):
        resource_server, separator, name = scope[len(_URN_PREFIX):].partition(":")
        return resource_server if separator and resource_server and name else None
    if scope.startswith(_URL_PREFIX):
        resource_server, separator, name = scope[len(_URL_PREFIX):].partition("/")
        return resource_server if separator and resource_server and name else None
    if scope in OIDC_SCOPES:
        return AUTH_RESOURCE_SERVER
    return None


def placeholder_username(identity_id: str) -> str:
    """Username for an identity we only know as a UUID (e.g. batch-added).

    The real service resolves identities through Globus Auth; Fauxbus has
    no identities lookup yet, so unknown UUIDs get a readable,
    deterministic placeholder.
    """
    return f"{identity_id}@fauxbus.example"


def client_username(client_id: str) -> str:
    """The username Globus gives a confidential client's own identity.

    Worth pausing on, because it is the hinge of the whole
    client-credentials story: in Globus Auth a registered client *is an
    identity*.  Its client_id is an identity UUID, and a token issued by
    the client_credentials grant acts as that identity — so a service
    that fetches its own token and then calls Groups shows up in the
    membership list as itself, not as a person.

    ``clients.auth.globus.org`` is the real Globus namespace for those
    identities, and Fauxbus uses it rather than its own
    ``@fauxbus.example`` convention on purpose (principle 5: faithful to
    Globus semantics).  A consumer that detects service accounts by
    checking this suffix should behave the same against the fake as
    against the real thing — and no mail was ever going to reach that
    domain either.  A seeded client may override it if a test needs a
    different name.
    """
    return f"{client_id}@clients.auth.globus.org"
