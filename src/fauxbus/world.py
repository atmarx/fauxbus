"""The in-memory world: groups, memberships, policies, preferences,
the OAuth2 client registry and the tokens it has issued, and — since the
Transfer task-monitoring slice — collections, their role grants, and
transfer tasks.

Truth grades (see SPEC.md "Recorded, documented, provisional"):
- Document shapes for groups, my_groups entries, policies, and DELETE
  responses are RECORDED — they match fixtures shipped inside
  globus-sdk 4.8.1 (globus_sdk/testing/data/groups/).
- Role/status semantics follow SDK docstrings where stated (DOCUMENTED).
- Anything marked PROVISIONAL is Fauxbus's best inference and carries an
  open conformance obligation against the real service.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from .auth import (
    AUTH_ISSUER,
    AUTH_RESOURCE_SERVER,
    Identity,
    check_issuer,
    client_username,
    derive_identity,
    placeholder_username,
    resource_server_for_scope,
)
from .errors import (
    ApiError,
    auth_forbidden,
    auth_unauthorized,
    endpoint_not_found,
    group_not_found,
    invalid_client,
    invalid_grant,
    invalid_request,
    not_implemented,
    task_not_found,
    transfer_bad_request,
    transfer_permission_denied,
    validation_error,
)
from .ids import (
    CODE_PREFIX,
    REQUEST_PREFIX,
    SESSION_PREFIX,
    access_token,
    access_token_number,
    minted_name,
    minted_number,
    sequential_id,
)
from .signing import at_hash, b64url

ROLES = ("member", "manager", "admin")
STATUSES = ("active", "declined", "invited", "left", "pending", "rejected", "removed")

DEFAULT_POLICIES: dict[str, Any] = {
    # Defaults mirror the recorded fixtures: new groups show
    # private/managers visibility and a 28800 assurance timeout.
    "is_high_assurance": False,
    "group_visibility": "private",
    "group_members_visibility": "managers",
    "join_requests": False,
    "signup_fields": [],
    "authentication_assurance_timeout": 28800,
}

GET_GROUP_INCLUDES = ("memberships", "my_memberships", "policies", "allowed_actions", "child_ids")

BATCH_VERBS = (
    "add",
    "invite",
    "accept",
    "decline",
    "approve",
    "reject",
    "join",
    "leave",
    "remove",
    "change_role",
    "request_join",
)
SELF_VERBS = frozenset({"accept", "decline", "join", "leave", "request_join"})
MANAGER_VERBS = frozenset({"add", "invite", "approve", "reject", "remove", "change_role"})


def _require_uuid(value: str, what: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError, TypeError):
        raise validation_error(f"{what} is not a valid UUID: {value!r}") from None


# The seed's scalars need the same manners as its UUIDs.  Before these,
# a seed carrying `"session_limit": "abc"` reached a bare int() and blew
# up as a 500 FAUXBUS_INTERNAL_ERROR — the response that means "Fauxbus
# is broken," when the truth was "your document is."  Wrong blame sends
# someone to the wrong repository.


def _require_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str, float)):
        raise validation_error(f"{what} must be an integer, got {type(value).__name__}")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise validation_error(f"{what} is not an integer: {value!r}") from None


def _optional_str(value: Any, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise validation_error(f"{what} must be a string or null, got {type(value).__name__}")
    return value


def _require_redirect_uri(value: Any, client_id: str) -> str:
    """A redirect URI a client may register (RFC 6749 §3.1.2).

    Absolute, no fragment, and — Fauxbus's own addition — no whitespace
    or control characters.  It ends up in a ``Location`` header, and a
    CR or LF there would let a seed forge response headers; the same
    reason ``server.checked_header`` exists.
    """
    if not isinstance(value, str) or not value:
        raise validation_error(f"client {client_id} redirect_uris must be non-empty strings")
    if not value.isascii() or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise validation_error(f"client {client_id} redirect_uri {value!r} contains whitespace, control or non-ASCII characters")
    parts = urlsplit(value)
    if not parts.scheme or parts.fragment:
        raise validation_error(
            f"client {client_id} redirect_uri {value!r} must be absolute and carry no "
            f"fragment (RFC 6749 §3.1.2)"
        )
    return value


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise validation_error(f"{what} must be an object, got {type(value).__name__}")
    return value


@dataclass
class Membership:
    identity_id: str
    username: str
    role: str
    status: str

    def doc(self, group_id: str) -> dict[str, Any]:
        return {
            "group_id": group_id,
            "identity_id": self.identity_id,
            "username": self.username,
            "role": self.role,
            "status": self.status,
        }


@dataclass
class Group:
    id: str
    name: str
    description: str | None
    parent_id: str | None = None
    group_type: str = "regular"
    enforce_session: bool = False
    session_limit: int = 28800
    session_timeouts: dict[str, Any] = field(default_factory=dict)
    policies: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_POLICIES))
    memberships: dict[str, Membership] = field(default_factory=dict)
    membership_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    subscription_id: str | None = None
    subscription_info: dict[str, Any] | None = None
    subscription_admin_verified_id: str | None = None

    def active_role(self, identity_id: str) -> str | None:
        m = self.memberships.get(identity_id)
        return m.role if m is not None and m.status == "active" else None

    def is_manager(self, identity_id: str) -> bool:
        return self.active_role(identity_id) in ("manager", "admin")

    def is_admin(self, identity_id: str) -> bool:
        return self.active_role(identity_id) == "admin"

    def active_admins(self) -> list[str]:
        return [m.identity_id for m in self.memberships.values() if m.status == "active" and m.role == "admin"]

    def visible_to(self, identity_id: str) -> bool:
        # PROVISIONAL visibility rule: "authenticated" groups are visible
        # to any authenticated caller; "private" groups only to identities
        # holding any membership record (any status — an invitee can see
        # the group they were invited to).
        if self.policies.get("group_visibility") == "authenticated":
            return True
        return identity_id in self.memberships


# RECORDED (globus_sdk/testing/data/auth/oauth2_client_credentials_tokens.py
# and oauth2_exchange_code_for_tokens.py, 4.8.1): both fixtures answer
# with expires_in 172800 — 48 hours.  Fauxbus uses the same number so a
# consumer that hard-codes an expectation from the fixture still passes.
DEFAULT_EXPIRES_IN = 172800

# The grant types Globus Auth actually supports.  This list is the hinge
# of a distinction principle 2 cares about: a grant on this list that
# Fauxbus has not built yet is a *Fauxbus* gap and gets a loud 501, while
# a grant that is not on it is a *client* error and gets the RFC 6749
# answer, unsupported_grant_type.  Answering "unsupported_grant_type" for
# authorization_code would be a lie about the real service — it supports
# that grant perfectly well; we are the ones who don't yet.
#
# DOCUMENTED: authorization_code, client_credentials, and refresh_token
# appear together in the SDK's client-registration examples
# (globus_sdk/services/auth/client/service_client.py); the dependent-token
# grant URN is named in OAuthDependentTokenResponse's docstring.
GLOBUS_GRANT_TYPES = (
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:globus:auth:grant_type:dependent_token",
)

# Which of those Fauxbus can actually perform today.  Everything else in
# GLOBUS_GRANT_TYPES hits the 501 wall with a pointer to the tracker.
IMPLEMENTED_GRANT_TYPES = ("client_credentials", "authorization_code")

# How long an authorization code stays redeemable, on the *logical*
# clock.  PROVISIONAL: the published reference gives no lifetime, and no
# fixture shows one.  Ten minutes is RFC 6749 §4.1.2's recommended
# ceiling.  Because the clock is logical, a code never ages in a test
# that does not tick — a harness proves expiry with ``POST
# /_fauxbus/tick {"seconds": 601}``, never with a sleep.
CODE_LIFETIME = 600

# The two answers to "what time is it?" for an ID token.  Read SPEC's
# "Clocks" section before choosing; the short form is that ``logical`` is
# the default and keeps principle 3 whole, and ``wall`` is the explicit
# opt-in an outside verifier like Keycloak needs, because it checks
# ``exp``/``iat`` against real time and cannot be asked to tick.
SIGNED_TOKEN_CLOCKS = ("logical", "wall")


@dataclass
class OAuthClient:
    """A registered confidential client — a piece of software with credentials.

    The thing to internalize: in Globus Auth a client *is an identity*.
    ``client_id`` is an identity UUID, and a token minted for this client
    acts as that identity everywhere downstream — so a provisioner
    service that fetches its own token and then calls Groups appears in
    the membership list under its own name, exactly like a person would.
    That is why ``identity_id`` here is not a separate field: it would
    only ever be a second copy of ``client_id``.

    Slice B added two things a *login* client needs and a service client
    never touches.  ``redirect_uris`` is the allow-list the authorize
    endpoint matches exactly — a client with none simply cannot run the
    browser flow, which is how Fauxbus says "this client does
    client_credentials only" without a separate grant-types field nobody
    would consult.  ``required_idp`` is DOCUMENTED ("in order to use this
    client a user must have an identity from this IdP in their identity
    set"), and it changes *who signs in*: see World.effective_identity.
    """

    client_id: str
    secret: str
    name: str
    username: str
    redirect_uris: list[str] = field(default_factory=list)
    required_idp: str | None = None


@dataclass
class IdentityProvider:
    """Where an identity comes from — a university, Globus ID, ORCID.

    Only ``name`` is modeled, because only ``name`` reaches the wire (as
    ``identity_provider_display_name``).  The recorded IdP document
    (``get_identity_providers.py``) also has ``short_name``, ``domains``
    and ``alternative_names``; they wait for the identity-providers
    lookup endpoint, which nobody has asked for.
    """

    id: str
    name: str


@dataclass
class GlobusIdentity:
    """One identity: a login at one provider.

    Field names are RECORDED from the identity object in
    ``get_identities.py`` (``id``, ``username``, ``identity_provider``,
    ``name``, ``email``, ``organization``).  ``status`` and
    ``identity_type`` from the same fixture are left out until a surface
    emits them.

    The UUID and the username are deliberately two fields.  SPEC's
    "identity churn" note: a rename changes the username and keeps the
    UUID, and collapsing them into one identifier would make that
    impossible to represent.  Free today, a migration later.
    """

    id: str
    username: str
    identity_provider: str
    name: str | None = None
    email: str | None = None
    organization: str | None = None


@dataclass
class Account:
    """A Globus account: a primary identity plus the identities linked to it.

    Named by its primary identity's UUID, because that is how Globus
    names an account — there is no separate account id on the wire.
    ``identities`` includes the primary, so every identity in the set is
    the same kind of object and "the account's identities" is one dict.
    """

    primary: str
    identities: dict[str, GlobusIdentity]

    def ordered(self) -> list[GlobusIdentity]:
        # Primary first, then the linked identities by UUID.  PROVISIONAL
        # as an *order* — the identity_set shape itself is unrecorded —
        # but it has to be some order, and this one is stable.
        rest = sorted(i for i in self.identities if i != self.primary)
        return [self.identities[self.primary], *(self.identities[i] for i in rest)]


@dataclass
class AuthorizationRequest:
    """An authorize request parked while the browser picks an account.

    The authorize endpoint cannot finish without a signed-in account,
    and Fauxbus will not take one as a query parameter (principle 4).
    So the request waits here, under a name the out-of-band picker
    carries in its URL, and the picker resumes it.  Everything the code
    will later be bound to is captured now, from the original request,
    so nothing about the login can be changed by tampering with the
    picker's form.
    """

    id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    state: str | None
    nonce: str | None
    code_challenge: str | None


@dataclass
class AuthorizationCode:
    """A one-use code, and everything the exchange must match against.

    Bound to the client, the exact redirect URI, the scopes, the nonce,
    the PKCE challenge, and the identity — RFC 6749 §4.1.2 and OIDC Core
    §3.1.2.  The exchange checks every one of them.  ``issued_at`` and
    ``expires_at`` are on the logical clock because Fauxbus is the only
    thing that validates a code; ``authenticated_at`` is a signed-token
    instant, because it ends up inside an ID token someone else checks.
    """

    code: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    state: str | None
    nonce: str | None
    code_challenge: str | None
    account: str
    identity_id: str
    authenticated_at: int
    issued_at: int
    expires_at: int
    used: bool = False


class RequiredIdpUnsatisfied(ApiError):
    """An account with no identity from the provider a client requires.

    How the real service behaves here is PROVISIONAL in its details, but
    not in its direction.  The reference says such a client can only be
    used by someone with an identity from that IdP "in their identity
    set," and describes the neighbouring ``session_required_single_domain``
    case as the user being "redirected to log in or link an identity" —
    that is, the user is kept *at Globus* and the client is never called
    back.  Fauxbus does the same: no ``error=`` redirect to the client, a
    refusal rendered at the picker, and the authorization request left
    parked so another account can be chosen.
    """

    def __init__(
        self, client: OAuthClient, account: Account, idps: dict[str, IdentityProvider]
    ) -> None:
        idp = idps.get(client.required_idp or "")
        label = f"{idp.name} ({idp.id})" if idp else client.required_idp
        super().__init__(
            403,
            "REQUIRED_IDP_UNSATISFIED",
            f"{client.name} requires an identity from {label}, and account "
            f"{account.primary} has none linked. Globus would ask this user to sign "
            f"in with, or link, an identity from that provider; the client is never "
            f"called back. Pick another account, or seed a linked identity.",
        )


@dataclass
class Session:
    """Fauxbus's own sign-in: which account this browser picked, and when.

    Out-of-band state wearing a cookie.  The real service's session is
    its own business and Fauxbus does not imitate it — this exists so a
    second authorize request can skip the picker, which is the behavior
    ``prompt=login`` is defined against.
    """

    id: str
    account: str
    authenticated_at: int


@dataclass
class IssuedToken:
    """One access token this world has minted, and everything it authorizes.

    Only consulted in two places, and they are worth telling apart:

    - ``identity_for_token`` looks here first *always*, so a token
      Fauxbus issued resolves to the client it was issued to instead of
      falling through to the derive-from-the-string default.  Without
      this, a service could fetch a token as itself and then be seen by
      Groups as some hash of the token text — a fake disagreeing with
      itself about who just called.
    - ``require_issued`` consults it only under
      ``--require-issued-tokens``, where the absence of a record is what
      makes an unknown token a 401.
    """

    token: str
    client_id: str
    identity_id: str
    username: str
    resource_server: str
    scopes: list[str]
    grant_type: str
    issued_at: int  # logical clock, not wall clock — see World.clock
    expires_at: int  # same clock
    revoked: bool = False
    # Set only for a token minted by the authorization-code grant, where
    # a *person* signed in.  ``account`` is that person's primary
    # identity, which userinfo needs to render ``identity_set``;
    # ``authenticated_at`` is when they signed in, for
    # ``last_authentication``.  A client_credentials token has neither,
    # because no person was there.
    account: str | None = None
    authenticated_at: int | None = None


# --------------------------------------------------------------- transfer
#
# The task-monitoring slice.  What follows is bookkeeping and nothing
# else: SPEC's bright line (2026-07-31) is that Fauxbus fakes the
# Transfer *API* and never the data plane, so a "file" here is a row with
# a path and a size, and "transferring" it is a counter going up.  No
# byte moves, no path is ever opened.

# DOCUMENTED (the SDK's own docstring for endpoint_manager_task_list:
# "in-progress tasks will have status ACTIVE or INACTIVE, and completed
# tasks will have status SUCCEEDED or FAILED").  INACTIVE is *not*
# finished — it is a task Globus has stopped making progress on, for
# credentials or a fault, that may yet resume.
TASK_RUNNING = ("ACTIVE", "INACTIVE")
TASK_TERMINAL = ("SUCCEEDED", "FAILED")
TASK_STATUSES = TASK_RUNNING + TASK_TERMINAL

# The roles on a collection that let an identity see *other people's*
# tasks there.  DOCUMENTED (docs.globus.org/api/transfer/roles, read
# 2026-10-14): ``activity_monitor`` may "view tasks and other activity to
# or from the collection", ``activity_manager`` may do that and control
# them, and ``administrator`` has "full capabilities".  The reference
# names two more — ``access_manager`` (guest-collection ACLs) and
# ``restricted_administrator`` — and neither one is about tasks, so the
# seed refuses them loudly rather than storing a role that would do
# nothing here.  Role *principals* are identities only: Globus also
# grants roles to groups, and nobody has asked Fauxbus to model that.
MONITOR_ROLES = ("activity_monitor", "activity_manager", "administrator")

# DOCUMENTED (the "Get tasks" query-parameter table): ``limit`` defaults
# to 100, and "the maximum allowed limit is 1000."
TASK_LIST_DEFAULT_LIMIT = 100
TASK_LIST_MAX_LIMIT = 1000

# The query parameters endpoint_manager/task_list understands here.  The
# real endpoint takes more (filter_task_id, filter_owner_id,
# filter_is_paused, filter_min_faults, filter_local_user, and a
# deprecated filter_username), and every one of those gets a loud 501
# rather than being ignored.  Ignoring a filter is the silent wrong
# answer principle 2 forbids in its purest form: the caller asked for
# fewer tasks and got all of them, and the response looks perfect.
TASK_LIST_PARAMS = frozenset(
    {
        "limit",
        "last_key",
        "filter_status",
        "filter_endpoint",
        "filter_endpoint_use",
        "filter_completion_time",
    }
)

# How many rows one page of successful_transfers carries.  PROVISIONAL:
# the reference documents the ``marker``/``next_marker`` paging and no
# page size, and the endpoint takes no ``limit``.  The number only
# decides how many pages a long task spans; the SDK's paginator walks
# them all whatever it is.
SUCCESSFUL_TRANSFERS_PAGE = 100

# RECORDED, from one example: the endpoint_manager_task_list fixture's
# ``deadline`` is its ``request_time`` plus exactly one day.  Fauxbus
# renders every task that way.
TASK_DEADLINE = 86400


@dataclass
class Collection:
    """A Globus collection, as far as task monitoring needs one.

    Three things only.  A name for the ``*_display_name`` fields.  A
    subscription, because the reference says "if the endpoint or
    collection is unsubscribed, activity manager and monitor roles
    become inactive" (DOCUMENTED, transfer/roles) — that is a real
    failure a consumer meets when a DTN's subscription lapses, and a fake
    with no subscription field could never show it.  And the role
    grants, identity id → role name.
    """

    id: str
    display_name: str
    subscription_id: str | None
    roles: dict[str, str] = field(default_factory=dict)

    def monitors(self, identity_id: str) -> bool:
        return self.subscription_id is not None and self.roles.get(identity_id) in MONITOR_ROLES


@dataclass
class TransferFile:
    """One file in a task: where it came from, where it went, how big.

    ``checksum`` and ``checksum_algorithm`` are whatever the harness
    says, or null.  Fauxbus will not compute a checksum — there are no
    bytes to compute one over — and it will not invent a plausible one
    either, because a consumer that compares checksums against its own
    copy would then be comparing against noise.
    """

    source_path: str
    destination_path: str
    size: int
    checksum: str | None = None
    checksum_algorithm: str | None = None


@dataclass
class TransferTask:
    """A transfer task's bookkeeping, on the logical clock.

    Progress is whole files, in list order: ``files_done`` is how many
    of ``files`` had finished at the last moment anyone pinned it down,
    and while the task is ACTIVE with a ``due_at`` the rest arrive
    linearly between ``active_since`` and ``due_at`` (see
    World.files_done_now).  Nothing is stored that the clock can derive,
    which is what keeps the round trip honest: a dump taken mid-transfer
    reloads to a task at the same point, because the point is a function
    of the dump's own ``clock``.

    ``request_time`` and ``completion_time`` are integer seconds on the
    world clock, rendered as ISO 8601 on the wire.
    """

    task_id: str
    owner_id: str
    owner_string: str
    source_endpoint_id: str
    destination_endpoint_id: str
    status: str
    request_time: int
    files: list[TransferFile]
    completion_time: int | None = None
    files_done: int = 0
    active_since: int = 0
    due_at: int | None = None
    faults: int = 0
    fatal_error: dict[str, Any] | None = None
    label: str | None = None
    source_base_path: str | None = None
    destination_base_path: str | None = None


def _iso(seconds: int) -> str:
    """World-clock seconds as the recorded wire format: ``2024-02-06T06:59:02+00:00``."""
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat()


def _parse_filter_instant(raw: str) -> float:
    """One side of ``filter_completion_time``, as epoch seconds.

    DOCUMENTED formats (the SDK docstring, quoting the reference):
    ``YYYY-MM-DDTHH:MM:SS``, with ``+/-HH:MM`` or ``Z`` or neither; a
    space may stand in for the ``T``; no zone means UTC.  The SDK
    itself always sends the second form — ``isoformat(timespec=
    "seconds")`` on an aware datetime gives ``+00:00`` — and requests
    percent-encodes the ``+``.

    One tolerance on top, for people with curl: an *unencoded* ``+`` in
    a query string decodes as a space, so ``...T12:00:00+00:00`` arrives
    as ``...T12:00:00 00:00``.  A trailing `` HH:MM`` after a time can
    only have been an offset, so it is read as one.
    """
    text = raw.strip()
    if re.search(r"\d{2}:\d{2}:\d{2} \d{2}:\d{2}$", text):
        text = text[:-6] + "+" + text[-5:]
    try:
        instant = datetime.fromisoformat(text)
    except ValueError:
        raise transfer_bad_request(
            f"filter_completion_time: {raw!r} is not an ISO 8601 date-time"
        ) from None
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=UTC)
    return instant.timestamp()


class World:
    """All mutable state, plus its (de)serialization for seed/state.

    The server holds one World behind a lock.  Everything here is plain
    data in, plain data out — no HTTP awareness.

    That split is the load-bearing design decision of the codebase:
    world.py knows the *rules* of the imitated service (who may do
    what, and when); server.py knows the *wire* (sockets, headers,
    routing).  You could drive a World from a REPL with no socket in
    sight.  Errors are raised, not returned — see errors.ApiError for
    why that keeps every signature clean.
    """

    def __init__(self) -> None:
        self.clock: int = 0
        self.counters: dict[str, int] = {}
        self.groups: dict[str, Group] = {}
        self.pinned_identities: dict[str, dict[str, str]] = {}  # token -> {identity_id, username}
        self.preferences: dict[str, dict[str, Any]] = {}  # identity_id -> prefs doc
        self.clients: dict[str, OAuthClient] = {}  # client_id -> registration
        self.tokens: dict[str, IssuedToken] = {}  # access token -> what it authorizes
        # Slice B.  The first two are configuration that lives in the
        # world rather than on the server, because the seed is
        # authoritative: a state dump must describe the world it came
        # from, and a world whose issuer lived only in a CLI flag would
        # dump as something else.  None means "not set here" — the
        # server's --issuer / --signed-token-clock defaults apply.
        self.issuer: str | None = None
        self.signed_token_clock: str | None = None
        self.identity_providers: dict[str, IdentityProvider] = {}
        self.accounts: dict[str, Account] = {}  # primary identity id -> account
        # The ephemeral half: a login in flight is world state too, so it
        # dumps and restores like everything else (a half-finished login
        # is a thing a harness can capture and replay).
        self.authorization_requests: dict[str, AuthorizationRequest] = {}
        self.authorization_codes: dict[str, AuthorizationCode] = {}
        self.sessions: dict[str, Session] = {}
        # Transfer task monitoring.  Collections (with their role grants)
        # are seeded and never change through the imitated surface —
        # the slice reads tasks, it does not administer endpoints.  Tasks
        # arrive by seed or through /_fauxbus/transfer/tasks and move
        # along by control-plane call or by tick.
        self.collections: dict[str, Collection] = {}
        self.transfer_tasks: dict[str, TransferTask] = {}

    # ------------------------------------------------------------------ ids

    def next_id(self, kind: str) -> str:
        # Determinism, layer by layer: a per-kind counter lives in world
        # state, and ids.sequential_id hashes (kind, counter) into a
        # stable UUID.  Reset the world → counters return to zero → the
        # next group created gets the same id as last run's first group.
        n = self.counters.get(kind, 0)
        self.counters[kind] = n + 1
        return sequential_id(kind, n)

    # ----------------------------------------------------------- identities

    def identity_for_token(self, token: str) -> Identity:
        # Three layers, most specific first.
        #
        # 1. A token Fauxbus *issued* knows exactly who it belongs to,
        #    and that beats everything: the token endpoint already
        #    decided this question when it minted the thing.  Skipping
        #    this layer would let a service fetch a token as itself and
        #    then be seen by Groups as a hash of the token text.
        # 2. Pins win over derivation: a seed's ``identities`` section
        #    maps chosen tokens to chosen UUIDs (how tests pin alice).
        # 3. Anything else falls through to the hash-derived identity.
        #
        # Either way the answer never changes between calls — that's the
        # contract.
        issued = self.tokens.get(token)
        if issued is not None:
            return Identity(identity_id=issued.identity_id, username=issued.username)
        pin = self.pinned_identities.get(token)
        if pin is not None:
            return Identity(identity_id=pin["identity_id"], username=pin["username"])
        return derive_identity(token)

    def username_for(self, identity_id: str) -> str:
        # Linear scan over pins, and that's fine: worlds are test-sized.
        # Clarity beats a reverse index we'd have to keep consistent.
        for pin in self.pinned_identities.values():
            if pin["identity_id"] == identity_id:
                return pin["username"]
        # A registered client is an identity too (see OAuthClient), so a
        # service added to a group by its client_id renders under its own
        # name rather than as a bare UUID placeholder.
        client = self.clients.get(identity_id)
        if client is not None:
            return client.username
        return placeholder_username(identity_id)

    # ------------------------------------------------------- oauth2 clients

    def authenticate_client(self, client_id: str, secret: str) -> OAuthClient:
        """Prove a confidential client is itself, or raise invalid_client.

        Two deliberate choices here.

        The comparison is a plain ``!=``.  A real service must use
        ``secrets.compare_digest``, because a byte-at-a-time comparison
        leaks the secret through timing.  Fauxbus does not, and says so
        rather than performing the ritual: the secrets in this registry
        arrive from a seed file that lives in the consumer's repository,
        there is nothing here worth stealing, and dressing a fake in
        security-grade primitives invites someone to mistake it for one.
        If you are copying this loop into something real, that is the
        line to change.

        The *error code* is the same either way — an unknown client and a
        wrong secret both answer ``invalid_client`` — because that is
        what the real service does and a consumer's error handling should
        meet the same wall against the fake.  Only the human-facing
        ``error_description`` distinguishes them, which is safe precisely
        because the SDK surfaces it nowhere (see errors.OAuthError): a
        test cannot come to depend on the distinction, and a developer
        curling the endpoint still learns whether they mistyped the id or
        the secret.
        """
        client = self.clients.get(client_id)
        if client is None:
            raise invalid_client(
                f"no client is registered with id {client_id!r}. Register one in the "
                f"seed document's 'clients' section."
            )
        if client.secret != secret:
            raise invalid_client(f"the secret presented for client {client_id!r} does not match")
        return client

    def scopes_by_resource_server(self, scopes: list[str]) -> dict[str, list[str]]:
        """Sort a request's scopes by the service each one is good at.

        A Globus access token belongs to exactly one resource server, and
        the request names it only indirectly — inside the scope strings.
        A request may name several, and the real service answers that
        with one token per service: a primary at the top of the document
        and the rest in ``other_tokens``.  So this is the function that
        decides how many tokens the endpoint is about to mint and what
        each one is for, and every way it can fail is a loud one.

        The dict keeps the order in which each resource server was first
        named, and that order is the answer to "which token is primary."
        It is PROVISIONAL: every token document globus-sdk 4.8.1 records
        has ``other_tokens: []``, so no fixture shows the real service
        choosing.  First-named is the rule a consumer can predict from
        its own request, which is the most a fake can honestly offer
        while it waits for a recording.  It matters less than it sounds:
        the SDK folds primary and others into ``by_resource_server``,
        which consumers index by service name, and a lookup by name never
        sees the order.  Code that reads ``response["access_token"]`` raw
        off a multi-service request — or takes the first entry of that
        dict, which Python's insertion order will happily hand it — is
        depending on a choice nobody has recorded, against the fake *or*
        the real thing.
        """
        by_server: dict[str, list[str]] = {}
        for scope in scopes:
            if "[" in scope or "]" in scope:
                raise not_implemented(
                    f"Fauxbus does not implement dependent scopes, and {scope!r} declares "
                    f"one. Real client code needs them?"
                )
            resource_server = resource_server_for_scope(scope)
            if resource_server is None:
                raise not_implemented(
                    f"Fauxbus cannot tell which resource server the scope {scope!r} belongs "
                    f"to, so it will not guess which service to mint a token for. Real "
                    f"client code uses this scope form?"
                )
            by_server.setdefault(resource_server, []).append(scope)
        return by_server

    def issue_token(
        self,
        client: OAuthClient,
        *,
        resource_server: str,
        scopes: list[str],
        grant_type: str,
        expires_in: int = DEFAULT_EXPIRES_IN,
        code: AuthorizationCode | None = None,
    ) -> IssuedToken:
        """Mint one access token and remember what it authorizes.

        The expiry is on the *logical* clock (World.clock), not the wall
        clock — so a test expires a token by POSTing to
        ``/_fauxbus/tick``, deterministically, rather than by sleeping
        for two days.  SPEC principle 3 holds here without an exception,
        because Fauxbus is the only thing that will ever validate this
        token.  Signed ID tokens are the one place it cannot hold — see
        ``id_token_claims``.

        Who the token *acts as* is the one thing that differs between the
        two grants.  Under client_credentials no person is present, so
        the token acts as the client, which is an identity in its own
        right.  Under authorization_code a person signed in, and the
        token acts as their *effective* identity — the client is only the
        requester.  That is the moment ``sub`` and ``client_id`` come
        apart in introspection, which slice A.2 predicted in a comment.
        """
        counter = self.counters.get("access_token", 0)
        self.counters["access_token"] = counter + 1
        if code is None:
            # A client IS its identity — see OAuthClient.
            identity_id, username = client.client_id, client.username
            account = authenticated_at = None
        else:
            identity = self.accounts[code.account].identities[code.identity_id]
            identity_id, username = identity.id, identity.username
            account, authenticated_at = code.account, code.authenticated_at
        issued = IssuedToken(
            token=access_token(counter),
            client_id=client.client_id,
            identity_id=identity_id,
            username=username,
            resource_server=resource_server,
            scopes=list(scopes),
            grant_type=grant_type,
            issued_at=self.clock,
            expires_at=self.clock + expires_in,
            account=account,
            authenticated_at=authenticated_at,
        )
        self.tokens[issued.token] = issued
        return issued

    def token_response(
        self, issued: IssuedToken, others: list[IssuedToken] | None = None
    ) -> dict[str, Any]:
        """The token document, field for field as globus-sdk expects it.

        RECORDED from
        ``globus_sdk/testing/data/auth/oauth2_client_credentials_tokens.py``
        (4.8.1).  ``other_tokens`` is the field to be careful about: it is
        present unconditionally, as ``[]``, even when a single token is
        issued.  That is not decoration — the SDK's
        ``OAuthTokenResponse._init_rs_dict`` indexes ``self["other_tokens"]``
        with no ``.get`` and no default, so omitting it raises a KeyError
        inside the SDK before the consumer's code ever sees the response.

        When a request spans services, each extra token rides in
        ``other_tokens`` as a document of its own.  The *entry* shape is
        PROVISIONAL — no recorded fixture has a non-empty list — but it is
        pinned from the reader's side: ``_init_rs_dict`` runs every entry
        through the same ``_convert_token_info_dict`` as the top level,
        which requires ``scope``, ``access_token`` and ``resource_server``
        and reads ``expires_in`` and ``token_type``.  So an entry carries
        the same five token fields the top level does, and not
        ``other_tokens`` itself — a token nested inside a token's list of
        other tokens would be a recursion nobody reads.

        ``expires_in`` is computed against the current clock rather than
        stored, so a token fetched, then aged with ``/_fauxbus/tick``,
        then re-rendered still reports the truth.
        """
        return {
            **self._token_fields(issued),
            "other_tokens": [self._token_fields(other) for other in others or []],
        }

    def _token_fields(self, issued: IssuedToken) -> dict[str, Any]:
        """The five fields every token in a token document carries."""
        return {
            "access_token": issued.token,
            "scope": " ".join(issued.scopes),
            "expires_in": max(0, issued.expires_at - self.clock),
            "token_type": "Bearer",
            "resource_server": issued.resource_server,
        }

    def require_issued(self, token: str, resource_server: str | None) -> IssuedToken:
        """Issued-token mode: the three checks the permissive default cannot make.

        Off by default (``--require-issued-tokens`` turns it on), because
        every consumer written against Fauxbus so far assumes any bearer
        token works and a fake that silently starts rejecting them broke
        its users to gain a feature nobody asked for.

        Turned on, it catches what the derive-from-the-string model
        structurally cannot: a token nobody issued, a token that has
        aged out, and a token minted for a different service.  Those are
        three real production failures that a consumer currently cannot
        write a test for, because the fake says yes to everything.

        What is deliberately *not* checked is per-operation scope — that
        a token carrying only ``view_my_groups_and_memberships`` may not
        create a group.  The scope names are SDK-grounded, but which
        operations each one covers is not, and a fake that rejects calls
        the real service allows is worse than one that permits too much:
        the first breaks working consumer code, the second only fails to
        catch a bug.  It is on the recording list.
        """
        issued = self.active_token(token)
        if issued is None:
            raise self._why_not_active(token)
        if resource_server is not None and issued.resource_server != resource_server:
            # PROVISIONAL: 403 rather than 401.  The token is genuine and
            # introspects fine — it simply is not good at this service —
            # which reads as "authenticated, not authorized."  Real Globus
            # services have not been observed answering this case, so the
            # status is an inference and the recording list says so.
            raise ApiError(
                403,
                "FORBIDDEN",
                f"That token was issued for {issued.resource_server}, and this endpoint "
                f"belongs to {resource_server}. A Globus access token is good at exactly "
                f"one resource server.",
            )
        return issued

    def active_token(self, token: str) -> IssuedToken | None:
        """The record for a token that is good *right now*, or None.

        One predicate, three callers, so they cannot drift: strict-mode
        authentication turns None into a 401, introspection turns it into
        ``active: false``, and revocation uses it to decide there is
        nothing to revoke.  Before this existed the expiry rule was
        spelled out inside ``require_issued`` alone; the moment a second
        surface needed the same question asked, a copy of that rule would
        have been a bug waiting for someone to fix only one of them.

        "Good right now" is three things: issued by this world, not
        revoked, and not aged past its expiry on the logical clock.  What
        it deliberately does *not* ask is which resource server the token
        is for — that is a question about a particular call, not about
        the token, and it belongs to the caller that knows the endpoint.
        """
        issued = self.tokens.get(token)
        if issued is None or issued.revoked or issued.expires_at <= self.clock:
            return None
        return issued

    def _why_not_active(self, token: str) -> ApiError:
        """The same no, said three different ways, because the fix differs.

        ``active_token`` answers yes or no; this answers "and here is
        what to do about it."  A token nobody issued means seed one or
        fetch one.  An expired token means tick, or don't.  A revoked
        token means the harness already did this on purpose and has
        forgotten.  Three very different afternoons, and a single
        "unauthorized" would have sent all of them to the same wrong
        place.
        """
        issued = self.tokens.get(token)
        if issued is None:
            return ApiError(
                401,
                "UNAUTHORIZED",
                "This Fauxbus runs with --require-issued-tokens, and no token by that "
                "name was issued here. Get one from POST /v2/oauth2/token, or seed it "
                "into the state document's 'tokens' section.",
            )
        if issued.revoked:
            return ApiError(
                401,
                "UNAUTHORIZED",
                "That token was revoked through POST /v2/oauth2/token/revoke. Revocation "
                "is world state, so POST /_fauxbus/reset undoes it along with everything "
                "else.",
            )
        return ApiError(
            401,
            "UNAUTHORIZED",
            f"Token expired at logical clock {issued.expires_at}; the clock now reads "
            f"{self.clock}. Fauxbus expires tokens on POST /_fauxbus/tick, never on "
            f"real time.",
        )

    def introspect(self, token: str) -> dict[str, Any]:
        """RFC 7662 introspection: what this Auth will say about a token.

        The document is RECORDED, key for key, from
        ``globus_sdk/testing/data/auth/oauth2_token_introspect.py``
        (4.8.1).  Two of the values in it are not.

        **The timestamps are on the logical clock.**  This is the first
        place the clock from principle 3 reaches the wire as an
        *instant* rather than a duration — ``expires_in`` was 172800
        against either clock, but ``exp`` is a point in time and has to
        pick one.  It picks Fauxbus's: ``iat`` is the clock when the
        token was minted, ``exp`` is that plus its lifetime, and
        ``/_fauxbus/tick`` is what moves them.  A fresh world starts at
        zero, so out of the box these read as 1970, and consumer code
        that compares ``exp`` against ``time.time()`` will call every
        token expired.

        The knob for that already exists and needed only to be said
        aloud: seed ``"clock": 1767225600`` and every timestamp on this
        endpoint is a real 2026 second.  It stays deterministic because
        *you* chose the number — which is the whole difference between a
        logical clock and a wall clock, and the reason Fauxbus will not
        pick a plausible-looking epoch on your behalf.

        **``aud`` is PROVISIONAL.**  The fixture shows
        ``[resource server, client_id]`` for a token whose resource
        server happened to be auth.globus.org, so the generalization to
        any resource server is an inference, not a recording.  It is on
        the list.
        """
        issued = self.active_token(token)
        if issued is None:
            # RFC 7662 §2.2, and recorded besides — the SDK's *revoke*
            # fixture is the bare ``{"active": False}``.  Nothing else
            # belongs in this document: not a reason, not an error code,
            # not a hint.  A caller asking about a token is not entitled
            # to learn whether it ever existed, when it died, or why.
            #
            # Which means this one answer covers four different worlds —
            # never issued, expired, revoked, and issued to someone else
            # entirely — and a harness debugging "why is my token
            # inactive" gets nothing from this endpoint.  That is the
            # correct behaviour and an annoying afternoon, so: the
            # answers are all in GET /_fauxbus/state, which is out-of-band
            # (principle 4) and under no obligation to be discreet.
            return {"active": False}
        client = self.clients.get(issued.client_id)
        person = self._person(issued)
        return {
            "active": True,
            "token_type": "Bearer",
            "scope": " ".join(issued.scopes),
            "client_id": issued.client_id,
            # The subject is an identity, and for a client_credentials
            # token that identity IS the client (see OAuthClient) — so
            # ``sub`` and ``client_id`` are the same UUID there, and that
            # is faithful rather than lazy.  They come apart for an
            # authorization-code token, where the person's *effective*
            # identity is the subject and the client only the requester.
            "sub": issued.identity_id,
            "username": issued.username,
            # PROVISIONAL: a client identity has no mailbox, and the
            # fixture's subject was a person.  The key is present and
            # null rather than absent, on the same reasoning that keeps
            # ``other_tokens`` present and empty: a consumer should meet
            # the same key set every time, and learn the answer from the
            # value.  A seeded token may name a client that was never
            # registered — deliberately allowed — which is the other way
            # ``name`` arrives as null.
            "name": person.name if person else client.name if client is not None else None,
            # A person has a mailbox; a client does not (see above).  The
            # recorded fixture's subject is a person, so this is the
            # branch the recording actually grounds.
            "email": person.email if person else None,
            "exp": issued.expires_at,
            "iat": issued.issued_at,
            # RFC 7662 §2.2: ``nbf`` is when the token becomes valid.
            # Fauxbus has no not-yet-valid tokens — a minted token works
            # immediately — so it equals ``iat``, which is also what the
            # recorded fixture shows.
            "nbf": issued.issued_at,
            # PROVISIONAL generalization; see the docstring.
            "aud": [issued.resource_server, issued.client_id],
            "iss": AUTH_ISSUER,
        }

    def _person(self, issued: IssuedToken) -> GlobusIdentity | None:
        """The signed-in identity behind a token, or None for a client's own token."""
        account = self.accounts.get(issued.account) if issued.account else None
        return account.identities.get(issued.identity_id) if account else None

    def revoke(self, client: OAuthClient, token: str) -> None:
        """Retire a token, if it is this client's to retire.

        Three decisions worth reading, because none is obvious.

        **A token nobody issued is not an error.**  RFC 7009 §2.2 is
        explicit: the endpoint answers 200 whether or not the token
        existed.  Revocation is idempotent by design, so a client
        cleaning up need not first find out what it holds.

        **Another client's token is invisible, not forbidden.**  RFC 7009
        §2.1 says a server MUST verify the token was issued to the client
        doing the asking, and refusing with an error would be the obvious
        reading.  It would also turn this endpoint into an oracle: ask
        about a string, and a 200 means "never existed" while an error
        means "exists, belongs to someone else."  So the answer is the
        same 200 and nothing happens — indistinguishable from the token
        never having been there, which is what a stranger is entitled to
        know.  PROVISIONAL: the real service has not been observed here.

        **The record survives, flagged.**  Deleting it would drop the
        token back through ``identity_for_token`` to the hash-derived
        default, where it would come back to life as a *different*
        caller — the fake disagreeing with itself about who just called.
        A ``revoked`` flag keeps one answer to that question.

        Note what this does not do in the permissive default: nothing
        visible.  A revoked token still authenticates, because the
        permissive surface checks no tokens at all — the same reason an
        expired one does.  Revocation bites under
        ``--require-issued-tokens``, which is the mode where "issued
        here" is a question anyone is asking.
        """
        issued = self.tokens.get(token)
        if issued is None or issued.client_id != client.client_id:
            return
        issued.revoked = True

    # ----------------------------------------------------------------- oidc

    def login_client(self, client_id: str, redirect_uri: str) -> OAuthClient:
        """The two checks the authorize endpoint makes before it trusts a redirect URI.

        Everything after these may be reported by redirecting the browser
        back to the client with ``error=`` on the query string (RFC 6749
        §4.1.2.1).  These two may not, because their failure means the
        redirect URI itself is not trustworthy, and redirecting to an
        unvetted URI on an error is how an authorization server becomes an
        open redirector.  So their errors are rendered, never redirected.

        The match is exact, string for string, with no normalization —
        not trailing slashes, not case, not query order.  That is what
        the RFC 6749 §3.1.2.3 and OAuth security BCP require, it is what
        Keycloak does on its own side, and a fake that matched loosely
        would pass a test that production fails.
        """
        if not client_id:
            raise invalid_request("'client_id' is required.")
        client = self.clients.get(client_id)
        if client is None:
            raise invalid_request(
                f"no client is registered with id {client_id!r}, so there is no redirect URI "
                f"Fauxbus can trust to report that to. Register it in the seed's 'clients'."
            )
        if not redirect_uri:
            raise invalid_request("'redirect_uri' is required.")
        if redirect_uri not in client.redirect_uris:
            raise invalid_request(
                f"redirect_uri {redirect_uri!r} is not registered for client {client_id}. "
                f"Registered: {client.redirect_uris or 'none'}. The match is exact — no "
                f"trailing-slash or case forgiveness."
            )
        return client

    def park_authorization(
        self,
        client: OAuthClient,
        *,
        redirect_uri: str,
        scopes: list[str],
        state: str | None,
        nonce: str | None,
        code_challenge: str | None,
    ) -> AuthorizationRequest:
        n = self.counters.get("authorization_request", 0)
        self.counters["authorization_request"] = n + 1
        request = AuthorizationRequest(
            id=minted_name(REQUEST_PREFIX, n),
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scopes=list(scopes),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
        self.authorization_requests[request.id] = request
        return request

    def open_session(self, account_id: str, authenticated_at: int) -> Session:
        if account_id not in self.accounts:
            raise validation_error(
                f"no account has primary identity {account_id!r}; seed it under 'accounts'."
            )
        n = self.counters.get("session", 0)
        self.counters["session"] = n + 1
        session = Session(minted_name(SESSION_PREFIX, n), account_id, authenticated_at)
        self.sessions[session.id] = session
        return session

    def effective_identity(self, account: Account, client: OAuthClient) -> GlobusIdentity | None:
        """Which of an account's identities signs in to this client — or None.

        DOCUMENTED (docs.globus.org/api/auth/reference, read 2026-10-12):
        ``sub`` is "the effective identity of the logged in Globus
        account," which is "the primary identity, or the appropriate
        linked identity if this client requires an identity from a
        particular provider."

        So without ``required_idp`` it is the primary.  With it, it is
        the identity from that provider — the primary itself if the
        primary qualifies, otherwise the linked identity with the lowest
        UUID if several do (an arbitrary but stable tiebreak for a case
        the docs do not address).  None means the account has no
        identity from that provider at all, and the login cannot finish.

        This is the line the whole slice exists for, from the consumer's
        side: an account whose primary is Globus ID signs in to a
        university's service *as its university identity*, and the
        service authorizes on that UUID.
        """
        if client.required_idp is None:
            return account.identities[account.primary]
        for identity in account.ordered():
            if identity.identity_provider == client.required_idp:
                return identity
        return None

    def complete_authorization(
        self, request: AuthorizationRequest, session: Session
    ) -> AuthorizationCode:
        """Turn a parked request plus a signed-in account into a one-use code.

        Raises ``RequiredIdpUnsatisfied`` when the client demands an
        identity provider this account has no identity from.  The request
        stays parked when that happens: the browser is still at the
        picker, and another account may do.
        """
        client = self.clients.get(request.client_id)
        account = self.accounts.get(session.account)
        if client is None or account is None:
            # Only reachable if a harness re-seeded the world out from under
            # a login in flight; the seed door validates both otherwise.
            raise validation_error("the client or account behind this login no longer exists")
        identity = self.effective_identity(account, client)
        if identity is None:
            raise RequiredIdpUnsatisfied(client, account, self.identity_providers)
        n = self.counters.get("authorization_code", 0)
        self.counters["authorization_code"] = n + 1
        code = AuthorizationCode(
            code=minted_name(CODE_PREFIX, n),
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scopes=list(request.scopes),
            state=request.state,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            account=account.primary,
            identity_id=identity.id,
            authenticated_at=session.authenticated_at,
            issued_at=self.clock,
            expires_at=self.clock + CODE_LIFETIME,
        )
        self.authorization_codes[code.code] = code
        del self.authorization_requests[request.id]
        return code

    def redeem_code(
        self,
        client: OAuthClient,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
    ) -> AuthorizationCode:
        """RFC 6749 §4.1.3: every binding checked, any mismatch the same refusal.

        Every failure is ``invalid_grant`` — RECORDED as a 401 with the
        bare ``{"error": "invalid_grant"}`` in
        ``oauth2_exchange_code_for_tokens.py`` — and a program cannot tell
        them apart, which is correct: "this code is someone else's" and
        "this code does not exist" must look the same to a caller who
        might be guessing.  The ``error_description`` tells a human which
        one it was, as it does everywhere else on this endpoint.

        The code is spent only on *success*.  A failed exchange — wrong
        verifier, wrong redirect — leaves it redeemable by the right
        caller.  What RFC 6749 §4.1.2 adds for a *second successful-looking*
        redemption (revoke everything the first one minted) is not built:
        a replayed code is refused, which is the part a broker's test can
        observe, and nobody has asked for the cascade.
        """
        record = self.authorization_codes.get(code)
        if record is None:
            raise invalid_grant("no such authorization code was issued here.")
        if record.used:
            raise invalid_grant("that authorization code has already been redeemed; codes are one-use.")
        if record.expires_at <= self.clock:
            raise invalid_grant(
                f"that authorization code expired at logical clock {record.expires_at}; the "
                f"clock now reads {self.clock}. Codes age on POST /_fauxbus/tick, never on "
                f"real time."
            )
        if record.client_id != client.client_id:
            raise invalid_grant("that authorization code was issued to a different client.")
        if record.redirect_uri != redirect_uri:
            raise invalid_grant(
                "redirect_uri does not match the one the authorization request used "
                "(RFC 6749 §4.1.3: it must be identical)."
            )
        if record.code_challenge is not None:
            # RFC 7636 §4.6, S256: BASE64URL(SHA256(verifier)) == challenge.
            if not code_verifier:
                raise invalid_grant("this code was issued with a PKCE challenge; 'code_verifier' is required.")
            derived = b64url(hashlib.sha256(code_verifier.encode("ascii", "replace")).digest())
            if derived != record.code_challenge:
                raise invalid_grant("code_verifier does not match the code_challenge (S256).")
        elif code_verifier:
            # A verifier for a code that never had a challenge is a client
            # confused about which login it is finishing.  RFC 7636 is
            # silent; refusing beats silently ignoring a security
            # parameter the client believes is being checked.
            raise invalid_grant("a code_verifier was sent, but this code was issued without a code_challenge.")
        record.used = True
        return record

    def identity_claims(
        self, account_id: str, identity_id: str, scopes: list[str], authenticated_at: int
    ) -> dict[str, Any]:
        """The claims about a person, shared by the ID token and userinfo.

        One function for both, because OIDC Core §5.3.2 requires
        userinfo's ``sub`` to equal the ID token's — and Keycloak checks
        exactly that, refusing the login if they differ.  Two functions
        would be two chances to drift.

        Scope gating is DOCUMENTED (docs.globus.org/api/auth/reference,
        read 2026-10-12): ``openid`` gives ``sub``, ``last_authentication``
        and ``identity_set``; ``email`` adds ``email``; ``profile`` adds
        ``name``, ``organization``, ``preferred_username``,
        ``identity_provider`` and ``identity_provider_display_name``.
        Note what ``openid`` alone does *not* include: any name or email
        for the person.  A broker that maps ``email`` and forgets to ask
        for the ``email`` scope gets a user with no email, against the
        fake and against the real thing alike.
        """
        account = self.accounts[account_id]
        effective = account.identities[identity_id]
        claims: dict[str, Any] = {
            "sub": effective.id,
            "last_authentication": authenticated_at,
            # PROVISIONAL, and the most consequential provisional in
            # Auth: no SDK fixture has a success body for userinfo or an
            # ID token, and the reference describes identity_set only as
            # "the identities linked to this account."  Each entry reuses
            # the claim names the reference defines for the top level,
            # plus ``username`` (the recorded identity-object field),
            # and every entry carries every field regardless of scope —
            # an inference the first recording session settles.
            "identity_set": [
                {
                    "sub": identity.id,
                    "username": identity.username,
                    "name": identity.name,
                    "email": identity.email,
                    "organization": identity.organization,
                    "identity_provider": identity.identity_provider,
                    "identity_provider_display_name": self._idp_name(identity),
                    # Only the identity that just signed in has a known
                    # last authentication; Fauxbus keeps no login history
                    # for the others, and null says so rather than inventing one.
                    "last_authentication": authenticated_at if identity.id == effective.id else None,
                }
                for identity in account.ordered()
            ],
        }
        if "profile" in scopes:
            claims.update(
                name=effective.name,
                organization=effective.organization,
                preferred_username=effective.username,
                identity_provider=effective.identity_provider,
                identity_provider_display_name=self._idp_name(effective),
            )
        if "email" in scopes:
            claims["email"] = effective.email
        return claims

    def _idp_name(self, identity: GlobusIdentity) -> str | None:
        idp = self.identity_providers.get(identity.identity_provider)
        return idp.name if idp is not None else None

    def id_token_claims(
        self,
        code: AuthorizationCode,
        access_token_value: str,
        *,
        issuer: str,
        now: int,
    ) -> dict[str, Any]:
        """Everything the signed ID token says, before it is signed.

        ``now`` is the signed-token instant the server chose — logical or
        wall, per the world's ``signed_token_clock`` — and this method
        never reads a clock itself.  World stays free of wall time even
        when the server does not.

        ``exp`` is ``iat`` plus the same 172800 seconds the recorded
        token and introspection fixtures show for access tokens; the ID
        token's own lifetime is unrecorded, and matching the access
        token's is the reading least likely to surprise a broker.
        """
        claims = self.identity_claims(code.account, code.identity_id, code.scopes, code.authenticated_at)
        claims.update(
            iss=issuer,
            # A string, not a list: one audience, the client that asked.
            # OIDC Core permits either; a list of one would oblige some
            # verifiers to look for an ``azp`` claim as well.
            aud=code.client_id,
            iat=now,
            exp=now + DEFAULT_EXPIRES_IN,
            at_hash=at_hash(access_token_value),
        )
        if code.nonce is not None:
            # OIDC Core §3.1.3.7: echoed unchanged, and only when sent.
            # The broker compares it to the nonce it generated, which is
            # what stops an ID token from one login being replayed into
            # another.
            claims["nonce"] = code.nonce
        return claims

    def userinfo_token(self, token: str | None) -> IssuedToken:
        """The access token userinfo will describe, or the recorded refusal.

        Userinfo is always strict, whatever ``--require-issued-tokens``
        says, for the same reason introspection is: its answer *is* the
        issued record.  A made-up bearer string has no account behind it
        and nothing to say.

        The statuses are PROVISIONAL even though both bodies are
        RECORDED.  The fixtures show a 401 and a 403 with identical text
        and no hint of which situation earns which.  Fauxbus reads them
        as the usual pair: 401 when there is no live token at all
        (missing, unknown, expired, revoked), 403 when the token is
        genuine but not one userinfo serves — the published reference
        requires a token "valid for at least the openid scope," and a
        token minted without a person behind it is not.
        """
        issued = self.active_token(token) if token else None
        if issued is None:
            raise auth_unauthorized()
        if (
            issued.resource_server != AUTH_RESOURCE_SERVER
            or "openid" not in issued.scopes
            or issued.account is None
            or issued.account not in self.accounts
        ):
            raise auth_forbidden()
        return issued

    def userinfo(self, issued: IssuedToken) -> dict[str, Any]:
        assert issued.account is not None and issued.authenticated_at is not None
        return self.identity_claims(
            issued.account, issued.identity_id, issued.scopes, issued.authenticated_at
        )

    # --------------------------------------------------------------- groups

    def get_group(self, group_id: str, caller: Identity) -> Group:
        # The one gate every group-touching path goes through: update,
        # delete, policies, batch — all resolve their group HERE.  So
        # the visibility rule and the 404-for-invisible stance (see
        # errors.group_not_found) hold everywhere by construction:
        # nobody can forget the check, because nobody else performs it.
        group_id = _require_uuid(group_id, "group_id")
        group = self.groups.get(group_id)
        if group is None or not group.visible_to(caller.identity_id):
            raise group_not_found(group_id)
        return group

    def create_group(self, caller: Identity, data: dict[str, Any]) -> Group:
        if not isinstance(data, dict) or not isinstance(data.get("name"), str) or not data["name"]:
            raise validation_error("group document requires a non-empty 'name'")
        parent_id = data.get("parent_id")
        if parent_id is not None:
            parent = self.get_group(str(parent_id), caller)
            # PROVISIONAL: subgroup creation requires admin on the parent.
            if not parent.is_admin(caller.identity_id):
                raise ApiError(403, "FORBIDDEN", "subgroup creation requires admin on the parent group")
            parent_id = parent.id
        group = Group(
            id=self.next_id("group"),
            name=data["name"],
            description=data.get("description"),
            parent_id=parent_id,
        )
        # The creating identity becomes an active admin.  (DOCUMENTED —
        # Globus's own docs; the SDK fixture's canned "member" role is a
        # canned response, not causality.)
        group.memberships[caller.identity_id] = Membership(
            identity_id=caller.identity_id,
            username=caller.username,
            role="admin",
            status="active",
        )
        self.groups[group.id] = group
        return group

    def update_group(self, caller: Identity, group_id: str, data: dict[str, Any]) -> Group:
        group = self.get_group(group_id, caller)
        # PROVISIONAL: update requires admin.
        if not group.is_admin(caller.identity_id):
            raise ApiError(403, "FORBIDDEN", "updating a group requires the admin role")
        if not isinstance(data, dict):
            raise validation_error("group update document must be an object")
        if "name" in data:
            if not isinstance(data["name"], str) or not data["name"]:
                raise validation_error("'name' must be a non-empty string")
            group.name = data["name"]
        if "description" in data:
            group.description = data["description"]
        return group

    def delete_group(self, caller: Identity, group_id: str) -> Group:
        group = self.get_group(group_id, caller)
        if not group.is_admin(caller.identity_id):
            raise ApiError(403, "FORBIDDEN", "deleting a group requires the admin role")
        # PROVISIONAL: deletion cascades to subgroups so no group is ever
        # left with a dangling parent_id.
        # The loop is a worklist: pop a doomed id, enqueue its children,
        # repeat — subtree deletion without recursion, and grandchildren
        # can't slip through because every popped id re-scans for kids.
        doomed = [group.id]
        while doomed:
            gid = doomed.pop()
            doomed.extend(g.id for g in self.groups.values() if g.parent_id == gid)
            self.groups.pop(gid, None)
        return group

    def child_ids(self, group_id: str) -> list[str]:
        return sorted(g.id for g in self.groups.values() if g.parent_id == group_id)

    def my_groups(self, caller: Identity, statuses: list[str] | None) -> list[Group]:
        found = []
        for group in self.groups.values():
            m = group.memberships.get(caller.identity_id)
            if m is None:
                continue
            if statuses and m.status not in statuses:
                continue
            found.append(group)
        return sorted(found, key=lambda g: g.id)

    # ------------------------------------------------------------- policies

    def set_policies(self, caller: Identity, group_id: str, data: dict[str, Any]) -> Group:
        group = self.get_group(group_id, caller)
        if not group.is_admin(caller.identity_id):
            raise ApiError(403, "FORBIDDEN", "setting policies requires the admin role")
        if not isinstance(data, dict):
            raise validation_error("policy document must be an object")
        unknown = set(data) - set(DEFAULT_POLICIES)
        if unknown:
            raise validation_error(f"unknown policy fields: {sorted(unknown)}")
        group.policies.update(data)
        return group

    # ---------------------------------------------------------- preferences

    def get_preferences(self, caller: Identity) -> dict[str, Any]:
        return self.preferences.get(caller.identity_id, {"allow_add": True})

    def set_preferences(self, caller: Identity, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise validation_error("preferences document must be an object")
        prefs = {"allow_add": bool(data.get("allow_add", True))}
        self.preferences[caller.identity_id] = prefs
        return prefs

    def allow_add(self, identity_id: str) -> bool:
        return bool(self.preferences.get(identity_id, {}).get("allow_add", True))

    # ------------------------------------------------------ batch membership

    def batch_action(
        self, caller: Identity, group_id: str, actions: dict[str, Any]
    ) -> dict[str, Any]:
        """Apply a batch membership document; partial success by design.

        PROVISIONAL response shape (the top recording priority): each verb
        key maps to the resulting membership documents; failures collect
        under "errors" as {verb: [{identity_id, code, detail}]}.  HTTP 200
        either way — partial success is the service's signature move.
        """
        group = self.get_group(group_id, caller)
        if not isinstance(actions, dict) or not actions:
            raise validation_error("batch membership document must be a non-empty object")
        unknown = set(actions) - set(BATCH_VERBS)
        if unknown:
            raise validation_error(f"unknown membership verbs: {sorted(unknown)}")

        results: dict[str, Any] = {}
        errors: dict[str, list[dict[str, str]]] = {}
        # Iterate OUR canonical verb list, not the request's keys: two
        # requests spelling the same actions in different JSON key order
        # must produce identical results and identical response bodies.
        # The request's ordering is an accident of serialization; the
        # world's must never be.
        for verb in BATCH_VERBS:
            entries = actions.get(verb)
            if entries is None:
                continue
            if not isinstance(entries, list):
                raise validation_error(f"'{verb}' must be a list of membership entries")
            for entry in entries:
                if not isinstance(entry, dict) or "identity_id" not in entry:
                    raise validation_error(f"every '{verb}' entry requires an identity_id")
                target = _require_uuid(str(entry["identity_id"]), "identity_id")
                try:
                    membership = self._apply_verb(caller, group, verb, target, entry)
                    results.setdefault(verb, []).append(membership.doc(group.id))
                except ApiError as err:
                    errors.setdefault(verb, []).append(
                        {"identity_id": target, "code": err.code, "detail": err.detail}
                    )
        if errors:
            results["errors"] = errors
        return results

    def _apply_verb(
        self, caller: Identity, group: Group, verb: str, target: str, entry: dict[str, Any]
    ) -> Membership:
        # Membership is a small state machine; each verb is one
        # transition with a permission gate.  The whole table:
        #
        #   verb          who        requires status       → new status
        #   add           manager+   not active            → active
        #   invite        manager+   not active            → invited
        #   accept        self       invited               → active
        #   decline       self       invited               → declined
        #   approve       manager+   pending               → active
        #   reject        manager+   pending               → rejected
        #   join          self       not active (open)     → active
        #   request_join  self       not active (requests) → pending
        #   leave         self       active                → left
        #   remove        manager+   active                → removed
        #   change_role   manager+   active                → active (role edits)
        #
        # The two guard clauses below enforce the "who" column once, up
        # front; require_status enforces the middle column per verb.
        # Admin-role edges and the last-admin invariant are the fine
        # print, handled inside the verbs they complicate.
        m = group.memberships.get(target)

        if verb in SELF_VERBS and target != caller.identity_id:
            # v0.1 identity sets are single-identity; a self-verb for any
            # other identity is out of the caller's set by construction.
            raise ApiError(403, "FORBIDDEN", "identity is not in the caller's identity set")
        if verb in MANAGER_VERBS and not group.is_manager(caller.identity_id):
            raise ApiError(403, "FORBIDDEN", f"'{verb}' requires the manager or admin role")

        role = entry.get("role", "member")
        if verb in ("add", "invite", "change_role") and role not in ROLES:
            raise validation_error(f"unknown role: {role!r}")

        def require_status(*allowed: str) -> Membership:
            if m is None or m.status not in allowed:
                have = m.status if m is not None else "no membership"
                raise ApiError(
                    409,
                    "INVALID_STATUS",
                    f"'{verb}' requires status {' or '.join(allowed)}; found {have}",
                )
            return m

        if verb == "add":
            if m is not None and m.status == "active":
                raise ApiError(409, "ALREADY_MEMBER", "identity is already an active member")
            if not self.allow_add(target):
                raise ApiError(
                    403, "NOT_ALLOWED", "identity preferences do not allow being added to groups"
                )
            # PROVISIONAL: only admins may add straight to the admin role.
            if role == "admin" and not group.is_admin(caller.identity_id):
                raise ApiError(403, "FORBIDDEN", "adding an admin requires the admin role")
            new = Membership(target, self.username_for(target), role, "active")
            group.memberships[target] = new
            return new

        if verb == "invite":
            if m is not None and m.status == "active":
                raise ApiError(409, "ALREADY_MEMBER", "identity is already an active member")
            if role == "admin" and not group.is_admin(caller.identity_id):
                raise ApiError(403, "FORBIDDEN", "inviting an admin requires the admin role")
            new = Membership(target, self.username_for(target), role, "invited")
            group.memberships[target] = new
            return new

        if verb == "accept":
            m = require_status("invited")
            m.status = "active"
            m.username = caller.username  # the invitee showed up; upgrade the placeholder
            return m

        if verb == "decline":
            m = require_status("invited")
            m.status = "declined"
            return m

        if verb == "approve":
            m = require_status("pending")
            m.status = "active"
            return m

        if verb == "reject":
            m = require_status("pending")
            m.status = "rejected"
            return m

        if verb == "join":
            # PROVISIONAL: direct join is open exactly when the group is
            # visible to all authenticated users.
            if group.policies.get("group_visibility") != "authenticated":
                raise ApiError(403, "FORBIDDEN", "group does not allow direct join")
            if m is not None and m.status == "active":
                raise ApiError(409, "ALREADY_MEMBER", "identity is already an active member")
            new = Membership(target, caller.username, "member", "active")
            group.memberships[target] = new
            return new

        if verb == "request_join":
            if not group.policies.get("join_requests"):
                raise ApiError(403, "FORBIDDEN", "group does not accept join requests")
            if m is not None and m.status == "active":
                raise ApiError(409, "ALREADY_MEMBER", "identity is already an active member")
            new = Membership(target, caller.username, "member", "pending")
            group.memberships[target] = new
            return new

        if verb == "leave":
            m = require_status("active")
            self._guard_last_admin(group, m, "leave")
            m.status = "left"
            return m

        if verb == "remove":
            m = require_status("active")
            if m.role == "admin" and not group.is_admin(caller.identity_id):
                raise ApiError(403, "FORBIDDEN", "removing an admin requires the admin role")
            self._guard_last_admin(group, m, "remove")
            m.status = "removed"
            return m

        if verb == "change_role":
            if "role" not in entry:
                raise validation_error("'change_role' entries require a role")
            m = require_status("active")
            # PROVISIONAL: any change involving the admin role (either
            # direction) requires the admin role — managers cannot touch
            # admins.
            if (m.role == "admin" or role == "admin") and not group.is_admin(caller.identity_id):
                raise ApiError(403, "FORBIDDEN", "changing admin roles requires the admin role")
            if m.role == "admin" and role != "admin":
                self._guard_last_admin(group, m, "demote")
            m.role = role
            return m

        raise validation_error(f"unknown membership verb: {verb!r}")  # unreachable

    @staticmethod
    def _guard_last_admin(group: Group, m: Membership, action: str) -> None:
        # PROVISIONAL: a group may never lose its last active admin.
        # The why: a group with zero active admins is unmanageable
        # forever — nobody left who can add, remove, or delete.
        # Refusing the final leave/remove/demote keeps the world free
        # of dead-end states a test would then have to debug.
        if m.role == "admin" and group.active_admins() == [m.identity_id]:
            raise ApiError(409, "LAST_ADMIN", f"cannot {action} the group's only admin")

    # -------------------------------------------------------- subscriptions

    def group_by_subscription(self, subscription_id: str) -> dict[str, Any]:
        subscription_id = _require_uuid(subscription_id, "subscription_id")
        for group in sorted(self.groups.values(), key=lambda g: g.id):
            if group.subscription_id == subscription_id:
                info = group.subscription_info or {}
                return {
                    "group_id": group.id,
                    "subscription_id": subscription_id,
                    # RECORDED: this endpoint returns the restricted
                    # projection of subscription_info.
                    "subscription_info": {
                        k: v
                        for k, v in info.items()
                        if k in ("is_high_assurance", "is_baa", "connectors")
                    },
                }
        raise ApiError(404, "NOT_FOUND", f"No group provides subscription {subscription_id}")

    def set_subscription_admin_verified(
        self, caller: Identity, group_id: str, subscription_id: str | None
    ) -> Group:
        group = self.get_group(group_id, caller)
        # PROVISIONAL: the real service checks subscription-manager rights;
        # Fauxbus has no subscription-manager concept yet, so group admin
        # is the bar.
        if not group.is_admin(caller.identity_id):
            raise ApiError(403, "FORBIDDEN", "verification requires the admin role")
        if subscription_id is not None:
            subscription_id = _require_uuid(str(subscription_id), "subscription_admin_verified_id")
        group.subscription_admin_verified_id = subscription_id
        return group

    # ----------------------------------------------------- membership fields

    def get_membership_fields(self, caller: Identity, group_id: str) -> dict[str, Any]:
        group = self.get_group(group_id, caller)
        # PROVISIONAL shape: fields are stored and returned as sent.
        return group.membership_fields.get(caller.identity_id, {})

    def set_membership_fields(
        self, caller: Identity, group_id: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        group = self.get_group(group_id, caller)
        if not isinstance(data, dict):
            raise validation_error("membership fields document must be an object")
        group.membership_fields[caller.identity_id] = data
        return data

    # ------------------------------------------------------------ rendering

    def group_doc(
        self, group: Group, caller: Identity, include: list[str] | None = None
    ) -> dict[str, Any]:
        """The single-group document — RECORDED shape (BASE_GROUP_DOC fixture).

        Caller-relative on purpose: ``my_memberships`` is the caller's
        own membership, so alice and bob GET the same group and receive
        different documents — exactly as the real service renders it.
        """
        include = include or []
        my = group.memberships.get(caller.identity_id)
        doc: dict[str, Any] = {
            "name": group.name,
            "description": group.description,
            "parent_id": group.parent_id,
            "id": group.id,
            "group_type": group.group_type,
            "enforce_session": group.enforce_session,
            "session_limit": group.session_limit,
            "session_timeouts": dict(group.session_timeouts),
            "my_memberships": [my.doc(group.id)] if my is not None else [],
            "policies": self._policy_summary(group),
            "subscription_id": group.subscription_id,
            "subscription_info": group.subscription_info,
        }
        if "memberships" in include:
            doc["memberships"] = [
                group.memberships[i].doc(group.id) for i in sorted(group.memberships)
            ]
        if "policies" in include:
            doc["policies"] = dict(group.policies)
        if "child_ids" in include:
            doc["child_ids"] = self.child_ids(group.id)
        if "allowed_actions" in include:
            doc["allowed_actions"] = self._allowed_actions(group, caller)
        return doc

    def my_groups_doc(self, group: Group, caller: Identity) -> dict[str, Any]:
        """The my_groups list entry — RECORDED shape, and it is slimmer than
        the single-group document: no description, no subscription fields."""
        my = group.memberships.get(caller.identity_id)
        return {
            "name": group.name,
            "parent_id": group.parent_id,
            "id": group.id,
            "group_type": group.group_type,
            "enforce_session": group.enforce_session,
            "session_limit": group.session_limit,
            "session_timeouts": dict(group.session_timeouts),
            "my_memberships": [my.doc(group.id)] if my is not None else [],
            "policies": self._policy_summary(group),
        }

    @staticmethod
    def _policy_summary(group: Group) -> dict[str, Any]:
        # RECORDED: group documents embed only the two visibility keys;
        # the full six-field document lives at the policies endpoint.
        return {
            "group_visibility": group.policies.get("group_visibility"),
            "group_members_visibility": group.policies.get("group_members_visibility"),
        }

    def _allowed_actions(self, group: Group, caller: Identity) -> list[str]:
        # PROVISIONAL: role-derived verb list; shape unrecorded.
        m = group.memberships.get(caller.identity_id)
        allowed = set()
        if m is not None:
            if m.status == "active":
                allowed.update({"leave"})
                if m.role in ("manager", "admin"):
                    allowed.update(MANAGER_VERBS)
            if m.status == "invited":
                allowed.update({"accept", "decline"})
        else:
            if group.policies.get("group_visibility") == "authenticated":
                allowed.add("join")
            if group.policies.get("join_requests"):
                allowed.add("request_join")
        return sorted(allowed)

    # ------------------------------------------------------------- transfer
    #
    # The endpoint-manager family: tasks seen by someone who did not
    # submit them, because they hold a role on a collection the task
    # touched.  That distinction is the whole slice — the plain
    # ``task_list`` returns only the caller's own tasks, and a service
    # watching a landing collection never submits anything there.

    def advance_clock(self, seconds: int) -> None:
        """Move logical time forward, and let whatever was due finish.

        The first thing in Fauxbus that ``tick`` *does* rather than
        merely counts, which is what SPEC promised the clock was for on
        day one.  A task that is ACTIVE with a ``due_at`` the new clock
        has reached becomes SUCCEEDED — and its ``completion_time`` is
        its ``due_at``, not the new clock.  A harness that ticks an hour
        past a task due at +60s should see a task that finished at +60s;
        stamping it with whenever the harness happened to look would
        make the completion time a fact about the test, not the task.
        """
        self.clock += seconds
        for task in self.transfer_tasks.values():
            if task.status == "ACTIVE" and task.due_at is not None and task.due_at <= self.clock:
                task.status = "SUCCEEDED"
                task.completion_time = task.due_at
                task.files_done = len(task.files)
                task.due_at = None

    def files_done_now(self, task: TransferTask) -> int:
        """How many of a task's files have arrived, as of the world clock.

        Whole files, in list order, arriving at an even pace between
        ``active_since`` and ``due_at``.  Integer arithmetic on purpose:
        the same clock always gives the same count, and a file is either
        there or not — Globus's successful-transfer list has no
        half-files in it either.  A task with no ``due_at`` (paused,
        failed, or ACTIVE with no duration given) stays where it was
        last pinned until the control plane moves it.
        """
        n = len(task.files)
        if task.status == "SUCCEEDED":
            return n
        if task.status != "ACTIVE" or task.due_at is None:
            return task.files_done
        if self.clock >= task.due_at:
            return n
        elapsed = max(0, self.clock - task.active_since)
        return task.files_done + (n - task.files_done) * elapsed // (task.due_at - task.active_since)

    def _monitor_refusal(self, caller: Identity, collection_id: str) -> str | None:
        """Why ``caller`` may not watch tasks on a collection, or None if they may.

        Two different afternoons, so two different sentences: a role
        that is missing, and a role that exists but went inactive when
        the subscription did.  The second is the one worth spelling out —
        it is the failure a consumer meets in production when a DTN's
        subscription lapses, with every grant still visibly in place.
        """
        collection = self.collections.get(collection_id)
        if collection is None:
            return f"collection {collection_id} is not one Fauxbus has been told about"
        role = collection.roles.get(caller.identity_id)
        if role not in MONITOR_ROLES:
            return (
                f"identity {caller.identity_id} holds no activity_monitor, activity_manager or "
                f"administrator role on collection {collection_id}"
            )
        if collection.subscription_id is None:
            # DOCUMENTED for the two activity roles ("if the endpoint or
            # collection is unsubscribed, activity manager and monitor
            # roles become inactive").  PROVISIONAL that administrator
            # loses endpoint-manager access the same way: the reference
            # puts the whole endpoint-manager API behind a subscription,
            # but says so only for the activity roles in as many words.
            return (
                f"collection {collection_id} is not subscribed, so the {role} role "
                f"identity {caller.identity_id} holds there is inactive"
            )
        return None

    def _task_visible(self, caller: Identity, task: TransferTask) -> bool:
        # PROVISIONAL: a role on the task's source *or* its destination
        # is enough.  The published reference says "source or
        # destination collection" for every endpoint_manager task call;
        # the SDK's docstrings for endpoint_manager_get_task and
        # endpoint_manager_task_event_list say "the destination endpoint
        # of the task."  The two disagree, and only a recording settles
        # it.  Fauxbus takes the reference, which is the more permissive
        # reading — SPEC's asymmetry again: a fake that refuses what the
        # real service allows breaks working code, and a consumer that
        # only ever watches a destination (Root Cellar does) passes
        # under either.
        return any(
            self._monitor_refusal(caller, cid) is None
            for cid in (task.source_endpoint_id, task.destination_endpoint_id)
        )

    def _transfer_task(self, task_id: str) -> TransferTask:
        """Resolve a task id from the imitated surface, or TaskNotFound."""
        try:
            task_id = str(UUID(task_id))
        except (ValueError, AttributeError, TypeError):
            # PROVISIONAL: a malformed task id answers 404 TaskNotFound
            # rather than a 400.  No task can have that id, which is
            # true either way; which status the real service picks is
            # unrecorded.
            raise task_not_found(task_id) from None
        task = self.transfer_tasks.get(task_id)
        if task is None:
            raise task_not_found(task_id)
        return task

    def endpoint_manager_get_task(self, caller: Identity, task_id: str) -> dict[str, Any]:
        task = self._transfer_task(task_id)
        if not self._task_visible(caller, task):
            raise transfer_permission_denied(
                f"identity {caller.identity_id} has no activity_monitor role (or a stronger "
                f"one) on a subscribed collection this task touched"
            )
        return self.task_doc(task)

    def endpoint_manager_task_list(self, caller: Identity, query: dict[str, str]) -> dict[str, Any]:
        """``GET /v0.10/endpoint_manager/task_list``: filter, order, page.

        In order: refuse what is not built, read the filters, decide
        which collections the caller may look at, filter, sort the way
        the reference says, page by ``last_key``.  Every refusal below
        that answers 400 is PROVISIONAL as to *which* malformed requests
        the real service refuses and with what message — the BadRequest
        code and status are recorded, and the rules come from the SDK's
        docstring, but nobody has watched the service apply them.
        """
        unknown = sorted(set(query) - TASK_LIST_PARAMS)
        if unknown:
            raise not_implemented(
                f"Fauxbus does not implement endpoint_manager/task_list's {', '.join(unknown)}, "
                f"and will not ignore a filter and hand back tasks the caller asked it to "
                f"leave out. Real client code sends it?"
            )

        statuses = [s.strip() for s in query.get("filter_status", "").split(",") if s.strip()]
        bad = sorted(set(statuses) - set(TASK_STATUSES))
        if bad:
            raise transfer_bad_request(
                f"filter_status: {', '.join(bad)} is not a task status ({', '.join(TASK_STATUSES)})"
            )

        try:
            limit = int(query.get("limit", TASK_LIST_DEFAULT_LIMIT))
        except ValueError:
            raise transfer_bad_request(f"limit: {query['limit']!r} is not an integer") from None
        if not 1 <= limit <= TASK_LIST_MAX_LIMIT:
            raise transfer_bad_request(f"limit must be between 1 and {TASK_LIST_MAX_LIMIT}")

        endpoint = query.get("filter_endpoint")
        use = query.get("filter_endpoint_use")
        if use is not None and use not in ("source", "destination"):
            raise transfer_bad_request("filter_endpoint_use must be 'source' or 'destination'")
        if use is not None and endpoint is None:
            # The SDK refuses this before it reaches the wire
            # (GlobusSDKUsageError); a raw client is told here.
            raise transfer_bad_request("filter_endpoint_use requires filter_endpoint")
        if endpoint is None and not (statuses and set(statuses) <= set(TASK_RUNNING)):
            # DOCUMENTED rule (SDK docstring): "for any query that doesn't
            # specify a filter_status that is a subset of (ACTIVE,
            # INACTIVE), at least one of filter_task_id or filter_endpoint
            # is required."  filter_task_id is not built, so here it is
            # filter_endpoint or nothing.
            raise transfer_bad_request(
                "filter_endpoint is required unless filter_status is a subset of ACTIVE,INACTIVE"
            )

        window = self._completion_window(query.get("filter_completion_time"))
        after = self._decode_last_key(query["last_key"]) if query.get("last_key") else None

        if endpoint is not None:
            try:
                endpoint = str(UUID(endpoint))
            except ValueError:
                # PROVISIONAL, the twin of the task-id case: a malformed
                # collection id is a collection nobody has, so 404.
                raise endpoint_not_found(endpoint) from None
            if endpoint not in self.collections:
                raise endpoint_not_found(endpoint)
            refusal = self._monitor_refusal(caller, endpoint)
            if refusal is not None:
                raise transfer_permission_denied(refusal)
            tasks = [
                t
                for t in self.transfer_tasks.values()
                if (use != "destination" and t.source_endpoint_id == endpoint)
                or (use != "source" and t.destination_endpoint_id == endpoint)
            ]
        else:
            tasks = [t for t in self.transfer_tasks.values() if self._task_visible(caller, t)]

        if statuses:
            tasks = [t for t in tasks if t.status in statuses]
        if window is not None:
            tasks = [t for t in tasks if self._in_window(t, window)]

        ordered = sorted(tasks, key=self._task_order)
        if after is not None:
            ordered = [t for t in ordered if self._task_order(t) > after]
        page = ordered[:limit]
        # RECORDED envelope (endpoint_manager_task_list.py): DATA,
        # DATA_TYPE "task_list", has_next_page, last_key — and no total.
        # The SDK's LastKeyPaginator reads has_next_page with a bare
        # index, so it is present on every page, never omitted.
        return {
            "DATA": [self.task_doc(t) for t in page],
            "DATA_TYPE": "task_list",
            "has_next_page": len(ordered) > limit,
            "last_key": self._encode_last_key(page[-1]) if page else None,
        }

    @staticmethod
    def _completion_window(raw: str | None) -> tuple[float | None, float | None] | None:
        """``filter_completion_time`` as (start, end) epoch seconds, None for a blank side.

        The SDK's encoding, read from its source rather than assumed
        (``services/transfer/client.py``, 4.8.1): a ``(start, end)``
        tuple of datetimes becomes ``f"{start.isoformat(timespec=
        'seconds')},{end.isoformat(...)}"`` — one comma, no brackets, a
        string passed through untouched.  "A blank string may be used
        for either the start or end (but not both)" is DOCUMENTED.
        """
        if raw is None:
            return None
        parts = raw.split(",")
        if len(parts) != 2:
            raise transfer_bad_request(
                "filter_completion_time takes a start and an end separated by one comma"
            )
        start, end = (p.strip() or None for p in parts)
        if start is None and end is None:
            raise transfer_bad_request("filter_completion_time may leave one side blank, not both")
        return (
            None if start is None else _parse_filter_instant(start),
            None if end is None else _parse_filter_instant(end),
        )

    @staticmethod
    def _in_window(task: TransferTask, window: tuple[float | None, float | None]) -> bool:
        start, end = window
        if task.completion_time is None:
            # DOCUMENTED: "If the end date is blank, the filter will also
            # include all active tasks, since they will complete some
            # time in the future."  With an end date, a task that has not
            # completed has no completion time to be inside it.
            return end is None
        # PROVISIONAL: both bounds inclusive.  The reference says
        # "in the specified range" and nothing about the edges.  A poller
        # that overlaps its windows, as it should, cannot tell.
        return (start is None or task.completion_time >= start) and (
            end is None or task.completion_time <= end
        )

    @staticmethod
    def _task_order(task: TransferTask) -> tuple[int, int, str]:
        """The sort key, which is also what ``last_key`` encodes.

        DOCUMENTED ordering: "Tasks that are still in progress are sorted
        by request_time descending (newest first).  Completed tasks are
        sorted by completion_time descending.  In progress tasks will be
        sorted before completed tasks."  The task id breaks ties, which
        on a logical clock are common (every task created before a tick
        shares a request_time).
        """
        if task.status in TASK_RUNNING:
            return (0, -task.request_time, task.task_id)
        assert task.completion_time is not None
        return (1, -task.completion_time, task.task_id)

    @staticmethod
    def _encode_last_key(task: TransferTask) -> str:
        # PROVISIONAL, all of it, and the reference calls the value
        # "opaque", so no consumer may read it.  The shape borrows the
        # recorded example's ("complete,2024-02-06T06:59:02.291996"),
        # which suggests the real key is the sort position too; Fauxbus
        # adds the task id, because a timestamp alone cannot resume
        # between two tasks that share one.  Keyset paging rather than
        # an offset, so a task that appears between two page requests
        # does not shift every later row by one.  Also PROVISIONAL: a
        # last page still carries its key (the recording does) and an
        # empty page carries null (nothing recorded).
        group, negative_time, task_id = World._task_order(task)
        word = "active" if group == 0 else "complete"
        return f"{word},{_iso(-negative_time)},{task_id}"

    @staticmethod
    def _decode_last_key(raw: str) -> tuple[int, int, str]:
        try:
            word, instant, task_id = raw.split(",", 2)
            group = {"active": 0, "complete": 1}[word]
            parsed = datetime.fromisoformat(instant)
            # A key Fauxbus wrote always carries +00:00; a hand-edited
            # one without a zone is read as UTC rather than as whatever
            # zone the machine running Fauxbus happens to be in.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            seconds = int(parsed.timestamp())
        except (ValueError, KeyError):
            raise transfer_bad_request(f"last_key {raw!r} is not one this service handed out") from None
        return (group, -seconds, task_id)

    def endpoint_manager_successful_transfers(
        self, caller: Identity, task_id: str, query: dict[str, str]
    ) -> dict[str, Any]:
        """One page of a task's successful-transfer list, marker-paged.

        PROVISIONAL for any task that is not SUCCEEDED: Fauxbus answers
        with the files that have arrived so far, which for a FAILED task
        is the part that made it.  The SDK's docstring says "for a
        completed Task," and whether the real service refuses a running
        one, or answers it the way Fauxbus does, is unrecorded.  A
        consumer that reads a FAILED task's partial list — to learn
        whose transfer stopped and where — is relying on this answer.
        """
        unknown = sorted(set(query) - {"marker"})
        if unknown:
            raise not_implemented(
                f"Fauxbus does not implement successful_transfers' {', '.join(unknown)}. "
                f"Real client code sends it?"
            )
        task = self._transfer_task(task_id)
        if not self._task_visible(caller, task):
            raise transfer_permission_denied(
                f"identity {caller.identity_id} has no activity_monitor role (or a stronger "
                f"one) on a subscribed collection this task touched"
            )
        try:
            marker = int(query.get("marker", "0"))
        except ValueError:
            raise transfer_bad_request(f"marker {query['marker']!r} is not an integer") from None
        if marker < 0:
            raise transfer_bad_request("marker may not be negative")
        done = task.files[: self.files_done_now(task)]
        rows = done[marker : marker + SUCCESSFUL_TRANSFERS_PAGE]
        # PROVISIONAL: the marker is an offset into the list.  The
        # reference types it as an integer and the recording shows
        # ``marker: 0`` on a first page and ``next_marker: 93979`` — an
        # internal row id, most likely — so it is opaque to consumers
        # either way.  One trap the offset happens to avoid, worth
        # knowing about before anyone changes it: the SDK's
        # NullableMarkerPaginator only sends a marker that is *truthy*,
        # so a next_marker of 0 would be dropped and page one requested
        # again, forever.  An offset past the first page is never 0.
        following = marker + SUCCESSFUL_TRANSFERS_PAGE
        return {
            # RECORDED envelope (endpoint_manager_task_successful_transfers.py).
            "DATA_TYPE": "successful_transfers",
            "marker": marker,
            "next_marker": following if following < len(done) else None,
            "DATA": [
                {
                    # RECORDED: the fixture's rows carry these three.
                    "DATA_TYPE": "successful_transfer",
                    "source_path": f.source_path,
                    "destination_path": f.destination_path,
                    # DOCUMENTED, not recorded: the reference's
                    # successful_transfer table adds these four.  The SDK
                    # fixture shows none of them, so a consumer reading
                    # ``size`` or ``checksum`` is leaning on the published
                    # docs alone until a recording says so.
                    "size": f.size,
                    "checksum": f.checksum,
                    "checksum_algorithm": f.checksum_algorithm,
                    # PROVISIONAL value: the reference gives ``false`` as
                    # its example and does not say what makes it true.
                    "dynamic": False,
                }
                for f in rows
            ],
        }

    def task_doc(self, task: TransferTask) -> dict[str, Any]:
        """The task document, key for key as the recorded fixture has it.

        RECORDED key set: every key in
        ``globus_sdk/testing/data/transfer/endpoint_manager_task_list.py``
        is here and nothing else is, because a consumer that reads
        ``task["source_endpoint_display_name"]`` should not meet a
        KeyError from the fake that the real service would never raise.

        The *values* split three ways.  Modeled, and true to the world:
        ids, owner, status, times, the file and byte counts, faults,
        label, base paths, fatal_error.  Constant, and recorded: the
        fixture's own values for things Fauxbus has no reason to vary
        (``command``, ``type``, ``verify_checksum``, ``recursive_symlinks``).
        And the rest — PROVISIONAL as values: ``deadline`` (one example's
        one day), the ``subtasks_*`` counts (the fixture's six subtasks
        for three files count directories Fauxbus does not have),
        ``is_ok``, ``nice_status``, ``effective_bytes_per_second``,
        ``username``, the legacy ``name#id`` endpoint strings, and every
        ``*_local_user``/``*_host_*``/``*_mapped_*`` field, which are
        null or the fixture's resting value because Fauxbus models no
        hosts, mappings or local accounts.
        """
        n = len(task.files)
        done = self.files_done_now(task)
        transferred = sum(f.size for f in task.files[:done])
        running = task.status in TASK_RUNNING
        end = task.completion_time if task.completion_time is not None else self.clock
        elapsed = max(0, end - task.request_time)

        def endpoint(cid: str) -> tuple[str, str | None]:
            collection = self.collections.get(cid)
            name = collection.display_name if collection is not None else None
            return f"{name or cid}#{cid}", name

        source, source_name = endpoint(task.source_endpoint_id)
        destination, destination_name = endpoint(task.destination_endpoint_id)
        return {
            "DATA_TYPE": "task",
            "bytes_checksummed": 0,
            "bytes_transferred": transferred,
            "canceled_by_admin": None,
            "canceled_by_admin_message": None,
            "command": "API 0.10",
            "completion_time": None if task.completion_time is None else _iso(task.completion_time),
            "deadline": _iso(task.request_time + TASK_DEADLINE),
            "delete_destination_extra": False,
            "destination_base_path": task.destination_base_path,
            "destination_endpoint": destination,
            "destination_endpoint_display_name": destination_name,
            "destination_endpoint_id": task.destination_endpoint_id,
            "destination_host_endpoint": None,
            "destination_host_endpoint_display_name": None,
            "destination_host_endpoint_id": None,
            "destination_host_path": None,
            "destination_local_user": None,
            "destination_local_user_status": None,
            "destination_mapped_collection_display_name": None,
            "destination_mapped_collection_id": None,
            "directories": 0,
            "effective_bytes_per_second": round(transferred / elapsed) if elapsed else 0,
            "encrypt_data": False,
            "fail_on_quota_errors": False,
            "fatal_error": task.fatal_error,
            "faults": task.faults,
            "files": n,
            "files_skipped": 0,
            "files_transferred": done,
            "filter_rules": None,
            "history_deleted": False,
            "is_ok": (task.status == "ACTIVE") if running else None,
            "is_paused": False,
            "label": task.label,
            "nice_status": None,
            "nice_status_details": None,
            "nice_status_expires_in": None,
            "nice_status_short_description": None,
            "owner_id": task.owner_id,
            "owner_string": task.owner_string,
            "preserve_timestamp": False,
            "recursive_symlinks": "ignore",
            "request_time": _iso(task.request_time),
            "skip_source_errors": False,
            "source_base_path": task.source_base_path,
            "source_endpoint": source,
            "source_endpoint_display_name": source_name,
            "source_endpoint_id": task.source_endpoint_id,
            "source_host_endpoint": None,
            "source_host_endpoint_display_name": None,
            "source_host_endpoint_id": None,
            "source_host_path": None,
            "source_local_user": None,
            "source_local_user_status": None,
            "source_mapped_collection_display_name": None,
            "source_mapped_collection_id": None,
            "status": task.status,
            "subtasks_canceled": 0,
            "subtasks_expired": 0,
            "subtasks_failed": n - done if task.status == "FAILED" else 0,
            "subtasks_pending": n - done if running else 0,
            "subtasks_retrying": 0,
            "subtasks_skipped_errors": 0,
            "subtasks_succeeded": done,
            "subtasks_total": n,
            "symlinks": 0,
            "sync_level": None,
            "task_id": task.task_id,
            "type": "TRANSFER",
            "username": task.owner_string,
            "verify_checksum": True,
        }

    # ---------------------------------------------- transfer: control plane
    #
    # How a test makes a task happen.  The imitated surface only reads
    # tasks (that is all the endpoint-manager family does), so creating
    # one and moving it along are harness acts, out-of-band per
    # principle 4 — the same way a group's subscription arrives by seed
    # because no Groups endpoint writes it.

    CREATE_TASK_FIELDS = frozenset(
        {
            "owner_id",
            "owner_string",
            "source_endpoint_id",
            "destination_endpoint_id",
            "files",
            "status",
            "duration",
            "files_succeeded",
            "faults",
            "fatal_error",
            "label",
            "source_base_path",
            "destination_base_path",
        }
    )
    MOVE_TASK_FIELDS = frozenset({"status", "duration", "files_succeeded", "faults", "fatal_error"})

    # PROVISIONAL shape: what a FAILED task carries in ``fatal_error``
    # when the harness does not say.  The reference describes the field
    # as an object with a ``code`` and a ``description``; no fixture
    # shows one, and the code here is Fauxbus's own word, named so that
    # nobody mistakes it for a Globus one.
    DEFAULT_FATAL_ERROR: dict[str, Any] = {
        "code": "FAUXBUS_FAILED",
        "description": "failed on demand through the Fauxbus control plane",
    }

    def _move_options(self, doc: dict[str, Any], status: str, n: int) -> tuple[int | None, int | None]:
        """Read ``duration`` and ``files_succeeded``, each only where it means something."""
        duration = doc.get("duration")
        if duration is not None:
            if status != "ACTIVE":
                raise validation_error("'duration' only applies to a task that is ACTIVE")
            duration = _require_int(duration, "duration")
            if duration < 1:
                raise validation_error("'duration' must be at least 1 second")
        succeeded = doc.get("files_succeeded")
        if succeeded is not None:
            if status not in ("FAILED", "INACTIVE"):
                raise validation_error(
                    "'files_succeeded' only applies to a task moving to FAILED or INACTIVE; "
                    "SUCCEEDED means all of them"
                )
            succeeded = _require_int(succeeded, "files_succeeded")
            if not 0 <= succeeded <= n:
                raise validation_error(f"'files_succeeded' must be between 0 and {n}")
        return duration, succeeded

    def create_transfer_task(self, doc: dict[str, Any]) -> TransferTask:
        """Start a task the way a researcher's submission would, from the harness.

        It begins at the current clock, in whatever status the harness
        names (ACTIVE by default).  ``duration`` sets it running toward
        completion on the logical clock: ``tick`` past it and the task is
        SUCCEEDED, with files arriving evenly on the way.  Leave it out
        and the task stays where it is until moved.  A task created
        already FAILED takes ``files_succeeded`` for how far it got.
        """
        doc = _require_mapping(doc, "task document")
        unknown = sorted(set(doc) - self.CREATE_TASK_FIELDS)
        if unknown:
            raise validation_error(f"unknown task fields: {unknown}")
        status = doc.get("status", "ACTIVE")
        if status not in TASK_STATUSES:
            raise validation_error(f"status {status!r} is not one of {TASK_STATUSES}")
        files = doc.get("files") or []
        n = len(files) if isinstance(files, list) else 0
        duration, succeeded = self._move_options(doc, status, n)
        terminal = status in TASK_TERMINAL
        record = {
            key: doc[key]
            for key in (
                "owner_id",
                "owner_string",
                "source_endpoint_id",
                "destination_endpoint_id",
                "files",
                "faults",
                "label",
                "source_base_path",
                "destination_base_path",
            )
            if key in doc
        }
        record.update(
            status=status,
            request_time=self.clock,
            active_since=self.clock,
            due_at=self.clock + duration if duration is not None else None,
            completion_time=self.clock if terminal else None,
            files_done=n if status == "SUCCEEDED" else (succeeded or 0),
            fatal_error=(doc.get("fatal_error") or self.DEFAULT_FATAL_ERROR)
            if status == "FAILED"
            else None,
        )
        # Ids come from the same deterministic counter as everything
        # else — but a seeded world may already hold the id the counter
        # is about to produce (a dump carries the counter, a hand-written
        # seed may not), so skip past any id in use.  Still
        # deterministic: the same world always mints the same next id,
        # and nothing seeded is ever written over.
        while True:
            task_id = self.next_id("transfer_task")
            if task_id not in self.transfer_tasks:
                break
        task = self._task_from_doc(task_id, record)
        self.transfer_tasks[task_id] = task
        return task

    def move_transfer_task(self, task_id: str, doc: dict[str, Any]) -> TransferTask:
        """Move a task along: pause it, resume it, finish it, fail it.

        A terminal task does not move again.  Globus never reports a
        finished task finishing a second way, and a harness that tried
        to make it would be testing a service that does not exist — the
        consumer's own "terminal means terminal" rule is exactly the
        kind of thing that should be tested against a fake that agrees.
        """
        doc = _require_mapping(doc, "move document")
        unknown = sorted(set(doc) - self.MOVE_TASK_FIELDS)
        if unknown:
            raise validation_error(f"unknown move fields: {unknown}")
        task = self.transfer_tasks.get(_require_uuid(task_id, "task id"))
        if task is None:
            raise ApiError(404, "NOT_FOUND", f"no transfer task {task_id} in this world")
        if task.status in TASK_TERMINAL:
            raise ApiError(
                409,
                "CONFLICT",
                f"task {task_id} is {task.status}, and a finished task stays finished",
            )
        status = doc.get("status")
        if status not in TASK_STATUSES:
            raise validation_error(f"'status' is required, one of {TASK_STATUSES}")
        n = len(task.files)
        duration, succeeded = self._move_options(doc, status, n)
        faults = _require_int(doc.get("faults", task.faults), "faults")
        if faults < 0:
            raise validation_error("'faults' may not be negative")
        if doc.get("fatal_error") is not None and status != "FAILED":
            raise validation_error("'fatal_error' only applies to a task moving to FAILED")
        fatal = _require_mapping(doc.get("fatal_error") or self.DEFAULT_FATAL_ERROR, "fatal_error")
        # Everything is validated; only now does the task change, so a
        # refused move leaves it exactly as it was.  Pin the progress so
        # far before anything changes the formula that computes it.
        done = self.files_done_now(task)
        task.faults = faults
        task.status = status
        task.due_at = None
        if status == "ACTIVE":
            task.files_done = done
            task.active_since = self.clock
            task.due_at = self.clock + duration if duration is not None else None
        elif status == "INACTIVE":
            task.files_done = succeeded if succeeded is not None else done
        elif status == "SUCCEEDED":
            task.files_done = n
            task.completion_time = self.clock
        else:  # FAILED
            task.files_done = succeeded if succeeded is not None else done
            task.completion_time = self.clock
            task.fatal_error = dict(fatal)
        return task

    def task_record(self, task: TransferTask) -> dict[str, Any]:
        """A task as the state dump holds it — the seed form, not the wire form."""
        return {
            "owner_id": task.owner_id,
            "owner_string": task.owner_string,
            "source_endpoint_id": task.source_endpoint_id,
            "destination_endpoint_id": task.destination_endpoint_id,
            "status": task.status,
            "request_time": task.request_time,
            "completion_time": task.completion_time,
            "active_since": task.active_since,
            "due_at": task.due_at,
            "files_done": task.files_done,
            "faults": task.faults,
            "fatal_error": None if task.fatal_error is None else dict(task.fatal_error),
            "label": task.label,
            "source_base_path": task.source_base_path,
            "destination_base_path": task.destination_base_path,
            "files": [
                {
                    "source_path": f.source_path,
                    "destination_path": f.destination_path,
                    "size": f.size,
                    "checksum": f.checksum,
                    "checksum_algorithm": f.checksum_algorithm,
                }
                for f in task.files
            ],
        }

    def _task_from_doc(self, task_id: str, t: Any) -> TransferTask:
        """Validate one task record — the seed's door and the create door both.

        One function for both on purpose: v0.2.11 found the policies
        endpoint and the seed disagreeing about what a valid policy was,
        and "one door's rules are every door's rules" has been the answer
        since.  The consistency checks at the end are the ones a
        hand-written seed is likeliest to get wrong — a SUCCEEDED task
        with no completion time would render as finished and sort as
        running.
        """
        what = f"transfer task {task_id}"
        t = _require_mapping(t, what)
        owner_id = _require_uuid(str(t.get("owner_id")), f"{what} owner_id")
        source = _require_uuid(str(t.get("source_endpoint_id")), f"{what} source_endpoint_id")
        destination = _require_uuid(
            str(t.get("destination_endpoint_id")), f"{what} destination_endpoint_id"
        )
        status = t.get("status", "ACTIVE")
        if status not in TASK_STATUSES:
            raise validation_error(f"{what} status {status!r} is not one of {TASK_STATUSES}")
        raw_files = t.get("files") or []
        if not isinstance(raw_files, list):
            raise validation_error(f"{what} 'files' must be a list")
        files = []
        for i, f in enumerate(raw_files):
            f = _require_mapping(f, f"{what} files[{i}]")
            for key in ("source_path", "destination_path"):
                if not isinstance(f.get(key), str) or not f[key]:
                    raise validation_error(f"{what} files[{i}] requires a non-empty {key!r}")
            size = _require_int(f.get("size", 0), f"{what} files[{i}] size")
            if size < 0:
                raise validation_error(f"{what} files[{i}] size may not be negative")
            files.append(
                TransferFile(
                    source_path=f["source_path"],
                    destination_path=f["destination_path"],
                    size=size,
                    checksum=_optional_str(f.get("checksum"), f"{what} files[{i}] checksum"),
                    checksum_algorithm=_optional_str(
                        f.get("checksum_algorithm"), f"{what} files[{i}] checksum_algorithm"
                    ),
                )
            )
        n = len(files)

        def optional_int(key: str) -> int | None:
            return None if t.get(key) is None else _require_int(t[key], f"{what} {key}")

        request_time = _require_int(t.get("request_time", self.clock), f"{what} request_time")
        completion_time = optional_int("completion_time")
        due_at = optional_int("due_at")
        active_since = _require_int(t.get("active_since", request_time), f"{what} active_since")
        files_done = _require_int(
            t.get("files_done", n if status == "SUCCEEDED" else 0), f"{what} files_done"
        )
        faults = _require_int(t.get("faults", 0), f"{what} faults")
        fatal_error = t.get("fatal_error")
        if fatal_error is not None:
            fatal_error = dict(_require_mapping(fatal_error, f"{what} fatal_error"))

        if not 0 <= files_done <= n:
            raise validation_error(f"{what} files_done must be between 0 and {n}")
        if faults < 0:
            raise validation_error(f"{what} faults may not be negative")
        if status in TASK_TERMINAL:
            if completion_time is None:
                raise validation_error(f"{what} is {status}, so it needs a completion_time")
            if due_at is not None:
                raise validation_error(f"{what} is {status}; a finished task has no due_at")
            if status == "SUCCEEDED" and files_done != n:
                raise validation_error(f"{what} SUCCEEDED, so files_done must be all {n} files")
        else:
            if completion_time is not None:
                raise validation_error(f"{what} is {status} and cannot have a completion_time")
            if due_at is not None and (status != "ACTIVE" or due_at <= active_since):
                raise validation_error(
                    f"{what}: due_at belongs only to an ACTIVE task, after its active_since"
                )

        return TransferTask(
            task_id=task_id,
            owner_id=owner_id,
            owner_string=str(t.get("owner_string") or self.username_for(owner_id)),
            source_endpoint_id=source,
            destination_endpoint_id=destination,
            status=status,
            request_time=request_time,
            files=files,
            completion_time=completion_time,
            files_done=files_done,
            active_since=active_since,
            due_at=due_at,
            faults=faults,
            fatal_error=fatal_error,
            label=_optional_str(t.get("label"), f"{what} label"),
            source_base_path=_optional_str(t.get("source_base_path"), f"{what} source_base_path"),
            destination_base_path=_optional_str(
                t.get("destination_base_path"), f"{what} destination_base_path"
            ),
        )

    def _load_transfer(self, doc: dict[str, Any]) -> None:
        """The seed's Transfer sections: collections with their roles, then tasks.

        Tasks do not have to name a seeded collection.  A researcher's
        laptop is the source of most real transfers into a landing
        collection, and making a harness register every source it
        invents would be ceremony with nothing behind it; an unknown
        collection simply grants nobody anything.
        """
        for cid, c in _require_mapping(doc.get("collections"), "collections").items():
            cid = _require_uuid(str(cid), "collection id")
            c = _require_mapping(c, f"collection {cid}")
            subscription = c.get("subscription_id")
            if subscription is not None:
                subscription = _require_uuid(str(subscription), f"collection {cid} subscription_id")
            roles: dict[str, str] = {}
            for iid, role in _require_mapping(c.get("roles"), f"collection {cid} roles").items():
                iid = _require_uuid(str(iid), f"collection {cid} role principal")
                if role not in MONITOR_ROLES:
                    raise validation_error(
                        f"collection {cid}: role {role!r} is not one Fauxbus models. The task-"
                        f"monitoring slice knows {', '.join(MONITOR_ROLES)}; Globus's "
                        f"access_manager and restricted_administrator do not reach tasks."
                    )
                roles[iid] = role
            self.collections[cid] = Collection(
                id=cid,
                display_name=str(c.get("display_name") or cid),
                subscription_id=subscription,
                roles=roles,
            )
        for tid, t in _require_mapping(doc.get("transfer_tasks"), "transfer_tasks").items():
            tid = _require_uuid(str(tid), "transfer task id")
            self.transfer_tasks[tid] = self._task_from_doc(tid, t)

    # ----------------------------------------------------------- seed/state

    def dump(self) -> dict[str, Any]:
        """The full state document.  Round-trip invariant: this document is
        a valid seed, and seeding a fresh world with it reproduces it.

        Every mapping is emitted in sorted order, which makes the
        serialization canonical: two worlds with equal state produce
        byte-identical JSON (given sorted keys and fixed indent).  That
        is what lets CI assert the shipped example seed equals its own
        re-dump to the byte — state comparison downgraded to string
        comparison, on purpose, because bytes don't argue.
        """
        return {
            "version": 0,
            "clock": self.clock,
            "counters": dict(sorted(self.counters.items())),
            "identities": {t: dict(p) for t, p in sorted(self.pinned_identities.items())},
            "preferences": {i: dict(p) for i, p in sorted(self.preferences.items())},
            "clients": {
                cid: {
                    "secret": c.secret,
                    "name": c.name,
                    "username": c.username,
                    "redirect_uris": list(c.redirect_uris),
                    "required_idp": c.required_idp,
                }
                for cid, c in sorted(self.clients.items())
            },
            # Issued tokens are world state, so they round-trip like
            # everything else — which also means a test can *seed* one,
            # including an already-expired one, without performing the
            # grant first.
            "tokens": {
                tok: {
                    "client_id": t.client_id,
                    "identity_id": t.identity_id,
                    "username": t.username,
                    "resource_server": t.resource_server,
                    "scopes": list(t.scopes),
                    "grant_type": t.grant_type,
                    "issued_at": t.issued_at,
                    "expires_at": t.expires_at,
                    "revoked": t.revoked,
                    "account": t.account,
                    "authenticated_at": t.authenticated_at,
                }
                for tok, t in sorted(self.tokens.items())
            },
            # Slice B.  Configuration first, then who exists, then the
            # login machinery in flight — all of it world state, all of
            # it round-tripping.  The private signing key is *not* here:
            # it is a constant in signing.py, the same in every world, and
            # a seed that could swap it would be a seed that could make
            # one Fauxbus's tokens verify against another's JWKS.
            "oidc": {"issuer": self.issuer, "signed_token_clock": self.signed_token_clock},
            "identity_providers": {
                iid: {"name": idp.name} for iid, idp in sorted(self.identity_providers.items())
            },
            "accounts": {
                primary: {
                    "identities": {
                        iid: {
                            "username": i.username,
                            "identity_provider": i.identity_provider,
                            "name": i.name,
                            "email": i.email,
                            "organization": i.organization,
                        }
                        for iid, i in sorted(a.identities.items())
                    }
                }
                for primary, a in sorted(self.accounts.items())
            },
            "authorization_requests": {
                rid: {
                    "client_id": r.client_id,
                    "redirect_uri": r.redirect_uri,
                    "scopes": list(r.scopes),
                    "state": r.state,
                    "nonce": r.nonce,
                    "code_challenge": r.code_challenge,
                }
                for rid, r in sorted(self.authorization_requests.items())
            },
            "authorization_codes": {
                code: {
                    "client_id": c.client_id,
                    "redirect_uri": c.redirect_uri,
                    "scopes": list(c.scopes),
                    "state": c.state,
                    "nonce": c.nonce,
                    "code_challenge": c.code_challenge,
                    "account": c.account,
                    "identity_id": c.identity_id,
                    "authenticated_at": c.authenticated_at,
                    "issued_at": c.issued_at,
                    "expires_at": c.expires_at,
                    "used": c.used,
                }
                for code, c in sorted(self.authorization_codes.items())
            },
            "sessions": {
                sid: {"account": x.account, "authenticated_at": x.authenticated_at}
                for sid, x in sorted(self.sessions.items())
            },
            # Transfer.  Collections carry their role grants; tasks are
            # in the seed form (task_record), which stores the pinned
            # progress and the clock marks rather than anything the
            # clock can derive — see TransferTask.
            "collections": {
                cid: {
                    "display_name": c.display_name,
                    "subscription_id": c.subscription_id,
                    "roles": dict(sorted(c.roles.items())),
                }
                for cid, c in sorted(self.collections.items())
            },
            "transfer_tasks": {
                tid: self.task_record(t) for tid, t in sorted(self.transfer_tasks.items())
            },
            "groups": {
                gid: {
                    "name": g.name,
                    "description": g.description,
                    "parent_id": g.parent_id,
                    "group_type": g.group_type,
                    "enforce_session": g.enforce_session,
                    "session_limit": g.session_limit,
                    "session_timeouts": dict(g.session_timeouts),
                    "policies": dict(g.policies),
                    "memberships": {
                        i: {"username": m.username, "role": m.role, "status": m.status}
                        for i, m in sorted(g.memberships.items())
                    },
                    "membership_fields": {
                        i: dict(f) for i, f in sorted(g.membership_fields.items())
                    },
                    "subscription_id": g.subscription_id,
                    "subscription_info": g.subscription_info,
                    "subscription_admin_verified_id": g.subscription_admin_verified_id,
                }
                for gid, g in sorted(self.groups.items())
            },
        }

    def load(self, doc: dict[str, Any]) -> None:
        # The seed is the one door where hand-authored data enters the
        # world, so validation is loud and immediate: a bad UUID, role,
        # or status fails the seed call itself — not three tests later
        # as an inexplicable 403.
        if not isinstance(doc, dict):
            raise validation_error("seed document must be an object")
        self.reset()
        self.clock = _require_int(doc.get("clock", 0), "clock")
        self.counters = {
            str(k): _require_int(v, f"counters[{k!r}]")
            for k, v in _require_mapping(doc.get("counters"), "counters").items()
        }
        for token, pin in _require_mapping(doc.get("identities"), "identities").items():
            if not isinstance(pin, dict) or "identity_id" not in pin:
                raise validation_error(f"identity pin for token {token!r} requires identity_id")
            identity_id = _require_uuid(str(pin["identity_id"]), "identity_id")
            self.pinned_identities[str(token)] = {
                "identity_id": identity_id,
                "username": str(pin.get("username") or placeholder_username(identity_id)),
            }
        for identity_id, prefs in _require_mapping(doc.get("preferences"), "preferences").items():
            prefs = _require_mapping(prefs, f"preferences[{identity_id!r}]")
            self.preferences[_require_uuid(str(identity_id), "identity_id")] = {
                "allow_add": bool(prefs.get("allow_add", True))
            }
        self._load_oidc_people(doc)
        for client_id, c in _require_mapping(doc.get("clients"), "clients").items():
            # A client id must be a UUID because a Globus client is an
            # identity, and identities are UUIDs everywhere else in this
            # world.  Letting "my-test-client" through here would produce
            # a group membership whose identity_id fails the same check
            # one call later, which is a confusing place to learn it.
            client_id = _require_uuid(str(client_id), "client_id")
            c = _require_mapping(c, f"clients[{client_id!r}]")
            if not c.get("secret"):
                raise validation_error(f"client {client_id} requires a non-empty 'secret'")
            redirect_uris = c.get("redirect_uris") or []
            if not isinstance(redirect_uris, list):
                raise validation_error(f"client {client_id} 'redirect_uris' must be a list")
            required_idp = c.get("required_idp")
            if required_idp is not None:
                required_idp = _require_uuid(str(required_idp), f"client {client_id} required_idp")
                if required_idp not in self.identity_providers:
                    # Loud here rather than at login: a required_idp
                    # naming a provider nobody can have an identity from
                    # would refuse every account with a reason that
                    # sounds like the account's fault.
                    raise validation_error(
                        f"client {client_id} requires identity provider {required_idp}, which "
                        f"is not in 'identity_providers'."
                    )
            self.clients[client_id] = OAuthClient(
                client_id=client_id,
                secret=str(c["secret"]),
                name=str(c.get("name") or client_id),
                username=str(c.get("username") or client_username(client_id)),
                redirect_uris=[_require_redirect_uri(u, client_id) for u in redirect_uris],
                required_idp=required_idp,
            )
        # What the mint has not yet reached, the mint still owns.  Read
        # before the loop because the loop must not move it.
        mints_next = self.counters.get("access_token", 0)
        for tok, t in _require_mapping(doc.get("tokens"), "tokens").items():
            # A seeded token may not wear a name the mint will later
            # produce.  Before this check, seeding ``fauxbus-at-0`` and
            # then performing one grant produced the same string twice:
            # issue_token wrote over the seeded record in place, without
            # a word.  A token seeded as already-expired came back alive;
            # a token seeded as alice came back as the client.  And
            # because ids here are deterministic, that was not a rare
            # race — it happened on every run, to anyone who read the
            # docs and seeded the token name the docs name.
            #
            # The line is drawn at the *counter*, not at the name shape,
            # and that is what keeps the round trip legal: a dump carries
            # ``fauxbus-at-0`` alongside ``counters.access_token: 1``, so
            # that token is already behind the mint and reloading it is
            # exactly as safe as it looks.
            reserved = access_token_number(str(tok))
            if reserved is not None and reserved >= mints_next:
                raise validation_error(
                    f"token {tok!r} is a name this world's token endpoint has not handed "
                    f"out yet — the next grant mints {access_token(mints_next)!r} — so the "
                    f"first grant would silently overwrite this record. Either name the "
                    f"token something outside the {access_token(0)[:-1]}N space, or set "
                    f"counters.access_token to {reserved + 1} or more so the mint starts "
                    f"past it."
                )
            # Deliberately *not* checked: that client_id names a client in
            # the registry above.  A harness that only wants a working
            # token — or an already-expired one — should not have to
            # register a client it will never authenticate as.  The
            # token record carries everything authorization needs on its
            # own, so a dangling client_id costs nothing but a name.
            t = _require_mapping(t, f"tokens[{tok!r}]")
            for required in ("client_id", "resource_server", "expires_at"):
                if required not in t:
                    raise validation_error(f"token {tok!r} requires {required!r}")
            client_id = _require_uuid(str(t["client_id"]), "client_id")
            identity_id = _require_uuid(str(t.get("identity_id") or client_id), "identity_id")
            scopes = t.get("scopes") or []
            if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
                raise validation_error(f"token {tok!r} 'scopes' must be a list of strings")
            self.tokens[str(tok)] = IssuedToken(
                token=str(tok),
                client_id=client_id,
                identity_id=identity_id,
                username=str(t.get("username") or client_username(client_id)),
                resource_server=str(t["resource_server"]),
                scopes=list(scopes),
                grant_type=str(t.get("grant_type", "client_credentials")),
                # ``issued_at`` defaults to the world's own clock rather
                # than to zero: a hand-written seed that gives only
                # ``expires_at`` means "this token is live now," and zero
                # would have introspection report it as minted before the
                # world began.
                issued_at=_require_int(t.get("issued_at", self.clock), f"token {tok!r} issued_at"),
                expires_at=_require_int(t["expires_at"], f"token {tok!r} expires_at"),
                revoked=bool(t.get("revoked", False)),
                account=self._require_account(t.get("account"), f"token {tok!r}"),
                authenticated_at=(
                    None
                    if t.get("authenticated_at") is None
                    else _require_int(t["authenticated_at"], f"token {tok!r} authenticated_at")
                ),
            )
        self._load_logins_in_flight(doc)
        # After pins and clients, because a task's default owner_string
        # is whatever username_for says about its owner.
        self._load_transfer(doc)
        for gid, g in _require_mapping(doc.get("groups"), "groups").items():
            gid = _require_uuid(str(gid), "group id")
            if not isinstance(g, dict) or not g.get("name"):
                raise validation_error(f"seed group {gid} requires a name")
            # Unknown policy keys are refused here exactly as the policies
            # endpoint refuses them.  They diverged once — PUT /policies
            # rejected a typo while the seed swallowed it — and a fixture
            # whose typo'd policy silently does nothing is a test asserting
            # against a world it doesn't have.  One door's rules are every
            # door's rules.
            seed_policies = _require_mapping(g.get("policies"), f"group {gid} policies")
            unknown = set(seed_policies) - set(DEFAULT_POLICIES)
            if unknown:
                raise validation_error(f"seed group {gid} has unknown policy fields: {sorted(unknown)}")
            policies = dict(DEFAULT_POLICIES)
            policies.update(seed_policies)
            group = Group(
                id=gid,
                name=str(g["name"]),
                description=g.get("description"),
                parent_id=g.get("parent_id"),
                group_type=str(g.get("group_type", "regular")),
                enforce_session=bool(g.get("enforce_session", False)),
                session_limit=_require_int(g.get("session_limit", 28800), f"group {gid} session_limit"),
                session_timeouts=_require_mapping(
                    g.get("session_timeouts"), f"group {gid} session_timeouts"
                ),
                policies=policies,
                subscription_id=g.get("subscription_id"),
                subscription_info=g.get("subscription_info"),
                subscription_admin_verified_id=g.get("subscription_admin_verified_id"),
            )
            for identity_id, m in _require_mapping(
                g.get("memberships"), f"group {gid} memberships"
            ).items():
                identity_id = _require_uuid(str(identity_id), "identity_id")
                m = _require_mapping(m, f"group {gid} membership {identity_id}")
                role = str(m.get("role", "member"))
                status = str(m.get("status", "active"))
                if role not in ROLES:
                    raise validation_error(f"seed membership role {role!r} is not one of {ROLES}")
                if status not in STATUSES:
                    raise validation_error(
                        f"seed membership status {status!r} is not one of {STATUSES}"
                    )
                group.memberships[identity_id] = Membership(
                    identity_id=identity_id,
                    username=str(m.get("username") or placeholder_username(identity_id)),
                    role=role,
                    status=status,
                )
            for identity_id, fields in _require_mapping(
                g.get("membership_fields"), f"group {gid} membership_fields"
            ).items():
                group.membership_fields[_require_uuid(str(identity_id), "identity_id")] = (
                    _require_mapping(fields, f"group {gid} membership_fields[{identity_id}]")
                )
            self.groups[gid] = group

    def _load_oidc_people(self, doc: dict[str, Any]) -> None:
        """Slice B's seed sections: configuration, providers, accounts.

        Loaded before ``clients`` because a client's ``required_idp`` must
        name a provider that exists, and before ``tokens`` because a
        person's token names an account.  The same loud-at-the-door rule
        as everywhere else: a typo fails the seed call, not a login three
        redirects later.
        """
        oidc = _require_mapping(doc.get("oidc"), "oidc")
        unknown = set(oidc) - {"issuer", "signed_token_clock"}
        if unknown:
            raise validation_error(f"unknown 'oidc' fields: {sorted(unknown)}")
        if oidc.get("issuer") is not None:
            try:
                self.issuer = check_issuer(str(oidc["issuer"]))
            except ValueError as err:
                raise validation_error(str(err)) from None
        clock_mode = oidc.get("signed_token_clock")
        if clock_mode is not None and clock_mode not in SIGNED_TOKEN_CLOCKS:
            raise validation_error(
                f"oidc.signed_token_clock must be one of {SIGNED_TOKEN_CLOCKS} or null, "
                f"got {clock_mode!r}"
            )
        self.signed_token_clock = clock_mode

        for iid, idp in _require_mapping(doc.get("identity_providers"), "identity_providers").items():
            iid = _require_uuid(str(iid), "identity provider id")
            idp = _require_mapping(idp, f"identity_providers[{iid!r}]")
            if not idp.get("name"):
                raise validation_error(f"identity provider {iid} requires a 'name'")
            self.identity_providers[iid] = IdentityProvider(id=iid, name=str(idp["name"]))

        owner: dict[str, str] = {}  # identity id -> the account that holds it
        for primary, a in _require_mapping(doc.get("accounts"), "accounts").items():
            primary = _require_uuid(str(primary), "account (primary identity) id")
            a = _require_mapping(a, f"accounts[{primary!r}]")
            identities: dict[str, GlobusIdentity] = {}
            for iid, i in _require_mapping(a.get("identities"), f"account {primary} identities").items():
                iid = _require_uuid(str(iid), f"account {primary} identity id")
                if iid in owner:
                    # An identity belongs to exactly one account in Globus —
                    # linking moves it, it is never shared — and two
                    # accounts claiming one identity would give that
                    # identity two different identity_sets.
                    raise validation_error(
                        f"identity {iid} appears in accounts {owner[iid]} and {primary}; an "
                        f"identity belongs to one account."
                    )
                owner[iid] = primary
                i = _require_mapping(i, f"identity {iid}")
                if not i.get("username"):
                    raise validation_error(f"identity {iid} requires a 'username'")
                idp_id = _require_uuid(str(i.get("identity_provider")), f"identity {iid} identity_provider")
                if idp_id not in self.identity_providers:
                    raise validation_error(
                        f"identity {iid} names identity provider {idp_id}, which is not in "
                        f"'identity_providers'."
                    )
                identities[iid] = GlobusIdentity(
                    id=iid,
                    username=str(i["username"]),
                    identity_provider=idp_id,
                    name=_optional_str(i.get("name"), f"identity {iid} name"),
                    email=_optional_str(i.get("email"), f"identity {iid} email"),
                    organization=_optional_str(i.get("organization"), f"identity {iid} organization"),
                )
            if primary not in identities:
                raise validation_error(
                    f"account {primary} is named for its primary identity, so that identity "
                    f"must appear in its own 'identities'."
                )
            self.accounts[primary] = Account(primary=primary, identities=identities)

    def _require_account(self, value: Any, what: str) -> str | None:
        if value is None:
            return None
        account = _require_uuid(str(value), f"{what} account")
        if account not in self.accounts:
            raise validation_error(f"{what} names account {account}, which is not in 'accounts'.")
        return account

    def _refuse_unminted(self, section: str, name: str, prefix: str, counter: str) -> None:
        """The ``fauxbus-at-N`` collision rule, for every other minted name.

        Codes, sessions and parked requests are minted from counters the
        same way access tokens are, so seeding ``fauxbus-code-0`` into a
        fresh world would be overwritten by the first login — silently,
        deterministically, every run.  Same refusal, same line drawn at
        the counter rather than the name shape; see the ``tokens`` loop
        in ``load`` for the whole story.
        """
        n = minted_number(prefix, name)
        mints_next = self.counters.get(counter, 0)
        if n is not None and n >= mints_next:
            raise validation_error(
                f"{section} entry {name!r} is a name this world has not minted yet — the next "
                f"one is {minted_name(prefix, mints_next)!r} — so it would be silently "
                f"overwritten. Use a name outside the {prefix}N space, or set "
                f"counters.{counter} to {n + 1} or more."
            )

    def _load_logins_in_flight(self, doc: dict[str, Any]) -> None:
        """Parked requests, issued codes, and sessions: a half-finished login.

        Joining the round trip was decided rather than defaulted: carving
        an exception out of an invariant is how invariants die, and being
        able to dump a world mid-login and restore it exactly is a thing a
        harness can genuinely use.
        """

        def binding(section: str, name: str, r: dict[str, Any]) -> dict[str, Any]:
            # The fields a parked request and a code share.
            client_id = _require_uuid(str(r.get("client_id")), f"{section} {name} client_id")
            if client_id not in self.clients:
                raise validation_error(f"{section} {name} names unregistered client {client_id}")
            scopes = r.get("scopes") or []
            if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
                raise validation_error(f"{section} {name} 'scopes' must be a list of strings")
            if not isinstance(r.get("redirect_uri"), str):
                raise validation_error(f"{section} {name} requires a 'redirect_uri'")
            return {
                "client_id": client_id,
                "redirect_uri": r["redirect_uri"],
                "scopes": list(scopes),
                "state": _optional_str(r.get("state"), f"{section} {name} state"),
                "nonce": _optional_str(r.get("nonce"), f"{section} {name} nonce"),
                "code_challenge": _optional_str(r.get("code_challenge"), f"{section} {name} code_challenge"),
            }

        for rid, r in _require_mapping(doc.get("authorization_requests"), "authorization_requests").items():
            rid = str(rid)
            self._refuse_unminted("authorization_requests", rid, REQUEST_PREFIX, "authorization_request")
            r = _require_mapping(r, f"authorization_requests[{rid!r}]")
            self.authorization_requests[rid] = AuthorizationRequest(id=rid, **binding("request", rid, r))

        for code, c in _require_mapping(doc.get("authorization_codes"), "authorization_codes").items():
            code = str(code)
            self._refuse_unminted("authorization_codes", code, CODE_PREFIX, "authorization_code")
            c = _require_mapping(c, f"authorization_codes[{code!r}]")
            account = self._require_account(c.get("account"), f"code {code!r}")
            if account is None:
                raise validation_error(f"code {code!r} requires an 'account'")
            identity_id = _require_uuid(str(c.get("identity_id") or account), f"code {code!r} identity_id")
            if identity_id not in self.accounts[account].identities:
                raise validation_error(f"code {code!r}: identity {identity_id} is not in account {account}")
            self.authorization_codes[code] = AuthorizationCode(
                code=code,
                **binding("code", code, c),
                account=account,
                identity_id=identity_id,
                authenticated_at=_require_int(c.get("authenticated_at", self.clock), f"code {code!r} authenticated_at"),
                issued_at=_require_int(c.get("issued_at", self.clock), f"code {code!r} issued_at"),
                expires_at=_require_int(
                    c.get("expires_at", self.clock + CODE_LIFETIME), f"code {code!r} expires_at"
                ),
                used=bool(c.get("used", False)),
            )

        for sid, x in _require_mapping(doc.get("sessions"), "sessions").items():
            sid = str(sid)
            self._refuse_unminted("sessions", sid, SESSION_PREFIX, "session")
            x = _require_mapping(x, f"sessions[{sid!r}]")
            account = self._require_account(x.get("account"), f"session {sid!r}")
            if account is None:
                raise validation_error(f"session {sid!r} requires an 'account'")
            self.sessions[sid] = Session(
                id=sid,
                account=account,
                authenticated_at=_require_int(
                    x.get("authenticated_at", self.clock), f"session {sid!r} authenticated_at"
                ),
            )

    def reset(self) -> None:
        self.clock = 0
        self.counters = {}
        self.groups = {}
        self.pinned_identities = {}
        self.preferences = {}
        # Tokens go with the world.  A reset that left live tokens behind
        # would leak authorization across the test boundary the reset
        # exists to draw — and the token counter is in `counters`, so the
        # next issued token is `fauxbus-at-0` again, as determinism wants.
        self.clients = {}
        self.tokens = {}
        # And every login in flight with them: a code that survived a
        # reset could be redeemed by the next test, and a session that
        # survived would sign the next test's browser in as the last
        # test's user without ever showing the picker.
        self.issuer = None
        self.signed_token_clock = None
        self.identity_providers = {}
        self.accounts = {}
        self.authorization_requests = {}
        self.authorization_codes = {}
        self.sessions = {}
        # Collections and their role grants go too: a role that outlived
        # a reset would let the next test watch tasks it never set up a
        # right to see.
        self.collections = {}
        self.transfer_tasks = {}
