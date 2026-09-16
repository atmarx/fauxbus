"""The in-memory world: groups, memberships, policies, preferences,
plus the OAuth2 client registry and the tokens it has issued.

Truth grades (see SPEC.md "Recorded, documented, provisional"):
- Document shapes for groups, my_groups entries, policies, and DELETE
  responses are RECORDED — they match fixtures shipped inside
  globus-sdk 4.8.1 (globus_sdk/testing/data/groups/).
- Role/status semantics follow SDK docstrings where stated (DOCUMENTED).
- Anything marked PROVISIONAL is Fauxbus's best inference and carries an
  open conformance obligation against the real service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from .auth import (
    Identity,
    client_username,
    derive_identity,
    placeholder_username,
    resource_server_for_scope,
)
from .errors import (
    ApiError,
    group_not_found,
    invalid_client,
    not_implemented,
    validation_error,
)
from .ids import access_token, access_token_number, sequential_id

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
IMPLEMENTED_GRANT_TYPES = ("client_credentials",)


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
    """

    client_id: str
    secret: str
    name: str
    username: str


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
    expires_at: int  # logical clock, not wall clock — see World.clock


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

    def resource_server_for_request(self, scopes: list[str]) -> str:
        """Which single service these scopes are asking for.

        A Globus access token belongs to exactly one resource server, and
        the request names it only indirectly — inside the scope strings.
        So this is the function that decides what the token endpoint is
        about to mint, and every way it can fail is a loud one.

        Asking for scopes across *two* services is legal at the real
        service: it answers with a primary token plus the rest in
        ``other_tokens``.  Fauxbus does not build that yet, and the
        tempting shortcut — issue for whichever resource server appeared
        first and quietly drop the other scopes — is the exact silent
        wrong answer principle 2 forbids.  The consumer would get a token
        that looks fine and fails later against a service it was never
        good for.  501 instead, with the tracker link.
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
        if len(by_server) > 1:
            raise not_implemented(
                f"Fauxbus issues one token per request, and these scopes span "
                f"{sorted(by_server)}. The real service answers multi-resource-server "
                f"requests with a primary token plus 'other_tokens'; that is a later "
                f"slice. Real client code needs it?"
            )
        return next(iter(by_server))

    def issue_token(
        self,
        client: OAuthClient,
        *,
        resource_server: str,
        scopes: list[str],
        grant_type: str,
        expires_in: int = DEFAULT_EXPIRES_IN,
    ) -> IssuedToken:
        """Mint one access token and remember what it authorizes.

        The expiry is on the *logical* clock (World.clock), not the wall
        clock — so a test expires a token by POSTing to
        ``/_fauxbus/tick``, deterministically, rather than by sleeping
        for two days.  SPEC principle 3 holds here without an exception,
        because Fauxbus is the only thing that will ever validate this
        token.  Signed ID tokens are the one place it cannot hold, and
        that is a Slice B problem.
        """
        counter = self.counters.get("access_token", 0)
        self.counters["access_token"] = counter + 1
        issued = IssuedToken(
            token=access_token(counter),
            client_id=client.client_id,
            identity_id=client.client_id,  # a client IS its identity — see OAuthClient
            username=client.username,
            resource_server=resource_server,
            scopes=list(scopes),
            grant_type=grant_type,
            expires_at=self.clock + expires_in,
        )
        self.tokens[issued.token] = issued
        return issued

    def token_response(self, issued: IssuedToken) -> dict[str, Any]:
        """The token document, field for field as globus-sdk expects it.

        RECORDED from
        ``globus_sdk/testing/data/auth/oauth2_client_credentials_tokens.py``
        (4.8.1).  ``other_tokens`` is the field to be careful about: it is
        present unconditionally, as ``[]``, even when a single token is
        issued.  That is not decoration — the SDK's
        ``OAuthTokenResponse._init_rs_dict`` indexes ``self["other_tokens"]``
        with no ``.get`` and no default, so omitting it raises a KeyError
        inside the SDK before the consumer's code ever sees the response.

        ``expires_in`` is computed against the current clock rather than
        stored, so a token fetched, then aged with ``/_fauxbus/tick``,
        then re-rendered still reports the truth.
        """
        return {
            "access_token": issued.token,
            "scope": " ".join(issued.scopes),
            "expires_in": max(0, issued.expires_at - self.clock),
            "token_type": "Bearer",
            "resource_server": issued.resource_server,
            "other_tokens": [],
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
        issued = self.tokens.get(token)
        if issued is None:
            raise ApiError(
                401,
                "UNAUTHORIZED",
                "This Fauxbus runs with --require-issued-tokens, and no token by that "
                "name was issued here. Get one from POST /v2/oauth2/token, or seed it "
                "into the state document's 'tokens' section.",
            )
        if issued.expires_at <= self.clock:
            raise ApiError(
                401,
                "UNAUTHORIZED",
                f"Token expired at logical clock {issued.expires_at}; the clock now reads "
                f"{self.clock}. Fauxbus expires tokens on POST /_fauxbus/tick, never on "
                f"real time.",
            )
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
                cid: {"secret": c.secret, "name": c.name, "username": c.username}
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
                    "expires_at": t.expires_at,
                }
                for tok, t in sorted(self.tokens.items())
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
            self.clients[client_id] = OAuthClient(
                client_id=client_id,
                secret=str(c["secret"]),
                name=str(c.get("name") or client_id),
                username=str(c.get("username") or client_username(client_id)),
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
                expires_at=_require_int(t["expires_at"], f"token {tok!r} expires_at"),
            )
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
