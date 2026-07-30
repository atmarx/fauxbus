"""The in-memory world: groups, memberships, policies, preferences.

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

from .auth import Identity, derive_identity, placeholder_username
from .errors import ApiError, group_not_found, validation_error
from .ids import sequential_id

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


class World:
    """All mutable state, plus its (de)serialization for seed/state.

    The server holds one World behind a lock.  Everything here is plain
    data in, plain data out — no HTTP awareness.
    """

    def __init__(self) -> None:
        self.clock: int = 0
        self.counters: dict[str, int] = {}
        self.groups: dict[str, Group] = {}
        self.pinned_identities: dict[str, dict[str, str]] = {}  # token -> {identity_id, username}
        self.preferences: dict[str, dict[str, Any]] = {}  # identity_id -> prefs doc

    # ------------------------------------------------------------------ ids

    def next_id(self, kind: str) -> str:
        n = self.counters.get(kind, 0)
        self.counters[kind] = n + 1
        return sequential_id(kind, n)

    # ----------------------------------------------------------- identities

    def identity_for_token(self, token: str) -> Identity:
        pin = self.pinned_identities.get(token)
        if pin is not None:
            return Identity(identity_id=pin["identity_id"], username=pin["username"])
        return derive_identity(token)

    def username_for(self, identity_id: str) -> str:
        for pin in self.pinned_identities.values():
            if pin["identity_id"] == identity_id:
                return pin["username"]
        return placeholder_username(identity_id)

    # --------------------------------------------------------------- groups

    def get_group(self, group_id: str, caller: Identity) -> Group:
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
        for verb in BATCH_VERBS:  # canonical order keeps runs deterministic
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
        """The single-group document — RECORDED shape (BASE_GROUP_DOC fixture)."""
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
        a valid seed, and seeding a fresh world with it reproduces it."""
        return {
            "version": 0,
            "clock": self.clock,
            "counters": dict(sorted(self.counters.items())),
            "identities": {t: dict(p) for t, p in sorted(self.pinned_identities.items())},
            "preferences": {i: dict(p) for i, p in sorted(self.preferences.items())},
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
        if not isinstance(doc, dict):
            raise validation_error("seed document must be an object")
        self.reset()
        self.clock = int(doc.get("clock", 0))
        self.counters = {str(k): int(v) for k, v in (doc.get("counters") or {}).items()}
        for token, pin in (doc.get("identities") or {}).items():
            if not isinstance(pin, dict) or "identity_id" not in pin:
                raise validation_error(f"identity pin for token {token!r} requires identity_id")
            identity_id = _require_uuid(str(pin["identity_id"]), "identity_id")
            self.pinned_identities[str(token)] = {
                "identity_id": identity_id,
                "username": str(pin.get("username") or placeholder_username(identity_id)),
            }
        for identity_id, prefs in (doc.get("preferences") or {}).items():
            self.preferences[_require_uuid(str(identity_id), "identity_id")] = {
                "allow_add": bool(prefs.get("allow_add", True))
            }
        for gid, g in (doc.get("groups") or {}).items():
            gid = _require_uuid(str(gid), "group id")
            if not isinstance(g, dict) or not g.get("name"):
                raise validation_error(f"seed group {gid} requires a name")
            policies = dict(DEFAULT_POLICIES)
            policies.update(g.get("policies") or {})
            group = Group(
                id=gid,
                name=str(g["name"]),
                description=g.get("description"),
                parent_id=g.get("parent_id"),
                group_type=str(g.get("group_type", "regular")),
                enforce_session=bool(g.get("enforce_session", False)),
                session_limit=int(g.get("session_limit", 28800)),
                session_timeouts=dict(g.get("session_timeouts") or {}),
                policies=policies,
                subscription_id=g.get("subscription_id"),
                subscription_info=g.get("subscription_info"),
                subscription_admin_verified_id=g.get("subscription_admin_verified_id"),
            )
            for identity_id, m in (g.get("memberships") or {}).items():
                identity_id = _require_uuid(str(identity_id), "identity_id")
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
            for identity_id, fields in (g.get("membership_fields") or {}).items():
                group.membership_fields[_require_uuid(str(identity_id), "identity_id")] = dict(
                    fields
                )
            self.groups[gid] = group

    def reset(self) -> None:
        self.clock = 0
        self.counters = {}
        self.groups = {}
        self.pinned_identities = {}
        self.preferences = {}
