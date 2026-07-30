"""Bearer-token handling and the token → identity derivation.

Tokens are not cryptographically validated (SPEC: real introspection
waits for an Auth service mock).  Any bearer token is accepted; its
identity is a pure function of the token string, so ``token-for-alice``
is the same caller — same UUID, same username — on every run.  The seed
document's ``identities`` section pins explicit mappings when a test
needs to control them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .ids import identity_id_for_token

ANONYMOUS_TOKEN = ""


@dataclass(frozen=True)
class Identity:
    identity_id: str
    username: str


def derive_identity(token: str) -> Identity:
    if token == ANONYMOUS_TOKEN:
        local = "anonymous"
    else:
        local = re.sub(r"[^a-z0-9_.-]+", "-", token.lower()).strip("-") or "caller"
    return Identity(
        identity_id=identity_id_for_token(token),
        username=f"{local[:64]}@fauxbus.example",
    )


def parse_bearer(header_value: str | None) -> str | None:
    """Return the token from an Authorization header, or None if absent/malformed."""
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


def placeholder_username(identity_id: str) -> str:
    """Username for an identity we only know as a UUID (e.g. batch-added).

    The real service resolves identities through Globus Auth; Fauxbus has
    no Auth service yet, so unknown UUIDs get a readable, deterministic
    placeholder.
    """
    return f"{identity_id}@fauxbus.example"
