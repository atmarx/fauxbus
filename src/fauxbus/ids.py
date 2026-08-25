"""Deterministic identifiers.

No ``uuid4`` anywhere: the same sequence of API calls yields the same
ids on every run.  Ids are uuid5 hashes of a Fauxbus namespace and a
per-kind monotonic counter; the counters live in world state, so
``/_fauxbus/reset`` restores id determinism along with everything else.

The lesson this file teaches: ``uuid4`` is 122 random bits — perfect
for a real service, poison for a test fake.  ``uuid5`` is the same
value every time for the same input: it hashes a namespace UUID plus a
name string into something UUID-shaped.  Pure function in, UUID out.
That is SPEC principle 3 ("deterministic by construction") at the
lowest level: don't scrub randomness out later — never let it in.
"""

from __future__ import annotations

import uuid

# The namespace is itself a uuid5, derived from a name under the
# reserved ``.invalid`` TLD (RFC 2606) — a domain that can never exist
# in real DNS, so ids minted here can never collide with ids anyone
# derives from a domain they actually own.
FAUXBUS_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "fauxbus.invalid")


def sequential_id(kind: str, counter: int) -> str:
    """The Nth object of a kind gets the same UUID in every universe.

    The counter comes from world state (World.next_id), not a module
    global: reset the world and the next group created is "group:0"
    again — the same UUID as the first group of every run before it.
    Tests can hard-code ids without embarrassment.
    """
    return str(uuid.uuid5(FAUXBUS_NS, f"{kind}:{counter}"))


def identity_id_for_token(token: str) -> str:
    """The stable token → identity mapping: same token, same caller, every run.

    This one line is the fake's entire authentication story.  No login,
    no session store, no token database — the token string IS the
    identity, hashed into UUID shape.  ``t-alice`` maps to the same
    UUID on your laptop, in CI, and in the shipped example seed.
    """
    return str(uuid.uuid5(FAUXBUS_NS, f"identity:{token}"))


def access_token(counter: int) -> str:
    """The Nth access token this world issues, spelled the same every run.

    Deliberately readable and deliberately guessable, and both halves of
    that need defending.

    Readable, because a token that says ``fauxbus-at-0`` in a log, a
    state dump, or a failing assertion tells you what it is and where it
    came from.  A realistic-looking opaque blob would tell you nothing
    and would invite someone to paste it somewhere it does not belong.

    Guessable, because principle 3 leaves no alternative: a random token
    would make every state dump differ from the last, and the round-trip
    invariant (dump is a valid seed that reproduces the dump) would die
    with it.  That is a real trade — under ``--require-issued-tokens``
    an attacker who can reach the fake can guess ``fauxbus-at-0`` and it
    will be a live token.  It is the right trade only because this is a
    fake: SPEC already treats every token here as a fixture rather than
    a credential, and the whole design leans on nobody ever being able
    to mistake a Fauxbus token for a real one.  The name helps with that.
    """
    return f"fauxbus-at-{counter}"
