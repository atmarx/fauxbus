"""Deterministic identifiers.

No ``uuid4`` anywhere: the same sequence of API calls yields the same
ids on every run.  Ids are uuid5 hashes of a Fauxbus namespace and a
per-kind monotonic counter; the counters live in world state, so
``/_fauxbus/reset`` restores id determinism along with everything else.
"""

from __future__ import annotations

import uuid

FAUXBUS_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "fauxbus.invalid")


def sequential_id(kind: str, counter: int) -> str:
    return str(uuid.uuid5(FAUXBUS_NS, f"{kind}:{counter}"))


def identity_id_for_token(token: str) -> str:
    """The stable token → identity mapping: same token, same caller, every run."""
    return str(uuid.uuid5(FAUXBUS_NS, f"identity:{token}"))
