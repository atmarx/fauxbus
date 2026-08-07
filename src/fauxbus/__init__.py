"""Fauxbus — a wire-level fake of the Globus API.

Point real globus-sdk client code at a Fauxbus server and it runs
unmodified: same paths, same response shapes, same status codes — plus
deterministic failure on demand via the /_fauxbus/ control plane.
"""

# THE version.  pyproject.toml reads this literal at build time
# ([tool.hatch.version]), so bumping this one line is the whole bump —
# there is no second copy to keep in sync.  It is also what the server
# reports on the wire, which is why it has to be right: a consumer
# debugging a conformance mismatch asks GET /_fauxbus/ what it is
# talking to, and a stale answer sends them looking in the wrong place.
__version__ = "0.1.2"

# The globus-sdk version whose GroupsClient surface v0.1 imitates.
# Response shapes marked "recorded" in this codebase come from fixtures
# shipped inside this SDK release (globus_sdk/testing/data/groups/).
SDK_PIN = "4.8.1"

# This URL ships inside every 501 body ("File an issue: ..."), which
# makes it principle 2's escape hatch: a loud 501 is only useful if the
# person reading it can act on it.  It pointed at the private Gitea
# through v0.1.1, so every stranger who hit an unimplemented endpoint
# was handed a link they couldn't open.  Public tracker or it's a dead
# end dressed up as an invitation.
ISSUES_URL = "https://github.com/atmarx/fauxbus/issues"
