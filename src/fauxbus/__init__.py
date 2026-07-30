"""Fauxbus — a wire-level fake of the Globus API.

Point real globus-sdk client code at a Fauxbus server and it runs
unmodified: same paths, same response shapes, same status codes — plus
deterministic failure on demand via the /_fauxbus/ control plane.
"""

__version__ = "0.1.0.dev0"

# The globus-sdk version whose GroupsClient surface v0.1 imitates.
# Response shapes marked "recorded" in this codebase come from fixtures
# shipped inside this SDK release (globus_sdk/testing/data/groups/).
SDK_PIN = "4.8.1"

ISSUES_URL = "https://git.dev.xram.net/atmarx/fauxbus/issues"
