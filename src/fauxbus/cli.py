"""fauxbus — the command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import SDK_PIN, __version__
from .server import boot_line, make_server
from .world import World


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fauxbus",
        description="A wire-level fake of the Globus API for E2E testing.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the fake")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=9800)
    serve.add_argument("--seed", type=Path, help="state document to load on boot")
    serve.add_argument(
        "--allow-anonymous",
        action="store_true",
        help="accept requests without a bearer token (defaults off: a client "
        "that forgets auth should fail in dev, not in prod)",
    )
    serve.add_argument(
        "--control-loopback-only",
        action="store_true",
        help="refuse /_fauxbus/ requests from non-loopback peers. Off by "
        "default: the imitated service answers the whole network, and "
        "harnesses are often sibling containers. Turn it on when the "
        "host is shared — the control plane is the surface that can "
        "rewrite the world and forge responses",
    )
    serve.add_argument("--verbose", action="store_true", help="log every request")

    sub.add_parser("version", help="print version and imitated SDK pin")

    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"fauxbus {__version__} (imitating the globus-sdk {SDK_PIN} GroupsClient surface)")
        return 0

    world = World()
    canonical_seed = None
    # The boot seed IS the canonical seed: POST /_fauxbus/reset
    # restores this exact document, so a container with a mounted seed
    # always comes home to it between tests.
    if args.seed:
        try:
            canonical_seed = json.loads(args.seed.read_text())
            world.load(canonical_seed)
        except Exception as err:  # noqa: BLE001 — boot failures should be plain, not tracebacks
            print(f"fauxbus: could not load seed {args.seed}: {err}", file=sys.stderr)
            return 2
        print(f"fauxbus: seeded {len(world.groups)} group(s) from {args.seed}", file=sys.stderr)

    server = make_server(
        args.host,
        args.port,
        world=world,
        allow_anonymous=args.allow_anonymous,
        verbose=args.verbose,
        canonical_seed=canonical_seed,
        control_loopback_only=args.control_loopback_only,
    )
    # Boot chatter goes to stderr, like all of it — stdout belongs to
    # whoever wants to pipe this process.
    print(boot_line(server), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("fauxbus: shutting down", file=sys.stderr)
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
