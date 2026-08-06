#!/bin/sh
# Fauxbus container entrypoint.
#
# The convention: mount a state document at /seed.json (read-only is
# fine) and the world exists before the first test connects.  No file,
# no seed — the server boots empty either way.
#
# Everything after the image name (compose `command:`, `docker run`
# args) is passed through to `fauxbus serve`, and argparse lets later
# flags win — so `--verbose`, `--allow-anonymous`, `--control-loopback-only`,
# even a different `--port` all work without touching this script.
#
# On `--host 0.0.0.0`: this is required, not careless.  A container that
# binds 127.0.0.1 is unreachable even through a published port, since the
# container's loopback is its own.  The CLI defaults to 127.0.0.1 for
# processes on a laptop; containers must bind wide to be usable at all.
# What that exposes — the unauthenticated control plane — is covered in
# SPEC.md under "Control-plane reachability", along with the flag that
# narrows it on a shared host.
set -e

if [ -f /seed.json ]; then
    exec fauxbus serve --host 0.0.0.0 --port 9800 --seed /seed.json "$@"
fi
exec fauxbus serve --host 0.0.0.0 --port 9800 "$@"
