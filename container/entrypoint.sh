#!/bin/sh
# Fauxbus container entrypoint.
#
# The convention: mount a state document at /seed.json (read-only is
# fine) and the world exists before the first test connects.  No file,
# no seed — the server boots empty either way.
#
# Everything after the image name (compose `command:`, `docker run`
# args) is passed through to `fauxbus serve`, and argparse lets later
# flags win — so `--verbose`, `--allow-anonymous`, even a different
# `--port` all work without touching this script.
set -e

if [ -f /seed.json ]; then
    exec fauxbus serve --host 0.0.0.0 --port 9800 --seed /seed.json "$@"
fi
exec fauxbus serve --host 0.0.0.0 --port 9800 "$@"
