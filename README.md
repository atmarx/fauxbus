# Fauxbus

A wire-level fake of the Globus API — deterministic failure on demand.

Point your `globus-sdk` client at `http://localhost:9800` instead of the real
service, and your integration tests stop having a Globus-sized hole in them.
Same requests, same response shapes, same status codes — plus the one thing
the real service will never give you on purpose: a 429 exactly when your
retry logic needs testing, a member that's mysteriously already in the
group, a task that fails at 60%.

**Status: early but real.** The complete `GroupsClient` surface of
globus-sdk 4.8.1 is implemented — all fourteen methods, all eleven batch
membership verbs — and the conformance suite drives every one of the
fourteen through the actual globus-sdk, unmodified, including its retry
logic sailing through an injected 429. Response shapes not yet backed by a recording are marked
`PROVISIONAL` in code and tracked as conformance obligations. Nothing is
stable yet — see [SPEC.md](SPEC.md) for the full design.

The source is written to be read.  Comments narrate the design
decisions where they live — why uuid5 and never uuid4, why one lock,
why 404 instead of 403, why injection can't touch the control plane —
at a depth meant for someone learning how to *build* a wire-level
fake, not just use one.

## Fake, not mock

Your code doesn't know Fauxbus is there. No monkeypatching, no fixture
dicts shaped like your guess about what Globus returns. The client library
you ship is the client library you test against — Fauxbus imitates what
`globus-sdk` actually sends and expects, pinned to a stated SDK version and
derived from real recorded responses, never guesswork.

If canned responses inside a Python unit test are all you need, use the
SDK's own `globus_sdk.testing` — that's the in-process layer, and its
fixtures are Fauxbus's ground truth.  Fauxbus is for the layer it
architecturally can't reach: a real socket your whole stack can talk
to, with state behind it (think moto next to botocore's `Stubber`).

## Quick start

```sh
# not on PyPI yet — install straight from the repo
pipx install git+https://git.dev.xram.net/atmarx/fauxbus
fauxbus serve --port 9800
```

Point `globus_sdk.GroupsClient(...)` (or any Globus client) at that port
instead of the real service host, and run your existing test suite.

## In a compose stack

The repo ships a `Containerfile`.  Zero runtime dependencies means the
image is the Python base plus one stdlib-only wheel — nothing else rides
along.  Mount a state document at `/seed.json` and the world exists
before the first test connects:

```yaml
services:
  fauxbus:
    build: { context: ., dockerfile: Containerfile }
    ports: ["9800:9800"]
    volumes: ["./seed.json:/seed.json:ro"]
```

The image ships a healthcheck on the control-plane index, so
`depends_on: { fauxbus: { condition: service_healthy } }` does the
waiting for you.  A runnable example — sibling-service pattern, seed
file included, both round-trip tested in CI — is in
[`examples/`](examples/).

## Loud 501s, no fiction

Fauxbus only implements endpoints a real consumer needs. Anything it
doesn't imitate yet returns a loud `501` with a pointer to file an issue —
never a silent wrong answer pretending to be Globus. If you hit one, that's
the fastest way to get it prioritized.

## The control plane

Everything test-harness-y lives under `/_fauxbus/`, a prefix no Globus API
will ever claim — the imitated surface stays pure. `GET /_fauxbus/state`
dumps everything in the world for assertions; `POST /_fauxbus/reset`
returns the world to its canonical seed (or to empty) between tests —
mutate freely, reset comes home. Full control-plane surface is in
[SPEC.md](SPEC.md).

## Not affiliated with Globus

Fauxbus is an independent test tool, not affiliated with or endorsed by
Globus or the University of Chicago. "Globus" is their trademark; this
project imitates the API's behavior for local testing only — the name is a
confession, not an infringement. It's *faux*.

## License

MIT. Fauxbus contains no Globus code: it imitates publicly documented
wire behavior, grounded against the Apache-2.0 `globus-sdk` as a
test-time dependency only.
