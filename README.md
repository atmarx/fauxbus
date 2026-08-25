# Fauxbus

A wire-level fake of the Globus API for E2E testing.

## The problem

Globus is the data fabric of research computing: it moves datasets
between universities, national labs, and HPC centers, and its API is how
institutions automate that world — group rosters that gate who can reach
which collection, permissions, transfer pipelines.  If you run research
infrastructure, sooner or later you have code calling this API, and that
code matters more than most: it decides who can touch the data.

Testing that code is where it gets uncomfortable.  Globus has no
sandbox, no emulator, no local mode.  The SDK ships a testing module,
but it is in-process canned responses — by its own docs "a best
approximation of API responses" — which serves unit tests well and
cannot back a socket.  So an integration test has two options: a real
tenancy (real credentials in CI, real groups with real people in them,
rate limits, shared mutable state, network weather), or nothing.  A lot
of shops choose nothing.  The layer that gates access to research data
ends up the least-tested code in the pipeline, precisely because it is
the riskiest thing to point a test at.

Fauxbus is a third option: a standalone HTTP server that imitates the
Globus API at the wire level.  Point your `globus-sdk` client at
`http://localhost:9800` instead of the real service and run your
existing suite — same requests, same response shapes, same status
codes.  Your code never learns it isn't talking to Globus.  And because
the whole point of a fake is control, failure is a feature you schedule:
a 429 on exactly the request where your retry logic needs exercise, an
identity that is already in the group, a batch action that partially
fails the way the real service partially fails.

**Status: early but real.**  The complete `GroupsClient` surface of
globus-sdk 4.8.1 is implemented — all fourteen methods, all eleven
batch membership verbs — plus the OAuth2 **client-credentials grant** at
`POST /v2/oauth2/token`, so a service can fetch a token as itself and
then spend it.  The conformance suite drives all of it through the
actual globus-sdk, unmodified, including the SDK's retry layer
recovering through an injected 429.  Response shapes not yet backed by a
recording are marked `PROVISIONAL` in code and tracked as conformance
obligations.  Nothing is stable yet — see [SPEC.md](SPEC.md) for the
full design.

## Fake, not mock

Your code doesn't know Fauxbus is there.  No monkeypatching, no fixture
dicts shaped like your guess about what Globus returns.  The client
library you ship is the client library you test against — Fauxbus
imitates what `globus-sdk` actually sends and expects, pinned to a
stated SDK version and derived from real recorded responses, never
guesswork.

If canned responses inside a Python unit test are all you need, use the
SDK's own `globus_sdk.testing` — that's the in-process layer, and its
fixtures are Fauxbus's ground truth.  Fauxbus is for the layer it
architecturally can't reach: a real socket your whole stack can talk
to, with state behind it (think moto next to botocore's `Stubber`).

## Quick start

```sh
pipx install fauxbus
fauxbus serve --port 9800
```

Point `globus_sdk.GroupsClient(...)` at that port instead of the real
service host and run your existing test suite.  Other Globus clients
will meet honest `501`s until their surfaces exist — see below.

## Tokens

By default any bearer token works, and its identity is a stable function
of the token string — `t-alice` is the same caller on every run, on
every machine.  That is usually what you want in a test.

When you need the real thing, register a confidential client in the seed
document and fetch a token the way your service will in production:

```python
from globus_sdk import ConfidentialAppAuthClient, AccessTokenAuthorizer, GroupsClient

auth = ConfidentialAppAuthClient(CLIENT_ID, SECRET, base_url="http://localhost:9800")
tokens = auth.oauth2_client_credentials_tokens(
    "urn:globus:auth:scope:groups.api.globus.org:all"
)
access_token = tokens.by_resource_server["groups.api.globus.org"]["access_token"]

groups = GroupsClient(base_url="http://localhost:9800",
                      authorizer=AccessTokenAuthorizer(access_token))
```

A Globus client *is* an identity, so that token acts as the client
itself — create a group with it and the client shows up as its own
`admin`, exactly as it would against the real service.

Start with `--require-issued-tokens` and Fauxbus stops accepting
made-up tokens: it checks that a token was issued here, hasn't expired
(on the logical clock — `POST /_fauxbus/tick` ages it, no sleeping), and
is good for the service being called.  Three production failures you
otherwise cannot write a test for.

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

## The control plane

Everything test-harness-y lives under `/_fauxbus/`, a prefix no Globus
API will ever claim — the imitated surface stays pure.  `GET
/_fauxbus/state` dumps everything in the world for assertions; `POST
/_fauxbus/reset` returns the world to its canonical seed (or to empty)
between tests — mutate freely, reset comes home.  Full control-plane
surface is in [SPEC.md](SPEC.md).

It is unauthenticated by design — it imitates a service that answers
the network, and harnesses are often sibling containers.  Which means
anyone who can reach the port can rewrite the world and arm forged
responses; for a fake, the sharpest risk isn't a crash but a lie, since
tests that trust it would go green when they should go red.  Run it
where you'd run any test fixture.  On a shared host,
`--control-loopback-only` refuses `/_fauxbus/` from non-loopback peers
without touching the imitated surface.  The reasoning, and the two
things that flag deliberately doesn't solve, are in
[SPEC.md](SPEC.md#control-plane-reachability).

## Loud 501s, no fiction

Fauxbus only implements endpoints a real consumer needs.  Anything it
doesn't imitate yet returns a loud `501` with a pointer to file an
issue — never a silent wrong answer pretending to be Globus.  If you
hit one, that's the fastest way to get it prioritized.

## The source is meant to be read

Comments narrate the design decisions where they live — why uuid5 and
never uuid4, why one lock, why 404 instead of 403, why failure
injection can't touch the control plane — at a depth meant for someone
learning how to *build* a wire-level fake, not just use one.

## Not affiliated with Globus

Fauxbus is an independent test tool, not affiliated with or endorsed by
Globus or the University of Chicago.  "Globus" is their trademark; this
project imitates the API's behavior for local testing only — the name
is a confession, not an infringement.  It's *faux*.

## License

MIT.  Fauxbus contains no Globus code: it imitates publicly documented
wire behavior, grounded against the Apache-2.0 `globus-sdk` as a
test-time dependency only.
