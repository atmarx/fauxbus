# Fauxbus

A wire-level fake of the Globus API — deterministic failure on demand.

Point your `globus-sdk` client at `http://localhost:9800` instead of the real
service, and your integration tests stop having a Globus-sized hole in them.
Same requests, same response shapes, same status codes — plus the one thing
the real service will never give you on purpose: a 429 exactly when your
retry logic needs testing, a member that's mysteriously already in the
group, a task that fails at 60%.

**Status: early.** The skeleton boots and answers the control plane; the
Groups API surface is landing next. Nothing here is stable yet — see
[SPEC.md](SPEC.md) for the full design and the v0.1 scope.

## Fake, not mock

Your code doesn't know Fauxbus is there. No monkeypatching, no fixture
dicts shaped like your guess about what Globus returns. The client library
you ship is the client library you test against — Fauxbus imitates what
`globus-sdk` actually sends and expects, pinned to a stated SDK version and
derived from real recorded responses, never guesswork.

## Quick start

```sh
pipx install fauxbus
fauxbus serve --port 9800
```

Point `globus_sdk.GroupsClient(...)` (or any Globus client) at that port
instead of the real service host, and run your existing test suite.

## Loud 501s, no fiction

Fauxbus only implements endpoints a real consumer needs. Anything it
doesn't imitate yet returns a loud `501` with a pointer to file an issue —
never a silent wrong answer pretending to be Globus. If you hit one, that's
the fastest way to get it prioritized.

## The control plane

Everything test-harness-y lives under `/_fauxbus/`, a prefix no Globus API
will ever claim — the imitated surface stays pure. `GET /_fauxbus/state`
dumps everything in the world for assertions; `POST /_fauxbus/reset` wipes
it between tests. Full control-plane surface is in [SPEC.md](SPEC.md).

## Not affiliated with Globus

Fauxbus is an independent test tool, not affiliated with or endorsed by
Globus or the University of Chicago. "Globus" is their trademark; this
project imitates the API's behavior for local testing only — the name is a
confession, not an infringement. It's *faux*.
