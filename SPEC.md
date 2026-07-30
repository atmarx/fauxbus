# Fauxbus — a wire-level fake of the Globus API

Point your Globus client at `http://localhost:9800` instead of
`https://groups.api.globus.org`, and your integration tests stop having a
Globus-sized hole in them.

Fauxbus is a standalone HTTP server that imitates Globus service APIs well
enough that **real client code runs against it unmodified** — same requests,
same response shapes, same status codes — plus the one thing the real service
will never give you: **deterministic failure on demand**.  A 429 exactly when
your retry logic needs testing.  A member that's mysteriously already in the
group.  A task that fails at 60%.

It is a *fake*, not a mock: your code doesn't know it's there.  No
monkeypatching, no fixture dicts shaped like your guess about what Globus
returns.  The client library you ship is the client library you test.

## Why this exists

Globus has no sandbox, no emulator, no local mode.  Anyone building against
it today either tests in production against a real tenancy (slow, stateful,
rate-limited, needs secrets in CI) or hand-rolls mocks that quietly encode
their own misunderstanding of the API.  Mocking a service you don't control
tests your fiction of it.  A shared, wire-level fake — kept honest by a
conformance suite that also runs against the real thing — is the missing
piece, and it gets more useful every year Globus grows.

## Design principles

1. **The SDK is the contract.**  Fauxbus imitates what the official
   `globus-sdk` actually sends and expects, pinned to a stated SDK version.
   Endpoint paths, payload shapes, and error documents are derived from the
   SDK's own calls and from responses recorded against the real service —
   never from guesswork.  If the SDK's method works against Fauxbus, that's
   the definition of working.
2. **Only what's used.**  Endpoints are added because a real consumer needs
   them, not for coverage's sake.  An unimplemented endpoint returns a loud
   `501` with a "file an issue" pointer — never a silent wrong answer.  The
   moment Fauxbus grows features nobody calls, it's a Globus emulator
   maintained as a hobby, which is a bug.
3. **Deterministic by construction.**  No wall-clock dependence, no random
   behavior unless armed.  The same test run gives the same answers.  Time
   only advances when the test says so (see the control plane).
4. **The control plane is out-of-band.**  Everything test-harness-y lives
   under `/_fauxbus/…`, a prefix no Globus API will ever claim.  The imitated
   surface stays pure.
5. **Faithful to Globus semantics, agnostic to yours.**  Fauxbus enforces
   what *Globus* enforces (role hierarchy, membership states, id formats).
   It does not enforce any consumer's house policy — your rules about who
   may hold what role belong in *your* test assertions, reading Fauxbus
   state through the control plane.

## v0.1 — Groups

The first release imitates the **Globus Groups API v2**, scoped to the
`globus-sdk` `GroupsClient` surface:

- create / get / delete a group; subgroup creation under a parent
- list "my groups" for the calling identity
- batch membership actions: add, remove, and the invite/approve family —
  with per-identity success/failure results in the response document, the
  way the real service partially succeeds
- group policies get/set
- membership roles as Globus defines them (`admin`, `manager`, `member`)
  with the real service's rules about who may perform which action

Response documents, id formats (UUIDs where Globus uses them), pagination
shape, and error bodies match recorded real-service responses.

### Auth posture

Requests must carry a bearer token — a client that forgets auth should fail
in dev, not in prod (`--allow-anonymous` exists but defaults off).  The
token is **not** cryptographically validated: by default, any token is
accepted and its *identity is derived from the token string itself* (a
stable mapping, so `token-for-alice` is always the same caller).  A config
file can pin explicit token → identity mappings when a test needs to be
picky.  Real token introspection is out of scope until an Auth API mock
exists (roadmap).

## The control plane (`/_fauxbus/`)

- `POST /_fauxbus/reset` — wipe all state; the between-tests handshake.
- `POST /_fauxbus/seed` — load a state document (groups, members, roles) so
  a test starts mid-story instead of building the world via API calls.
- `GET  /_fauxbus/state` — dump everything, for assertions.  Your test
  checks what's *actually in the directory*, not what your code claims it
  did.
- `POST /_fauxbus/failures` — arm failure injection: match on method +
  path glob, respond with a chosen status/body, for the next N matching
  requests (or until cleared).  `DELETE /_fauxbus/failures` disarms.
  One-shot inline variant: send `X-Fauxbus-Fail: 429` on any request to get
  that failure exactly once, for quick cases.
- `POST /_fauxbus/tick` — advance Fauxbus's clock (roadmap: what makes
  transfer-task progression testable without `sleep`).

State is in-memory and disposable by design.  `--seed state.json` on boot
covers the compose-stack case where the world should exist before the first
test connects.

## Packaging

- Python ≥3.11.  `pipx install fauxbus && fauxbus serve --port 9800`.
- A container image for compose stacks and CI services.
- Dependency-light on purpose; nothing exotic.
- BSD-3-Clause (recommended — sits comfortably next to the Apache-2 SDK).

## The conformance tether

The repo ships one test suite that runs against **two backends**: Fauxbus
(every CI run) and the real Globus service (opt-in, env-gated, against a
sacrificial group in a real tenancy — run before each release).  Every
recorded behavior Fauxbus imitates gets a conformance case.  If the real
service and the fake ever answer differently, this suite is where it shows
— it is the mechanism that keeps Fauxbus from becoming someone's fiction,
and a divergence is a release-blocking bug in Fauxbus, not in the caller.

## Roadmap (after Groups earns its keep)

- **Transfer** — the big one: endpoints/collections, task submission, and a
  simulated task lifecycle (ACTIVE → SUCCEEDED/FAILED with byte progress)
  driven by `/_fauxbus/tick`, so e2e suites can watch a transfer "run"
  in milliseconds and fail it at will.
- **Auth** — identities lookup, token introspection, dependent tokens; at
  that point the Groups auth posture can grow real introspection.
- Whatever consumers file issues for, in that order, per principle 2.

## Not affiliated with Globus

Fauxbus is an independent test tool, not affiliated with or endorsed by
Globus or the University of Chicago.  "Globus" is their trademark; this
project imitates the API's behavior for local testing only, and the name is
a confession, not an infringement: it's *faux*.
