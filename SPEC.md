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

### Prior art: `globus_sdk.testing`

The SDK ships a testing module, and Fauxbus is deliberately not a
second one.  `globus_sdk.testing` (public as of SDK 4.x; `_testing` in
3.x) is an in-process mock layer built on the `responses` library: it
intercepts HTTP inside the Python process that activates it, replaying
canned per-method fixtures.  For unit tests — "my function calls
`get_group` and handles the response" — it is the right tool and
lighter than Fauxbus.  Use it there.

What it cannot be, by architecture rather than by gap, is a server.
Nothing listens on a socket, so a containerized app, a compose stack, a
non-Python client, or plain `curl` cannot reach it.  Its fixtures are
stateless — create a group, then list groups, and the list fixture
doesn't know — and its own docs scope the payloads as "a best
approximation of API responses" that "may change in any SDK release."
(The Globus-operated `sandbox`/`preview`/`test` environments the SDK
config knows about are the other direction: real, online, credentialed,
shared, non-deterministic — not a local dev tool either.)

Fauxbus is the complementary layer, in the same relationship to
`globus_sdk.testing` as moto stands to botocore's `Stubber`, or
WireMock to Mockito stubs: the stateful wire fake next to the
in-process mock, a standard pairing in mature ecosystems.  Not a rival
but a consumer — the RECORDED truth grade is *defined* as "backed by a
fixture the SDK ships," which mostly means that module's data.  Their
mock data is our ground truth; our conformance suite drives their real
client.

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
**complete `globus-sdk` `GroupsClient` surface, pinned to SDK 4.8.1** —
all fourteen client methods, not a subset.  The SDK client is the
guidepost: if `GroupsClient` has a method, Fauxbus answers it.

**Group lifecycle**
- `POST /v2/groups` — create; subgroups via `parent_id` in the document;
  the creating identity becomes an active `admin`
- `GET /v2/groups/{id}` — with `include=` support for `memberships`,
  `my_memberships`, `policies`, `allowed_actions`, `child_ids`
- `PUT /v2/groups/{id}` — update name/description
- `DELETE /v2/groups/{id}` — returns the deleted group document (recorded
  SDK-fixture behavior, not a guess)

**Membership**
- `GET /v2/groups/my_groups` — the calling identity's groups, with the
  `statuses` filter.  Note a recorded quirk: the list-view documents are
  *slimmer* than the single-group document (no `description`, no
  subscription fields), and the response is a **bare JSON array** — no
  pagination envelope.
- `POST /v2/groups/{id}` — batch membership actions, all eleven verbs:
  `add`, `invite`, `accept`, `decline`, `approve`, `reject`, `join`,
  `leave`, `remove`, `change_role`, `request_join` — with per-identity
  success/failure results in the response document, the way the real
  service partially succeeds.  Membership statuses as Globus defines
  them: `active`, `invited`, `pending`, `rejected`, `removed`, `left`,
  `declined`.
- Roles as Globus defines them (`admin`, `manager`, `member`) with the
  real service's rules about who may perform which action — including
  the guardrails: managers cannot touch admins, the last admin cannot
  leave.

**Policies, preferences, fields**
- `GET/PUT /v2/groups/{id}/policies` — the six-field policy document
- `GET/PUT /v2/preferences` — identity preferences (`allow_add` is
  enforced: an identity that set `allow_add: false` cannot be added)
- `GET/PUT /v2/groups/{id}/membership_fields`

**Subscriptions**
- `GET /v2/subscription_info/{subscription_id}` — group lookup by
  subscription, returning the restricted `subscription_info` projection
  (`is_high_assurance`, `is_baa`, `connectors`)
- `PUT /v2/groups/{id}/subscription_admin_verified`

Response documents, id formats (UUIDs where Globus uses them), and error
bodies match recorded real-service responses where recordings exist.

### Recorded, documented, provisional

Every imitated behavior carries one of three grades of truth, and the
code says which:

1. **Recorded** — backed by a response fixture shipped in the SDK itself
   or captured from the real service.  The strongest grade.
2. **Documented** — stated by SDK docstrings or the published API docs,
   but not yet witnessed on the wire.
3. **Provisional** — Fauxbus's best inference where neither exists,
   marked `PROVISIONAL` in code.  Every provisional behavior is an open
   conformance obligation: the tether run against the real service either
   promotes it or corrects it.  The batch-action response document is the
   most prominent provisional today and the top priority for the first
   recording session.

Error documents are shaped `{"code": ..., "detail": ...}` — the form the
SDK's error classes parse into `.code` and `.message` regardless of which
of its three error-format branches fires.

### Auth posture

Requests must carry a bearer token — a client that forgets auth should fail
in dev, not in prod (`--allow-anonymous` exists but defaults off).  The
token is **not** cryptographically validated: by default, any token is
accepted and its *identity is derived from the token string itself* (a
stable mapping, so `token-for-alice` is always the same caller — same
UUID, same username, every run).  When a test needs to be picky, the seed
document's `identities` section pins explicit token → identity mappings;
because the state dump includes the same section, pinning is just seeding.
Real token introspection is out of scope until an Auth API mock exists
(roadmap).

## The control plane (`/_fauxbus/`)

- `POST /_fauxbus/reset` — the between-tests handshake.  If a canonical
  seed is on record (`--seed` at boot, `/seed.json` in the container, or
  `seed?canonical=true`), reset restores *that world*, not an empty one:
  the canonical document is the fixed point tests come home to, and
  every mutation in between was a throw-away.  Body `{"to": "empty"}`
  opts out of the restore.  Either way, armed failures are disarmed.
- `POST /_fauxbus/seed` — load a state document (groups, members, roles)
  so a test starts mid-story instead of building the world via API
  calls.  Seeding always replaces the whole world, never merges.  With
  `?canonical=true` the document is also pinned as what reset restores —
  the over-HTTP twin of booting with `--seed`, for harnesses that can't
  mount files.  `DELETE /_fauxbus/seed` forgets the pin (the current
  world is untouched).
- `GET  /_fauxbus/state` — dump everything, for assertions.  Your test
  checks what's *actually in the directory*, not what your code claims it
  did.
- `POST /_fauxbus/failures` — arm failure injection: match on method +
  path glob, respond with a chosen status (optional custom body/headers),
  for the next N matching requests (or until cleared).  `GET
  /_fauxbus/failures` lists what's armed; `DELETE /_fauxbus/failures`
  disarms (all, or one by `?id=`).  Injection applies only to the
  imitated `/v2/…` surface — you cannot brick the control plane with it.
  One-shot inline variant: send `X-Fauxbus-Fail: 429` on any request to get
  that failure exactly once, for quick cases.
- `POST /_fauxbus/tick` — advance Fauxbus's logical clock by N seconds
  (roadmap: what makes transfer-task progression testable without
  `sleep`; nothing consumes it in v0.1, but it exists from day one so
  determinism is load-bearing, not retrofitted).

**The round-trip invariant:** the document `GET /_fauxbus/state` returns
is a valid `POST /_fauxbus/seed` body, and seeding a fresh world with a
state dump reproduces that state exactly.  Dump, seed, dump again: byte
-identical.  This is tested, not aspirational.

State is in-memory and disposable by design.  `--seed state.json` on boot
covers the compose-stack case where the world should exist before the first
test connects.

## Packaging

- Python ≥3.11.  `pipx install fauxbus && fauxbus serve --port 9800`.
- A container image (`Containerfile`, OCI-neutral name) for compose
  stacks and CI services.  Conventions: mount a state document at
  `/seed.json` and it loads on boot; the healthcheck probes the
  control-plane index, so `depends_on: service_healthy` just works;
  runtime args pass through to `fauxbus serve`.  Runs unprivileged
  (uid 9800 — yes, the port).  `examples/compose.yaml` is the copyable
  pattern, and `examples/seed.json` is a real state dump kept honest by
  a byte-identical round-trip test in CI.
- Zero runtime dependencies — stdlib only, on purpose.  A test fake
  consumers add to their dev environments should not bring a supply
  chain with it.
- MIT (decided 2026-07-30).  We reviewed the Globus Connect source
  license first: it covers GCS/GCP source code only — not the APIs, not
  the Apache-2 SDK — and Fauxbus stays entirely outside its scope by
  never touching that source.  With provenance handled by discipline,
  the outbound license just needs to be short and adoptable.

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
  in milliseconds and fail it at will.  The bright line (decided
  2026-07-31): Fauxbus fakes the Transfer *API* — the bookkeeping —
  never the data plane.  No GridFTP, no byte movement.  Three reasons
  the line holds: consumer code can only observe the API, so faking it
  covers everything a test can see; the data plane is Globus Connect
  Server territory, the source this project never reads; and only the
  bookkeeping can be made deterministic.  One deliberate extension
  waits behind a real consumer need: optionally materializing declared
  placeholder files into a mounted volume when a task completes
  ("presto, a file appears"), so post-transfer filesystem checks can
  pass — strictly opt-in, because an API fake that writes to disks is
  a different risk class.  Likely first slice, per principle 2: ACLs
  and guest-collection permissions (group-membership-driven data
  access), which is Groups-shaped CRUD — task lifecycle lands when a
  pipeline consumer shows up.
- **Auth** — identities lookup, token introspection, dependent tokens; at
  that point the Groups auth posture can grow real introspection.
- **Web interface** (penciled for v0.4) — a browser face at
  `app.fauxbus.local` (mocked in DNS) that lightly mirrors
  `app.globus.org`: browse groups and memberships, watch transfer tasks
  progress as tests drive them.  Strictly an *observer* over the same
  in-memory world — it reads what the control plane reads, changes
  nothing, and lives on the harness side of the principle-4 line.  Makes
  Fauxbus a debugging companion, not just a CI fixture.
- Whatever consumers file issues for, in that order, per principle 2.

## Not affiliated with Globus

Fauxbus is an independent test tool, not affiliated with or endorsed by
Globus or the University of Chicago.  "Globus" is their trademark; this
project imitates the API's behavior for local testing only, and the name is
a confession, not an infringement: it's *faux*.

## Changelog

- **v0.2.5** (2026-08-04) — CI exists, so the tether's Fauxbus leg is
  machinery instead of intent: `.woodpecker.yml` runs lint, the suite,
  and a wheel build across 3.11/3.12/3.13, plus one image build that
  boots the container and waits on the same control-plane probe the
  healthcheck uses.  The find that prompted it: with globus-sdk absent,
  `importorskip` deleted the whole conformance file and the run still
  reported green — the SDK-is-the-contract suite testing no SDK at all.
  A bare checkout still skips; `FAUXBUS_REQUIRE_CONFORMANCE=1`, which CI
  sets, turns the skip into a collection error.  The real-service leg
  stays unwired until the recording session — a gate nobody can run is
  worse than an honest gap.
- **v0.2.4** (2026-07-31) — reset learns the canonical seed: with
  `--seed`/`/seed.json`/`seed?canonical=true` on record,
  `POST /_fauxbus/reset` restores that world instead of an empty one
  (`{"to": "empty"}` opts out; `DELETE /_fauxbus/seed` forgets the
  pin).  The staged-fixture workflow — canonical roster seeded, tests
  mutate as throw-aways, reset comes home — is now a single call, with
  the container's mounted seed as the fixed point.  Also drew the
  Transfer bright line in the roadmap: fake the API's bookkeeping,
  never the data plane.
- **v0.2.3** (2026-07-30) — prior-art section added after xram asked
  the question any Globus engineer would ask first: doesn't
  `globus_sdk.testing` already do this?  Answer, grounded in the 4.8.1
  wheel and their docs: no — it's an in-process `responses`-based mock
  (no socket, stateless fixtures, "best approximation" by its own
  docs), and Fauxbus is the complementary stateful wire layer that
  *consumes* those fixtures as ground truth.  moto : Stubber ::
  Fauxbus : globus_sdk.testing.
- **v0.2.2** (2026-07-30) — the container image lands: multi-stage
  `Containerfile` (wheel-only final image, unprivileged uid 9800),
  seed-at-`/seed.json` convention, healthcheck on the control-plane
  index, and `examples/` with a compose pattern plus a seed file that
  CI round-trips byte-identically.  Packaging bullet promoted from
  "dependency-light" to the truth: zero runtime dependencies.
- **v0.2.1** (2026-07-30) — license decided: MIT, xram's stamp, after
  reviewing the Globus Connect source license and confirming the SDK's
  Apache-2.0 terms from the wheel itself.  BSD-3 recommendation retired
  (that rationale belonged to root-cellar's iRODS alignment).
- **v0.2** (2026-07-30) — Groups scope expanded from a five-bullet subset
  to the complete `GroupsClient` surface, pinned to globus-sdk 4.8.1, per
  xram's directive that the SDK client is the guidepost.  Added the
  recorded/documented/provisional truth grades, the seed/state round-trip
  invariant, identity pinning via the seed document, and corrected the
  pagination claim: Groups `my_groups` returns a bare array, no envelope.
- **v0.1** (2026-07-30) — founding document, spun off from #root-cellar.
