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

### Control-plane reachability

The control plane has no authentication, and that is a decision rather
than an omission: Fauxbus stands in for a service that answers the
whole network, the harness driving it is routinely a sibling container
rather than a process on the same host, and a fake that demands
credentials to be reset is a fake that gets fought with.  The default
therefore matches the thing being imitated — bound where you bind it,
open to whoever can reach it.

What that means, stated plainly rather than left implied: **anyone who
can reach the port can dump the world, rewrite it, and arm forged
responses.**  The last one is the interesting risk, and it is peculiar
to fakes.  An attacker does not need to crash anything — seeding a
world where the assertion happens to hold, or arming a `200` over a
path that should `403`, makes the *tests* wrong while everything looks
healthy.  A tool whose whole value is being believed can be attacked by
being made to lie.

`--control-loopback-only` refuses `/_fauxbus/` from non-loopback peers
for anyone who wants the boundary — a shared dev host, a CI runner with
neighbors.  It is off by default because turning it on breaks the
sibling-container pattern the project ships in `examples/`.  The
imitated surface is never affected by the flag; a container's own
healthcheck dials `127.0.0.1` and stays green under it.

Two things the flag deliberately does not solve.  It is a *network*
boundary, not a local one: code already running beside the tests — a
compromised transitive dev dependency, say — reaches loopback as easily
as the harness does, and no socket rule fixes that.  And the state dump
returns pinned tokens in cleartext, because the `identities` section is
a token→identity map and the dump must round-trip as a seed; those
tokens are fixtures, never real credentials, and treating them as
secrets would be a fiction of its own.

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

- **Package release: fauxbus 0.1.2** (2026-08-07, tag `v0.1.2`) — the
  first release published to PyPI, and cut *because* of that: an
  upload is burn-once, so release #1 under the reserved name had to be
  one that identifies itself correctly.  v0.1.0 and v0.1.1 do not —
  both report `0.1.0.dev0` on the wire and hand every 501 an issues
  link on a private host.  Neither is on PyPI and neither will be; the
  git tags carry that history.  A patch, not a minor: no API changes,
  no imitated-surface changes, every test that passed against v0.1.1
  passes here.  Note the version walks *backwards* from `main`'s
  `0.2.0.dev0` — that marker was a guess that the next release would
  be a minor, and the guess was wrong.  `main` returns to `0.2.0.dev0`
  after the tag, where the next real surface work still points.
  PROVISIONAL inventory unchanged at 16 markers; the batch-action
  response document remains recording target #1.  Full detail in
  v0.2.12 below.
- **v0.2.12** (2026-08-07) — what the artifact says about itself, made
  true.  Found while checking the package over ahead of a first PyPI
  upload, and both defects shipped in v0.1.0 *and* v0.1.1.  **The
  version was a lie.**  It lived in two places — `pyproject.toml` and
  `__init__.py` — with nothing tying them together, so the release
  ritual bumped one and forgot the other, and both tags answered
  `--version`, the startup banner, and `GET /_fauxbus/` with
  "0.1.0.dev0".  That is the exact question a consumer asks when a
  conformance run changes behavior, and it was answering with a
  pre-release of a version two tags stale.  Hatchling now reads the
  module literal at build time, so the wheel name, the PyPI metadata,
  and the wire answer are one string with nothing left to disagree
  with; the test that would have caught it exists now, comparing the
  control-plane index against `importlib.metadata` — what pip actually
  installed, not what the source says about itself.  **The issues link
  was a dead end.**  `ISSUES_URL` ships inside every 501 body, which
  makes it principle 2's escape hatch, and it pointed at the private
  Gitea — so every stranger who hit an unimplemented endpoint got a
  loud, correct, actionable error and a link they could not open.
  Homepage, Issues, and the image's `org.opencontainers.image.source`
  now point at `github.com/atmarx/fauxbus`.  The pattern in both:
  a claim nothing checked.  Same shape as the silently-skipping
  conformance suite (v0.2.5) and the seed validation that promised
  "loud and immediate" in its own comment (v0.2.11) — this project
  keeps finding its own documentation used as evidence for itself.
- **Package release: fauxbus 0.1.1** (2026-08-06, tag `v0.1.1`) —
  security patch, and the first release cut for a reason other than
  "the surface is ready."  Supersedes v0.1.0, which carried a
  response-header injection, a request-parsing flaw that could park
  worker threads, and — found while fixing that one — a request
  smuggling follow-on.  **Consumers on v0.1.0 should move.**  No API
  changes, no behavior changes to the imitated surface: every existing
  test that passed against v0.1.0 passes against v0.1.1.  New optional
  `--control-loopback-only` flag, off by default.  Full detail in
  v0.2.11 below.  PROVISIONAL inventory unchanged at 16 markers; the
  batch-action response document remains recording target #1.
- **v0.2.11** (2026-08-06) — first outside security review, and the
  hardening it bought.  An independent reviewer read the code cold:
  0 critical, 0 high, 3 medium, 3 low, 1 informational, every finding
  reproduced locally before acting on it.  Fixed: CRLF/NUL now refused
  in failure-rule header names and values (a rule could forge extra
  headers, or split the response outright — validated at arm time, so
  the failing call is the one that wrote the bad rule); `Content-Length`
  validated and capped at 32 MiB (`int("-1")` reached `read(-1)`, which
  on a keep-alive connection parked a worker thread forever);
  `X-Fauxbus-Fail` now range-checks its status like the armed-rule path
  always did.  Bucket A, the one that stung: seed validation promised
  in its own comment to be "loud and immediate" but silently accepted
  unknown policy keys — a typo'd fixture policy did nothing, quietly —
  and answered malformed scalars with a 500 blaming Fauxbus for the
  document's mistake.  Both now 422, with the seed's rules matching the
  policies endpoint's exactly.  Posture decided rather than drifted
  (see "Control-plane reachability"): the control plane stays open by
  default because it imitates a networked service and harnesses are
  often sibling containers, with `--control-loopback-only` for shared
  hosts.  28 regression tests, each one failing before its fix.
- **v0.2.10** (2026-08-05) — PyPI publishing written down while the
  iron was warm, parked until it can actually run: the name checked
  free, the v0.1.0 artifacts verified against `twine check`, and
  `.woodpecker.yml` now carries a parked tag-gated publish step
  (token via Woodpecker secret; a guard dies loudly if the tag's
  version disagrees with the build — uploads are burn-once).  Tag
  events now trigger CI, so the step has something to hang on when
  restored.  RELEASING.md records the four-move sequence — manual
  first upload, scoped token, restore the step, docs flip *last* —
  and the prerequisite in front of all of it: public-facing URLs.
  Nothing flips today, per xram: install stays from-repo until he
  takes the mirror public.
- **Package release: fauxbus 0.1.0** (2026-08-05, tag `v0.1.0`) — the
  Groups surface, shipped.  Fourteen GroupsClient methods, every one
  driven through the real globus-sdk 4.8.1 in CI; eleven batch verbs;
  the `/_fauxbus/` control plane (state/reset/seed/failures/tick);
  canonical-seed restore; container image with healthcheck and its own
  CycloneDX SBOM; zero runtime dependencies, and the SBOM proves it.
  Consumer-proven before tagging: root-cellar runs its entire Globus
  wire surface against it, 9/9, zero 501s possible by architecture.
  Ships with 16 PROVISIONAL markers documented in-code (the
  batch-action response document remains the #1 recording target);
  per RELEASING.md, the real-service recording session becomes
  release-blocking the moment a tenancy makes it possible.
- **v0.2.9** (2026-08-05) — xram's two release conditions, met.  SBOM:
  the image now generates and carries its own CycloneDX bill of
  materials (`/usr/share/fauxbus/sbom.json`), built from a clean venv
  holding only the fauxbus wheel so the generator never pollutes the
  receipt; CI asserts presence and contents on every image build.
  Verified locally before shipping: components `[fauxbus, pip]`,
  license record `MIT (declared)` read straight from wheel metadata —
  the zero-dependency claim, machine-readable.  License once-over:
  LICENSE is clean MIT (© 2026 Andrew Marx), pyproject and the OCI
  label agree, README's License section already states the posture
  (no Globus code; globus-sdk consumed under Apache-2.0 as a
  test-time dependency only; fixture-string echoes scrubbed in
  85f876d).  Confirmed good — nothing needed fixing.
- **v0.2.8** (2026-08-05) — the pre-tag audit, prompted by xram's
  "convince me": four of the fourteen GroupsClient methods had never
  been driven through the real SDK (`get_membership_fields`,
  `set_membership_fields`, `set_subscription_admin_verified`,
  `get_group_by_subscription_id`) — wire-tested by hand-rolled HTTP,
  but the SDK's own spelling of them unproven.  Conformance cases
  added; all passed first try, and now all fourteen are CI-enforced
  rather than coincidentally correct.  Also: README's `pipx install
  fauxbus` promised a PyPI package that doesn't exist — replaced with
  the honest from-repo install; `[project.urls]` added to pyproject.
- **v0.2.7** (2026-08-05) — the first consumer answered, and the
  answer reshapes the roadmap's ground truth (#fauxbus
  >>01KZ82F5ECFR8E75GN8162PRMJ).  Root-cellar wired fauxbus in six
  days ago — 9/9 green, including the injected-429-through-real-
  SDK-retry test — and its 501 list is empty **by architecture**:
  five GroupsClient calls, all implemented, and no other Globus
  client imported anywhere in their plane.  The v0.1 Groups surface
  is consumer-complete.  Transfer order confirmed as penciled (ACLs
  first, task lifecycle later) but explicitly architecture-derived,
  not a blocked pipeline — so per principle 2, Transfer work waits
  for a consumer with a real door.  Recorded traffic: none exists
  anywhere, by design (no dev tenancy — the reason fauxbus exists);
  the first recording session targets work's staging tenancy, batch-
  membership bodies priority #1.  Woodpecker trust landed: pip
  caches and the image build-and-boot step restored, keyed on
  pipeline number so same-SHA pushes to two branches can't collide.
  RELEASING.md codifies the release ritual, including the tether
  posture until a tenancy exists and root-cellar's one-commit
  re-pin handshake.
- **v0.2.6** (2026-08-04) — the code becomes deliberate teaching
  material, at xram's direction: a comment pass across src/ narrating
  the important logic where it lives — the uuid5 determinism trick,
  the one-lock threading story, the membership state-machine table,
  405-versus-501 wire manners, why injection can never reach the
  control plane, the canonical-bytes round trip.  The standard is
  standing, not one-time: new code explains itself at student depth.
  Woodpecker registration also landed (repo 45), and the pipeline's
  first run taught its own lesson: untrusted repos may not mount
  `volumes` — correctly, since a repo-borne config that could mount
  the docker socket would own the host — so CI runs volume-free
  (no pip cache, image build parked in a comment) until the repo is
  marked trusted.
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
