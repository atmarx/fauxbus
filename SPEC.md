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

Auth's grades were audited on 2026-08-24 against the fixtures shipped in
`globus_sdk/testing/data/auth/`, before any of it was built — cheaper to
learn what can be grounded while the design is still prose.  Most of the
token surface comes back **recorded**: the client-credentials and
code-exchange responses, the identity object (`email`, `id`,
`identity_provider`, `name`, `organization`, `status`, `username`, plus
`identity_type` where present), and the 401/403 error documents for
`userinfo`.  One thing does not.  **There is no success fixture for
`userinfo` anywhere in the SDK** — only the two error cases — which
leaves `identity_set`, the linked-identity list a consumer actually
authorizes against, graded **provisional**.  That is an uncomfortable
place for it: of every shape in the Auth slices, `identity_set` is the
one a login design depends on most and the one the SDK can ground least.
It joins the batch-action document at the top of the recording list,
alongside one Groups question a consumer's self-serve model does lean
on: where exactly the manager/admin boundary sits for adding a member
directly to the admin role, marked `PROVISIONAL` in `world.py` today.

Building slice A added four more to that list, and it is worth noticing
that every one of them is a question the audit could not have asked
before the code existed:

1. **The status for a token presented to the wrong resource server.**
   Fauxbus answers 403 — the token is genuine and introspects fine, it
   simply is not good here, which reads as "authenticated, not
   authorized."  No fixture covers it and the case is entirely
   plausible as a 401.  `PROVISIONAL` in `world.require_issued`.
2. **Which Groups operations each scope actually covers.**  The two
   scope names are recorded; the mapping is not, which is why
   per-operation enforcement was left out rather than guessed.
3. **Whether the real endpoint answers a `client_credentials` request
   carrying `openid` with an `id_token` at all** — there is no person
   for an ID token to describe, so it may simply decline.  Fauxbus 501s
   either way today, which is right until someone can say.
4. **The token endpoint's error bodies beyond `invalid_grant`.**  One
   fixture grounds one case; `invalid_client`, `invalid_request`, and
   `unsupported_grant_type` follow RFC 6749 and the status pattern the
   fixture set, which is inference dressed in a standard.

Error documents are shaped `{"code": ..., "detail": ...}` — the form the
SDK's error classes parse into `.code` and `.message` regardless of which
of its three error-format branches fires.  With one exception, added in
v0.2: the OAuth2 token endpoint answers RFC 6749 §5.2's
`{"error", "error_description"}`, because that is what the SDK's own
fixture shows Globus sending from that path.  Two error dialects in one
server is not a wart — it is the fake being faithful to a service that
really does speak both.

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
**Issued-token mode** arrived with Auth slice A (v0.2), and it is
opt-in: `--require-issued-tokens`.  The derive-from-the-string behavior
above stays the default, because every consumer written against Fauxbus
so far assumes it, and a fake that silently starts rejecting tokens is a
fake that broke its users to gain a feature they did not ask for.

Turned on, Fauxbus checks three things a permissive fake structurally
cannot: that the token was **issued here**, that it has **not expired**
(on the logical clock — `/_fauxbus/tick` ages a token, never a sleep),
and that it is good for **this resource server** (a Transfer token
presented to Groups is refused).  Those are three real production
failures a consumer currently cannot write a test for.

A fourth check was considered and deliberately left out: **per-operation
scope**, the rule that a token carrying only
`view_my_groups_and_memberships` may not create a group.  The scope
*names* are SDK-grounded (`globus_sdk/scopes/data/groups.py` lists
exactly two), but which operations each one covers is not grounded
anywhere, and the failure modes are not symmetric — a fake that rejects
calls the real service allows breaks working consumer code, while one
that permits too much merely fails to catch a bug.  It is on the
recording list, and this paragraph exists because an earlier draft of
this document promised four checks and the code shipped three.

One divergence worth naming, because it will look like a bug.  The SDK
computes `expires_at_seconds` as `int(time.time() + expires_in)` — real
wall-clock time, in the consumer's process, outside anything Fauxbus
controls.  So a consumer that caches by that field believes its token is
good for the next 48 hours while Fauxbus, counting on the logical clock,
may have expired it one `tick` ago.  Both are behaving correctly; they
are simply keeping different time.

## v0.2 — Auth slice A: the client-credentials grant

**`POST /v2/oauth2/token`, `grant_type=client_credentials`** — the grant
a service uses to act as *itself* rather than on behalf of a person.
Built **resource-server-generic**: nothing in `auth_api.py` knows Groups
exists.  The requested scope names the service, so the same endpoint
that hands a WordPress provisioner a Groups token hands Root Cellar's
poller a Transfer token.  One endpoint, two consumers.

The load-bearing idea, and the one to carry away from this slice: **in
Globus Auth a registered client is an identity.**  Its `client_id` is an
identity UUID, and a token minted by this grant acts as that identity
everywhere downstream — so a provisioner that fetches its own token and
then calls Groups appears in the membership list under its own name,
`<client_id>@clients.auth.globus.org`, exactly as a person would.
`World.identity_for_token` therefore consults issued tokens *before* the
seed pins and before the derive-from-the-string fallback.  Skipping that
step would leave the fake disagreeing with itself about who just called.

**Response** — RECORDED from
`globus_sdk/testing/data/auth/oauth2_client_credentials_tokens.py`:
`access_token`, `scope`, `expires_in` (172800), `token_type`,
`resource_server`, `other_tokens`.  That last one is not decoration and
not optional: `OAuthTokenResponse._init_rs_dict` indexes
`self["other_tokens"]` with no `.get` and no default, so omitting it
raises a `KeyError` *inside globus-sdk* — a traceback pointing at the
library rather than at the fake that lied.

**Client authentication** — both legal forms, because the two known
consumers split across them.  HTTP Basic is what globus-sdk sends
(`ConfidentialAppAuthClient` installs a `BasicAuthorizer`) and is
RECORDED.  `client_id`/`client_secret` in the form body is DOCUMENTED
(RFC 6749 §2.3.1) and is what identity brokers usually send — Keycloak
calls it `client_secret_post`, and a broker is precisely the consumer
slice B is being built for.  Sending both at once is refused: the RFC
forbids it, and if the two disagree any choice the server makes is a
security decision made by accident.

**A form body, not JSON.**  RFC 6749 §4.4.2 requires it and the SDK
sends it, so the transport learned to parse `Content-Type:
application/x-www-form-urlencoded` and to record on `Ctx` which encoding
arrived.  Recording it matters: a JSON body deserializes into a dict
shaped exactly like a form dict, so without the check every field lookup
would have succeeded and Fauxbus would have minted a token for a request
the real service rejects outright — a fake teaching a habit that breaks
in production.

**Errors speak a different dialect here**, and it is the only place in
Fauxbus that does.  Everywhere else the body is `{"code", "detail"}`,
the shape `GlobusAPIError` parses.  The token endpoint answers RFC 6749
§5.2's `{"error", "error_description"}`, because that is what the SDK's
own fixture shows Globus sending from this path — 401 with
`{"error": "invalid_grant"}` in
`oauth2_exchange_code_for_tokens.py`.  Two things came out of that
recording.  The status is a **401**, where RFC 6749 says `invalid_grant`
is a 400; the recording wins, and the other credential-shaped failures
match it.  And the body carries *nothing* the SDK's error parser
recognizes, so `GlobusAPIError.code` and `.message` both come back
`None` (measured against 4.8.1 on 2026-08-24) and a consumer is left
with the status and the raw JSON.  Fauxbus reproduces that blindness
rather than improving on it: a fake kinder than the service hides a
rough edge the consumer meets in production anyway.  The one addition is
`error_description`, which is free — RFC-optional, sent by Globus on
other Auth endpoints, and surfaced by *none* of the SDK's message
fields, so no test can come to depend on it while a human reading a
`curl` still learns what went wrong.

**Three ways to be refused, and whose fault each one is.**  This is
principle 2 at its sharpest, because the grant type is where a fake is
most tempted to lie on its own behalf:

- A grant Globus supports *and Fauxbus has built* runs.
- A grant Globus supports and **Fauxbus has not built** — `authorization_code`,
  `refresh_token`, the dependent-token grant — is **our** gap and gets a
  loud 501 with a tracker link.  Answering `unsupported_grant_type` there
  would be Fauxbus slandering the real service to cover its own absence.
- A grant **Globus does not offer** gets RFC 6749's
  `unsupported_grant_type`, which is what the real endpoint would say.

The same instinct governs scopes.  Scopes spanning two resource servers
are legal at the real service, which answers with a primary token plus
the rest in `other_tokens`; Fauxbus does not build that yet, and the
tempting shortcut — issue for whichever service parsed first and quietly
drop the other scopes — is the exact silent wrong answer principle 2
forbids, because the consumer would get a token that looks fine and
fails later against a service it was never good for.  501, naming both
services.  A scope form Fauxbus cannot parse is likewise a 501 rather
than a guess.  And a request carrying `openid` is refused rather than
answered without an `id_token`: this document promises that field,
signing waits for slice B, and a missing key would surface as a
`KeyError` in the consumer's code pointing nowhere near the cause.

**Token strings are readable and guessable**, both on purpose.
`fauxbus-at-0` says what it is in a log or a failing assertion, where an
opaque blob would say nothing and would invite someone to paste it
somewhere it does not belong.  Guessable is what principle 3 costs: a
random token would break the round-trip invariant and make every state
dump differ from the last.  Under `--require-issued-tokens` that means
an attacker who can reach the fake can guess a live token — an
acceptable trade only because this is a fake, where SPEC already treats
every token as a fixture rather than a credential, and the whole design
leans on nobody being able to mistake a Fauxbus token for a real one.
The name helps with that.

**New world state**, both round-tripping through dump/seed like
everything else: `clients` (a registry of `client_id` → secret, name,
username) and `tokens` (what each issued token authorizes).  Seeding a
token directly means a harness can start with an already-expired one
without performing the grant and ticking the clock first.

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
  chain with it.  Tested against its hardest case on 2026-08-24: signing
  RS256 ID tokens looks like it requires a crypto library and turns out
  not to (roadmap → Auth).  The rule has not needed an exception yet,
  and "we checked" is a stronger claim than "we intend to."
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
  a different risk class.  **First slice, per principle 2: task
  monitoring** — reordered 2026-08-16 when the pipeline consumer this
  bullet was waiting for actually showed up.  Root Cellar is dropping
  the premium Globus iRODS Connector in favour of land-then-register:
  Globus puts bytes on a POSIX path, their governance layer registers
  them in place and writes the AVUs.  That design needs a
  transfer-completion signal, and Globus offers no webhook — the Task
  Management API has no push mechanism at all, and task events are
  documented as being for human troubleshooting.  Polling is the
  supported answer, so a poller is the consumer.  They chose the
  Transfer API over Globus Flows deliberately: Flows sits *on top of*
  Transfer and invokes it underneath, so faking Flows would mean faking
  Transfer plus an orchestration state machine.  Transfer is the floor
  either way.

  The surface that buys, confirmed against globus-sdk 4.8.1 and *not*
  guessed: `endpoint_manager_task_list`, `endpoint_manager_get_task`,
  and `endpoint_manager_task_event_list` — the `endpoint_manager_*`
  family, not the plain `task_list`.  The distinction is the whole
  requirement.  `task_list` returns only tasks submitted by the calling
  identity; Root Cellar's researchers submit their own transfers into
  the DTN collections, so its service identity never sees them there.
  Seeing another user's tasks needs the `activity_monitor` role on a
  *subscribed* collection — confirmed on 2026-08-16 that Root Cellar
  holds the subscription, the DTNs are subscribed, and the role grant is
  available.  So the fake imitates the manager-scoped documents and the
  role-gated auth posture, not the owner-scoped ones.

  ACLs and guest-collection permissions (group-membership-driven data
  access) were the previously-penciled first slice on the reasoning that
  they are Groups-shaped CRUD.  They keep their place in the roadmap and
  lose their place in the queue: nobody has filed for them, and
  principle 2 orders by consumer need, not by implementation
  convenience.
- **Auth** — two slices, both with named consumers as of 2026-08-24.
  This bullet used to read "identities lookup, token introspection,
  dependent tokens."  Those keep their place in the roadmap and lose
  their place in the queue, for the same reason ACLs did: principle 2
  orders by consumer need, and a consumer arrived asking for something
  else.  A WordPress fleet wants Globus login brokered through a real
  identity broker, with a Globus group deciding who may sign in where.

  **Slice A shipped in v0.2** — `client_credentials` at
  `/v2/oauth2/token`, resource-server-generic, plus issued-token mode.
  It has its own section above; what remains here is what it *deferred*,
  each item a deliberate refusal rather than an oversight:

  - **Multi-resource-server responses** — the primary token plus the
    rest in `other_tokens`.  Requesting scopes across two services is a
    loud 501 today.
  - **`id_token` on an `openid` request**, which needs slice B's signing.
    Refused rather than answered without the field.
  - **Dependent scopes** (`scope[dependent]`) and the dependent-token
    grant.
  - **`refresh_token`** as a grant, and refresh tokens in the response.
  - **Per-operation scope enforcement** — see Auth posture for why this
    one is a considered omission rather than a queue position.

  **Slice B — the OIDC authorization-code flow**, so a real identity
  broker can authenticate a seeded account against Fauxbus.  Principle 1
  survives this better than expected: `get_openid_configuration`,
  `get_jwk`, `userinfo`, and `oauth2_exchange_code_for_tokens` are all
  real methods on the pinned 4.8.1, so the SDK still drives most of the
  surface.  But the **browser redirect leg is the first place where the
  SDK is not the whole contract** — nothing in `globus-sdk` performs an
  interactive authorization, because no library can.  There the contract
  is OIDC itself plus what a broker actually does on the wire, and the
  honest consequence is that Fauxbus cannot claim SDK-grade conformance
  for `/v2/oauth2/authorize` the way it can everywhere else.  Say so
  rather than let the grade be assumed.  The broker-in-a-container
  acceptance test belongs to the consumer's repo: making a broker a
  Fauxbus dev dependency would mean acquiring a second supply chain in
  order to test a fake whose entire pitch is not having one.

  Test control for the redirect leg stays out-of-band per principle 4.
  No `fauxbus_*` query parameters on `/v2/oauth2/authorize` — an
  unauthenticated authorize request redirects to a `/_fauxbus/` account
  picker that establishes a Fauxbus-only session and resumes the pending
  request.  The imitated surface keeps no knowledge that it is fake.

  **Signing: stdlib, decided 2026-08-24.**  ID tokens have to be signed
  with something a real broker will validate, which looks like it forces
  a crypto dependency and a hole in the zero-dependency rule.  It does
  not.  RS256 is RSASSA-PKCS1-v1_5 over SHA-256 — `hashlib`, a fixed DER
  prefix, and one `pow(m, d, n)`, with Python's built-in bignums doing
  the arithmetic.  Verified on 2026-08-24: roughly twenty lines of
  stdlib produce a JWT that PyJWT and `cryptography` accept through a
  real JWKS `kid` lookup, and reject when the payload is tampered with.
  What makes hand-rolled JWT code acceptable here is an asymmetry —
  **Fauxbus only ever signs, and never verifies.**  Verification is
  where JWT implementations get dangerous (`alg: none`, key confusion,
  padding oracles) and none of that surface exists in a signer.  The
  fixture private key ships **published in the repo, on purpose**:
  anyone can forge a Fauxbus token, so nobody can ever be tempted to
  trust one.  That turns "don't point production at the fake" from a
  sentence in a document into a property of the system.

  **Clocks: signed tokens are the one exception to principle 3.**
  Fauxbus has no wall-clock dependence; time advances when a test says
  so.  That holds for everything *Fauxbus itself* validates —
  authorization-code expiry, token expiry, membership state.  It cannot
  hold for an ID token, because the thing checking `exp` and `iat` is an
  outside verifier running on real time that never agreed to participate
  in our logical clock.  A logical clock anchored at a fixed epoch mints
  tokens that are permanently expired or permanently not-yet-valid, and
  determinism does not rescue it, because the verifier is not playing.
  Found on 2026-08-24 by a signing probe that failed on
  `ImmatureSignatureError` before it ever reached a signature check.  So
  `iat`/`exp` on signed tokens anchor to real time, and determinism is
  preserved in the *offset* rather than the absolute value.  Worth
  stating loudly: the symptom is "login just fails," which points
  nowhere near the cause.

  **Identity churn: a constraint, not a feature.**  This bullet briefly
  required the seed model to *stage* renames through the control plane —
  a username changing while the UUID holds, and the reverse.  It lasted
  about an hour.  The consumer that motivated it decided to treat its
  institutional usernames as stable and handle the rare rename by hand,
  which leaves the requirement with nobody calling it, and principle 2
  is unambiguous about what an uncalled feature is.  Out of the queue.

  What stays costs nothing: **the identity model must not be shaped so
  that a rename is impossible to represent.**  Keep the durable UUID and
  the mutable username as separate things rather than collapsing them
  into one identifier, because that distinction is free today and a
  schema migration later.  Staging a rename live waits for a consumer
  who needs it — which is the same answer ACLs got, for the same reason.

  **Issuer.**  Auth mode requires an explicit public issuer, and every
  surface must agree on it — discovery metadata, `iss`, the authorize
  and token URLs, userinfo, JWKS.  Fauxbus must **refuse to start** if
  the configured issuer names a real Globus domain.  Refuse, not warn:
  the failure being prevented is a production client trusting a fake,
  and that is not a thing to leave to whether someone read the output.
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

- **Package release: fauxbus 0.2.0** (2026-09-04, tag `v0.2.0`) — Auth
  slice A reaches consumers.  **A minor, not a patch**, and for once the
  `.dev0` marker on `main` guessed right: this release adds imitated
  surface (`POST /v2/oauth2/token`), a new CLI flag
  (`--require-issued-tokens`), and a transport the server did not speak
  before (form-encoded request bodies).  New surface is a minor even
  when nothing existing changed shape — and nothing existing did, which
  is the other half of the claim: every test that passed against v0.1.2
  passes here, and 126 pass with `FAUXBUS_REQUIRE_CONFORMANCE=1`.

  It also carries the contract-pin fix from v0.2.14, which is the part a
  consumer feels without reading a changelog.  `[conformance]` now pins
  `globus-sdk==4.8.1` exactly rather than `>=4.8.1,<5`, so installing
  the extra gets the SDK version SPEC actually names.  Anyone who
  installed the extra between 4.9.0's release and v0.2.14 was conforming
  against an SDK this document never claimed.

  Cut eleven days after the code was finished, which is eleven days too
  many — both named Auth consumers were waiting on a `pipx install` for
  work that was already green.  Noted because the gap was invisible:
  nothing on the board and nothing in CI reports "finished but
  unreleased," and a release ritual this careful has no trigger telling
  anyone to start it.

  **PROVISIONAL inventory: 17 markers**, up one from v0.1.2's 16.  The
  addition is `world.require_issued` answering 403 rather than 401 for a
  token presented to the wrong resource server — genuine token,
  introspects fine, simply not good here, which reads as
  "authenticated, not authorized."  No fixture covers it and 401 is
  entirely plausible.  The batch membership response document remains
  recording target #1.  Slice A added four questions to the recording
  list in total; only this one is code-marked, because the other three
  are about surfaces deliberately not built.  Generate the inventory
  with `grep -rn PROVISIONAL src/` — and count it with `wc -l`, not by
  eye off a truncated listing.

  The real Globus leg of the conformance tether remains unrun.  No
  sacrificial tenancy exists anywhere; that absence is why this project
  is load-bearing for its first consumer, and it is the single item
  that would retire all 17 markers at once.

- **v0.2.16** (2026-08-24) — **Auth slice A shipped**: the
  client-credentials grant at `POST /v2/oauth2/token`, built
  resource-server-generic, plus opt-in issued-token mode.  Full write-up
  in the v0.2 section above; what belongs in a changelog is what the
  building taught, and it was mostly about temptation.

  **Every interesting decision here was a chance to lie helpfully.**
  Multi-resource-server scopes could have issued for whichever service
  parsed first and dropped the rest — the consumer would have received a
  token that looked perfectly valid and failed later somewhere else.  An
  `openid` request could have been answered without the `id_token` this
  document promises, surfacing as a `KeyError` in the consumer's code
  pointing nowhere near the cause.  `authorization_code` could have been
  refused with `unsupported_grant_type`, which is a real OAuth error and
  a slander: Globus supports that grant fine, Fauxbus is the one that
  hasn't built it.  Each of those is now a loud 501 naming whose gap it
  is.  Principle 2 turns out not to be about unrouted paths at all — it
  is about the moment a fake could plausibly answer and shouldn't.

  **The fake had to be less helpful than it wanted to be.**  The token
  endpoint's error body carries nothing `GlobusAPIError` parses, so
  `.code` and `.message` come back `None` and a consumer is left with a
  status and raw JSON.  Adding a `detail` would have fixed that in five
  characters and made the fake kinder than the service, which is how a
  consumer ships error handling that only works in CI.  The blindness is
  reproduced deliberately and pinned by a conformance test, because a
  claim no test checks is the species of bug this changelog is mostly
  made of.

  **A promise in this document turned out to be wrong, and the code was
  right.**  The v0.2.15 entry above said issued-token mode would check
  four things, scope among them.  Three shipped.  Per-operation scope
  enforcement was left out because the two Groups scope *names* are
  SDK-grounded while the mapping from operations to scopes is not, and
  the failure modes are not symmetric: a fake that rejects calls the real
  service allows breaks working consumer code, where one that permits too
  much merely fails to catch a bug.  The honest fix was to correct the
  spec rather than build the guess — noted here because the reflex runs
  the other way.

  **Two error dialects in one server**, which looked like a wart and is
  not.  Everything answers `{"code", "detail"}`; the token endpoint
  answers RFC 6749's `{"error", "error_description"}`.  Globus really
  does speak both, and its own fixture proves it — including a 401 for
  `invalid_grant` where the RFC says 400.  The recording wins over the
  standard the service was implementing, every time.

  33 new tests, 126 total.  Building the thing added four fresh entries
  to the recording list, all of them questions the pre-build audit had no
  way to ask.

- **v0.2.15** (2026-08-24) — Auth got a consumer and a design review, and
  the grading happened before the code for once.

  A proposal arrived from outside the project: a WordPress fleet wants
  Globus login brokered through a real identity broker, with a Globus
  group deciding who may sign in to which site.  It was a good proposal
  — it respected principle 4 without being told, refused to claim
  `auth.globus.org` as an issuer, and staged its own slices behind
  consumers.  It has been answered rather than filed, and the settled
  parts are in the roadmap above.

  **The grounding audit ran first.**  Every prior finding in this
  changelog was discovered after shipping: the `importorskip` that
  deleted its own file, the seed validation that promised loud failure,
  the artifact that misreported its version, the pin that did not pin.
  Four bugs, all the same species — a claim nobody had compared to a
  reality.  So this time the SDK's own fixtures were read *before* a
  line of Auth was written, and the answer was worth having early: the
  token surface grades **recorded**, and `identity_set` does not,
  because `globus_sdk/testing/data/auth/userinfo.py` ships only its 401
  and 403 cases.  The single field a login design leans on hardest is
  the single field the SDK cannot ground.  Better to know that while the
  design is still prose than to discover it in a conformance run.

  **The zero-dependency rule survived its hardest test.**  Signed ID
  tokens looked like they forced a crypto dependency.  RS256 is
  `hashlib`, a DER constant, and one `pow(m, d, n)`; twenty lines of
  stdlib produced a token that PyJWT and `cryptography` validated
  through a JWKS `kid` lookup and rejected when tampered with.  Safe
  because Fauxbus only ever signs and never verifies, and because the
  private key is published on purpose — a forgeable token is one nobody
  can be tempted to trust in production.

  **Principle 3 gets its first stated exception.**  Determinism holds
  for everything Fauxbus validates.  It cannot hold for `exp` and `iat`
  on a token handed to an outside verifier running on real time, and the
  probe that found this failed with `ImmatureSignatureError` before it
  reached a signature check.  The exception is now written down, because
  the symptom of getting it wrong is "login just fails," which points
  nowhere near the clock.

- **v0.2.14** (2026-08-16) — the contract pin was a range, and Transfer
  found its consumer.  Two findings, one of each kind this project keeps
  producing.

  **The pin didn't pin.** `globus-sdk>=4.8.1,<5` is a range; SPEC,
  README, and the pyproject comment above it all said the contract was
  4.8.1.  Resolved live on 2026-08-16 it installs **4.9.0**, so every CI
  run since 4.9.0 reached PyPI had been conforming against an SDK the
  spec never named — green the whole time, because nothing compared the
  claim to the reality.  Now `==4.8.1`, with
  `test_installed_sdk_is_the_stated_contract_version` asserting the
  installed SDK matches `CONTRACT_SDK_VERSION` and naming the remedy in
  its own failure message.  Bumping is a deliberate three-file act.
  Worth recording that the suite passed against 4.9.0 — the Groups fake
  evidently holds on both — but "it happened to work" and "we tested
  what we said we tested" are different claims, and only one of them is
  the tether's job.  This is the fourth honesty bug here after the
  `importorskip` that deleted its own file, the seed validation that
  promised loud failure, and the artifact that misreported its version.
  The logic keeps being fine.  It is always the claims.

  **Transfer's first slice is now task monitoring, not ACLs** — see the
  roadmap above.  Root Cellar dropped the premium iRODS Connector after
  a source-level review (the connector writes an epoch timestamp into
  the AVU *unit* field for its checksum cache, propagates no metadata
  across transfers, and would put a second writer on a catalog their
  governance layer already owns), and the land-then-register design that
  replaces it needs a completion signal that Globus only offers by
  polling.  That makes a poller the pipeline consumer this bullet had
  been parked on since 2026-08-05, and it wants `endpoint_manager_*`
  documents rather than the owner-scoped `task_list`.  No implementation
  yet — principle 2 says the door is open, not that the work is done.

- **v0.2.13** (2026-08-08) — tags publish themselves.  The
  `publish-pypi` step written on 2026-08-05 and parked behind two
  conditions is live: a project-scoped `pypi_token` exists as a
  Woodpecker repo secret allowed for the `tag` event, and the public
  URLs landed with v0.1.2.  **Pushing a tag is now an irreversible
  public act** — RELEASING.md says so in a callout, because the ritual
  changed shape and a checklist that describes the old shape is how
  this project already walked past one bug twice.  Two decisions worth
  the annotation they got in the step: no `--skip-existing`, because a
  force-moved tag would then upload nothing and go green, and a silent
  wrong answer is the one thing this codebase refuses to ship; and an
  explicit empty-token guard, because Woodpecker delivers a
  wrongly-scoped secret as an empty string and twine's resulting auth
  error blames the credential instead of the scoping.  Caught while
  arming it: the guard's own message contained a colon-space, which
  ends a plain YAML scalar — the command list silently parsed as a
  mapping and the step stopped being a step.  Found by parsing the
  file and asserting every command is a string, which is now how any
  change here gets checked.
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
