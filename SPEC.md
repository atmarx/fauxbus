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
- `GET /v2/groups/my_groups` — the caller's groups, with the `statuses`
  filter.  Two DOCUMENTED rules from Globus's published Groups OpenAPI:
  with no filter, `statuses` means `active` (an invited or removed
  member does not see the group), and the list covers "the user and its
  linked identities", so a person signed in as one identity sees the
  groups a linked identity is in.  Note a recorded quirk: the list-view documents are
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

Building slice A added four more to that list, slice A.2 three more,
multi-resource-server responses two, slice B five, Transfer task
monitoring nine, and the login shim's first step one — and it is worth noticing that every one of them is a
question the audit could not have asked before the code existed:

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
5. **Introspection's `aud`.**  The fixture shows
   `[resource server, client_id]` for a token whose resource server
   happened to be `auth.globus.org` — the one case where the
   generalization cannot be distinguished from a constant.  Fauxbus
   generalizes; a recording session settles it in one call.
6. **`email` and `name` for a client identity.**  The introspection
   fixture's subject is a person with a mailbox.  A registered client
   has neither, and both keys are present-and-null rather than absent,
   on the same reasoning that keeps `other_tokens` present-and-empty:
   a consumer should meet the same key set every time and learn the
   answer from the value.  Whether the real service omits them instead
   is unobserved.
7. **What revocation tells a client that does not own the token.**
   Fauxbus answers the same `{"active": false}` it gives for a string
   that never existed, refusing to become an oracle.  RFC 7009 permits
   this reading and does not require it.
8. **Which token is primary when a request spans services.**  Every
   token document the SDK records has `other_tokens: []`, so no fixture
   shows the real service choosing.  Fauxbus puts the first-named
   service on top — the one rule a consumer can predict from its own
   request.  An SDK consumer looking tokens up by service name in
   `by_resource_server` never sees the choice; code reading
   `response["access_token"]` raw, or taking that dict's first entry,
   does.
   `PROVISIONAL` in `world.scopes_by_resource_server`.  Slice B adds
   one case to the same question: when `openid` is among the scopes,
   the `auth.globus.org` token goes on top wherever `openid` was named,
   because `id_token` sits beside the primary and the SDK reads it from
   nowhere else.  The fixture shows `openid` alone.  `PROVISIONAL` in
   `auth_api._authorization_code`.
9. **The shape of an `other_tokens` entry.**  Unrecorded, but pinned
   from the reader's side: the SDK runs each entry through the same
   `_convert_token_info_dict` as the top level, so an entry carries the
   top level's five token fields and no nested `other_tokens`.
   `PROVISIONAL` in `world.token_response`.
10. **What happens when a client's `required_idp` is unsatisfied.**
    Fauxbus keeps the person at the picker and never calls the client
    back, on the strength of the reference's wording for a neighbouring
    case.  The real service might instead redirect with an error.
    `PROVISIONAL` in `world.RequiredIdpUnsatisfied`.
11. **How long an authorization code lives.**  Unpublished; Fauxbus
    uses RFC 6749's recommended ten minutes, on the logical clock.
    `PROVISIONAL` at `world.CODE_LIFETIME`.
12. **Which userinfo refusal is a 401 and which a 403.**  Both bodies
    are recorded, with identical text.  Fauxbus answers 401 for no live
    token and 403 for a genuine token with no person or no `openid`
    behind it.  `PROVISIONAL` in `world.userinfo_token`.
13. **Whether the token endpoint accepts `client_secret_post`.**  The
    real service's own discovery document advertises
    `client_secret_basic` only; Fauxbus accepts both (slice A's
    decision) and advertises only Basic.  A broker configured with
    `client_secret_post` passes against Fauxbus and may fail in
    production.  `PROVISIONAL` in `oidc_api.discovery`.
14. **Whether the openid code exchange echoes `state`.**  The SDK's
    default code-exchange fixture carries `"state"` in the body; its
    openid variant does not.  Fauxbus echoes in both.  `PROVISIONAL` in
    `auth_api._authorization_code`.
15. **Which collection a task's visibility hangs on.**  The published
    reference says a role on the "source or destination collection"
    lets a caller see a task; the SDK's docstrings for
    `endpoint_manager_get_task` and `endpoint_manager_task_event_list`
    say "the destination endpoint of the task."  They disagree.
    Fauxbus takes the reference, the more permissive reading.
    `PROVISIONAL` in `World._task_visible`.
16. **Whether `administrator` goes quiet when a subscription lapses.**
    The reference says the two activity roles do.  Fauxbus treats
    administrator the same.  `PROVISIONAL` in `World._monitor_refusal`.
17. **What a malformed id answers.**  A task id or collection id that is
    not a UUID gets 404 `TaskNotFound` / `EndpointNotFound` rather than
    a 400.  Two markers, in `World._transfer_task` and
    `endpoint_manager_task_list`.
18. **Which malformed task-list requests are refused.**  The
    `BadRequest` code is recorded and the rules come from the SDK's
    docstring (`filter_endpoint` required unless every status asked
    for is a running one) and the reference (`limit` at most 1000), but
    nobody has watched the service apply them, or seen its messages.
    `PROVISIONAL` in `endpoint_manager_task_list`.
19. **Whether `filter_completion_time`'s edges are inclusive.**  Fauxbus
    includes both.  `PROVISIONAL` in `World._in_window`.
20. **What `last_key` holds.**  The reference calls it opaque.  Fauxbus
    borrows the recorded example's shape (`complete,<time>`), adds the
    task id so two tasks with one timestamp can be told apart, and
    pages by key rather than by offset.  A last page still carries its
    key (the recording does); an empty page carries null (nothing
    recorded).  Two markers in `World._encode_last_key`.
21. **How `successful_transfers` pages.**  No page size is documented;
    Fauxbus uses 100.  The marker is an integer in the reference and
    an offset in Fauxbus.  Two markers, at
    `SUCCESSFUL_TRANSFERS_PAGE` and in
    `endpoint_manager_successful_transfers`.
22. **Whether the endpoint-manager file list refuses a running task.**
    The reference says the owner's `/task/<id>/successful_transfers`
    answers 400 `ClientError.BadRequest` for a task "not yet
    complete"; the endpoint-manager page does not restate it.  Fauxbus
    applies the same rule to both.  `PROVISIONAL` in
    `endpoint_manager_successful_transfers`.
23. **The values of the task fields Fauxbus does not model.**  The key
    set is recorded and complete; `deadline`, the `subtasks_*` counts,
    `is_ok`, `nice_status`, `effective_bytes_per_second`, `username`,
    the legacy `name#id` endpoint strings, and the host, mapped and
    local-user fields are null or a resting value.  So is
    `successful_transfer.dynamic`, which the reference shows as
    `false` and does not explain.  Two markers, in `World.task_doc`
    and on `dynamic`.
24. **How linked identities show up in a Groups answer.**  The
    published OpenAPI says `my_groups` covers the user's linked
    identities, and Fauxbus lists every linked identity's membership
    that passes the filter, in the account's identity order.  That
    order is `PROVISIONAL` in `World.my_groups`.  Unmarked, because no
    source says anything about it: whether a single-group GET's
    `my_memberships`, and the role checks behind every write, follow
    linked identities too.  Fauxbus answers both for the calling
    identity alone, which is the conservative reading — a fake that
    refuses where the real service allows breaks a test loudly, and
    the reverse lets a bug through quietly.

And `identity_set`, already at the top of this list since v0.2.15, now
has code to point at: its entry shape and its order are two
`PROVISIONAL` markers in `world.identity_claims` and `Account.ordered`,
one obligation.

Slice B also *retired* questions, which this list has not had a chance
to record before.  The first real-service capture (2026-10-12, two
public unauthenticated GETs — see the slice B section) made the
discovery document's keys, the JWKS entry's keys, the `/jwk.json` path,
and the RS512 algorithm RECORDED before they could ever be guessed.

Error documents are shaped `{"code": ..., "detail": ...}` — the form the
SDK's error classes parse into `.code` and `.message` regardless of which
of its three error-format branches fires.  With one exception, added in
v0.2: the OAuth2 token endpoint answers RFC 6749 §5.2's
`{"error", "error_description"}`, because that is what the SDK's own
fixture shows Globus sending from that path.  Two error dialects in one
server is not a wart — it is the fake being faithful to a service that
really does speak both.  Slice B made it three: userinfo answers Globus
Auth's own document, a JSON:API `errors` list with RFC 6749's
`error`/`error_description` beside it, RECORDED from
`globus_sdk/testing/data/auth/userinfo.py` — and unlike the token
endpoint's, those errors *do* reach the SDK's `.code` and `.message`.
Transfer made it four: `{code, message, request_id, resource}`,
RECORDED in the SDK's Transfer fixtures — see the Transfer section.

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

**Issued-token mode is a fidelity feature, not an access control**, and
the difference matters enough to state before someone leans on it.  The
tokens it checks are minted on the same deterministic counter as
everything else in Fauxbus: the first access token of a run is always
the literal string `fauxbus-at-0`, the second `fauxbus-at-1`, and a
world reset returns the counter to zero so the next one is
`fauxbus-at-0` again.  That is principle 3 working as designed — a test
that asserts on a token value has to get the same value every run — and
it is not going to change, because randomness here would cost more than
it buys.

What follows from it is the part to be explicit about: **an issued
token is a known constant, not a secret.**  The three checks above stop
a token Fauxbus never minted, one the logical clock has aged out, and
one belonging to another resource server.  They do not stop anyone who
can reach the port, because that person does not have to guess
`fauxbus-at-0` — they can read it here.  Do not read "the token was
issued here" as "the caller is authorized"; it means "this token is one
of ours," which is a statement about bookkeeping.

This is worth its own paragraph because of one configuration in
particular.  `--control-loopback-only` closes `/_fauxbus/` to the
network while deliberately leaving the imitated surface open, and
`--require-issued-tokens` is the only gate left on that surface.  A
neighbour on a shared dev host who cannot reach the control plane can
still send `Authorization: Bearer fauxbus-at-0` and be admitted as
whichever client minted it.  The flag combination narrows the blast
radius from "rewrite the world" to "act as a client inside it," which
is a real improvement and is not the same as a boundary.  The
paragraph above about the control plane still governs: a tool whose
whole value is being believed can be attacked by being made to lie, and
no token check changes that.

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
the rest in `other_tokens`.  Slice A shipped refusing that with a 501,
because the tempting shortcut — issue for whichever service parsed
first and quietly drop the other scopes — is the exact silent wrong
answer principle 2 forbids.  As of v0.2.18 it is built: one token per
service, each carrying only its own service's scopes, the first-named
service on top (see the recording list for why that order is
provisional).  A scope form Fauxbus cannot parse is a 501 rather than a
guess, and it mints *nothing* — a refusal on the third scope does not
leave two orphan tokens behind.  And a request carrying `openid` is refused rather than
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
without performing the grant and ticking the clock first — but **not
under a name the mint has not reached yet.**  Seeding `fauxbus-at-0` and
then performing one grant used to produce that same string twice, with
the mint writing over the seeded record in place: a token seeded as
expired came back alive, a token seeded as one identity came back as
another, silently and on every run.  Determinism did that — two values
that were both guessable by design guessed each other.  The seed door
refuses it now, and draws the line at `counters.access_token` rather
than at the `fauxbus-at-N` name shape, which is what keeps a state dump
reloadable: a dump carries `fauxbus-at-0` alongside `access_token: 1`,
so that token is already behind the mint.

## v0.2 — Auth slice A.2: introspection and revocation

`POST /v2/oauth2/token/introspect` (RFC 7662) and
`POST /v2/oauth2/token/revoke` (RFC 7009) — the other end of the story
slice A started.  The token endpoint is where a service *gets* a
credential; these are where the service on the receiving end asks
whether the credential it was handed is real, and where the service that
issued one takes it back.  Fauxbus has held every answer introspection
needs since slice A, inside `IssuedToken`, and had no way for anyone
outside to ask.

They were picked as the next slice for a reason worth stating: of
everything left unbuilt in Auth, **introspection is the shape the SDK
grounds best.**  `oauth2_token_introspect.py` is a complete recorded
document, key for key, and the revoke fixture is the bare
`{"active": false}`.  Slice B's surface, by contrast, is the one place
the SDK cannot be the whole contract.  Building the recorded thing first
is what principle 1 means when there is a choice.

**Who may ask differs between the two, and the difference is the
design.**  Introspection is *not* scoped to the issuing client:
introspection exists for resource servers, which by definition did not
issue the token they are holding, so scoping it would make it useless to
its only audience.  Revocation is the opposite — RFC 7009 §2.1 says
verify the token was issued to the caller.  Fauxbus verifies, and a
stranger gets `{"active": false}` with nothing revoked, identical to the
answer for a string that never existed.  Refusing with an error would
have turned the endpoint into an oracle: 200 means "never existed," an
error means "exists, belongs to someone else."  PROVISIONAL — the real
service has not been observed here.

**Inactive says nothing else.**  Never issued, expired, revoked, and
issued-to-someone-else all answer the same bare `{"active": false}`
(RFC 7662 §2.2).  That is correct and it is an annoying afternoon for
anyone debugging a harness, so: every reason is in `GET /_fauxbus/state`,
which is out-of-band per principle 4 and under no obligation to be
discreet.  The imitated surface keeps the secret; the control plane
does not have one.

**A revoked token keeps its record.**  Deleting it would drop the token
back through `identity_for_token` to the hash-derived default, where it
would come back to life as a *different* caller — the fake disagreeing
with itself about who just called, which is the same failure
`identity_for_token`'s ordering exists to prevent.  So revocation sets a
flag, and the flag round-trips through dump/seed like everything else.
Note what revocation does under the permissive default: nothing visible.
That surface checks no tokens at all, which is what makes it permissive,
so it ignores revocation for the same reason it ignores expiry.

**Introspection makes `--require-issued-tokens` visible from outside**,
and this will look like a contradiction before it looks like a feature.
Under the permissive default, `t-alice` is a perfectly good caller
against Groups *and* introspects as inactive, because introspection
answers about tokens this Auth issued — which is what the real service
can answer about.  Permissive bearer handling is how Fauxbus decides who
is calling, not a claim that Globus minted anything.  A consumer whose
resource-server code introspects the tokens it holds should be handed
tokens from the token endpoint, which is what the strict flag is for.

**Timestamps: the logical clock reaches the wire as an instant.**  This
is the first endpoint where it does.  `expires_in` was a duration and
read the same against either clock; `exp` is a point in time and has to
pick one.  It picks Fauxbus's — `iat` is the clock at minting, `exp` is
that plus the lifetime, `/_fauxbus/tick` moves neither but moves *now* —
which means a fresh world introspects as 1970 and consumer code doing
`if exp < time.time()` calls every token expired.

The knob for that already existed and only needed saying aloud: **seed
`"clock": 1767225600`** and every timestamp on this endpoint is a real
2026 second.  It stays deterministic because the harness chose the
number.  Fauxbus will not pick a plausible-looking epoch on its own,
because a fixed epoch that satisfies `exp > now` and `iat < now` at the
same time does not exist, and one that reads the real clock to find it
is a wall clock wearing a disguise.

**`include=identity_set` is a loud 501.**  Fauxbus does not model
identity linking — there is no way to seed a second identity onto
anyone — so the only answer it could give is a list of one, every time,
for everybody.  That is exactly the plausible-looking answer to an
unanswerable question principle 2 forbids: a consumer testing "this user
has three linked identities" would get a passing test against a world
that cannot have them.  It is the same `identity_set` the grading audit
already calls the most consequential provisional in Auth, which is why
it gets refused rather than guessed twice.

## v0.2 — Auth slice B: the OIDC authorization-code flow

A real, unmodified Keycloak can now broker a sign-in against Fauxbus:
its login page, a button, Fauxbus's authorize endpoint, a page listing
seeded accounts, back to Keycloak with a code, a signed ID token
Keycloak verifies against Fauxbus's published key, a userinfo call, and
a brokered Keycloak user whose federated identity is a Globus identity
UUID.  `examples/keycloak_broker.py` runs exactly that against
`quay.io/keycloak/keycloak:26.0`, and it passed on 2026-10-12 with both
`client_secret_basic` and `client_secret_post`.

**The surface**, all of it rebuilt on one configured issuer:

- `GET /.well-known/openid-configuration` — discovery.
- `GET /jwk.json` — the public signing key.
- `GET /v2/oauth2/authorize` — the browser leg: `response_type=code`,
  `client_id`, `redirect_uri`, `scope`, `state`, `nonce`,
  `prompt=login`, and PKCE `S256`.
- `POST /v2/oauth2/token` with `grant_type=authorization_code` — the
  code exchange, client auth by Basic or form body.
- `GET`/`POST /v2/oauth2/userinfo` — the ID token's claims, live.
- Out-of-band, under `/_fauxbus/auth/`: the account picker (`GET` and
  `POST /_fauxbus/auth/login`) and a headless sign-in
  (`POST /_fauxbus/auth/session`).

**The first recording from the real service.**  Every grade in this
project has so far come from the SDK's fixtures, because no tenancy
exists to record against.  Two documents need no tenancy at all:
`https://auth.globus.org/.well-known/openid-configuration` and the
`/jwk.json` it points at are public, unauthenticated GETs.  Captured on
2026-10-12, and they corrected this document twice before a line of
signing code was written.  The real service signs ID tokens with
**RS512**, not the RS256 SPEC's 2026-08-24 probe assumed; and its token
endpoint advertises **`client_secret_basic` only**.  The discovery
document's key set, the JWKS entry's key set, the `/jwk.json` path, and
the algorithm are therefore RECORDED, and Fauxbus serves them key for
key.  The published reference (docs.globus.org/api/auth/reference, read
the same day) grounded three more things as DOCUMENTED: which scope
gates which claim, what `sub` is, and what `required_idp` means.

**Discovery tells the truth about Fauxbus where it must.**  The keys are
the live document's.  Values describe *this* server, because a broker
acts on them: `response_types_supported` is `["code"]` where the live
service also lists implicit and hybrid types nobody has asked Fauxbus to
build.  The one place the fake is kinder than its own document is client
authentication — discovery says Basic, as recorded, and the token
endpoint still accepts `client_secret_post` too, as slice A decided.
Whether the real endpoint does is unobserved, and the recording list
says so.  **A broker should be configured with Basic**, against the fake
and the real thing alike.

**Claims, by scope** — DOCUMENTED.  `openid` gives `sub`,
`last_authentication`, and `identity_set`, plus the token claims `iss`,
`aud`, `exp`, `iat`, `at_hash`, and `nonce` when one was sent.  `email`
adds `email`.  `profile` adds `name`, `organization`,
`preferred_username`, `identity_provider`, and
`identity_provider_display_name`.  Note what `openid` alone leaves out:
any name or address for the person.  A broker that maps `email` and
forgets to request the `email` scope gets a user with no email, and
should — that is what the real service would hand it.  One function
builds the claims for both the ID token and userinfo, because OIDC
requires their `sub` to match and Keycloak checks it.

**`sub` is the effective identity**, and this is the line the slice
exists for.  The reference defines it as "the primary identity, or the
appropriate linked identity if this client requires an identity from a
particular provider."  So the seed models an account as a primary
identity plus linked ones, a client may carry `required_idp`, and an
account whose primary is Globus ID signs in to a university's client
*as its university identity*.  The proof run shows it end to end:
Keycloak's federated link for alice is her university UUID, not her
Globus ID.  When an account has no identity from the required provider,
Fauxbus keeps the person at the picker with a 403 explaining why and
never calls the client back — the reference describes the neighbouring
case as the user being "redirected to log in or link an identity," which
is a stay-at-Globus behavior, not an `error=` redirect.  The details are
PROVISIONAL.

**`identity_set` is still the provisional that matters most.**  The
reference confirms it arrives under `openid` and describes it only as
"the identities linked to this account."  No fixture and no doc shows an
entry.  Fauxbus reuses the top-level claim names plus `username`, lists
the primary first and the rest by UUID, and gives `last_authentication`
only to the identity that just signed in (null for the others, rather
than an invented history).  Two markers, one obligation, still at the top
of the recording list.

**Three refusals at authorize, one rule each.**  The redirect URI is
matched exactly — no trailing-slash or case forgiveness, as RFC 6749
§3.1.2.3 and Keycloak's own side both require.  When the redirect URI
cannot be trusted (unknown client, missing or unregistered URI) the
error is rendered and never redirected, because redirecting errors to
an unvetted URI is how an authorization server becomes an open
redirector.  When the client asked for something malformed, it gets
RFC 6749 §4.1.2.1's `error=` redirect with its own `state`.  And when it
asked for something Globus does and Fauxbus has not built — `prompt=none`,
offline access, PKCE `plain`, another `response_mode` — it gets the loud
501, rendered, because an `error=` code would tell the client *it* was
wrong.  The same three-way split the token endpoint makes for grant
types, for the same reason.

**The code** is one-use, bound to the client, the exact redirect URI,
the scopes, the nonce, the PKCE challenge, and the identity, and every
mismatch at the exchange is the RECORDED 401 `invalid_grant`.  It lives
600 seconds on the logical clock (PROVISIONAL — no lifetime is
published), so a test proves expiry with a `tick`, and a failed exchange
does not spend it.  The response is the recorded document: `other_tokens`
always present, `resource_server` flipped to `auth.globus.org` with
`id_token` beside it whenever `openid` was asked — even when another
service's scope was named first, since `id_token` is only ever read from
the top level — and the authorize request's `state` echoed in the body,
as the SDK's default fixture shows.  A public (native-app) client's
exchange is a 501: Fauxbus registers confidential clients only.

**Signing is RS512 in `signing.py`, stdlib only.**  The zero-dependency
rule held: the switch from the probe's RS256 was one constant, the
SHA-512 `DigestInfo` prefix.  The fixture private key is in the source,
published on purpose, and the `kid` is its RFC 7638 thumbprint.  Every
ID token the suite mints goes through PyJWT and through globus-sdk's own
`decode_id_token`, which arrives with the conformance extra — so a wrong
byte in a hand-rolled signer is a red test, not a mystery in a broker
log.

### Clocks: logical by default, wall time by explicit opt-in

The roadmap settled on 2026-08-24 that signed-token instants must anchor
to real time, because the verifier is not playing.  Building it turned
"must" into a question of *who decides*, and the answer is the harness,
out loud.

`oidc.signed_token_clock` is `"logical"` (the default) or `"wall"`, set
in the seed or by `--signed-token-clock` at boot.  Under **logical**, an
ID token's `iat` is the world clock: deterministic, byte-identical
across runs (a test can assert on the whole token string), and right for
anything a harness verifies with its own clock or seeds to a real
second.  Under **wall**, `iat` is real time, and that is right for an
outside verifier like Keycloak.  Determinism survives in the offsets —
`exp - iat` is always 172800 — rather than in the absolute value.

What `wall` changes is deliberately narrow: ID-token `iat`/`exp` and the
`last_authentication` recorded at sign-in.  Authorization codes and
access tokens stay on the logical clock, because Fauxbus is the one
validating those.  `tick` does not move wall time.  And there is exactly
one wall-clock read in the codebase, `FauxbusServer.signed_now`, with the
clock injectable so the suite can freeze it; `world.py` never reads time
at all.

Why not wall by default, given the trap?  Because principle 3 is a
promise to every consumer that did not ask for an outside verifier, and
a fake that starts reading the wall clock on its own is a fake whose
dumps stopped being reproducible without anyone choosing that.  The
price is that a Keycloak user who forgets the flag gets ID tokens from
1970 and a login that "just fails."  So the boot line and
`GET /_fauxbus/` both name the clock in use, the README's Keycloak
section leads with it, and `examples/seed.json` — the copyable pattern —
sets `"wall"`.

### Issuer versus reachability

In a compose network the browser reaches Fauxbus as
`http://localhost:9800` and the broker reaches it as
`http://fauxbus:9800`.  A broker checks `iss` as a string, so the issuer
cannot be derived from whichever `Host` header a request carried; it is
configuration, `--issuer` or the seed's `oidc.issuer`, and every surface
answers with it regardless of the name it was reached by.  Pick the
name the *browser* uses — it is the one in the authorize URL — and give
the broker the network name for its back-channel URLs.  Keycloak takes
the four endpoints separately, which is exactly what makes this work.
With no issuer configured, the OIDC surfaces answer a 503 saying so
rather than guess.  An issuer under `globus.org` or `globusid.org` is
refused at boot (exit 2) and at the seed door (422).

Seed authoritative, flag as default: a seeded issuer beats `--issuer`,
the state dump shows only the world's own value (null when unset), and
`GET /_fauxbus/` shows the effective one.  A world reset to empty, or a
seed that never mentions OIDC, still leaves a broker pointed at a
working issuer.

### The seed model

```json
{
  "oidc": {"issuer": "http://localhost:9800", "signed_token_clock": "wall"},
  "identity_providers": {
    "41143743-f3c8-4d60-bbdb-eeecaba85bd9": {"name": "Globus ID"},
    "00000000-0000-4000-8000-0000000001d9": {"name": "Night Owl University"}
  },
  "accounts": {
    "<primary identity id>": {
      "identities": {
        "<primary identity id>": {"username": "...", "identity_provider": "...",
                                  "name": "...", "email": "...", "organization": "..."},
        "<linked identity id>":  {"...": "..."}
      }
    }
  },
  "clients": {
    "<client id>": {"secret": "...", "name": "...",
                    "redirect_uris": ["https://broker.example/realms/x/broker/globus/endpoint"],
                    "required_idp": "<identity provider id or null>"}
  }
}
```

An account is named by its primary identity, as Globus names one, and
lists every identity including the primary.  An identity belongs to one
account.  UUID and username stay separate fields, which keeps a rename
representable (see the roadmap's identity-churn note).  A client with no
`redirect_uris` cannot run the browser flow, which is how Fauxbus says
"client_credentials only" without a grant-types field nobody would
consult.  The identity object's `status` and `identity_type` are left
out until a surface emits them.

The login in flight is world state too — parked authorization requests,
issued codes, sessions — and it round-trips like everything else, so a
harness can dump a half-finished login and restore it exactly.  Reset
clears all three: a surviving code could be redeemed by the next test,
and a surviving session would sign the next test's browser in as the
last test's user.  Their minted names (`fauxbus-code-N`,
`fauxbus-session-N`, `fauxbus-request-N`) get the same seed-door guard
`fauxbus-at-N` got in v0.2.17.

## v0.2 — Transfer task monitoring

A researcher sends a dataset to a landing collection.  Nobody at the
receiving end submitted that transfer, and Globus will not call anyone
when it finishes: there is no webhook, so a service that needs to know
polls.  It asks the Transfer API, as an *endpoint manager*, which
tasks came into the collection and which files each one delivered.
Root Cellar's poller does exactly that, and this slice is the API it
asks.  Its three calls run against Fauxbus unmodified; the conformance
suite repeats them argument for argument.

**The surface**, three `TransferClient` methods of globus-sdk 4.8.1:

- `endpoint_manager_task_list` — `GET /v0.10/endpoint_manager/task_list`,
  with `filter_endpoint`, `filter_endpoint_use`, `filter_status`,
  `filter_completion_time`, `limit`, and `last_key` paging.
- `endpoint_manager_get_task` — `GET /v0.10/endpoint_manager/task/{id}`.
- `endpoint_manager_task_successful_transfers` —
  `GET /v0.10/endpoint_manager/task/{id}/successful_transfers`, paged
  by `next_marker`.

`endpoint_manager_task_event_list` is not built and answers the loud
501; no consumer calls it, and the reference itself says task events
are for troubleshooting.  The task list's other filters
(`filter_task_id`, `filter_owner_id`, `filter_is_paused`,
`filter_min_faults`, `filter_local_user`) are a 501 too, *by name* —
an ignored filter is the purest silent wrong answer there is, since
the caller asked for fewer tasks and got all of them in a response that
looks perfect.

**Grades.**  RECORDED, from
`globus_sdk/testing/data/transfer/`: the task-list envelope (`DATA`,
`DATA_TYPE`, `has_next_page`, `last_key`, and no total); the task
document's full key set, which a conformance test reads out of the
fixture's source with `ast` and compares key for key; the
successful-transfer envelope and the three row fields the fixture
shows (`DATA_TYPE`, `source_path`, `destination_path`); and Transfer's
error document, `{code, message, request_id, resource}`.  DOCUMENTED,
from the published reference (read 2026-10-14): the four other row
fields (`size`, `checksum`, `checksum_algorithm`, `dynamic`); the
ordering (running tasks first, newest request first, then finished
tasks, newest completion first); `limit`'s default of 100 and ceiling
of 1000; the roles; the subscription rule; the completion-time formats
and the blank-end rule; `fatal_error`'s shape; and that a running
task's file list is a 400.  PROVISIONAL: nine obligations, items 15–23
on the recording list.

**The SDK's fixture does not ground the fields the consumer stores.**
Worth its own paragraph, because it is the kind of thing this project
exists to notice.  The successful-transfer rows in 4.8.1's fixture
carry a source path and a destination path and nothing else.  `size`,
`checksum` and `checksum_algorithm` — the three things a poller writes
down beside each path — come from the published reference alone.
Fauxbus serves them, graded DOCUMENTED, and they are the first thing a
recording session should look at.

**Who may look.**  A Transfer token (under `--require-issued-tokens`,
a Groups token here is refused, the same check that has kept Transfer
tokens out of Groups since slice A), and an identity holding
`activity_monitor`, `activity_manager` or `administrator` on a
collection the task touched.  The role only counts while the
collection is subscribed: the reference says "if the endpoint or
collection is unsubscribed, activity manager and monitor roles become
inactive," which is a production failure — a lapsed subscription, every
grant still in place, the poller suddenly refused — that a fake with no
subscription field could never show.  Role principals are identities;
Globus also grants roles to groups, and nobody has asked for that.
Without `filter_endpoint` (legal only when asking for running tasks),
a caller sees the tasks its roles reach — the SDK's docstring describes
the method as listing tasks "visible via activity_monitor role."

**The model is bookkeeping.**  The bright line from 2026-07-31 holds:
no byte moves, no path is opened, no GridFTP.  A collection is a name,
a subscription, and role grants.  A task is an owner, a source and
destination, a status, and a list of files that are rows with a path
and a size.  Progress is whole files in list order, arriving evenly
between `active_since` and `due_at` on the logical clock, computed
rather than stored, so a dump taken mid-transfer reloads to the same
point.  Checksums are whatever the harness says, or null: there are no
bytes to compute one over, and an invented one would have a consumer
comparing its own copy against noise.

**The control plane, and why this shape.**  Two routes and a clock:

- `POST /_fauxbus/transfer/tasks` creates a task at the current clock.
  `duration` sets it running; `status` can start it anywhere.
- `POST /_fauxbus/transfer/tasks/<id>` moves it: `INACTIVE` pauses,
  `ACTIVE` with a `duration` resumes, `SUCCEEDED` finishes it now,
  `FAILED` with `files_succeeded` fails it part-way.  A finished task
  does not move again (409): Globus never reports a terminal task
  finishing a second way, and a consumer's "terminal means terminal"
  rule deserves a fake that agrees.
- `POST /_fauxbus/tick` finishes every ACTIVE task its seconds carry
  past due, stamped with the time it was *due*, not the time the
  harness looked.

The alternative was imitating task submission (`submit_transfer`) and
letting tests create tasks through the imitated surface.  That would
mean building submission documents, submission ids, endpoint
activation, and a data plane's worth of validation for a call no
consumer makes — the poller only reads.  So creation is a harness act,
out-of-band per principle 4, the same way a group's subscription
arrives by seed because no Groups endpoint writes one.  Duration plus
tick, rather than "complete it now" alone, because a poller's window
logic is about *when* things finished, and only the clock can test that
without a sleep.  Explicit moves, alongside it, because "fail it at
60%" is SPEC's opening promise and an outage is not a duration.
Failure injection needed nothing new: armed rules and `X-Fauxbus-Fail`
already reach every path outside `/_fauxbus/`, `/v0.10/` included.

**Seed the clock to a real second.**  Task times are the logical clock
rendered as ISO 8601, so a fresh world's tasks finish in 1970, and a
poller asking for "completed since ten minutes ago" by its own wall
clock finds nothing.  This is introspection's lesson again (seed
`"clock": 1767225600`), and it bites harder here, because the poller's
window is computed from its *own* `now`.  A long-running dev stack must
also tick the fake forward as wall time passes, or the tasks it creates
fall behind the window.  `examples/seed.json` seeds a real second.

**A fourth error dialect.**  Transfer's errors say `message` where the
rest of Globus says `detail`, carry a `request_id` and the `resource`
path, and use CamelCase codes (`PermissionDenied`, `TaskNotFound`,
`EndpointNotFound`, `BadRequest`, and the reference's own
`ClientError.BadRequest` for a running task's file list).  The SDK
reads either key into `.message`, so a consumer cannot tell, but a raw
reader can, and the fake says what the service says.  The `request_id`
is nine characters hashed from the code and the path rather than drawn
at random, so the same failure renders the same bytes every run.
Fauxbus's own errors — the 501s, a missing token — keep Fauxbus's
dialect, because those are the fake speaking about itself.

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
  imitated surface (`/v2/…`, `/v0.10/…`, and the OIDC discovery and
  JWKS paths) — you cannot brick the control plane with it.
  One-shot inline variant: send `X-Fauxbus-Fail: 429` on any request to get
  that failure exactly once, for quick cases.
- `GET /_fauxbus/auth/login?request=…` and `POST /_fauxbus/auth/login`
  — the account picker a browser with no Fauxbus session is sent to by
  `/v2/oauth2/authorize` (slice B).  Plain HTML, one form per seeded
  account, no password field and never will be.  Picking signs the
  browser in with a `fauxbus_session` cookie and finishes the parked
  authorization request.
- `POST /_fauxbus/auth/session` — `{"account": "<primary identity id>"}`
  signs a headless test in before it starts a login, so authorize skips
  the picker.  Returns the cookie in `Set-Cookie` and in the body.
- `POST /_fauxbus/tick` — advance Fauxbus's logical clock by N seconds.
  It existed from day one with nothing consuming it, so that
  determinism would be load-bearing rather than retrofitted.  Token and
  code expiry read it since the Auth slices, and since the Transfer
  slice it does what the roadmap built it for: an ACTIVE task whose
  duration a tick carries past is SUCCEEDED, stamped with the time it
  was due.
- `POST /_fauxbus/transfer/tasks` — create a transfer task at the
  current clock: `owner_id`, `source_endpoint_id`,
  `destination_endpoint_id`, `files` (each `source_path`,
  `destination_path`, `size`, optional `checksum` and
  `checksum_algorithm`), and optionally `status`, `duration`,
  `files_succeeded`, `faults`, `fatal_error`, `label`, base paths.
  Answers with the task's id and its seed form.
- `POST /_fauxbus/transfer/tasks/<id>` — move a task along: `{"status":
  "INACTIVE"}`, `{"status": "ACTIVE", "duration": 60}`, `{"status":
  "SUCCEEDED"}`, `{"status": "FAILED", "files_succeeded": 3}`.  A
  finished task is final (409).  Collections and their role grants
  arrive only by seed (`collections`), since the slice reads tasks and
  administers nothing.

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
  (uid 9800 — yes, the port), on an Alpine final stage: with a
  pure-stdlib app the distro *is* the attack surface, and Debian slim
  carried 55 unfixable Highs Fauxbus never touches (see the comment in
  `Containerfile` for the measurements).  `examples/compose.yaml` is the copyable
  pattern, and `examples/seed.json` is a real state dump kept honest by
  a byte-identical round-trip test in CI.
- Zero runtime dependencies — stdlib only, on purpose.  A test fake
  consumers add to their dev environments should not bring a supply
  chain with it.  Tested against its hardest case on 2026-08-24, and
  then built against it in slice B: signing ID tokens looks like it
  requires a crypto library and turns out not to — `signing.py` signs
  RS512 with `hashlib` and `pow()`.  The rule has not needed an
  exception yet, and "we built it" is a stronger claim than "we
  checked," which was stronger than "we intend to."
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

- **Reordered 2026-10-14: Transfer task monitoring first.**  Andrew,
  2026-10-14: Transfer task monitoring moves ahead of the login shim;
  Root Cellar's Globus door is built and its dev end-to-end test needs
  it.  Built in v0.2.22 (the "Transfer task monitoring" section above).
  The login-shim milestone below is unchanged and comes after it, its
  steps in the order written.

- **The milestone after that, decided 2026-10-12: the Globus login shim.**
  @xram's framing: *a way to mock Globus login reliably in code for
  e2e testing.*  A shim, never a real identity provider.  Everything
  in this document that makes Fauxbus untrustworthy on purpose (the
  published signing key, the password-less account picker, the
  unauthenticated control plane) stays exactly as it is.

  **Acceptance test for the whole milestone:** an *unmodified* app
  built on Globus login runs its full login and its Globus calls
  against Fauxbus, with only configuration changed, while the test
  drives every step from code: who signs in, when tokens expire, which
  call fails.  "Unmodified" is literal: globus-sdk reads
  `GLOBUS_SDK_SERVICE_URL_AUTH` / `_GROUPS` / `_TRANSFER`, each set to
  the bare server root, and a broker takes an issuer URL.  (This plan
  first said `GROUPS` needed a `/v2/` suffix.  Step 1 tried it: every
  4.8.1 `GroupsClient` path already starts with `/v2/`, so the suffix
  sends `/v2/v2/groups`.)

  In order, each one a commit and a board post:

  1. **Drop-in by environment.**  *Done in v0.2.23.*  Conformance tests that reach Fauxbus
     through the env vars instead of `base_url`; a README section,
     "point your app at Fauxbus"; and a test that a person's
     authorization-code token works against Groups *as that person*,
     which is the group-gated-login story most consumers want.  Nearly
     free, and it becomes the harness every later step is judged by.
  2. **Native-app (public) clients with PKCE, and the
     `/v2/web/auth-code` page.**  Today a public client's exchange is a
     501.  This unlocks `NativeAppAuthClient` and the SDK's `UserApp`,
     so every CLI and notebook built on globus-sdk.  The SDK sends
     those clients to `{auth}/v2/web/auth-code` to display the code;
     like authorize, that page is a browser surface the SDK cannot
     ground, so it is graded against what the SDK does with it.
  3. **Refresh tokens.**  `access_type=offline` / `offline_access`
     yields a `refresh_token` on every token in the document (primary
     and `other_tokens`); `grant_type=refresh_token`; refresh tokens
     revocable; access-token expiry on the logical clock, so
     `RefreshTokenAuthorizer` can be proved to survive a `tick` past
     expiry.  There is no refresh fixture in 4.8.1: the shape is pinned
     from the reader's side (`refresh_token` via `.get`), and whether
     Globus rotates refresh tokens is PROVISIONAL.
  4. **`fauxbus.testing`, an in-process harness.**  A context manager
     (and a pytest fixture when pytest is present) that starts a server
     on a free port, seeds it, and gives a test `sign_in(account)`,
     `tick(seconds)`, `fail(...)`, `state()`.  These are thin wrappers
     over the HTTP control plane, never a backdoor into `World`, so
     principle 4 holds and the harness tests the same server everyone
     else runs.  Stdlib only.  This is what turns the pieces into
     something a test author uses in five lines.
  5. **Identities lookup**: `GET /v2/api/identities` by ids and
     usernames, from the recorded `get_identities` fixture.  For apps
     that show names or add group members by username.
  6. **A second relying party**: `examples/oauth2_proxy.py`, a generic
     OIDC client beside the Keycloak one, plus a headless `UserApp`
     example.  Proof that Fauxbus is a Globus login fake, not a
     Keycloak special case.
  7. **Release 0.4.0.**

  Steps 2 and 3 come first among the real work because they are the
  first two refusals a real app hits: most Globus apps are native
  clients, and most ask for refresh tokens.  Deferred until a consumer
  asks: dependent tokens, `prompt=none` and session step-up, logout,
  the consents API.  Transfer stayed held when this was written; the
  reorder above moved its first slice ahead.

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

  **Queue position held 2026-09-04**, by operator decision: Groups and
  Auth were the larger needs, so Transfer waits.  Recorded rather than
  silently reordered, because the consumer need behind this bullet has
  not gone anywhere — Root Cellar has already dropped the iRODS
  Connector for land-then-register, so the completion signal is load-
  bearing for a design that exists, and the wait is a scheduling
  decision rather than a reassessment.  Nothing here needs redesigning
  when it resumes; the surface below is confirmed and still current.

  **Resumed 2026-10-14, and the first slice is built** (v0.2.22, the
  "Transfer task monitoring" section above).  The confirmed surface
  held, with one adjustment each way.  The poller that arrived also
  reads `endpoint_manager_task_successful_transfers`, which this bullet
  had not named, because a completion signal is only half the answer
  without the list of what completed.  And
  `endpoint_manager_task_event_list` stays a loud 501, because the
  poller does not call it.  Next in Transfer, when a consumer asks:
  event lists, the other task-list filters, then ACLs.

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

  - ~~**Multi-resource-server responses**~~ — **built in v0.2.18.**  It
    was the largest remaining fidelity gap in Auth, and it turned out
    to be slice B's floor as well: a broker that signs people in and
    checks their groups asks for `openid` and a Groups scope in one
    request, which is two services.
  - ~~**`id_token` on an `openid` request**~~ — **built in slice B**,
    for the authorization-code grant, where a person signed in for the
    token to describe.  Under `client_credentials` it is still refused:
    recording list #3 asks whether the real service answers that at
    all.
  - **Dependent scopes** (`scope[dependent]`) and the dependent-token
    grant.
  - **`refresh_token`** as a grant, and refresh tokens in the response.
    Requesting one is a loud 501 as of slice A.2, in **both** spellings:
    the `offline_access` scope that a broker sends, and
    `access_type=offline`, which is what globus-sdk actually sends
    (`flow_managers/authorization_code.py`, 4.8.1).  Catching only the
    first would have left the pinned SDK — the thing principle 1 calls
    the contract — as the caller Fauxbus failed quietly.
  - **Per-operation scope enforcement** — see Auth posture for why this
    one is a considered omission rather than a queue position.

  **Slice A.2 shipped** — token introspection and revocation, chosen
  next because they are the best-recorded shapes left in Auth (see their
  section above).  What this bullet used to promise and now delivers:
  "token introspection" is built; **identities lookup** and **dependent
  tokens** keep their place in the roadmap and still have no consumer
  asking.

  **Slice B shipped** (v0.2.21, its own section above) — the paragraphs
  below are the design as it was settled beforehand, kept because the
  section above refers back to them, with corrections marked where the
  building changed them.

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
  order to test a fake whose entire pitch is not having one.  (Held:
  Fauxbus ran it once itself, as `examples/keycloak_broker.py` — a
  script, not a test, outside the suite and outside every dependency
  list — and hands it to consumers as the template.)

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
  sentence in a document into a property of the system.  *Corrected in
  slice B:* the real service signs **RS512**, captured from its live
  discovery document and JWKS on 2026-10-12; RS256 was the probe's
  choice, not Globus's.  The recording won, and the switch was one
  constant.

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
  nowhere near the cause.  *Refined in slice B:* real time is an
  explicit opt-in (`signed_token_clock: "wall"`), not the default — see
  "Clocks" in the slice B section for why the harness, not Fauxbus,
  makes that call.

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
  (Built as stated; the "every surface must agree" half turned out to
  need a corollary about Host headers — see "Issuer versus
  reachability" above.)
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

- **v0.2.23** (2026-10-14) — **Login shim, step 1: an app points at
  Fauxbus by environment alone, and `my_groups` stops letting removed
  members in.**  The step was meant to prove what already worked.
  Writing it down found two things that didn't.

  **The plan had the Groups variable wrong.**  SPEC's roadmap, written
  two days ago, said `GLOBUS_SDK_SERVICE_URL_GROUPS` takes a `/v2/`
  suffix.  It doesn't: every `GroupsClient` path in 4.8.1 already
  begins with `/v2/`, so the suffix sends `/v2/v2/groups`.  All three
  variables are the bare server root.  The first new test checks that
  before any request leaves, so an SDK that stops honouring the
  variables fails there instead of reaching for the real service.

  **`my_groups` was more permissive than Globus.**  With no `statuses`
  filter it returned every membership: invited, removed, left.
  Globus's published Groups OpenAPI says the default is `active`.  The
  group-gated-login test found it: remove a member, and the app still
  saw them in the group.  That is the worst direction for a fake to be
  wrong in, because the consumer's test passes while the bug it should
  catch ships.  The same document says `my_groups` covers "the user and
  its linked identities", which Fauxbus also missed — a person signed
  in as their university identity didn't see groups their Globus ID
  identity belonged to.  Both fixed, both DOCUMENTED.  A test that
  pinned the old default (`test_my_groups_statuses_filter`) was
  asserting the bug, and now asserts the documented rule.  Anyone who
  relied on seeing invitations without asking for them needs
  `statuses=invited`, as they would against Globus.

  **What now runs with nothing but the environment changed:** a
  confidential login client's code flow with the ID token verified by
  the SDK; that person acting at Groups as themselves; a
  group-gated login whose answer the test flips by changing the
  membership; and the SDK's own `ClientApp` fetching its own tokens and
  calling Transfer and Groups.  README gains "Point your app at
  Fauxbus".

  264 tests, up from 259; 37 through the real globus-sdk, up from 33.

  **PROVISIONAL inventory: 45 markers**, up one from 44, **one new
  obligation** (recording list 24, linked identities in a Groups
  answer).

- **v0.2.22** (2026-10-14) — **Transfer task monitoring: a poller can
  watch a landing collection against Fauxbus.**  Moved ahead of the
  login shim the same day (Andrew, 2026-10-14: Transfer task
  monitoring moves ahead of the login shim; Root Cellar's Globus door
  is built and its dev end-to-end test needs it).  Three
  `endpoint_manager_*` routes (task list, task, successful transfers),
  collections with role grants and subscriptions in the seed, tasks
  created and moved through `/_fauxbus/transfer/tasks`, and the first
  `tick` that finishes something.  Full design in its section above.

  **Three sources, and they did not agree.**  The SDK's fixtures, the
  SDK's docstrings, and the published reference each ground part of
  this surface, and reading all three is what turned up the slice's
  real findings.  The fixture's successful-transfer rows carry two
  paths and nothing else, while the consumer stores `size`, `checksum`
  and `checksum_algorithm` beside each one — fields only the reference
  documents.  The SDK's docstrings put task visibility on the
  *destination* collection; the reference says source or destination.
  And the reference's task page, read after the code was written,
  corrected it before it left this branch: the first draft
  answered a running task's file list with the files so far, under a
  PROVISIONAL marker, and the reference says plainly that the service
  "returns 400 ClientError.BadRequest if the task is not yet complete."
  Slice B's changelog said the cheapest grounding ran last and should
  have run first.  It ran in the middle this time, which is better and
  still not first.

  **What a poller should know, from the reference, before it meets the
  real thing.**  A successful-transfer path is "relative to the guest
  collection root, as submitted in the transfer request" — whatever the
  submitter typed, not a normalized absolute path.
  `destination_base_path` is null unless the submitter set
  `store_base_path_info`, so it cannot be relied on to name a project.
  And task times on a fresh Fauxbus world are 1970: a poller that
  windows by its own wall clock needs the fake's clock seeded to a real
  second, and ticked forward as the run goes on.

  259 tests, up from 223; 33 through the real globus-sdk, up from 25,
  including the consumer's three calls with its exact arguments, both
  pagination styles across more than one page, and the task document's
  key set compared against the fixture's source read with `ast`.

  **PROVISIONAL inventory: 44 markers**, up thirteen from 31, **nine new
  obligations** (recording list 15–23).  Four obligations carry two
  markers each: malformed ids (task and collection), `last_key`'s shape
  and its last-page behaviour, `successful_transfers`' page size and
  marker meaning, and the unmodeled task fields plus `dynamic`.
  Counted with `grep -rn PROVISIONAL src/ | wc -l`.

- **Package release: fauxbus 0.3.0** (2026-10-12, tag `v0.3.0`) — **Auth
  slice B reaches consumers**, and with it everything since 0.2.0.  A
  minor: new imitated surface (introspection, revocation, discovery,
  `/jwk.json`, authorize, the `authorization_code` grant, userinfo),
  new CLI flag (`--signed-token-clock`), and a changed container base.
  One behaviour an 0.2.0 consumer could have relied on changed, on
  purpose: asking for a refresh token (`offline_access`, or
  `access_type=offline`) used to get a 200 that quietly had no
  `refresh_token` in it, and now gets the 501 it always deserved.
  Requests spanning two services went the other way, from 501 to 200.

  What a consumer gets, in the order it landed: token introspection and
  revocation (v0.2.17); the two slice A bugs that came with them — the
  mint overwriting seeded tokens, and `offline_access` treated as a
  service (v0.2.17); multi-resource-server token responses (v0.2.18);
  the OIDC authorization-code flow with signed RS512 ID tokens, linked
  identities and `required_idp` (v0.2.21).

  **Proved by its consumer before the tag existed.**  Root Cellar drove
  slice B end to end on its dev stack at `7f8a483` — this exact tree —
  through its Keycloak `globus-desk` broker: a person with a linked
  university identity signed in and was role-gated correctly, and a
  person without one was refused at the broker, as `required_idp`
  should.  Root Cellar is waiting on this tag, because 0.2.0 refuses a
  seed with an `oidc` section.

  **The container changes under you.**  The image's final stage is
  `python:3.13-alpine` now, not Debian slim (v0.2.19): no bash, no apt,
  busybox `sh` instead.  Nothing in Fauxbus depends on the old base,
  but `docker exec … bash` will fail.  uid is still 9800; gid is now
  9800 too.  The reason is the scan: a fresh build went from 161 grype
  findings to 5 Medium, all acked in `.grype.yaml`, and CI now fails on
  anything Medium-or-above that is not (v0.2.20).  **Rebuild with
  `--pull`** — a consumer image built a month ago carried 14 Criticals
  that a fresh build does not.

  **Re-pin handshake:** Root Cellar moves both of its pins to
  `fauxbus==0.3.0` in one commit, alongside its OIDC seed.  Its own
  seat carries that.

  Verified before the tag, from a `git archive` of the release commit:
  a clean-venv install reports 0.3.0 from `fauxbus version`, from
  `importlib.metadata`, from the module literal, and on the wire at
  `GET /_fauxbus/` — with no runtime dependencies.  `twine check`
  passes.  223 tests, 25 through the real globus-sdk.

  **PROVISIONAL inventory: 31 markers**, up from 0.2.0's 17 — fourteen
  across three releases' worth of surface, every one listed on the
  recording list with the version that added it.  The real-Globus leg
  of the conformance tether is still unrun.  One partial exception,
  worth naming because it is new: slice B fetched the real service's
  *public* discovery document and JWKS, and they corrected two things
  (RS512, not RS256; Basic client auth as the advertised method).
  Everything behind authentication is still graded against SDK
  fixtures, and a sacrificial tenancy is still the single item that
  would retire the most markers at once.

- **v0.2.21** (2026-10-12) — **Auth slice B: a real Keycloak signs
  someone in through Fauxbus.**  Discovery, `/jwk.json`, the authorize
  endpoint with an out-of-band account picker, the `authorization_code`
  grant, signed ID tokens, userinfo, linked identities and
  `required_idp`.  Root Cellar's dev realm is the consumer; its
  `globus-desk` broker points here next.  Full design in the slice B
  section above.

  **The real service was asked first, and it corrected the plan
  twice.**  Every grade in this project has come from SDK fixtures,
  because there is no tenancy to record against.  But discovery and the
  JWKS are public, unauthenticated GETs, and nobody had fetched them.
  Fetched before writing the signer, they said **RS512** — SPEC's
  2026-08-24 probe, and the brief for this slice, both said RS256 —
  and that the token endpoint advertises **`client_secret_basic` only**,
  where slice A had built `client_secret_post` with Keycloak's default
  in mind.  The signer took the recorded algorithm (one constant
  changed); the post method stays accepted but goes on the recording
  list, and the advice to consumers flips to Basic.  The published
  reference, read the same afternoon, turned three planned guesses into
  DOCUMENTED: `identity_set` arrives under plain `openid` (this
  slice's own first draft had it gated behind `view_identity_set`, a
  real scope name that turned out to gate nothing here), `sub` is the *effective* identity, and
  `required_idp` swaps it for the linked one.  Cheapest grounding this
  project has ever done, and it ran last.  It should have run in
  August.

  **The clock decision: logical by default, wall time by stated
  opt-in.**  The roadmap had already settled that ID-token instants
  must anchor to real time for an outside verifier.  Building it, the
  open question was who flips that switch, and the answer is the
  harness: `oidc.signed_token_clock: "wall"` in the seed, or
  `--signed-token-clock wall`.  One wall-clock read in the codebase
  (`FauxbusServer.signed_now`, injectable), `world.py` still reads no
  time at all, codes and access tokens stay logical, and under the
  default an ID token is byte-identical across runs.  The trap is
  named on the boot line, in `GET /_fauxbus/`, in the README, and
  pre-set in `examples/seed.json`.

  **The proof ran.**  `examples/keycloak_broker.py` drives
  `quay.io/keycloak/keycloak:26.0` with `urllib` and a cookie jar:
  Keycloak's login page, the identity-provider button, Fauxbus's
  authorize and picker, back to Keycloak with a code, first-broker-
  login, a Keycloak token for alice.  Keycloak's federated identity for
  her is `00000000-…-00000000000a` — her *university* identity, because
  the seeded client requires that provider — with both
  `client_secret_basic` and `client_secret_post`.  Fauxbus's own
  request log shows what Keycloak actually sent: `code_challenge` with
  S256, a `nonce`, its long dotted `state`, then a token exchange, a
  JWKS fetch, and a userinfo call.  **Nothing in Keycloak forced a
  Fauxbus change.**  One thing a consumer will want to know: Keycloak's
  attribute importer flattens `identity_set` objects into Java
  `{key=value}` strings, not JSON.

  Caught before commit, both by reading rather than testing: an issuer
  checked *after* the code was redeemed would have answered a 503 while
  leaving a spent code and minted tokens behind — slice A's orphan
  problem through a side door — so the issuer is now required before
  the code is touched; and response headers were validated after the
  status line went out, too late to turn a refusal into a clean error.

  223 tests, up from 161; 25 through the real globus-sdk, including its
  own `decode_id_token` verifying a Fauxbus ID token through discovery
  and the JWK.

  **PROVISIONAL inventory: 31 markers**, up eight from 23, **five new
  obligations** (recording list 10–14: the unsatisfied-`required_idp`
  behavior, code lifetime, userinfo's 401/403 split, whether
  `client_secret_post` is accepted, the `state` echo on openid).  The
  other three markers attach to obligations already listed:
  `identity_set`'s entry shape and its order (two markers, the
  standing top-priority item), and `openid` on top of a multi-service
  response (#8, one case narrower).  Counted with
  `grep -rn PROVISIONAL src/ | wc -l`.

- **v0.2.20** (2026-10-10) — **CI scans the image, and CVEs get acked
  rather than ignored.**  New `scan-image` step: grype v0.112.0 against
  the image `build-image` just built, failing on any Medium-or-above
  finding not acknowledged in `.grype.yaml`.  @xram asked for a way to
  mark the unfixable ones so they drop off the scream count, and the
  design question was how to do that without building a mute button.

  The answer is that **every ack pins CVE + package + exact installed
  version**, with a `reason`.  Grype suppresses only when every field in
  the rule matches, so the moment the package changes the ack stops
  matching and the finding comes back to be looked at again.  An ack
  cannot outlive the thing it was about.  The common alternative, a
  bare `- vulnerability: CVE-...` line, suppresses that ID in every
  package, through every fix, forever, which is how an allowlist
  quietly turns into a blindfold.  Both behaviours were verified
  against the pinned grype before shipping: a rule with the wrong
  version does not suppress, and `reason` comes back in the JSON
  output, so the justification travels with every scan result.

  Five acks to start, all Medium: busybox's `wget` request-line
  injection (three packages; Fauxbus never runs `wget`), and two CPython
  CVEs in `poplib` and `tempfile`, neither of which Fauxbus imports.
  The CPython two are worth a note because v0.2.19's board post got
  them wrong.  It said they would clear on the next 3.13 patch.  They
  will not: grype marks them "fixed", but the fixes landed only on the
  3.15 pre-release line.  "Fixed" in a scanner means fixed *somewhere*,
  which is not the same as fixable from here.

- **v0.2.19** (2026-10-10) — **The container's final stage moves to
  Alpine**, after @xram asked about CVEs.  A fresh `--pull` of the old
  `python:3.13-slim` image scanned (grype) at 161 findings: 0 Critical,
  55 High, and every High marked `wont-fix` or `not-fixed` by Debian —
  util-linux, perl, ncurses, glibc, the gcc runtime.  No rebuild would
  ever clear them, and Fauxbus calls none of them.  `python:3.13-alpine`
  plus `apk upgrade` scans at **5 Medium and nothing above**, at half
  the size.  For a pure-stdlib app the base image *is* the security
  decision; musl versus glibc does not matter to code that links
  against neither.  uid stays 9800, and gains a matching gid 9800
  instead of busybox's shared `nogroup`.

  Worth recording what the scan *also* showed, because it was the
  bigger number.  A consumer-built image four weeks old carried **14
  Critical**, every one already fixed upstream (openssl, glibc, perl,
  Python 3.13.15).  That is not a Containerfile problem — it is a
  stale base layer, the same failure the `--pull` fix in CI exists
  for.  Fauxbus publishes no image; consumers build it, so the advice
  ships in the README: build with `--pull`, and rebuild on a schedule
  rather than when a scanner complains.

- **v0.2.18** (2026-09-28) — **Multi-resource-server token responses.**
  Scopes spanning two services now get what the real service sends:
  one token per service, the primary at the top of the document and the
  rest in `other_tokens`, each carrying only its own service's scopes.
  It was a 501 through slice A and A.2, and SPEC called it the largest
  remaining fidelity gap in Auth.

  Chosen next for a reason that only became visible on a second look:
  **it is slice B's prerequisite.**  The WordPress broker that slice B
  exists for wants to know who someone is *and* which groups they are
  in, which means `openid` plus a Groups scope in one authorization
  request — `auth.globus.org` and `groups.api.globus.org`.  Slice B
  built on a token endpoint that refuses two services would have hit
  this wall on its first real request.

  **Less recorded than SPEC implied, and said so.**  The roadmap called
  this well grounded.  It is half grounded.  globus-sdk 4.8.1 records
  four token documents and every one has `other_tokens: []` — there is
  no fixture anywhere showing a populated list.  What is recorded is
  the *reader*: `OAuthTokenResponse._init_rs_dict` runs every entry
  through the same `_convert_token_info_dict` as the top level, which
  pins the entry shape from the consuming side.  Which token the real
  service puts on top is not pinned by anything; Fauxbus uses
  first-named.  Both are new entries on the recording list (8 and 9),
  and the order question is softer than it sounds — the SDK folds both
  into `by_resource_server`, and a consumer that looks tokens up there
  by service name, which is what it is for, never sees the order.  (A
  first draft of this entry said *no* SDK consumer could see it, on the
  theory that a dict has no first.  A Python dict keeps insertion
  order, so `next(iter(...))` sees it fine.  Caught before commit.)

  All-or-nothing minting: every scope parses before any token is
  minted, so a 501 on the last scope cannot leave orphans in
  `/_fauxbus/state` or shift the numbering of every token after them.

  161 tests, 20 through the real globus-sdk — the new one requests
  Transfer and Groups together and then spends the Groups token on a
  real `create_group`.

  **PROVISIONAL inventory: 23 markers**, up two, **two obligations** —
  one marker each this time, the primary rule and the entry shape.
  Counted with `grep -rn PROVISIONAL src/ | wc -l`.

- **v0.2.17** (2026-09-15) — **Auth slice A.2: introspection and
  revocation**, plus two bugs found by reading slice A adversarially
  rather than by a failing test.

  The bugs first, because they are the same species and the species is
  the lesson: **a value that was deterministic on one side of the code
  met a value that was deterministic on the other, and nobody checked
  whether they were the same value.**

  *The mint overwrote seeded tokens, silently, every run.*  `dump()`
  advertises that a harness may seed an already-issued token "without
  performing the grant first."  Take it up on that with the name the
  docs name — `fauxbus-at-0` — and the first grant hands out that string
  and writes over the record in place.  A token seeded as expired came
  back alive; a token seeded as one identity came back as another.  Not
  a race: determinism made it *certain*.  The existing test dodged it by
  naming its seeded token `"handmade"`, which is why 129 tests never saw
  it.  Refused at the seed door now, where every other bad-document
  check lives, with the line drawn at `counters.access_token` so a state
  dump stays reloadable.

  *`offline_access` was filed as if it named a service.*  It sat in
  `OIDC_SCOPES` beside `openid`/`profile`/`email`, all of which really
  do map to `auth.globus.org`.  It names no service at all — it is a
  modifier meaning "and also give me a refresh token."  So
  `offline_access <groups scope>`, ordinary broker client code, looked
  like a two-resource-server request and earned a 501 describing a gap
  it had nothing to do with, pointing the reader at the wrong issue to
  file.  Asked alone it was worse: **200**, an `auth.globus.org` token,
  no refresh token, no hint that the thing the caller asked for had
  quietly not happened — principle 2's silent wrong answer, live on the
  endpoint.  Now it gets `openid`'s 501, for `openid`'s reason: both
  scopes are promises about the response *document*.  `access_type=
  offline` is refused alongside it, because that is the spelling
  globus-sdk actually sends.

  The general lesson, and why both got this much comment: **a scope
  grammar has more than one kind of word in it, and a parser that knows
  only one kind will answer confidently about the others.**

  Then the slice.  `POST /v2/oauth2/token/introspect` (RFC 7662) and
  `POST /v2/oauth2/token/revoke` (RFC 7009), chosen next because of
  everything left unbuilt in Auth they are **the shapes the SDK grounds
  best** — a complete recorded introspection document, key for key,
  against a slice B whose authorize leg the SDK cannot ground at all.
  Building the recorded thing first is what principle 1 means when there
  is a choice.  Their own section above has the design; the three
  decisions worth carrying are that introspection is deliberately *not*
  scoped to the issuing client (resource servers are its only audience,
  and they never issued anything), that revocation flags rather than
  deletes (a deleted token would rise again as a hash-derived stranger),
  and that `{"active": false}` says nothing else at all, with every
  reason available out-of-band in `/_fauxbus/state` instead.

  It is also the first endpoint where the logical clock reaches the wire
  as an *instant* rather than a duration, which needed an answer rather
  than a shrug.  The answer: `exp`/`iat`/`nbf` ride the logical clock, a
  fresh world therefore introspects as 1970, and the fix for a consumer
  comparing against `time.time()` is to seed `"clock": 1767225600` —
  a knob that already existed and only needed saying aloud.  Fauxbus
  will not pick a plausible epoch on its own: no fixed epoch satisfies
  `exp > now` and `iat < now` at once, and one that reads the real clock
  to find one is a wall clock wearing a disguise.

  155 tests, 19 of them through the real globus-sdk — including
  `oauth2_revoke_token` followed by `oauth2_token_introspect`, which is
  the confirmation loop the SDK's own docstring tells consumers to use.

  **PROVISIONAL inventory: 21 markers**, up four from v0.2.16's 17 —
  but **three obligations**, not four.  Introspection's `aud`
  generalization carries two markers, one in the docstring that explains
  it and one on the field itself, because a reader who lands on the
  field should not have to go looking.  The other two are the
  present-and-null `email`/`name` for a client identity, and what
  revocation tells a stranger.  All three are listed under "Recorded,
  documented, provisional" above, and the gap between 4 and 3 is
  recorded here because this project has shipped a wrong marker count
  before and the count is exactly the kind of number nobody re-derives.

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
