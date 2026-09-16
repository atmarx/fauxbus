"""The OAuth2 token endpoint on the wire: POST /v2/oauth2/token.

Auth slice A — ``grant_type=client_credentials``, the grant a service
uses to act as *itself*.  These tests stay at the byte level because
that is where this endpoint is unusual: a form body instead of JSON, an
Authorization header carrying a client secret instead of a bearer token,
and an error dialect (RFC 6749 §5.2) that looks nothing like the rest of
Fauxbus.  Driving it through globus-sdk lives in test_sdk_conformance.

The grading discipline from SPEC applies throughout, and the comments
say which grade each assertion is standing on.
"""

from __future__ import annotations

from conftest import CLIENT_ID, CLIENT_SECRET, GROUPS_SCOPE, TRANSFER_SCOPE

TOKEN = "/v2/oauth2/token"
CREDS = (CLIENT_ID, CLIENT_SECRET)


def fetch(client, scope=GROUPS_SCOPE, **extra):
    fields = {"grant_type": "client_credentials", "scope": scope, **extra}
    return client.form_post(TOKEN, fields, basic=CREDS)


# ------------------------------------------------------------ the happy path


def test_client_credentials_returns_the_recorded_document(registered):
    status, doc, _ = fetch(registered)
    assert status == 200
    # RECORDED, field for field, from
    # globus_sdk/testing/data/auth/oauth2_client_credentials_tokens.py.
    # The equality is on the whole key set on purpose: an *extra* field
    # is as much a conformance break as a missing one, because it teaches
    # a consumer to expect something the real service never sends.
    assert set(doc) == {
        "access_token",
        "scope",
        "expires_in",
        "token_type",
        "resource_server",
        "other_tokens",
    }
    assert doc["token_type"] == "Bearer"
    assert doc["scope"] == GROUPS_SCOPE
    assert doc["resource_server"] == "groups.api.globus.org"
    assert doc["expires_in"] == 172800


def test_other_tokens_is_present_and_empty_not_absent(registered):
    """The field the SDK will crash on if you treat it as optional.

    OAuthTokenResponse._init_rs_dict reads ``self["other_tokens"]`` with
    no ``.get`` and no default, so a response that omits it raises a
    KeyError *inside globus-sdk* — a traceback pointing at the library
    rather than at the fake that lied.  One token issued, still ``[]``.
    """
    _, doc, _ = fetch(registered)
    assert doc["other_tokens"] == []


def test_the_endpoint_is_resource_server_generic(registered):
    """Nothing in the token endpoint knows that Groups exists.

    Slice A was built for two consumers at once — a WordPress provisioner
    that wants a Groups token and a Transfer poller that wants a Transfer
    token — and the only thing that differs between them is the scope
    string they send.  If this test ever needs a Transfer-shaped branch
    in auth_api.py to pass, the design has drifted.
    """
    _, groups, _ = fetch(registered, scope=GROUPS_SCOPE)
    _, transfer, _ = fetch(registered, scope=TRANSFER_SCOPE)
    assert groups["resource_server"] == "groups.api.globus.org"
    assert transfer["resource_server"] == "transfer.api.globus.org"


def test_the_url_scope_form_resolves_too(registered):
    # DOCUMENTED: Globus's newer URL scope form alongside the URN form.
    _, doc, _ = fetch(registered, scope="https://auth.globus.org/scopes/groups.api.globus.org/all")
    assert doc["resource_server"] == "groups.api.globus.org"


def test_two_scopes_for_one_service_ride_on_one_token(registered):
    both = f"{GROUPS_SCOPE} urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships"
    status, doc, _ = fetch(registered, scope=both)
    assert status == 200
    assert doc["scope"] == both
    assert doc["resource_server"] == "groups.api.globus.org"


def test_tokens_are_deterministic_across_a_reset(registered):
    """SPEC principle 3, applied to the newest piece of mutable state.

    The token counter lives in world.counters, so reset returns it to
    zero along with everything else.  A test may hard-code a token string
    for the same reason it may hard-code a group id.
    """
    _, first, _ = fetch(registered)
    assert first["access_token"] == "fauxbus-at-0"
    _, second, _ = fetch(registered)
    assert second["access_token"] == "fauxbus-at-1"

    registered.post("/_fauxbus/seed", {"clients": {CLIENT_ID: {"secret": CLIENT_SECRET}}})
    _, after_reseed, _ = fetch(registered)
    assert after_reseed["access_token"] == "fauxbus-at-0"


def test_the_issued_token_acts_as_the_client_itself(registered):
    """The whole point of the grant, and the reason client_id is a UUID.

    A confidential client in Globus Auth is an identity.  So a service
    that fetches its own token and then calls Groups must show up as
    *itself* — not as a hash of the token string, which is what the
    permissive default would have derived.  This is the assertion that
    proves world.identity_for_token consults issued tokens first.
    """
    _, tokens, _ = fetch(registered)
    access_token = tokens["access_token"]

    created = registered.post(
        "/v2/groups", {"name": "Provisioned", "description": ""}, token=access_token
    )[1]
    (membership,) = created["my_memberships"]
    assert membership["identity_id"] == CLIENT_ID
    assert membership["username"] == f"{CLIENT_ID}@clients.auth.globus.org"
    assert membership["role"] == "admin"


def test_in_body_client_authentication_works(registered):
    """client_secret_post, which is what identity brokers usually send.

    globus-sdk uses Basic, so Basic is what the conformance tether
    exercises — but Slice B's consumer is a broker, and Keycloak defaults
    to putting the credentials in the form body.  RFC 6749 §2.3.1 allows
    both, so Fauxbus accepts both rather than making the broker wrong.
    """
    status, doc, _ = registered.form_post(
        TOKEN,
        {
            "grant_type": "client_credentials",
            "scope": GROUPS_SCOPE,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert status == 200
    assert doc["resource_server"] == "groups.api.globus.org"


# --------------------------------------------------------- the error dialect


def test_errors_speak_rfc_6749_not_the_globus_error_shape(registered):
    """Two error vocabularies in one server, and this endpoint uses the other one.

    Everywhere else Fauxbus answers ``{"code", "detail"}`` because that
    is what GlobusAPIError parses.  Here it must answer ``{"error",
    "error_description"}``, because that is what the SDK's own fixture
    shows Globus sending from this path.  Asserting the absence of
    ``code``/``detail`` matters as much as the presence of ``error``: a
    body carrying both would let a consumer write error handling that
    only works against the fake.
    """
    status, doc, _ = registered.form_post(TOKEN, {"grant_type": "client_credentials"}, basic=CREDS)
    assert status == 400
    assert doc["error"] == "invalid_request"
    assert "error_description" in doc
    assert "code" not in doc and "detail" not in doc


def test_json_body_is_refused_even_though_it_would_have_parsed(registered):
    """The check that exists because the failure would otherwise be silent.

    A JSON body deserializes into a dict shaped exactly like a form dict,
    so every field lookup downstream would have succeeded and a token
    would have been minted for a request the real Globus Auth rejects.
    A fake that is more permissive than the service teaches a habit that
    breaks in production.
    """
    status, doc, _ = registered.post(
        TOKEN, {"grant_type": "client_credentials", "scope": GROUPS_SCOPE}
    )
    assert status == 400
    assert doc["error"] == "invalid_request"
    assert "form" in doc["error_description"]


def test_no_credentials_is_invalid_client(registered):
    status, doc, _ = registered.form_post(
        TOKEN, {"grant_type": "client_credentials", "scope": GROUPS_SCOPE}
    )
    assert status == 401
    assert doc["error"] == "invalid_client"


def test_unknown_client_and_wrong_secret_are_indistinguishable_to_a_program(registered):
    """Same error code both ways; only the human-facing description differs.

    A consumer's error handling has to meet the same wall against the
    fake as against the real service, so the machine-readable half is
    identical.  The description can be helpful precisely because the SDK
    surfaces it nowhere — no test can come to depend on it, and a
    developer curling the endpoint still learns which half they typo'd.
    """
    unknown = registered.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=("00000000-0000-4000-8000-00000000dead", CLIENT_SECRET),
    )
    wrong = registered.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=(CLIENT_ID, "wrong"),
    )
    assert unknown[0] == wrong[0] == 401
    assert unknown[1]["error"] == wrong[1]["error"] == "invalid_client"
    assert unknown[1]["error_description"] != wrong[1]["error_description"]


def test_credentials_in_two_places_at_once_are_refused(registered):
    # RFC 6749 §2.3.1: a client MUST NOT use more than one method.  If the
    # two disagree the server has to pick, and any pick is a security
    # decision made by accident.
    status, doc, _ = registered.form_post(
        TOKEN,
        {
            "grant_type": "client_credentials",
            "scope": GROUPS_SCOPE,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        basic=CREDS,
    )
    assert status == 400
    assert doc["error"] == "invalid_request"


def test_missing_grant_type_is_invalid_request(registered):
    status, doc, _ = registered.form_post(TOKEN, {"scope": GROUPS_SCOPE}, basic=CREDS)
    assert status == 400
    assert doc["error"] == "invalid_request"


def test_missing_scope_is_invalid_request(registered):
    # Globus cannot fall back to a default scope the way RFC 6749 imagines:
    # a token is issued for exactly one resource server, and the scope is
    # the only place the request names it.
    status, doc, _ = registered.form_post(TOKEN, {"grant_type": "client_credentials"}, basic=CREDS)
    assert status == 400
    assert doc["error"] == "invalid_request"


def test_a_grant_globus_has_but_fauxbus_lacks_is_a_loud_501(registered):
    """Principle 2's sharpest edge, and the reason GLOBUS_GRANT_TYPES exists.

    Globus supports authorization_code perfectly well; Fauxbus is the one
    that has not built it. Answering ``unsupported_grant_type`` would be
    the fake telling a lie about the real service on its own behalf. 501
    with a tracker link says whose gap it is.
    """
    status, doc, _ = registered.form_post(
        TOKEN, {"grant_type": "authorization_code", "code": "x"}, basic=CREDS
    )
    assert status == 501
    assert doc["code"] == "NOT_IMPLEMENTED"
    assert "issues" in doc["detail"]


def test_a_grant_globus_does_not_have_is_the_clients_mistake(registered):
    status, doc, _ = registered.form_post(
        TOKEN, {"grant_type": "password", "username": "a", "password": "b"}, basic=CREDS
    )
    assert status == 400
    assert doc["error"] == "unsupported_grant_type"


def test_scopes_spanning_two_services_refuse_rather_than_drop_one(registered):
    """The silent wrong answer this endpoint could most easily have given.

    Issuing for whichever resource server parsed first and quietly
    dropping the rest would hand back a token that looks perfectly valid
    and fails later, somewhere else, against a service it was never good
    for. Multi-resource-server responses are a later slice; until then
    the honest answer is a refusal that names both services.
    """
    status, doc, _ = fetch(registered, scope=f"{GROUPS_SCOPE} {TRANSFER_SCOPE}")
    assert status == 501
    assert "groups.api.globus.org" in doc["detail"]
    assert "transfer.api.globus.org" in doc["detail"]


def test_an_unparseable_scope_refuses_to_guess(registered):
    status, doc, _ = fetch(registered, scope="wat")
    assert status == 501
    assert "'wat'" in doc["detail"]


def test_openid_refuses_rather_than_omit_the_id_token(registered):
    """A missing field would have blamed the consumer for our gap.

    SPEC promises an openid response carries an ``id_token``, and signing
    one waits for slice B. Issuing the token without the field would
    surface as a KeyError in the consumer's own code, pointing nowhere
    near the cause.
    """
    status, doc, _ = fetch(registered, scope="openid")
    assert status == 501
    assert "id_token" in doc["detail"] or "ID token" in doc["detail"]


def test_a_request_for_a_refresh_token_names_the_right_gap(registered):
    """The same lesson as ``openid``, one field over — and it used to lie.

    ``offline_access`` asks for a ``refresh_token`` field. Fauxbus has no
    refresh-token grant, so the honest answer is the 501.

    What makes this a regression test and not just a feature test is what
    it used to do instead. ``offline_access`` was filed with the other
    OIDC scopes, all of which map to auth.globus.org — so asked next to a
    Groups scope it looked like a request spanning two resource servers,
    and the 501 that came back described a multi-token gap that had
    nothing to do with anything. Asked alone it was worse: a 200, for an
    auth.globus.org token, silently missing the field the caller asked
    for. Both are fixed here, and both assertions are load-bearing.
    """
    status, doc, _ = fetch(registered, scope=f"offline_access {GROUPS_SCOPE}")
    assert status == 501
    assert "refresh" in doc["detail"]
    assert "other_tokens" not in doc["detail"]  # the gap it used to name

    status, doc, _ = fetch(registered, scope="offline_access")
    assert status == 501, doc  # was a 200 with no refresh_token in it


def test_the_sdk_spelling_of_offline_access_is_refused_too(registered):
    """globus-sdk does not send the scope — it sends access_type=offline.

    RECORDED: globus_sdk/services/auth/flow_managers/authorization_code.py
    and native_app.py (4.8.1) both build ``"access_type": (self.refresh_
    tokens and "offline") or "online"``. Two spellings of one request,
    and catching only the broker's would mean the SDK — the thing
    principle 1 calls the contract — is the caller Fauxbus fails quietly.
    """
    status, doc, _ = fetch(registered, access_type="offline")
    assert status == 501
    assert "refresh" in doc["detail"]

    # "online" is the same parameter saying the opposite thing, and it
    # must not trip the wire.
    assert fetch(registered, access_type="online")[0] == 200


# ------------------------------------------------- issued-token mode (opt-in)


def test_the_default_still_accepts_any_token_at_all(registered):
    """The promise the flag is defined against.

    Every consumer written against Fauxbus so far assumes a made-up
    bearer token works. Slice A must not have quietly changed that.
    """
    status, _, _ = registered.get("/v2/groups/my_groups", token="a-token-nobody-issued")
    assert status == 200


def test_strict_mode_rejects_a_token_nobody_issued(strict):
    status, doc, _ = strict.get("/v2/groups/my_groups", token="a-token-nobody-issued")
    assert status == 401
    assert doc["code"] == "UNAUTHORIZED"
    assert "--require-issued-tokens" in doc["detail"]


def test_strict_mode_accepts_a_token_it_issued(strict):
    strict.post("/_fauxbus/seed", {"clients": {CLIENT_ID: {"secret": CLIENT_SECRET}}})
    _, tokens, _ = strict.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=CREDS,
    )
    status, _, _ = strict.get("/v2/groups/my_groups", token=tokens["access_token"])
    assert status == 200


def test_strict_mode_expires_a_token_on_the_logical_clock(strict):
    """Expiry you can test in a millisecond instead of two days.

    The token endpoint stamps ``expires_at`` against World.clock, not the
    wall clock, so ``/_fauxbus/tick`` is what ages it. Principle 3 holds
    here with no exception because Fauxbus is the only thing that will
    ever validate this token — signed ID tokens are the one place it
    cannot, and that is slice B's problem.
    """
    strict.post("/_fauxbus/seed", {"clients": {CLIENT_ID: {"secret": CLIENT_SECRET}}})
    _, tokens, _ = strict.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=CREDS,
    )
    access_token = tokens["access_token"]
    assert strict.get("/v2/groups/my_groups", token=access_token)[0] == 200

    strict.post("/_fauxbus/tick", {"seconds": tokens["expires_in"]})
    status, doc, _ = strict.get("/v2/groups/my_groups", token=access_token)
    assert status == 401
    assert "expired" in doc["detail"]


def test_strict_mode_rejects_a_token_meant_for_another_service(strict):
    """A Transfer token is not a Groups token, and the fake should say so.

    PROVISIONAL: 403 rather than 401. The token is genuine and
    introspects fine, it simply is not good here — "authenticated, not
    authorized". No recording against the real service exists yet.
    """
    strict.post("/_fauxbus/seed", {"clients": {CLIENT_ID: {"secret": CLIENT_SECRET}}})
    _, tokens, _ = strict.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": TRANSFER_SCOPE},
        basic=CREDS,
    )
    status, doc, _ = strict.get("/v2/groups/my_groups", token=tokens["access_token"])
    assert status == 403
    assert "transfer.api.globus.org" in doc["detail"]
    assert "groups.api.globus.org" in doc["detail"]


def test_the_token_endpoint_itself_stays_reachable_in_strict_mode(strict):
    """Otherwise the flag would lock the door and keep the only key inside.

    The token endpoint is where tokens come *from*, so it cannot be made
    to require one. It is registered auth=False for exactly this reason.
    """
    strict.post("/_fauxbus/seed", {"clients": {CLIENT_ID: {"secret": CLIENT_SECRET}}})
    status, _, _ = strict.form_post(
        TOKEN,
        {"grant_type": "client_credentials", "scope": GROUPS_SCOPE},
        basic=CREDS,
    )
    assert status == 200


# ----------------------------------------------------------- state round-trip


def test_clients_and_tokens_round_trip_as_a_seed(registered):
    """SPEC's round-trip invariant, extended to the new state.

    A dump has to be a valid seed. That is what lets a test capture a
    world mid-story and replay it — including, now, an already-issued
    token, so a harness can seed an expired one without performing the
    grant and ticking the clock first.
    """
    fetch(registered)
    _, state, _ = registered.get("/_fauxbus/state")
    assert state["clients"][CLIENT_ID]["secret"] == CLIENT_SECRET
    assert state["tokens"]["fauxbus-at-0"]["resource_server"] == "groups.api.globus.org"

    registered.post("/_fauxbus/reset", {"to": "empty"})
    registered.post("/_fauxbus/seed", state)
    _, replayed, _ = registered.get("/_fauxbus/state")
    assert replayed == state


def test_a_seeded_token_authenticates_without_ever_calling_the_grant(strict):
    strict.post(
        "/_fauxbus/seed",
        {
            "clients": {CLIENT_ID: {"secret": CLIENT_SECRET}},
            "tokens": {
                "handmade": {
                    "client_id": CLIENT_ID,
                    "resource_server": "groups.api.globus.org",
                    "scopes": [GROUPS_SCOPE],
                    "expires_at": 100,
                }
            },
        },
    )
    assert strict.get("/v2/groups/my_groups", token="handmade")[0] == 200
    strict.post("/_fauxbus/tick", {"seconds": 100})
    assert strict.get("/v2/groups/my_groups", token="handmade")[0] == 401


def test_a_seeded_token_may_not_wear_a_name_the_mint_has_not_reached(strict):
    """The collision that used to happen silently, on every run.

    A harness reads the docs, learns that the first token of a world is
    ``fauxbus-at-0``, and seeds that name with an already-expired record
    to test its refresh path. Then something performs a grant. The mint
    hands out ``fauxbus-at-0`` — the same string — and writes straight
    over the seeded record: the expired token comes back alive, and a
    token seeded as one identity comes back as another.

    Determinism is what made this certain rather than rare. Two things
    were guessable by design, so they guessed each other.

    The seed door is where it gets caught, which is the same rule every
    other check in ``World.load`` follows: a bad document fails the seed
    call, not three tests later as an inexplicable 200.
    """
    status, doc, _ = strict.post(
        "/_fauxbus/seed",
        {
            "clients": {CLIENT_ID: {"secret": CLIENT_SECRET}},
            "tokens": {
                "fauxbus-at-0": {
                    "client_id": CLIENT_ID,
                    "resource_server": "groups.api.globus.org",
                    "expires_at": 0,
                }
            },
        },
    )
    assert status == 422
    assert doc["code"] == "VALIDATION_ERROR"
    # The message has to carry the way out, not just the complaint.
    assert "counters.access_token" in doc["detail"]


def test_the_counter_is_the_line_not_the_name_shape(strict):
    """Which is what keeps a dump reloadable.

    A state dump carries ``fauxbus-at-0`` in ``tokens`` *and*
    ``access_token: 1`` in ``counters`` — the token is behind the mint,
    so there is nothing left to collide with and reloading it is safe.
    Drawing the line at the counter rather than at the ``fauxbus-at-N``
    name shape is the difference between a check and a papercut.
    """
    status, _, _ = strict.post(
        "/_fauxbus/seed",
        {
            "counters": {"access_token": 1},
            "clients": {CLIENT_ID: {"secret": CLIENT_SECRET}},
            "tokens": {
                "fauxbus-at-0": {
                    "client_id": CLIENT_ID,
                    "resource_server": "groups.api.globus.org",
                    "expires_at": 100,
                }
            },
        },
    )
    assert status == 200
    assert strict.get("/v2/groups/my_groups", token="fauxbus-at-0")[0] == 200
    # And the next grant really does start past it, rather than trusting
    # the seed's word for it.
    _, doc, _ = fetch(strict)
    assert doc["access_token"] == "fauxbus-at-1"


def test_a_name_the_mint_can_never_produce_is_the_harness_to_use(strict):
    # ``access_token`` emits no leading zeros, so ``fauxbus-at-007`` is
    # not a name it will ever reach — and a harness may have it.
    status, _, _ = strict.post(
        "/_fauxbus/seed",
        {
            "clients": {CLIENT_ID: {"secret": CLIENT_SECRET}},
            "tokens": {
                "fauxbus-at-007": {
                    "client_id": CLIENT_ID,
                    "resource_server": "groups.api.globus.org",
                    "expires_at": 100,
                }
            },
        },
    )
    assert status == 200


def test_a_client_id_that_is_not_a_uuid_fails_the_seed_loudly(fx):
    # A Globus client is an identity, and identities are UUIDs everywhere
    # else in this world.  Letting "my-client" through here would produce
    # a group membership that fails the same check one call later, which
    # is a confusing place to learn it.
    status, doc, _ = fx.post("/_fauxbus/seed", {"clients": {"my-client": {"secret": "s"}}})
    assert status == 422
    assert doc["code"] == "VALIDATION_ERROR"
