"""Introspection and revocation on the wire.

``POST /v2/oauth2/token/introspect`` and ``POST /v2/oauth2/token/revoke``
— the two endpoints that let something *outside* Fauxbus ask about a
token it is holding.  Slice A built the mint; these are the assay office
and the shredder.

Both are client-authenticated the way the token endpoint is (Basic, or
credentials in the form body), and in both the ``token`` field is the
*subject* of the question, never the credential for asking it.  Getting
those two roles confused is the mistake these endpoints invite, so
several tests below exist only to pin the distinction.
"""

from __future__ import annotations

from conftest import CLIENT_ID, CLIENT_SECRET, GROUPS_SCOPE, TRANSFER_SCOPE

TOKEN = "/v2/oauth2/token"
INTROSPECT = "/v2/oauth2/token/introspect"
REVOKE = "/v2/oauth2/token/revoke"
CREDS = (CLIENT_ID, CLIENT_SECRET)

# A second registered client, for the tests about strangers.
NEIGHBOUR = "00000000-0000-4000-8000-0000000c11e8"
NEIGHBOUR_CREDS = (NEIGHBOUR, CLIENT_SECRET)
TWO_CLIENTS = {
    CLIENT_ID: {"secret": CLIENT_SECRET, "name": "Test dispatcher"},
    NEIGHBOUR: {"secret": CLIENT_SECRET, "name": "Nosy neighbour"},
}


def mint(client, scope=GROUPS_SCOPE, creds=CREDS):
    status, doc, _ = client.form_post(
        TOKEN, {"grant_type": "client_credentials", "scope": scope}, basic=creds
    )
    assert status == 200, doc
    return doc["access_token"]


def ask(client, token, creds=CREDS, **extra):
    return client.form_post(INTROSPECT, {"token": token, **extra}, basic=creds)


# ------------------------------------------------------------ the recorded shape


def test_an_active_token_introspects_to_the_recorded_document(registered):
    """RECORDED, key for key, from
    ``globus_sdk/testing/data/auth/oauth2_token_introspect.py`` (4.8.1).

    The equality is on the whole key set for the same reason the token
    document's is: an extra field teaches a consumer to expect something
    the real service never sends, which is as much a conformance break
    as a missing one.
    """
    status, doc, _ = ask(registered, mint(registered))
    assert status == 200
    assert set(doc) == {
        "active",
        "token_type",
        "scope",
        "client_id",
        "sub",
        "username",
        "name",
        "email",
        "exp",
        "iat",
        "nbf",
        "aud",
        "iss",
    }
    assert doc["active"] is True
    assert doc["token_type"] == "Bearer"
    assert doc["scope"] == GROUPS_SCOPE
    assert doc["client_id"] == CLIENT_ID
    assert doc["iss"] == "https://auth.globus.org"


def test_sub_and_client_id_are_the_same_uuid_and_that_is_faithful(registered):
    """Because a Globus client IS an identity — the hinge of slice A.

    It looks like duplication and it isn't: ``sub`` is who the token acts
    as, ``client_id`` is who asked for it, and under
    ``client_credentials`` those are the same party. They come apart the
    moment slice B lands an authorization-code token, where a person is
    the subject and the client is only the requester. Pinning the
    equality here means that day shows up as a failing test rather than
    as a surprise.
    """
    _, doc, _ = ask(registered, mint(registered))
    assert doc["sub"] == doc["client_id"] == CLIENT_ID
    assert doc["username"] == f"{CLIENT_ID}@clients.auth.globus.org"
    assert doc["name"] == "Test dispatcher"
    # PROVISIONAL: a client identity has no mailbox. Present and null
    # rather than absent, so the key set never moves under a consumer.
    assert doc["email"] is None


def test_timestamps_ride_the_logical_clock(registered):
    """The first place principle 3's clock reaches the wire as an *instant*.

    ``expires_in`` was a duration and read the same against either clock.
    ``exp`` is a point in time and has to pick one, and it picks the
    logical clock — so a fresh world introspects as 1970 and only
    ``/_fauxbus/tick`` moves anything.
    """
    token = mint(registered)
    _, doc, _ = ask(registered, token)
    assert doc["iat"] == 0
    assert doc["nbf"] == doc["iat"]  # Fauxbus has no not-yet-valid tokens
    assert doc["exp"] == 172800  # RECORDED lifetime, counted from zero

    registered.post("/_fauxbus/tick", {"seconds": 100})
    _, doc, _ = ask(registered, token)
    assert doc["iat"] == 0  # minting time doesn't move
    assert doc["exp"] == 172800  # nor does expiry; the *clock* moved


def test_seeding_the_clock_makes_the_timestamps_real_seconds(fx):
    """The knob for consumers that compare ``exp`` against wall time.

    A consumer doing ``if exp < time.time(): refresh()`` calls every
    Fauxbus token expired, because a fresh world starts at zero. The fix
    is not for Fauxbus to invent a plausible epoch — that would be a wall
    clock wearing a disguise. It is to seed the clock with a real second,
    which keeps determinism because the harness chose the number.
    """
    fx.post("/_fauxbus/seed", {"clock": 1767225600, "clients": TWO_CLIENTS})
    _, doc, _ = ask(fx, mint(fx))
    assert doc["iat"] == 1767225600  # 2026-01-01T00:00:00Z
    assert doc["exp"] == 1767225600 + 172800


def test_aud_names_the_resource_server_and_the_client(registered):
    # PROVISIONAL: the fixture shows [resource server, client_id] for a
    # token whose resource server happened to be auth.globus.org, so
    # generalizing to any resource server is an inference.
    _, doc, _ = ask(registered, mint(registered, scope=TRANSFER_SCOPE))
    assert doc["aud"] == ["transfer.api.globus.org", CLIENT_ID]


# ------------------------------------------------------------- the inactive answer


def test_a_token_nobody_issued_is_inactive_and_says_nothing_else(registered):
    """RFC 7662 §2.2: the bare ``{"active": false}``, and no more.

    ``t-alice`` is a perfectly good caller against Groups under the
    permissive default — and introspects as inactive, because
    introspection answers about tokens this *Auth* issued, which is what
    the real service can answer about. The fake is not contradicting
    itself: permissive bearer handling is how Fauxbus decides who is
    calling, not a claim that Globus minted anything.
    """
    assert registered.get("/v2/groups/my_groups", token="t-alice")[0] == 200
    status, doc, _ = ask(registered, "t-alice")
    assert status == 200
    assert doc == {"active": False}


def test_expiry_shows_up_as_inactive_with_no_explanation(registered):
    token = mint(registered)
    assert ask(registered, token)[1]["active"] is True
    registered.post("/_fauxbus/tick", {"seconds": 172800})
    # Still the bare document. Not a reason, not a code, not a hint —
    # a caller is not entitled to learn *why*. The reasons are all in
    # GET /_fauxbus/state, which is out-of-band and under no such duty.
    assert ask(registered, token)[1] == {"active": False}
    assert registered.get("/_fauxbus/state")[1]["tokens"][token]["expires_at"] == 172800


# ----------------------------------------------------------------- who may ask


def test_introspection_is_not_scoped_to_the_issuing_client(fx):
    """Deliberate, and the difference between this endpoint and revoke.

    Introspection exists for *resource servers*, which by definition did
    not issue the token they are holding. Scoping it to the issuing
    client would make it useless to its only real audience.
    """
    fx.post("/_fauxbus/seed", {"clients": TWO_CLIENTS})
    token = mint(fx)
    assert ask(fx, token, creds=NEIGHBOUR_CREDS)[1]["active"] is True


def test_an_unauthenticated_caller_gets_nothing(registered):
    # The token in the body is the subject of the question, never the
    # credential for asking it. RFC 7662 §2.1 wants the caller
    # authenticated, and holding the token is not authentication.
    status, doc, _ = registered.form_post(INTROSPECT, {"token": mint(registered)})
    assert status == 401
    assert doc["error"] == "invalid_client"


def test_a_missing_token_field_is_the_clients_mistake(registered):
    status, doc, _ = registered.form_post(INTROSPECT, {}, basic=CREDS)
    assert status == 400
    assert doc["error"] == "invalid_request"


def test_identity_sets_refuse_rather_than_answer_one(registered):
    """Fauxbus does not model identity linking, so it will not fake it.

    The only answer it could give is a list of one, every time, for
    everybody — exactly the plausible-looking answer to an unanswerable
    question that principle 2 forbids. A consumer testing "this user has
    three linked identities" would get a passing test against a world
    that cannot have them.
    """
    status, doc, _ = ask(registered, mint(registered), include="identity_set")
    assert status == 501
    assert "identity_set" in doc["detail"]


def test_a_token_type_hint_is_ignored_not_rejected(registered):
    # RFC 7662 §2.1 calls it a hint the server MAY use. Refusing one the
    # real service tolerates would be a fake failing a call that works in
    # production — the worse direction to be wrong in.
    token = mint(registered)
    assert ask(registered, token, token_type_hint="access_token")[1]["active"] is True
    assert ask(registered, token, token_type_hint="nonsense")[1]["active"] is True


# ----------------------------------------------------------------- revocation


def test_revoking_a_token_takes_it_out_of_strict_mode(strict):
    strict.post("/_fauxbus/seed", {"clients": TWO_CLIENTS})
    token = mint(strict)
    assert strict.get("/v2/groups/my_groups", token=token)[0] == 200

    status, doc, _ = strict.form_post(REVOKE, {"token": token}, basic=CREDS)
    assert status == 200
    # RECORDED (oauth2_revoke_token.py, 4.8.1).
    assert doc == {"active": False}

    status, refusal, _ = strict.get("/v2/groups/my_groups", token=token)
    assert status == 401
    # The three ways a token can be no good need three different
    # afternoons' worth of advice, so they say different things.
    assert "revoked" in refusal["detail"]
    assert ask(strict, token)[1] == {"active": False}


def test_a_stranger_cannot_revoke_and_cannot_tell(fx):
    """RFC 7009 §2.1 says verify the token was issued to the caller.

    Refusing with an error would be the obvious reading — and would turn
    this endpoint into an oracle, where 200 means "never existed" and an
    error means "exists, belongs to someone else." So a stranger gets the
    same 200 and nothing happens. PROVISIONAL: the real service has not
    been observed here.
    """
    fx.post("/_fauxbus/seed", {"clients": TWO_CLIENTS})
    token = mint(fx)
    stranger = fx.form_post(REVOKE, {"token": token}, basic=NEIGHBOUR_CREDS)
    nonsense = fx.form_post(REVOKE, {"token": "never-existed"}, basic=NEIGHBOUR_CREDS)
    assert stranger[:2] == nonsense[:2] == (200, {"active": False})
    assert ask(fx, token)[1]["active"] is True  # untouched


def test_revocation_is_idempotent(registered):
    token = mint(registered)
    for _ in range(3):
        assert registered.form_post(REVOKE, {"token": token}, basic=CREDS)[1] == {"active": False}


def test_a_revoked_token_still_works_under_the_permissive_default(registered):
    """Which is not a bug, and is worth one test's worth of saying so.

    The permissive surface checks no tokens at all — that is what makes
    it permissive — so it ignores revocation for exactly the same reason
    it ignores expiry. Revocation bites under ``--require-issued-tokens``,
    the mode where "issued here" is a question anyone is asking.
    """
    token = mint(registered)
    registered.form_post(REVOKE, {"token": token}, basic=CREDS)
    assert registered.get("/v2/groups/my_groups", token=token)[0] == 200
    # But the fake does not disagree with itself about who that is: the
    # record survives revocation precisely so the identity stays put.
    assert registered.get("/_fauxbus/state")[1]["tokens"][token]["revoked"] is True


def test_revocation_round_trips_through_the_state_document(registered):
    token = mint(registered)
    registered.form_post(REVOKE, {"token": token}, basic=CREDS)
    _, state, _ = registered.get("/_fauxbus/state")
    registered.post("/_fauxbus/reset", {"to": "empty"})
    registered.post("/_fauxbus/seed", state)
    assert registered.get("/_fauxbus/state")[1] == state


def test_reset_undoes_revocation_along_with_everything_else(strict):
    strict.post("/_fauxbus/seed", {"clients": TWO_CLIENTS})
    strict.form_post(REVOKE, {"token": mint(strict)}, basic=CREDS)
    strict.post("/_fauxbus/reset", {"to": "empty"})
    strict.post("/_fauxbus/seed", {"clients": TWO_CLIENTS})
    # Determinism: the counter reset too, so this is the same string.
    assert mint(strict) == "fauxbus-at-0"
    assert ask(strict, "fauxbus-at-0")[1]["active"] is True
