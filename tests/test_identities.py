"""GET /v2/api/identities on the wire — login shim step 5.

The SDK-driven half (``get_identities`` and ``IdentityMap``, unmodified)
lives in test_sdk_conformance.py.  These pin the decisions the SDK
cannot see: which identities Fauxbus answers for, which it refuses
loudly, and which it leaves out.
"""

from __future__ import annotations

from urllib.parse import quote

from conftest import (
    ALICE,
    ALICE_GLOBUSID,
    ALICE_UNIVERSITY,
    BOB_GLOBUSID,
    CLIENT_ID,
    CLIENT_SECRET,
    GLOBUSID_IDP,
    GROUPS_SCOPE,
    basic_header,
    oidc_seed,
)

PATH = "/v2/api/identities"
# Any bearer string will do in the default posture, as it does for
# Groups — the token is not what these tests are about.
ANYONE = "t-anyone"
VIEW_IDENTITIES = "urn:globus:auth:scope:auth.globus.org:view_identities"
UNKNOWN = "00000000-0000-4000-8000-00000000dead"

# RECORDED: the keys of an identity record in get_identities.py
# (globus-sdk 4.8.1), less ``identity_type``, which only one of the
# fixture's three records carries.
RECORD_KEYS = {"id", "username", "identity_provider", "name", "email", "organization", "status"}


def lookup(fx, token: str | None = ANYONE, **params: str):
    query = "&".join(f"{k}={quote(v, safe=',@')}" for k, v in params.items())
    return fx.get(f"{PATH}?{query}", token=token)


def found(fx, **params: str) -> list[dict]:
    status, doc, _ = lookup(fx, **params)
    assert status == 200, doc
    return doc["identities"]


def seed(fx, **extra):
    status, doc, _ = fx.post("/_fauxbus/seed", oidc_seed(fx.base_url, **extra))
    assert status == 200, doc


# -------------------------------------------------------- the answered case


def test_a_seeded_identity_comes_back_as_the_recorded_record(oidc):
    (alice,) = found(oidc, ids=ALICE_GLOBUSID)
    assert set(alice) == RECORD_KEYS
    assert alice == {
        "id": ALICE_GLOBUSID,
        "username": "alice@globusid.org",
        "identity_provider": GLOBUSID_IDP,
        "name": "Alice Example",
        "email": "alice@example.org",
        "organization": "Independent",
        "status": "used",
    }


def test_by_username_is_the_same_record(oidc):
    assert found(oidc, usernames="alice@globusid.org") == found(oidc, ids=ALICE_GLOBUSID)


def test_unset_fields_are_null_not_missing(oidc):
    """Bob was seeded with no organization; the fixture's own records carry nulls."""
    (bob,) = found(oidc, ids=BOB_GLOBUSID)
    assert set(bob) == RECORD_KEYS
    assert bob["organization"] is None


def test_a_linked_identity_is_its_own_record(oidc):
    """Lookup is per identity, not per account: alice's university login
    answers with its own username and provider, not her primary's."""
    (uni,) = found(oidc, ids=ALICE_UNIVERSITY)
    assert uni["username"] == "ae123@example.edu"
    assert uni["identity_provider"] != GLOBUSID_IDP


def test_answers_come_in_the_order_asked_each_once(oidc):
    ids = f"{BOB_GLOBUSID},{ALICE_GLOBUSID},{BOB_GLOBUSID}"
    assert [i["id"] for i in found(oidc, ids=ids)] == [BOB_GLOBUSID, ALICE_GLOBUSID]


def test_the_same_identity_by_two_usernames_is_still_once(oidc):
    """Not possible — one identity has one username — but asking for the
    same username twice must not double the answer either."""
    names = "bob@globusid.org,bob@globusid.org"
    assert len(found(oidc, usernames=names)) == 1


# ------------------------------------------------------- the omitted case


def test_an_unknown_identity_is_left_out(oidc):
    ids = f"{UNKNOWN},{ALICE_GLOBUSID},not-a-uuid"
    assert [i["id"] for i in found(oidc, ids=ids)] == [ALICE_GLOBUSID]
    assert found(oidc, usernames="nobody@example.org") == []


def test_asking_for_nothing_is_an_empty_answer(oidc):
    """The SDK's commajoin sends an empty list as an empty string."""
    assert found(oidc, ids="") == []


def test_usernames_match_exactly(oidc):
    """PROVISIONAL: no case folding, because none is recorded."""
    assert found(oidc, usernames="Alice@GlobusID.org") == []


# --------------------------------------- the named-but-unrecorded case: 501


def test_a_client_identity_is_a_loud_gap_not_an_absence(oidc):
    """A client is an identity in Globus Auth, so the real service would
    answer — and Fauxbus has no provider or name to answer with.  Leaving
    it out would tell a test "no such identity", which is false."""
    status, doc, _ = lookup(oidc, ids=CLIENT_ID)
    assert (status, doc["code"]) == (501, "NOT_IMPLEMENTED")
    assert "registered client" in doc["detail"]
    status, _, _ = lookup(oidc, usernames=f"{CLIENT_ID}@clients.auth.globus.org")
    assert status == 501


def test_a_pinned_identity_is_a_loud_gap(oidc):
    status, doc, _ = lookup(oidc, ids=ALICE)
    assert status == 501
    assert "pinned" in doc["detail"]


def test_a_bare_uuid_group_member_is_a_loud_gap(fx):
    seed(
        fx,
        groups={
            "00000000-0000-4000-8000-00000000960a": {
                "name": "lab",
                "memberships": {UNKNOWN: {"role": "member"}},
            }
        },
    )
    status, doc, _ = lookup(fx, ids=UNKNOWN)
    assert status == 501
    assert "member of group" in doc["detail"]


# ------------------------------------------------------ provision and both


def test_provision_for_a_username_nobody_holds_is_a_501(oidc):
    status, doc, _ = lookup(oidc, usernames="new@example.org", provision="true")
    assert status == 501
    assert "provision" in doc["detail"]


def test_provision_for_a_known_username_just_answers(oidc):
    (bob,) = found(oidc, usernames="bob@globusid.org", provision="true")
    assert bob["id"] == BOB_GLOBUSID


def test_ids_and_usernames_together_are_refused_in_auths_own_words(oidc):
    status, doc, _ = lookup(oidc, ids=ALICE_GLOBUSID, usernames="bob@globusid.org")
    assert status == 400
    (error,) = doc["errors"]
    assert (error["status"], error["code"]) == ("400", "BAD_REQUEST")


# ------------------------------------------------------------ who may ask


def test_no_token_is_the_recorded_auth_401(oidc):
    status, doc, _ = lookup(oidc, token=None, ids=ALICE_GLOBUSID)
    assert status == 401
    assert doc["errors"][0]["code"] == "UNAUTHORIZED"
    assert doc["errors"][0]["detail"] == "Call must be authenticated"


def test_a_clients_own_id_and_secret_is_a_501(oidc):
    status, doc, _ = oidc.get(
        f"{PATH}?ids={ALICE_GLOBUSID}",
        headers={"Authorization": basic_header(CLIENT_ID, CLIENT_SECRET)},
    )
    assert (status, doc["code"]) == (501, "NOT_IMPLEMENTED")


def client_token(fx, scope: str) -> str:
    status, doc, _ = fx.form_post(
        "/v2/oauth2/token",
        {"grant_type": "client_credentials", "scope": scope},
        basic=(CLIENT_ID, CLIENT_SECRET),
    )
    assert status == 200, doc
    return doc["access_token"]


def test_strict_mode_wants_a_live_token_for_auth(strict):
    status, doc, _ = strict.post("/_fauxbus/seed", oidc_seed(strict.base_url))
    assert status == 200, doc

    status, doc, _ = lookup(strict, token="never-issued", ids=BOB_GLOBUSID)
    assert (status, doc["errors"][0]["code"]) == (401, "UNAUTHORIZED")

    status, doc, _ = lookup(strict, token=client_token(strict, GROUPS_SCOPE), ids=BOB_GLOBUSID)
    assert (status, doc["errors"][0]["code"]) == (403, "FORBIDDEN")

    status, doc, _ = lookup(strict, token=client_token(strict, VIEW_IDENTITIES), ids=BOB_GLOBUSID)
    assert status == 200
    assert doc["identities"][0]["username"] == "bob@globusid.org"


# --------------------------------------------------- Groups agrees with it


def test_a_seeded_account_added_by_uuid_keeps_its_username_in_groups(oidc):
    """The bug this step flushed out.  Adding alice to a group by UUID used
    to file her as "<uuid>@fauxbus.example" — Groups never consulted the
    seeded accounts — so the identities lookup and the membership list
    named the same person two different ways."""
    status, group, _ = oidc.post("/v2/groups", {"name": "lab", "description": ""}, token=ANYONE)
    assert status == 200, group
    status, doc, _ = oidc.post(
        f"/v2/groups/{group['id']}", {"add": [{"identity_id": ALICE_GLOBUSID}]}, token=ANYONE
    )
    assert status == 200, doc
    (added,) = doc["add"]
    (record,) = found(oidc, ids=ALICE_GLOBUSID)
    assert added["username"] == record["username"] == "alice@globusid.org"


def test_injected_failures_reach_the_lookup(oidc):
    status, _, _ = oidc.get(
        f"{PATH}?ids={ALICE_GLOBUSID}", token=ANYONE, headers={"X-Fauxbus-Fail": "503"}
    )
    assert status == 503
