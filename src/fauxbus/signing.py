"""Signed ID tokens, in the standard library, with a key everyone can read.

This file exists because an identity broker will not take Fauxbus's word
for who just signed in.  Keycloak — and globus-sdk's own
``decode_id_token`` — fetch the public key from the JWKS document,
check the ID token's signature against it, and refuse the login if it
does not verify.  So Fauxbus has to *sign*, which looks like it forces a
crypto library into a project whose packaging promise is zero runtime
dependencies.  It does not, and the reason is worth understanding.

**What an RSA signature actually is.**  RSASSA-PKCS1-v1_5 (RFC 8017
§8.2) is three steps, and none of them needs anything Python lacks:

1. Hash the message (``hashlib``).
2. Wrap the hash in a fixed byte prefix that names the hash algorithm
   (the ASN.1 ``DigestInfo``; it is a constant, so it is written below
   as a constant), then pad the front with ``00 01 FF FF ... FF 00`` out
   to the key's length.
3. Treat those bytes as one big integer ``m`` and compute ``m ** d mod
   n``.  Python's built-in ``pow(m, d, n)`` does modular exponentiation
   on arbitrary-size integers, which is the entire "crypto" part.

**Why hand-rolling this is acceptable here and nowhere else.**  Fauxbus
only ever *signs*; it never *verifies*.  Every famous JWT disaster lives
on the verifying side — ``alg: none`` accepted, an HMAC key confused for
an RSA public key, padding checks done with string comparison.  A signer
has none of that surface: it produces bytes and hands them to someone
else's verifier, and if the bytes are wrong the verifier says so.  The
tests run every token Fauxbus mints through PyJWT and ``cryptography``
precisely so that a wrong byte here is a red test, not a mystery.

There is also no side-channel story to tell, because there is no secret:

**The private key below is published on purpose.**  Anyone can read it,
so anyone can forge a Fauxbus ID token — which means nobody can ever be
tempted to trust one.  That turns "never point a production client at
the fake" from a sentence in a README into a property of the system.  If
you find this key configured as a trusted issuer anywhere real, that
configuration is the bug.  (It was generated for Fauxbus on 2026-10-12
and has never protected anything.)

**RS512, not RS256.**  SPEC's 2026-08-24 signing probe used RS256, the
algorithm everyone reaches for first.  The real service does not use it:
``GET https://auth.globus.org/.well-known/openid-configuration``,
captured on 2026-10-12, advertises ``id_token_signing_alg_values_supported:
["RS512"]``, and its ``/jwk.json`` key carries ``"alg": "RS512"``.  That
is a recording, and the recording wins — a broker configured against the
fake should meet the same algorithm it will meet in production.  The
cost of the switch was one constant: the SHA-512 ``DigestInfo`` prefix
instead of the SHA-256 one.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

# The signing algorithm, named once.  RECORDED from the live discovery
# document and JWKS (see the module docstring).
ALGORITHM = "RS512"

# The fixture key: a 2048-bit RSA modulus ``N`` and private exponent
# ``D``, as hex.  ``E`` is the public exponent nearly every RSA key in
# the world uses.  Published deliberately — read the module docstring
# before you read these as a mistake.
E = 65537
N = int(
    "be97bf7951150d5a181305b0d5048f1b390ba203ebc3a2e933174a97ee43197b"
    "222554675c712cbe3a41c4b175552ac1d76c3bce512eeb104730c4af53e8ff5a"
    "82dbe3e3e36a28118c6b98856099ec653ad3fa5f26a2f344fb5c2780747cf4c6"
    "d49d3a73e31cda6085566caefa6e5bcdef7f385607f530431794fc4f3ef2b759"
    "e5e704a2b7e9e3ebb9d06d950eb8ddc4f6ddb916bf28ad91f802a512394a6c72"
    "7174c20ebd32320aae1c1e0c87635145f452905a3fa7f9ddc30f6aaa72493440"
    "751b3f7b70706bf830c4d6a9d59dfbeb1892d23bf68ac7426289ba0f294368c1"
    "4a439d55bae808ca34044718097525ac3b73dc7254d8840192a3749c8569bca5",
    16,
)
D = int(
    "2325bd5dfc3da76170b49b554da74253c91c93d368c842740263be720fb28891"
    "ac4d9987d92496d57acd539e4d2eb84c987341812df7fac9dcf309a67291327c"
    "08cb4fb6a022dcc245b4b6e30bda3eddb9304bc8fdc94996f44abd8f230c4320"
    "a2a75f16ed704df644489890d9267e6017154d38924d9d499620f7b98e7878a6"
    "b6075497b6f4d726cc53d4f4dec03dd4ea6ed39a61b4dbbaf1b1600ecc06b1c1"
    "fc50db6f33563e08670febc3c528068731641cbf6268b6b18e56a69060cb26f1"
    "aa16b04a4da065e5e2c86c26caa974c06123bb06bfeba38f484f969e8cba9fcd"
    "70300e18900478dde3d9b783d7e64c82583508f719055b91acbba0869930c0e1",
    16,
)

# The key's length in bytes.  Every signature is exactly this long, and
# the padding in step 2 fills the message out to exactly this length.
_KEY_BYTES = (N.bit_length() + 7) // 8

# ASN.1 DER encoding of "this is a SHA-512 digest, and here it comes":
# SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.3, NULL }, OCTET STRING
# (64 bytes) }.  RFC 8017 §9.2 note 1 lists these prefixes verbatim; the
# verifier rebuilds the same bytes and compares, so this constant has to
# be right to the bit — which is why a test checks it against
# ``cryptography`` rather than trusting the transcription.
_SHA512_DIGEST_INFO = bytes.fromhex("3051300d060960864801650304020305000440")


def b64url(data: bytes) -> str:
    """Base64url without padding — the only base64 a JWT speaks (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_b64url(value: int) -> str:
    # JWK encodes RSA integers as big-endian bytes, minimal length, then
    # base64url (RFC 7518 §6.3.1).
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _public_jwk_members() -> dict[str, str]:
    return {"e": _int_b64url(E), "kty": "RSA", "n": _int_b64url(N)}


# The key id.  A JWT header names its key by ``kid`` so a verifier can
# pick the right one out of a JWKS — the real service rotates keys, and
# the ``kid`` is how a broker survives a rotation.  Fauxbus derives it as
# the RFC 7638 thumbprint: SHA-256 over the key's required members in a
# canonical JSON form.  Deterministic, standard, and it changes if and
# only if the key does, which is the one property a kid needs.  (The
# real service's kid is a string of digits; nothing a verifier does
# depends on the shape, only on header and JWKS agreeing.)
KID = b64url(
    hashlib.sha256(
        json.dumps(_public_jwk_members(), separators=(",", ":"), sort_keys=True).encode()
    ).digest()
)


def jwks() -> dict[str, Any]:
    """The public half, as a JWKS document.  Never the private exponent.

    Key-for-key the shape the live ``/jwk.json`` serves (captured
    2026-10-12): ``alg``, ``e``, ``kid``, ``kty``, ``n``, ``use``.  One
    key, because globus-sdk's ``pem_decode_jwk_data`` reads
    ``keys[0]`` and nothing else — a second key would be invisible to
    the SDK and would only matter to a broker, where a kid lookup finds
    it.  One is the honest number while there is nothing to rotate.
    """
    return {"keys": [{**_public_jwk_members(), "alg": ALGORITHM, "kid": KID, "use": "sig"}]}


def _rsassa_pkcs1_v1_5_sign(message: bytes) -> bytes:
    """The three steps from the module docstring, in order."""
    # 1. hash
    digest = hashlib.sha512(message).digest()
    # 2. DigestInfo, then EMSA-PKCS1-v1_5 padding to the key length
    #    (RFC 8017 §9.2): 00 01, at least eight FF bytes, 00, payload.
    payload = _SHA512_DIGEST_INFO + digest
    encoded = b"\x00\x01" + b"\xff" * (_KEY_BYTES - len(payload) - 3) + b"\x00" + payload
    # 3. the RSA private-key operation itself, on Python's bignums.
    signature = pow(int.from_bytes(encoded, "big"), D, N)
    return signature.to_bytes(_KEY_BYTES, "big")


def sign_jwt(claims: dict[str, Any]) -> str:
    """A compact JWS: ``header.payload.signature``, each part base64url.

    The JSON is serialized with sorted keys and no whitespace, so the
    same claims always produce the same token string.  That matters for
    principle 3 even though ID tokens are the one place wall time can
    enter (see SPEC "Clocks"): under the logical clock an ID token is
    byte-identical across runs, and a test may assert on it.
    """
    header = {"alg": ALGORITHM, "kid": KID, "typ": "JWT"}

    def part(obj: dict[str, Any]) -> str:
        return b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())

    signing_input = f"{part(header)}.{part(claims)}"
    return f"{signing_input}.{b64url(_rsassa_pkcs1_v1_5_sign(signing_input.encode('ascii')))}"


def at_hash(access_token: str) -> str:
    """OIDC Core §3.1.3.6: bind the ID token to the access token issued beside it.

    Hash the access token with the hash the signature uses (SHA-512, for
    RS512), keep the left half, base64url it.  A verifier recomputes this
    from the access token it received and refuses a mismatch — which is
    what stops someone pairing a stolen ID token with an access token
    from a different login.
    """
    digest = hashlib.sha512(access_token.encode("ascii")).digest()
    return b64url(digest[: len(digest) // 2])
