"""A real Keycloak brokers a sign-in through Fauxbus — end to end, no browser.

Auth slice B's acceptance test, and the one the SDK cannot run for us.
It starts two throwaway containers on a private docker network:

- **fauxbus**, from this checkout's ``src/`` (mounted read-only into a
  stock Python image — no build), seeded from ``examples/seed.json``
  with the issuer rewritten for this run;
- **keycloak**, ``quay.io/keycloak/keycloak:26.0`` in ``start-dev``,
  unprivileged, configured entirely through its admin REST API.

Then it plays the browser with nothing but ``urllib`` and a cookie jar:
Keycloak's login page → the "fauxbus" identity-provider button →
Fauxbus's authorize endpoint → the out-of-band account picker → back to
Keycloak with a code → Keycloak's first-broker-login → a Keycloak
authorization code for a test app → a Keycloak token.  Last, it asks
Keycloak's admin API which Fauxbus identity the new user is linked to.

**The two-name problem, which is the point of the wiring.**  The browser
reaches Fauxbus at ``http://localhost:19800``; Keycloak, inside the
docker network, reaches it at ``http://fauxbus-slice-b-fx:9800``.  So
Keycloak's identity provider is given the *browser's* URL for the
authorize endpoint and the *network's* URLs for the back-channel token,
JWKS and userinfo calls — and one issuer string, which Fauxbus stamps
into every ID token regardless of which name it was reached by.

Why this is a script in ``examples/`` rather than a test in the suite:
Keycloak is a ~450 MB image and a second supply chain, and Fauxbus's
pitch is not having one.  SPEC's slice-B note puts the broker-in-a-
container test in the consumer's repo; this script is the proof the
fake ran it once itself, and a template for the consumer's version.

    python examples/keycloak_broker.py          # run, print the evidence, tear down
    python examples/keycloak_broker.py --keep   # leave both containers up to poke at

Needs docker and nothing else.  Every container and the network carry
the ``fauxbus-slice-b-`` prefix and are removed on the way out.
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent

NETWORK = "fauxbus-slice-b-net"
FX_NAME = "fauxbus-slice-b-fx"
KC_NAME = "fauxbus-slice-b-kc"
FX_PORT = 19800  # on 127.0.0.1 only
KC_PORT = 18080  # on 127.0.0.1 only
KC_IMAGE = "quay.io/keycloak/keycloak:26.0"
PY_IMAGE = "python:3.12-alpine"

# The two names for one Fauxbus.
FX_BROWSER = f"http://localhost:{FX_PORT}"  # what the browser (this script) dials
FX_NETWORK = f"http://{FX_NAME}:9800"  # what Keycloak dials
ISSUER = FX_BROWSER  # one issuer string; see the module docstring
KC = f"http://localhost:{KC_PORT}"

REALM = "fauxbus-proof"
IDP_ALIAS = "fauxbus"
APP_CLIENT, APP_SECRET = "proof-app", "proof-app-secret"
APP_REDIRECT = "http://localhost:18999/callback"  # never served; we read the Location

# From examples/seed.json: the login client Keycloak authenticates as,
# and alice, whose account links a university identity to a Globus ID
# primary.  The client requires the university IdP, so alice should
# arrive in Keycloak as her *university* identity.
LOGIN_CLIENT = "00000000-0000-4000-8000-00000000c0de"
LOGIN_SECRET = "web-login-secret-not-a-real-one"
ALICE_ACCOUNT = "00000000-0000-4000-8000-00000000a11c"
ALICE_UNIVERSITY = "00000000-0000-4000-8000-00000000000a"
BROKER_ENDPOINT = f"{KC}/realms/{REALM}/broker/{IDP_ALIAS}/endpoint"

# The identity-provider configuration this script proves.  Printed at the
# end, because it is the thing a consumer copies.
IDP_CONFIG = {
    "issuer": ISSUER,
    "authorizationUrl": f"{FX_BROWSER}/v2/oauth2/authorize",
    "tokenUrl": f"{FX_NETWORK}/v2/oauth2/token",
    "jwksUrl": f"{FX_NETWORK}/jwk.json",
    "userInfoUrl": f"{FX_NETWORK}/v2/oauth2/userinfo",
    "clientId": LOGIN_CLIENT,
    "clientSecret": LOGIN_SECRET,
    # The real service's discovery advertises client_secret_basic only,
    # so that is what a consumer should configure; Fauxbus also accepts
    # client_secret_post, which the real one may not.
    "clientAuthMethod": "client_secret_basic",
    "validateSignature": "true",
    "useJwksUrl": "true",
    "pkceEnabled": "true",
    "pkceMethod": "S256",
    "defaultScope": "openid profile email",
    "syncMode": "FORCE",
    "disableUserInfo": "false",
}


def log(msg: str) -> None:
    print(f"[proof] {msg}", flush=True)


def docker(*args: str, check: bool = True) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout.strip()


def teardown() -> None:
    for name in (KC_NAME, FX_NAME):
        docker("rm", "-f", name, check=False)
    docker("network", "rm", NETWORK, check=False)


# ------------------------------------------------------------- the browser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class _LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    """Send Secure cookies over http://localhost, as real browsers do.

    Keycloak 26 marks its session cookies ``Secure; SameSite=None`` even
    in start-dev over plain http.  Browsers treat localhost as a secure
    context and send them anyway; Python's cookie jar does not, and
    without this the login dies at the first-broker-login step with a
    "cookie not found" page that has nothing to do with Fauxbus.
    """

    def return_ok_secure(self, cookie: Any, request: Any) -> bool:
        return True


class Browser:
    """Just enough browser: a cookie jar and manual redirects, every hop logged."""

    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar(policy=_LocalhostPolicy())
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect
        )

    def go(self, url: str, form: dict[str, str] | None = None) -> tuple[int, str, str]:
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        try:
            with self.opener.open(req, timeout=30) as resp:
                status, headers, body = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as err:
            status, headers, body = err.code, err.headers, err.read()
        location = headers.get("Location", "")
        if location:
            location = urllib.parse.urljoin(url, location)
        log(f"{'POST' if data else 'GET '} {url[:110]} -> {status}" + (f" -> {location[:110]}" if location else ""))
        return status, location, body.decode("utf-8", "replace")

    def follow(self, url: str, form: dict[str, str] | None = None, stop_at: str = "") -> tuple[int, str, str]:
        """Follow redirects until a page (or a URL starting with ``stop_at``)."""
        here = url
        status, location, body = self.go(url, form)
        while status in (301, 302, 303, 307) and location:
            if stop_at and location.startswith(stop_at):
                return status, location, body
            here = location
            status, location, body = self.go(location)
        return status, here, body


def form_on(page: str) -> tuple[str, dict[str, str]]:
    """The first form on a page: its action and its current input values."""
    match = re.search(r'<form[^>]*action="([^"]+)"', page)
    if not match:
        raise RuntimeError(f"no form on page:\n{page[:2000]}")
    fields = {}
    for tag in re.findall(r"<input[^>]*>", page):
        name = re.search(r'name="([^"]+)"', tag)
        if name:
            value = re.search(r'value="([^"]*)"', tag)
            fields[name.group(1)] = unescape(value.group(1)) if value else ""
    return unescape(match.group(1)), fields


# ------------------------------------------------------------ admin calls


def admin_token() -> str:
    body = urllib.parse.urlencode(
        {"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"}
    ).encode()
    with urllib.request.urlopen(f"{KC}/realms/master/protocol/openid-connect/token", body) as r:
        return json.load(r)["access_token"]


def admin(method: str, path: str, token: str, doc: Any = None) -> Any:
    req = urllib.request.Request(
        f"{KC}/admin/realms{path}",
        data=json.dumps(doc).encode() if doc is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def wait_for(url: str, what: str, seconds: int = 120) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                log(f"{what} is up")
                return
        except Exception:  # noqa: BLE001 — anything short of a 200 means "not yet"
            time.sleep(1)
    raise RuntimeError(f"{what} did not come up at {url}")


def jwt_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# ------------------------------------------------------------------ the run


def start(seed_dir: Path) -> None:
    seed = json.loads((REPO / "examples" / "seed.json").read_text())
    # Two edits for this run: the issuer is the browser-facing name, and
    # the login client's registered redirect URI is this realm's broker
    # endpoint — Fauxbus matches it exactly, so it must be exact.
    seed["oidc"] = {"issuer": ISSUER, "signed_token_clock": "wall"}
    seed["clients"][LOGIN_CLIENT]["redirect_uris"] = [BROKER_ENDPOINT]
    (seed_dir / "seed.json").write_text(json.dumps(seed))
    seed_dir.chmod(0o755)
    (seed_dir / "seed.json").chmod(0o644)

    docker("network", "create", NETWORK)
    docker(
        "run", "-d", "--name", FX_NAME, "--network", NETWORK,
        "-p", f"127.0.0.1:{FX_PORT}:9800",
        "-v", f"{REPO / 'src'}:/app/src:ro",
        "-v", f"{seed_dir / 'seed.json'}:/seed.json:ro",
        "-e", "PYTHONPATH=/app/src",
        PY_IMAGE,
        "python", "-m", "fauxbus.cli", "serve", "--host", "0.0.0.0", "--port", "9800",
        "--seed", "/seed.json", "--verbose",
    )
    docker(
        "run", "-d", "--name", KC_NAME, "--network", NETWORK,
        "-p", f"127.0.0.1:{KC_PORT}:8080",
        "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
        "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
        KC_IMAGE, "start-dev",
    )
    wait_for(f"{FX_BROWSER}/_fauxbus/", "fauxbus")
    wait_for(f"{KC}/realms/master", "keycloak", seconds=180)


def configure_keycloak() -> str:
    token = admin_token()
    admin("POST", "", token, {"realm": REALM, "enabled": True})
    admin(
        "POST", f"/{REALM}/clients", token,
        {
            "clientId": APP_CLIENT,
            "secret": APP_SECRET,
            "publicClient": False,
            "standardFlowEnabled": True,
            "redirectUris": [APP_REDIRECT],
        },
    )
    admin(
        "POST", f"/{REALM}/identity-provider/instances", token,
        {"alias": IDP_ALIAS, "providerId": "oidc", "enabled": True, "config": IDP_CONFIG},
    )
    # Keep the Globus identity UUIDs on the Keycloak user, where an
    # entitlement component can read them: the effective identity (sub)
    # as one attribute, and the whole identity_set as another.
    for name, claim, attribute in (
        ("globus-sub", "sub", "globus_sub"),
        ("globus-identity-set", "identity_set", "globus_identity_set"),
    ):
        admin(
            "POST", f"/{REALM}/identity-provider/instances/{IDP_ALIAS}/mappers", token,
            {
                "name": name,
                "identityProviderAlias": IDP_ALIAS,
                "identityProviderMapper": "oidc-user-attribute-idp-mapper",
                "config": {"syncMode": "INHERIT", "claim": claim, "user.attribute": attribute},
            },
        )
    log("realm, app client, identity provider and mappers configured")
    return token


def sign_in() -> dict[str, Any]:
    browser = Browser()
    start_url = f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(
        {
            "client_id": APP_CLIENT,
            "redirect_uri": APP_REDIRECT,
            "response_type": "code",
            "scope": "openid",
            "state": "proof-state",
        }
    )
    # 1. Keycloak's own login page, with a button per identity provider.
    status, _, page = browser.go(start_url)
    assert status == 200, f"expected Keycloak's login page, got {status}"
    match = re.search(rf'href="([^"]*/broker/{IDP_ALIAS}/login[^"]*)"', page)
    assert match, "no 'fauxbus' identity-provider button on Keycloak's login page"
    # 2. Press it: Keycloak redirects the browser to Fauxbus's authorize
    #    endpoint, which (no Fauxbus session yet) sends it to the picker.
    status, picker_url, page = browser.follow(urllib.parse.urljoin(KC, unescape(match.group(1))))
    assert "/_fauxbus/auth/login" in picker_url, picker_url
    assert "alice@globusid.org" in page, "the picker should list the seeded accounts"
    # 3. Pick alice.  Fauxbus redirects back to Keycloak's broker endpoint
    #    with a code; Keycloak exchanges it on the back channel, checks
    #    the ID token, calls userinfo, and starts first-broker-login.
    action, fields = None, None
    for form in re.findall(r"<form.*?</form>", page, re.S):
        if ALICE_ACCOUNT in form:
            action, fields = form_on(form)
    assert action and fields
    status, where, page = browser.follow(urllib.parse.urljoin(picker_url, action), fields, stop_at=APP_REDIRECT)
    # 4. First broker login may ask the user to review their profile —
    #    Keycloak's default user profile wants a first and last name,
    #    and Globus sends a single ``name``.  Fill whatever is empty.
    rounds = 0
    while not where.startswith(APP_REDIRECT):
        rounds += 1
        assert rounds < 5, f"stuck in Keycloak at {where}:\n{page[:3000]}"
        action, fields = form_on(page)
        fields.setdefault("firstName", "")
        fields.setdefault("lastName", "")
        for key, value in {"firstName": "Alice", "lastName": "Example"}.items():
            if not fields.get(key):
                fields[key] = value
        log(f"Keycloak form {action[:90]} fields={sorted(fields)}")
        status, where, page = browser.follow(urllib.parse.urljoin(where, action), fields, stop_at=APP_REDIRECT)
    # 5. Back at the app with Keycloak's code; trade it for Keycloak's tokens.
    callback = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(where).query))
    assert callback.get("state") == "proof-state", callback
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": callback["code"],
            "redirect_uri": APP_REDIRECT,
            "client_id": APP_CLIENT,
            "client_secret": APP_SECRET,
        }
    ).encode()
    with urllib.request.urlopen(f"{KC}/realms/{REALM}/protocol/openid-connect/token", body) as r:
        return json.load(r)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--keep", action="store_true", help="leave the containers running")
    parser.add_argument(
        "--client-auth",
        choices=("client_secret_basic", "client_secret_post"),
        default="client_secret_basic",
        help="how Keycloak authenticates to Fauxbus's token endpoint (default: Basic, "
        "the only method the real service's discovery advertises)",
    )
    args = parser.parse_args()
    IDP_CONFIG["clientAuthMethod"] = args.client_auth
    teardown()  # a previous --keep, or a crashed run
    try:
        with tempfile.TemporaryDirectory(prefix="fauxbus-slice-b-") as tmp:
            start(Path(tmp))
            token = configure_keycloak()
            kc_tokens = sign_in()
            claims = jwt_claims(kc_tokens["access_token"])
            log(f"Keycloak access token: preferred_username={claims.get('preferred_username')!r} "
                f"email={claims.get('email')!r} iss={claims.get('iss')!r}")
            (user,) = admin("GET", f"/{REALM}/users?briefRepresentation=false", token)
            links = admin("GET", f"/{REALM}/users/{user['id']}/federated-identity", token)
            log(f"Keycloak user {user['username']!r} attributes={json.dumps(user.get('attributes', {}))}")
            log(f"federated identities: {json.dumps(links)}")
            (link,) = links
            assert link["identityProvider"] == IDP_ALIAS
            assert link["userId"] == ALICE_UNIVERSITY, (
                f"expected the university identity {ALICE_UNIVERSITY} (required_idp), got {link['userId']}"
            )
            log("PASS: Keycloak brokered alice through Fauxbus as her university identity")
            print(json.dumps({k: v for k, v in IDP_CONFIG.items() if k != "clientSecret"}, indent=2))
            if args.keep:
                log(f"--keep: Keycloak at {KC} (admin/admin), Fauxbus at {FX_BROWSER}")
                return 0
    except Exception:
        for name in (FX_NAME, KC_NAME):
            log(f"--- last log lines of {name} ---")
            print(docker("logs", "--tail", "40", name, check=False), file=sys.stderr)
        raise
    finally:
        if not args.keep:
            teardown()
            log("containers and network removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
