"""
oidc.py
~~~~~~~
OpenID Connect authorization-code sign-in for the dashboard, using only the
libraries Skyfarer already has (requests and cryptography). Discovery, PKCE,
state/nonce checks and ID-token verification live here; admin.py owns the two
HTTP routes and the session.

The provider is trusted only after the signed ID token has been checked against
its issuer, audience, expiry and the nonce from this browser's session. Group
and role claims come from that token (or the userinfo endpoint over the same
TLS connection), never from the browser.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from urllib.parse import urlencode, urlsplit

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import settings

log = logging.getLogger("skyfarer.dashboard")

ALGORITHM = "RS256"
TIMEOUT = 10          # seconds for each provider call
CLOCK_LEEWAY = 60     # seconds, for slightly skewed provider clocks
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OidcError(Exception):
    """A problem with the provider or the sign-in, safe to show the user."""


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def truthy(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def enabled(values: dict) -> bool:
    return truthy(values.get("OIDC_ENABLED"), False)


def _valid_url(value: str, *, what: str, web_only: bool = True,
               allow_query: bool = False) -> str:
    value = (value or "").strip()
    parts = urlsplit(value)
    # Compare the parsed host, so http://localhost.evil.test isn't "local".
    local = (parts.hostname or "").lower() in LOCAL_HOSTS
    if parts.scheme not in ("https", "http") or not parts.netloc or \
            (parts.query and not allow_query) or parts.fragment or \
            (web_only and parts.scheme == "http" and not local):
        raise OidcError(f"{what} must be an absolute https URL (http is only "
                        "allowed for localhost).")
    return value.rstrip("/") if what == "Issuer URL" else value


def require_config(values: dict) -> None:
    """Check the saved settings before starting a sign-in (never logs secrets)."""
    if not enabled(values):
        raise OidcError("Single sign-on isn't enabled.")
    _valid_url(values.get("OIDC_ISSUER", ""), what="Issuer URL")
    if not values.get("OIDC_CLIENT_ID", "").strip():
        raise OidcError("The OIDC client ID isn't set.")
    if not values.get("OIDC_CLIENT_SECRET", "").strip():
        raise OidcError("The OIDC client secret isn't set or can't be decrypted.")
    scopes = set(values.get("OIDC_SCOPES", "").split())
    if "openid" not in scopes:
        raise OidcError("OIDC scopes must include 'openid'.")
    if values.get("OIDC_REDIRECT_URI", "").strip():
        _valid_url(values["OIDC_REDIRECT_URI"], what="Redirect URI")
    mapping_keys = ("OIDC_ROLE_CLAIM", "OIDC_ADMIN_EMAILS", "OIDC_VIEWER_EMAILS",
                    "OIDC_ADMIN_GROUPS", "OIDC_VIEWER_GROUPS")
    if not any(values.get(k, "").strip() for k in mapping_keys):
        raise OidcError("Set at least one OIDC role, email or group mapping.")


def redirect_uri(values: dict, default: str) -> str:
    return values.get("OIDC_REDIRECT_URI", "").strip() or default


def _get(url: str, what: str, **kwargs) -> dict:
    try:
        response = requests.get(url, timeout=TIMEOUT, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as err:
        raise OidcError(f"Could not read the {what} (HTTP error).") from err
    except ValueError as err:
        raise OidcError(f"The {what} wasn't valid JSON.") from err


def discovery(values: dict) -> dict:
    """Read and sanity-check the provider's discovery document."""
    require_config(values)
    issuer = values["OIDC_ISSUER"].strip().rstrip("/")
    parts = urlsplit(issuer)
    # OIDC Discovery 1.0 appends the well-known path to the whole issuer, path
    # included (https://kc.example/realms/ops/.well-known/...). Putting it
    # before the path is RFC 8414's rule for OAuth servers, not OIDC.
    discovery_url = f"{issuer}/.well-known/openid-configuration"
    meta = _get(discovery_url, "discovery document")
    if str(meta.get("issuer", "")).rstrip("/") != issuer:
        raise OidcError("The provider's issuer URL doesn't match the saved one.")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        try:
            _valid_url(str(meta.get(key, "")), what=key, allow_query=True)
        except OidcError:
            raise OidcError(f"The discovery document has no usable {key}.") from None
    algs = meta.get("id_token_signing_alg_values_supported") or [ALGORITHM]
    if ALGORITHM not in algs:
        raise OidcError("The provider doesn't sign ID tokens with RS256, which "
                        "Skyfarer requires.")
    return meta


def new_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def authorization_url(values: dict, *, state: str, nonce: str, verifier: str,
                      redirect: str, meta: dict) -> str:
    params = {
        "response_type": "code",
        "client_id": values["OIDC_CLIENT_ID"].strip(),
        "redirect_uri": redirect,
        "scope": " ".join(values.get("OIDC_SCOPES", "openid email profile").split()),
        "state": state,
        "nonce": nonce,
        "code_challenge": new_challenge(verifier),
        "code_challenge_method": "S256",
    }
    endpoint = meta["authorization_endpoint"]
    return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)


def exchange_code(values: dict, code: str, verifier: str, redirect: str,
                  meta: dict) -> dict:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect,
        "client_id": values["OIDC_CLIENT_ID"].strip(),
        "client_secret": values["OIDC_CLIENT_SECRET"].strip(),
        "code_verifier": verifier,
    }
    try:
        response = requests.post(meta["token_endpoint"], data=data,
                                 headers={"Accept": "application/json"}, timeout=TIMEOUT)
    except requests.RequestException as err:
        raise OidcError("Could not contact the identity provider's token endpoint.") from err
    if response.status_code >= 400:
        raise OidcError(f"The identity provider refused the sign-in "
                        f"(HTTP {response.status_code}).")
    try:
        tokens = response.json()
    except ValueError as err:
        raise OidcError("The token endpoint returned invalid JSON.") from err
    if tokens.get("error"):
        raise OidcError(f"The identity provider refused the sign-in: "
                        f"{tokens.get('error')}.")
    if not tokens.get("access_token") or not tokens.get("id_token"):
        raise OidcError("The token response was missing an access or ID token.")
    return tokens


def _public_key(jwks: dict, header: dict):
    kid = header.get("kid")
    keys = [k for k in jwks.get("keys", [])
            if k.get("kty") == "RSA" and k.get("alg", ALGORITHM) == ALGORITHM
            and k.get("use", "sig") == "sig"
            and (not kid or k.get("kid") == kid)]
    if len(keys) != 1:
        raise OidcError("The provider's signing keys didn't identify the ID token's key.")
    try:
        numbers = rsa.RSAPublicNumbers(
            int.from_bytes(_unb64url(keys[0]["e"]), "big"),
            int.from_bytes(_unb64url(keys[0]["n"]), "big"))
        return numbers.public_key()
    except (KeyError, ValueError, TypeError) as err:
        raise OidcError("The provider's signing key is malformed.") from err


def verify_id_token(values: dict, token: str, nonce: str, meta: dict) -> dict:
    """Verify the JWT signature and the claims that bind it to this login."""
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("The identity provider returned a malformed ID token.")
    try:
        header = json.loads(_unb64url(parts[0]))
        claims = json.loads(_unb64url(parts[1]))
    except (ValueError, UnicodeDecodeError) as err:
        raise OidcError("The ID token isn't readable.") from err
    if header.get("alg") != ALGORITHM:
        raise OidcError(f"The ID token uses {header.get('alg')}, not {ALGORITHM}.")
    jwks = _get(meta["jwks_uri"], "signing keys")
    key = _public_key(jwks, header)
    try:
        key.verify(_unb64url(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"),
                   padding.PKCS1v15(), hashes.SHA256())
    except Exception as err:  # InvalidSignature and malformed signatures
        raise OidcError("The ID token's signature isn't valid.") from err

    issuer = values["OIDC_ISSUER"].strip().rstrip("/")
    audience = claims.get("aud")
    audience = [audience] if isinstance(audience, str) else (audience or [])
    client_id = values["OIDC_CLIENT_ID"].strip()
    now = int(time.time())
    try:
        expired = int(claims.get("exp", 0)) + CLOCK_LEEWAY <= now
        issued_later = int(claims.get("iat", 0)) - CLOCK_LEEWAY > now
    except (TypeError, ValueError):
        expired = issued_later = True
    if str(claims.get("iss", "")).rstrip("/") != issuer or client_id not in audience \
            or (claims.get("azp") and claims["azp"] != client_id) \
            or expired or issued_later or claims.get("nonce") != nonce:
        raise OidcError("The ID token doesn't match this sign-in. Try again.")
    return claims


def userinfo(values: dict, access_token: str, meta: dict) -> dict:
    endpoint = meta.get("userinfo_endpoint")
    if not endpoint:
        return {}
    try:
        response = requests.get(endpoint, timeout=TIMEOUT,
                                headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as err:
        raise OidcError("Could not read the identity provider's userinfo endpoint.") from err
    except ValueError as err:
        raise OidcError("The userinfo response wasn't valid JSON.") from err
    return data if isinstance(data, dict) else {}


def identity(values: dict, tokens: dict, nonce: str, meta: dict) -> dict:
    """Return the combined, verified claims used for role mapping."""
    claims = verify_id_token(values, tokens["id_token"], nonce, meta)
    if not str(claims.get("sub") or "").strip():
        raise OidcError("The ID token has no subject.")
    extra = userinfo(values, tokens["access_token"], meta)
    if extra:
        # sub is required in both; a userinfo answer without it can't be
        # shown to belong to this person, so it isn't used.
        if extra.get("sub") != claims["sub"]:
            raise OidcError("The userinfo response belongs to another identity.")
        merged = dict(extra)
        merged.update(claims)   # the signed ID token wins on overlapping claims
        claims = merged
    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise OidcError("The identity provider didn't give a usable email address.")
    if truthy(values.get("OIDC_REQUIRE_VERIFIED_EMAIL"), True) and \
            not truthy(claims.get("email_verified")):
        raise OidcError("The identity provider hasn't verified this email address.")
    return claims


def _claim_values(claims: dict, path: str) -> list[str]:
    current = claims
    for part in path.split("."):
        if not isinstance(current, dict):
            return []
        current = current.get(part)
    if current is None:
        return []
    items = current if isinstance(current, list) else [current]
    found = []
    for item in items:
        if isinstance(item, dict):
            item = next((item[k] for k in ("name", "display", "value") if k in item), None)
        if item is not None and not isinstance(item, (dict, list)):
            found.append(str(item).strip())
    return found


def _mapped(values: dict, key: str) -> set[str]:
    return {v.casefold() for v in settings.split_list(values.get(key, ""))}


def role_for(claims: dict, values: dict) -> str | None:
    """Map the verified claims to a Skyfarer role. Every source counts (role
    claim, email lists, group lists), and admin from any of them wins."""
    role_path = values.get("OIDC_ROLE_CLAIM", "").strip()
    roles = ({v.casefold() for v in _claim_values(claims, role_path)}
             if role_path else set())
    emails = {str(claims.get("email") or "").strip().casefold()}
    groups = {v.casefold() for v in
              _claim_values(claims, values.get("OIDC_GROUP_CLAIM", "").strip() or "groups")}
    if "admin" in roles or emails & _mapped(values, "OIDC_ADMIN_EMAILS") \
            or groups & _mapped(values, "OIDC_ADMIN_GROUPS"):
        return "admin"
    if "viewer" in roles or emails & _mapped(values, "OIDC_VIEWER_EMAILS") \
            or groups & _mapped(values, "OIDC_VIEWER_GROUPS"):
        return "viewer"
    return None


def subject(claims: dict) -> str:
    """The provider's stable ID for this person: issuer plus subject. Unlike an
    email address, it can't be claimed by someone else at the provider."""
    return f"{str(claims.get('iss') or '').rstrip('/')}|{claims.get('sub') or ''}"


def display_name(claims: dict) -> str:
    return str(claims.get("name") or claims.get("preferred_username") or
               claims.get("email") or "SSO user").strip()[:120]
