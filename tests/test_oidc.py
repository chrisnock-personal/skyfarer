"""OpenID Connect helpers and the dashboard routes that use them.
No provider or database is contacted: the HTTP calls and settings helpers are
mocked. Run with: python -m unittest discover tests"""
import base64
import contextlib
import hashlib
import json
import os
import sys
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import admin  # noqa: E402
import db  # noqa: E402
import oidc  # noqa: E402
import settings  # noqa: E402


VALUES = {
    "OIDC_ENABLED": "true",
    "OIDC_ISSUER": "https://id.example.test",
    "OIDC_CLIENT_ID": "skyfarer",
    "OIDC_CLIENT_SECRET": "secret",
    "OIDC_SCOPES": "openid email profile groups",
    "OIDC_ADMIN_EMAILS": "boss@example.test",
    "OIDC_VIEWER_GROUPS": "read-only",
}

META = {
    "issuer": "https://id.example.test",
    "authorization_endpoint": "https://id.example.test/authorize",
    "token_endpoint": "https://id.example.test/token",
    "jwks_uri": "https://id.example.test/keys",
    "userinfo_endpoint": "https://id.example.test/userinfo",
    "id_token_signing_alg_values_supports": ["RS256"],
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class FakeResponse:
    def __init__(self, data, status=200):
        self.data = data
        self.status_code = status

    def json(self):
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


def make_jwt(key, claims, *, sign=True):
    header = {"alg": "RS256", "kid": "key-1", "typ": "JWT"}
    parts = [b64(json.dumps(header).encode()), b64(json.dumps(claims).encode())]
    message = ".".join(parts).encode("ascii")
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256()) if sign else b"bad"
    return ".".join(parts + [b64(signature)])


def id_claims(**overrides):
    now = int(time.time())
    claims = {"iss": "https://id.example.test", "aud": "skyfarer",
              "sub": "person-1", "email": "Person@Example.test",
              "email_verified": True, "name": "Person", "nonce": "nonce-1",
              "iat": now, "exp": now + 300}
    claims.update(overrides)
    return claims


class Helpers(unittest.TestCase):
    def test_config_requires_provider_client_and_a_mapping(self):
        self.assertIsNone(oidc.require_config(VALUES))
        for key in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
                    "OIDC_ADMIN_EMAILS"):
            with self.subTest(key=key):
                values = dict(VALUES)
                values.pop(key)
                if key == "OIDC_ADMIN_EMAILS":
                    values["OIDC_VIEWER_GROUPS"] = ""
                with self.assertRaises(oidc.OidcError):
                    oidc.require_config(values)
        values = dict(VALUES, OIDC_ISSUER="http://id.example.test")
        with self.assertRaises(oidc.OidcError):
            oidc.require_config(values)

    def test_authorization_url_uses_state_nonce_and_pkce(self):
        verifier = "verifier-" + "x" * 40
        url = oidc.authorization_url(VALUES, state="state-1", nonce="nonce-1",
                                     verifier=verifier, redirect="https://sf.test/oidc/callback",
                                     meta=META)
        from urllib.parse import parse_qs, urlsplit
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        expected = b64(hashlib.sha256(verifier.encode()).digest())
        self.assertEqual(query["code_challenge"], [expected])
        self.assertEqual(query["state"], ["state-1"])
        self.assertEqual(query["nonce"], ["nonce-1"])
        self.assertEqual(query["redirect_uri"], ["https://sf.test/oidc/callback"])

    def test_role_maps_role_claim_emails_and_groups_with_admin_winning(self):
        self.assertEqual(oidc.role_for({"custom_role": "viewer",
                                        "email": "boss@example.test"},
                                       dict(VALUES, OIDC_ROLE_CLAIM="custom_role")), "viewer")
        self.assertEqual(oidc.role_for({"email": "Person@Example.test"}, VALUES), None)
        self.assertEqual(oidc.role_for({"email": "Person@Example.test"},
                                       dict(VALUES, OIDC_VIEWER_EMAILS="person@example.test")),
                         "viewer")
        self.assertEqual(oidc.role_for({"groups": ["read-only", "other"]}, VALUES), "viewer")
        self.assertEqual(oidc.role_for({"groups": ["read-only"],
                                        "email": "boss@example.test"}, VALUES), "admin")
        self.assertEqual(oidc.role_for({"resource_access": {"app": {"roles": ["admin"]}}},
                                       dict(VALUES, OIDC_GROUP_CLAIM="resource_access.app.roles")),
                         None)  # admin groups aren't configured in VALUES
        self.assertEqual(oidc.role_for({"resource_access": {"app": {"roles": ["read-only"]}}},
                                       dict(VALUES, OIDC_GROUP_CLAIM="resource_access.app.roles")),
                         "viewer")

    def test_discovery_checks_the_issuer_and_algorithm(self):
        with mock.patch.object(oidc.requests, "get",
                               return_value=FakeResponse(dict(META, issuer="https://evil.test"))):
            with self.assertRaises(oidc.OidcError):
                oidc.discovery(VALUES)
        with mock.patch.object(oidc.requests, "get", return_value=FakeResponse(
                dict(META, id_token_signing_alg_values_supports=["HS256"]))):
            with self.assertRaises(oidc.OidcError):
                oidc.discovery(VALUES)
        with mock.patch.object(oidc.requests, "get", return_value=FakeResponse(META)) as get:
            self.assertEqual(oidc.discovery(VALUES)["token_endpoint"], META["token_endpoint"])
        self.assertEqual(get.call_args.args[0],
                         "https://id.example.test/.well-known/openid-configuration")

    def test_exchange_code_sends_pkce_verifier_and_rejects_errors(self):
        with mock.patch.object(oidc.requests, "post", return_value=FakeResponse(
                {"access_token": "a", "id_token": "i"})) as post:
            tokens = oidc.exchange_code(VALUES, "code-1", "verifier-1",
                                        "https://sf.test/oidc/callback", META)
        self.assertEqual(tokens["id_token"], "i")
        self.assertEqual(post.call_args.kwargs["data"]["code_verifier"], "verifier-1")
        self.assertEqual(post.call_args.kwargs["data"]["client_secret"], "secret")
        with mock.patch.object(oidc.requests, "post", return_value=FakeResponse({}, 401)):
            with self.assertRaises(oidc.OidcError):
                oidc.exchange_code(VALUES, "code-1", "v", "https://sf.test/oidc/callback", META)


class Tokens(unittest.TestCase):
    def setUp(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.key.public_key().public_numbers()
        jwks = {"keys": [{"kty": "RSA", "kid": "key-1", "alg": "RS256", "use": "sig",
                          "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                          "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))}]}
        patcher = mock.patch.object(oidc.requests, "get", return_value=FakeResponse(jwks))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_signed_token_with_matching_claims_is_accepted(self):
        token = make_jwt(self.key, id_claims())
        self.assertEqual(oidc.verify_id_token(VALUES, token, "nonce-1", META)["sub"],
                         "person-1")

    def test_wrong_nonce_audience_issuer_expiry_and_signature_are_rejected(self):
        bad = [
            (id_claims(nonce="other"), "nonce-1"),
            (id_claims(aud="other"), "nonce-1"),
            (id_claims(iss="https://evil.test"), "nonce-1"),
            (id_claims(exp=int(time.time()) - 120), "nonce-1"),
        ]
        for claims, nonce in bad:
            with self.subTest(claims=claims):
                with self.assertRaises(oidc.OidcError):
                    oidc.verify_id_token(VALUES, make_jwt(self.key, claims), nonce, META)
        with self.assertRaises(oidc.OidcError):
            oidc.verify_id_token(VALUES, make_jwt(self.key, id_claims(), sign=False),
                                 "nonce-1", META)

    def test_identity_merges_userinfo_but_requires_verified_email(self):
        token = make_jwt(self.key, id_claims())
        tokens = {"access_token": "a", "id_token": token}
        with mock.patch.object(oidc, "userinfo", return_value={
                "sub": "person-1", "groups": ["read-only"], "email": "other@example.test"}):
            claims = oidc.identity(VALUES, tokens, "nonce-1", META)
        self.assertEqual(claims["email"], "Person@Example.test")  # signed token wins
        self.assertEqual(oidc.role_for(claims, VALUES), "viewer")
        with mock.patch.object(oidc, "userinfo", return_value={"sub": "someone-else"}):
            with self.assertRaises(oidc.OidcError):
                oidc.identity(VALUES, tokens, "nonce-1", META)
        unverified = make_jwt(self.key, id_claims(email_verified=False))
        with mock.patch.object(oidc, "userinfo", return_value={}):
            with self.assertRaises(oidc.OidcError):
                oidc.identity(VALUES, {"access_token": "a", "id_token": unverified},
                              "nonce-1", META)


class Web(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__, template_folder=os.path.join(ROOT, "templates"))
        app.config.update(TESTING=True, SECRET_KEY="test-secret")

        @app.get("/history", endpoint="history_page")
        def history_page():
            return "history"

        app.register_blueprint(admin.bp)
        self.conn = object()
        self.values = dict(VALUES)
        patches = [
            mock.patch.object(admin, "_next_poll", return_value="from its next poll"),
            mock.patch.object(db, "get_conn", side_effect=lambda: contextlib.nullcontext(self.conn)),
            mock.patch.object(settings, "bootstrap"),
            mock.patch.object(settings, "apply", return_value=self.values),
            mock.patch.object(settings, "user_count", return_value=1),
            mock.patch.object(settings, "load", return_value=self.values),
            mock.patch.object(settings, "user", return_value={"id": 1, "name": "Admin",
                                                               "role": "admin"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = app.test_client()

    def with_session(self, **values):
        with self.client.session_transaction() as sess:
            sess["csrf"] = "token"
            sess.update(values)

    def test_login_offers_sso_only_when_it_is_configured(self):
        self.assertIn(b"identity provider", self.client.get("/login").data)
        self.values.pop("OIDC_CLIENT_SECRET")
        self.assertNotIn(b"identity provider", self.client.get("/login").data)

    def test_login_redirects_to_the_provider_with_pkce(self):
        with mock.patch.object(oidc, "discovery", return_value=META) as discovery:
            response = self.client.get("/oidc/login?next=%2Fhistory")
        self.assertEqual(response.status_code, 302)
        self.assertIn("code_challenge_method=S256", response.headers["Location"])
        discovery.assert_called_once()
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["oidc_next"], "/history")
            self.assertTrue(sess["oidc_state"])
            self.assertTrue(sess["oidc_nonce"])
            self.assertTrue(sess["oidc_verifier"])

    def test_callback_refuses_a_bad_state_before_any_provider_call(self):
        self.with_session(oidc_state="right", oidc_nonce="n", oidc_verifier="v",
                          oidc_redirect_uri="https://sf.test/oidc/callback")
        with mock.patch.object(oidc, "discovery") as discovery:
            response = self.client.get("/oidc/callback?code=c&state=wrong")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login?next=/")
        discovery.assert_not_called()

    def test_callback_creates_an_sso_user_and_signs_them_in(self):
        self.with_session(oidc_state="right", oidc_nonce="n", oidc_verifier="v",
                          oidc_redirect_uri="https://sf.test/oidc/callback",
                          oidc_next="/history")
        claims = {"email": "Person@Example.test", "name": "Person",
                  "groups": ["read-only"]}
        with mock.patch.object(oidc, "discovery", return_value=META), \
                mock.patch.object(oidc, "exchange_code", return_value={"id_token": "i"}), \
                mock.patch.object(oidc, "identity", return_value=claims), \
                mock.patch.object(settings, "user_by_email", return_value=None), \
                mock.patch.object(settings, "create_user",
                                  return_value=settings.NewLink(42, "")) as create, \
                mock.patch.object(settings, "record_sso_login") as record:
            response = self.client.get("/oidc/callback?code=c&state=right")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/history")
        self.assertEqual(create.call_args.args[3], "viewer")
        self.assertTrue(create.call_args.kwargs["sso"])
        record.assert_called_once_with(self.conn, 42)
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["uid"], 42)
            self.assertNotIn("oidc_state", sess)

    def test_callback_updates_an_existing_users_mapped_role(self):
        self.with_session(oidc_state="right", oidc_nonce="n", oidc_verifier="v",
                          oidc_redirect_uri="https://sf.test/oidc/callback")
        claims = {"email": "boss@example.test", "name": "Boss"}
        with mock.patch.object(oidc, "discovery", return_value=META), \
                mock.patch.object(oidc, "exchange_code", return_value={"id_token": "i"}), \
                mock.patch.object(oidc, "identity", return_value=claims), \
                mock.patch.object(settings, "user_by_email",
                                  return_value={"id": 7, "role": "viewer", "kind": "human"}), \
                mock.patch.object(settings, "set_role", return_value=None) as role, \
                mock.patch.object(settings, "record_sso_login"):
            response = self.client.get("/oidc/callback?code=c&state=right")
        self.assertEqual(response.status_code, 302)
        role.assert_called_once_with(self.conn, 7, "admin", "SSO")

    def test_a_service_account_cannot_sign_in_through_sso(self):
        self.with_session(oidc_state="right", oidc_nonce="n", oidc_verifier="v",
                          oidc_redirect_uri="https://sf.test/oidc/callback")
        with mock.patch.object(oidc, "discovery", return_value=META), \
                mock.patch.object(oidc, "exchange_code", return_value={"id_token": "i"}), \
                mock.patch.object(oidc, "identity",
                                  return_value={"email": "bot@example.test"}), \
                mock.patch.object(settings, "user_by_email",
                                  return_value={"id": 7, "role": "viewer", "kind": "service"}), \
                mock.patch.object(settings, "record_sso_login") as record:
            response = self.client.get("/oidc/callback?code=c&state=right")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].startswith("/login"))
        record.assert_not_called()
        with self.client.session_transaction() as sess:
            self.assertNotIn("uid", sess)

    def test_sso_settings_page_never_shows_the_stored_secret(self):
        self.with_session(uid=1)
        with mock.patch.object(settings, "secret_meta", return_value={
                "OIDC_CLIENT_SECRET": {"updated_at": __import__("datetime").datetime.now()}}):
            response = self.client.get("/settings/sso")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Single sign-on", response.data)
        self.assertNotIn(b">secret<", response.data)
        self.assertIn(b"Stored", response.data)

    def test_sso_page_shows_configuration_errors_even_when_pre_existing(self):
        self.with_session(uid=1)
        with mock.patch.object(settings, "check", return_value=[]), \
                mock.patch.object(settings, "secret_meta", return_value={}), \
                mock.patch.object(settings, "save") as save:
            response = self.client.post("/settings/sso", data={
                "csrf": "token", "OIDC_ENABLED": "true", "OIDC_ISSUER": "https://id.example.test",
                "OIDC_CLIENT_ID": "", "OIDC_SCOPES": "openid email groups"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"client ID isn&#39;t set", response.data)
        save.assert_not_called()

    def test_sso_settings_save_uses_the_shared_validation(self):
        self.with_session(uid=1)
        self.values["OIDC_ENABLED"] = "false"
        with mock.patch.object(settings, "check", return_value=[]) as check, \
                mock.patch.object(settings, "save", return_value=["SSO enabled"]) as save:
            response = self.client.post("/settings/sso", data={
                "csrf": "token", "OIDC_ENABLED": "true", "OIDC_ISSUER": "https://id.example.test",
                "OIDC_CLIENT_ID": "skyfarer", "OIDC_SCOPES": "openid email groups",
                "OIDC_ADMIN_EMAILS": "boss@example.test"})
        self.assertEqual(response.status_code, 302)
        proposed = check.call_args.args[1]
        self.assertEqual(proposed["OIDC_ADMIN_EMAILS"], "boss@example.test")
        self.assertEqual(proposed["OIDC_CREATE_USERS"], "false")
        self.assertEqual(save.call_args.args[1]["OIDC_ENABLED"], "true")


if __name__ == "__main__":
    unittest.main()
