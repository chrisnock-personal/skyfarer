# Single sign-on (OIDC)

Skyfarer can let an OpenID Connect provider sign people in, while keeping local
passwords as a fallback. This is optional: the first admin is still created with
the setup code printed in the dashboard log, so an identity provider can never
be the only way into an empty installation.

## Set it up

1. In your provider, register a web application with the redirect URI
   `https://<your-dashboard>/oidc/callback`. The dashboard shows the exact URL at
   **Settings > Single sign-on**. Use authorization code with PKCE and request
   the `openid`, `email` and `profile` scopes (plus whatever scope carries your
   groups, e.g. `groups`).
2. In Skyfarer, open **Settings > Single sign-on** and fill in the issuer URL
   (the provider's exact `iss` value, not its login page), client ID and client
   secret. The secret is encrypted in Postgres and never shown again.
3. Decide who gets which role. At least one of these is required:
   - a **role claim** containing `admin` or `viewer` (dot notation works for
     nested claims, e.g. `resource_access.skyfarer.roles`);
   - **admin/viewer emails** — exact email addresses from the ID token;
   - **admin/viewer groups** — group names from the groups claim (default
     `groups`, also dot-addressable).

   Every source counts, and admin from any of them wins over viewer: a role
   claim of `viewer` doesn't stop an email or group on the admin list. On
   every sign-in the mapped role is applied, so changing someone's groups at
   the provider changes their Skyfarer role.
4. Leave "Create accounts on first sign-in" on to add new people automatically
   from the verified email and name claims. Turn it off to require an admin to
   add each account first. "Require a verified email" is on by default and
   should stay on.

   The first SSO sign-in to an account links it to that person's issuer and
   subject (`sub`) at the provider; after that only the same identity can use
   it, even if someone else at the provider later shows the same email. With
   verified emails not required, SSO creates new accounts but won't link to
   an existing one, such as the local first admin.

The same keys can be set from `.env` on first start (`OIDC_ENABLED`,
`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, the mapping lists, etc.),
but as with every other setting the database wins afterwards. Use the
dashboard or `skyfarer settings set` to change them later.

## How a sign-in works

The login page offers a **Sign in with your identity provider** button once the
configuration is complete. Clicking it:

1. makes a discovery request to `<issuer>/.well-known/openid-configuration`;
2. sends an authorization request with a random `state`, a nonce and an S256
   PKCE challenge, all kept in the signed dashboard session;
3. exchanges the returned code at the token endpoint with the PKCE verifier;
4. verifies the ID token's RS256 signature against the provider's JWKS and
   checks its issuer, audience, expiry, nonce and authorized party;
5. optionally reads the userinfo endpoint, requiring the same subject;
6. maps the verified claims to a role, creates or finds the account, and starts
   a normal 12-hour Skyfarer session.

The browser's `state` must match the session's, so a callback can't be forged or
replayed. Group and role values come only from signed ID-token or TLS userinfo
claims, never from form fields or query strings. Secrets and tokens are never
logged. Sign-out clears the Skyfarer session; it does not sign you out of the
provider.

## Safety notes

- Provider endpoints must be HTTPS; plain HTTP is allowed only for
  `localhost`/`127.0.0.1` so a local test provider can be used.
- RS256 is the supported ID-token algorithm (it's mandatory in OIDC Core).
  Providers using only HS256 or ES256 are not supported.
- Scope authorization to the dashboard callback URL only, and keep the client
  secret out of client-side code. The config is a normal web client, not a
  confidential CLI: PKCE is used as well as the secret.
- If the provider omits an email or leaves it unverified, sign-in is refused.
- If the mapped role would demote the last admin, sign-in is refused and an
  admin must fix the mapping or promote someone else first.
- Local passwords keep working. Remove or disable an SSO configuration at any
  time by clearing `OIDC_ENABLED` in the dashboard; no accounts are deleted.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No SSO button on the login page | `OIDC_ENABLED` is off, or a required setting is missing (the password form still works). |
| "issuer URL doesn't match" | The saved issuer differs from the provider's discovery `iss`, including a trailing-slash difference. |
| "provider doesn't sign ID tokens with RS256" | Change the provider's token signing algorithm or use a different client. |
| "ID token doesn't match this sign-in" | The nonce, audience or client ID changed mid-flow; try again. Check that the provider uses the exact redirect URI shown in Skyfarer. |
| "isn't mapped to a Skyfarer role" | Add the email/group to a mapping, or set a role claim. |
| "email address isn't usable" / "hasn't verified" | The provider must return a verified `email` claim; add the `email` scope. |
| "client secret isn't set or can't be decrypted" | `SKYFARER_SECRET_KEY` changed since the secret was stored; enter the secret again. |

Discovery, token and JWKS calls use a 10-second timeout. Failures are shown on
the login page as a flash message and logged by the dashboard, without token
values. Behind a TLS proxy set `DASHBOARD_HTTPS=true` so the callback URL is
built with `https://` and the session cookie is secure.
