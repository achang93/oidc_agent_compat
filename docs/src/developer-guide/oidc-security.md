# OIDC Security

OIDC login is split between the native relay (`crates/relay/src/login.rs`)
and central (`crates/central/src/oidc_bootstrap.rs`). The relay owns the
browser and loopback callback; central owns the client secret, token exchange,
and all authorization-relevant claim validation.

## RFC compliance

| Standard | Requirement | Implementation |
|---|---|---|
| RFC 8252 (Native Apps) | Loopback redirect, random port, PKCE | ✅ Binds `127.0.0.1:0`, substitutes actual port into redirect URI |
| RFC 7636 (PKCE) | S256, 32-octet verifier | ✅ `PkceCodeChallenge::new_random_sha256` |
| RFC 9700 (OAuth Security BCP) | S256 mandatory, state, exact redirect, no token storage v1 | ✅ S256 only, `state` verified, loopback redirect, no token storage |
| OIDC Core §3.1.3.7 | ID token validation (iss, aud, exp, nonce, sig, alg pin) | ✅ All steps implemented |
| NIST SP 800-90A | OS CSPRNG for key generation | ✅ `OsRng` via `rand` |
| NIST SP 800-131A | 256-bit minimum key length | ✅ 256-bit central-minted tokens |
| OWASP ASVS V2/V3 | Auth, session, federated auth controls | ✅ |
| CWE-208 | Constant-time comparison (timing attack prevention) | ✅ `subtle::ConstantTimeEq`, no early return |

## Login flow

1. **Loopback redirect validation** — `validate_loopback_redirect()`:
   - Requires scheme `http` and loopback IP host (`127.0.0.0/8` or `::1`).
   - Rejects `localhost` hostname, `https`, non-loopback, substring
     bypasses like `127.0.0.1.evil.com`.
   - RFC 8252.

2. **Relay HTTP client** — `build_http_client()`:
   - `redirect::Policy::none()` — no redirects (SSRF prevention).
   - `use_rustls_tls()` — rustls, not native-tls.
   - `CONNECT_TIMEOUT = 10s`, `REQUEST_TIMEOUT = 30s`.

3. **Relay OIDC discovery** — `CustomProviderMetadata::discover_async()`.

4. **Loopback listener** — binds `127.0.0.1:0` (random port, RFC 8252
   §7.3). Substitutes actual port into redirect URI.

5. **Public native client construction** — `CustomClient` from provider
   metadata + `ClientId`, with no client secret on the laptop.

6. **PKCE + state + nonce**:
   - PKCE: `PkceCodeChallenge::new_random_sha256` (S256, RFC 7636/9700).
   - `state`: `CsrfToken::new_random` (CSRF defense).
   - `nonce`: `Nonce::new_random` (replay defense).

7. **Authorize URL** — scopes: `openid` always added first; configured
   scopes filtered to skip `openid` (avoid duplicate).

8. **Browser launch** — `open_browser(url)`:
   - macOS: `open <url>`
   - Linux: `xdg-open <url>`
   - Windows: `cmd /C start <url>`

9. **Callback wait** — `wait_for_callback(listener, 300s)`:
    - `tokio::time::timeout(300s, listener.accept())`.
    - Reads request with 10s sub-timeout.
    - Parses `GET /callback?code=...&state=... HTTP/1.1`.
    - If `error` param present → `Error::oidc`.
    - Writes minimal HTML response.

10. **State verification** — compares returned `state` against the one
    sent (CSRF defense).

11. **Secure handoff to central** — relay sends the one-time authorization
    code, PKCE verifier, exact loopback redirect URI, and nonce to
    `POST {central}/v1/tokens` over mTLS. These values are not `Debug` and are
    never logged. Caller-supplied subject, issuer, email, display name,
    groups, and identity IDs are not accepted.

12. **Central confidential-client setup and token exchange** — central reads
    the client secret from the environment variable named by
    `client_secret_env`, discovers the configured issuer, validates that the
    supplied redirect URI is loopback, then calls `exchange_code()` with the
    PKCE verifier and exact redirect URI.

13. **Central ID-token validation**:
    - **Alg pin** — `is_allowed_alg()` accepts only:
      - `RS256` (`RsaSsaPkcs1V15Sha256`)
      - `ES256` (`EcdsaP256Sha256`)
      - Rejects `none`, all `HS*`, and other RSA/ECDSA variants.
      - Checked **before** signature verification.
    - **Claims verification** — `id_token.claims(&verifier, &nonce)`:
      - `iss` (issuer) matches.
      - `aud` (audience) matches `client_id`.
      - `exp` (expiry) in the future.
      - `nonce` matches the one sent.
      - Signature verified via JWKS.
    - **`at_hash` validation** (OIDC Core §3.1.3.7 step 3) — if
      the IdP includes `at_hash`, verifies it against the access token.
      Prevents token substitution.

14. **Central userinfo** — `client.user_info(...)`. Falls back to
    `claims_from_id_token()` on userinfo failure. Extracts:
    - `subject` (sub claim).
    - `email` (email claim).
    - `display_name` (name → preferred_username).
    - `groups` (via `union_groups_roles` + `groups_to_json_string`).

15. **Complete login** — central stores the verified claim snapshot with the
    new opaque token and returns both to the relay. The relay:
    - `key_store.upsert_identity(...)` — stores only the central-verified
      identity locally.
    - `agent_config::inject(...)` — writes the token into the agent config.

## Allowed signing algorithms

```rust
pub const ALLOWED_SIGNING_ALGS: &[&str] = &["RS256", "ES256"];
```

- `is_allowed_signing_alg(alg)` — case-insensitive check.
- Rejects `none` (no signature), all `HS*` (symmetric, client secret as
  HMAC key), and other RSA/ECDSA variants.
- This prevents alg downgrade attacks.

## Groups extraction

Groups are extracted from the signed ID token (or TLS-protected userinfo)
via `CustomAdditionalClaims`:

```rust
pub struct CustomAdditionalClaims {
    pub groups: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
}
```

`union_groups_roles()` deduplicates and sorts groups + roles into a single
list. `groups_to_json_string()` serializes as a JSON array string for the
token record's `groups` field (originally extracted from the IdP at
login time and stored in the central token record).

> **Note:** Groups extraction from userinfo is not a standard OIDC claim.
> The `groups` scope must be requested in the relay's OIDC config.

## Manual verification

Run `oac-relay login` on the **host** against dev Keycloak:

```sh
cargo build --release -p oac-relay
./docker/dev.sh up
./target/release/oac-relay \
  --config docker/dev/configs/relay-login-test.toml login
```

The containerized relay cannot do login (no host browser / loopback
callback).
