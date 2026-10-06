//! OIDC login flow for the relay.
//!
//! This module implements the `login` subcommand: it runs the OIDC
//! authorization-code + PKCE flow against the enterprise IdP, persists the
//! identity locally, requests a central-minted token from the central proxy,
//! and injects it into the agent's config.
//!
//! # Security
//!
//! - Loopback redirect URI (`http://127.0.0.1:{port}/callback`), RFC 8252.
//! - PKCE S256, `state`, `nonce`.
//! - Secure grant handoff to central for ID-token validation with alg pin
//!   {RS256, ES256}.
//! - The central token is never printed; it's auto-injected into the agent
//!   config.

use std::time::Duration;

use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::oidc;

use crate::agent_config::{AgentConfig, inject};
use crate::keystore::KeyStore;

use oidc_agent_common::oidc::{CustomClient, CustomProviderMetadata};
use openidconnect::core::CoreResponseType;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};

/// The maximum time to wait for the user to complete the browser login (5 min).
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Parses a TTL duration string into seconds.
///
/// Supported formats:
/// - `1d` — days (1d = 86400s)
/// - `12h` — hours (1h = 3600s)
/// - `30m` — minutes (1m = 60s)
/// - `3600s` — seconds
/// - `1y` — years (1y = 365d = 31536000s)
/// - `3600` — bare integer (seconds)
///
/// Returns `Ok(None)` for an empty string (meaning "never expire").
///
/// # Errors
///
/// Returns [`Error::Config`] if the format is unrecognized or the numeric
/// portion is not a valid positive integer.
pub fn parse_ttl_to_seconds(s: &str) -> Result<Option<i64>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Determine the unit suffix and the numeric prefix.
    let (num_str, multiplier): (&str, i64) = if let Some(rest) = trimmed.strip_suffix('d') {
        (rest, 86_400)
    } else if let Some(rest) = trimmed.strip_suffix('h') {
        (rest, 3_600)
    } else if let Some(rest) = trimmed.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = trimmed.strip_suffix('s') {
        (rest, 1)
    } else if let Some(rest) = trimmed.strip_suffix('y') {
        (rest, 31_536_000)
    } else {
        (trimmed, 1) // bare integer = seconds
    };
    let value: i64 = num_str
        .trim()
        .parse::<i64>()
        .map_err(|e| Error::Config(format!("invalid TTL value '{num_str}': {e}")))?;
    if value <= 0 {
        return Err(Error::Config(format!(
            "TTL must be a positive integer, got {value}"
        )));
    }
    value
        .checked_mul(multiplier)
        .ok_or_else(|| Error::Config(format!("TTL overflow: {value} * {multiplier}")))
        .map(Some)
}

/// The result of a successful login.
#[derive(Debug)]
pub struct LoginResult {
    /// The identity's subject (from the IdP).
    pub subject: String,
    /// The identity's email (if provided).
    pub email: Option<String>,
    /// The agent config injection result.
    pub injection: crate::agent_config::InjectionResult,
}

/// Request body for `POST /v1/tokens` (central token mint).
#[derive(Serialize)]
struct MintTokenRequest {
    /// One-time OIDC authorization code.
    authorization_code: String,
    /// PKCE verifier paired with the S256 challenge.
    pkce_verifier: String,
    /// Exact loopback redirect URI used by the authorization request.
    redirect_uri: String,
    /// OIDC nonce generated for the authorization request.
    nonce: String,
    /// Human-readable label.
    label: String,
    /// Requested token lifetime in seconds. `None` = never expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<i64>,
}

/// Response body for `POST /v1/tokens` (central token mint).
#[derive(Debug, Deserialize)]
struct MintTokenResponse {
    /// The plaintext opaque token (`oac_...`). Returned once; never persisted.
    token: String,
    /// The stored token row id (UUID).
    #[allow(dead_code)]
    token_id: String,
    /// When the token expires (RFC 3339), or `null` for never.
    #[allow(dead_code)]
    expires_at: Option<String>,
    /// The OIDC issuer validated by central.
    issuer: String,
    /// The subject validated by central.
    subject: String,
    /// The email validated by central, if present.
    email: Option<String>,
    /// The display name validated by central, if present.
    display_name: Option<String>,
    /// The group and role claims validated by central, if present.
    groups: Option<String>,
}

/// The one-time authorization-code grant passed to [`complete_login`].
///
/// This type intentionally does not implement `Debug`: the authorization
/// code and PKCE verifier are short-lived secrets and must not reach logs.
pub struct AuthorizationCodeGrant<'a> {
    /// The authorization code returned to the loopback callback.
    pub authorization_code: &'a str,
    /// The PKCE verifier paired with the authorization request.
    pub pkce_verifier: &'a str,
    /// The exact loopback redirect URI used for the authorization request.
    pub redirect_uri: &'a str,
    /// The OIDC nonce generated for the authorization request.
    pub nonce: &'a str,
}

/// Completes login by asking central to exchange and validate the OIDC grant.
///
/// This is called by the `login` subcommand after the OIDC callback has
/// returned the one-time authorization code. It:
/// 1. Calls central's `POST /v1/tokens`, which exchanges the code and validates
///    the ID token and userinfo response.
/// 2. Upserts only the identity returned by central in the local database.
/// 3. Injects the base URL + central token into the agent's config.
///
/// # Security
///
/// The relay never receives the OIDC client secret and never decides which
/// claims are trusted for central authorization. The one-time code and PKCE
/// verifier are sent only to central over the configured mTLS connection.
///
/// # Errors
///
/// Returns [`Error`] if the database upsert, central token mint, or config
/// injection fails.
pub async fn complete_login(
    key_store: &KeyStore,
    config: &RelayConfig,
    client: &reqwest::Client,
    grant: AuthorizationCodeGrant<'_>,
    ttl_seconds: Option<i64>,
) -> Result<LoginResult> {
    // 1. Exchange and validate the one-time grant at central, then mint a
    // central token for the identity central derived from the IdP response.
    let mint_request = MintTokenRequest {
        authorization_code: grant.authorization_code.to_string(),
        pkce_verifier: grant.pkce_verifier.to_string(),
        redirect_uri: grant.redirect_uri.to_string(),
        nonce: grant.nonce.to_string(),
        label: "default".to_string(),
        ttl_seconds,
    };
    let url = format!("{}/v1/tokens", config.central.url);

    // Compute the device fingerprint from the mTLS client cert (if available).
    // In dev mode, this is None — no device binding.
    let device_fingerprint = if config.dev_mode {
        None
    } else {
        oidc_agent_common::mtls::cert_fingerprint(&config.central.client_cert_path)
    };

    let mut req = client.post(&url).json(&mint_request);
    if let Some(ref fp) = device_fingerprint {
        req = req.header(oidc_agent_common::identity::HEADER_DEVICE_FINGERPRINT, fp);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| Error::http(format!("failed to mint token from central: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(Error::http(format!(
            "failed to mint token from central: {status} {body}"
        )));
    }
    let minted: MintTokenResponse = resp
        .json()
        .await
        .map_err(|e| Error::http(format!("failed to parse central token response: {e}")))?;

    // 2. Persist only the identity that central verified.
    key_store
        .upsert_identity(
            &minted.issuer,
            &minted.subject,
            minted.email.as_deref(),
            minted.display_name.as_deref(),
            minted.groups.as_deref(),
        )
        .await?;

    // 3. Inject the central token into the agent config.
    let base_url = format!("http://{}/v1", config.listen_addr);
    let agent_config = AgentConfig {
        base_url,
        api_key: minted.token,
    };
    let injection = inject(&agent_config)?;

    Ok(LoginResult {
        subject: minted.subject,
        email: minted.email,
        injection,
    })
}

/// Runs the full OIDC authorization-code + PKCE login flow.
///
/// # Flow
///
/// 1. Validate the loopback redirect URI (RFC 8252).
/// 2. Discover the IdP's metadata via the issuer URL.
/// 3. Generate PKCE (S256), `state`, and `nonce`.
/// 4. Bind a one-shot loopback HTTP listener (random port).
/// 5. Build the authorization URL and open it in the browser.
/// 6. Receive the callback and verify `state`.
/// 7. Send the one-time code and PKCE verifier to central over mTLS.
/// 8. Central exchanges the code, validates the ID token and userinfo, and
///    mints the opaque agent token.
/// 9. Persist the central-verified identity and inject the agent token.
///
/// # Security
///
/// - PKCE S256 (RFC 7636, RFC 9700 §2.1.1).
/// - `state` (CSRF) is verified by the relay; central verifies `nonce` and
///   performs all ID-token validation.
/// - The native relay never receives the OIDC client secret.
/// - Loopback redirect only (RFC 8252 §7.3).
/// - HTTP client never follows redirects (SSRF prevention).
/// - The central token is never printed; it's auto-injected into the agent
///   config.
///
/// # Errors
///
/// Returns [`Error::Oidc`] on any protocol, validation, or network failure.
pub async fn run_login(
    config: &RelayConfig,
    key_store: &KeyStore,
    ttl: Option<&str>,
) -> Result<LoginResult> {
    // 1. Validate the redirect URI is a loopback http URL.
    oidc::validate_loopback_redirect(&config.oidc.redirect_uri)?;

    // 2. Build the HTTP client (no redirects, rustls, timeouts).
    let http_client = oidc::build_http_client()?;

    // 3. Discover the IdP metadata needed to build the authorization URL.
    let issuer_url = IssuerUrl::new(config.oidc.issuer.clone())
        .map_err(|e| Error::oidc(format!("invalid issuer URL: {e}")))?;
    let provider_metadata = CustomProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| Error::oidc(format!("OIDC discovery failed: {e}")))?;

    // 4. Bind a one-shot loopback listener to get a real port (RFC 8252 §7.3).
    //    The config redirect_uri may use port 0 (any port); we substitute the
    //    actual bound port. The IdP MUST allow any loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::oidc(format!("bind callback listener: {e}")))?;
    let callback_port = listener
        .local_addr()
        .map_err(|e| Error::oidc(format!("callback local_addr: {e}")))?
        .port();
    let redirect_uri_str = format!("http://127.0.0.1:{callback_port}/callback");
    let redirect_uri = RedirectUrl::new(redirect_uri_str)
        .map_err(|e| Error::oidc(format!("invalid redirect URL: {e}")))?;
    let bootstrap_redirect_uri = redirect_uri.to_string();

    // 5. Build the public native OIDC client. Central alone holds the secret
    // and performs the eventual token exchange.
    let client = CustomClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.oidc.client_id.clone()),
        None,
    )
    .set_redirect_uri(redirect_uri);

    // 6. Generate PKCE (S256), state, and nonce.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // 7. Build the authorization URL.
    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        // Add configured scopes (skip "openid", already added).
        .add_scopes(
            config
                .oidc
                .scopes
                .iter()
                .filter(|s| s.as_str() != "openid")
                .map(|s| Scope::new(s.clone())),
        )
        .set_pkce_challenge(pkce_challenge)
        .url();

    // 8. Open the browser (best effort); always print the URL as fallback.
    let url_string = authorize_url.to_string();
    println!("Open this URL in your browser to log in:\n{url_string}\n");
    open_browser(&url_string);

    // 9. Wait for the callback (with timeout).
    let (code, state) = wait_for_callback(listener, CALLBACK_TIMEOUT).await?;

    // 10. Verify state (CSRF defense).
    if state.secret() != csrf_state.secret() {
        return Err(Error::oidc(
            "state mismatch — possible CSRF attack or stale callback",
        ));
    }

    // 11. Let central exchange the code, validate identity, mint, and return
    // the verified identity for local convenience storage.
    let ttl_seconds = match ttl {
        Some(t) => parse_ttl_to_seconds(t)?,
        None => None,
    };
    let central_client = crate::proxy::forward::build_client(config)?;
    let grant = AuthorizationCodeGrant {
        authorization_code: code.secret(),
        pkce_verifier: pkce_verifier.secret(),
        redirect_uri: &bootstrap_redirect_uri,
        nonce: nonce.secret(),
    };
    complete_login(key_store, config, &central_client, grant, ttl_seconds).await
}

/// Waits for a single OIDC callback on the loopback listener.
///
/// Parses the GET request, extracts `code` and `state` from the query string,
/// writes a minimal HTML response, and returns the authorization code and
/// state. Times out after `timeout`.
///
/// # Errors
///
/// Returns [`Error::Oidc`] on timeout, parse failure, or missing parameters.
async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    timeout: Duration,
) -> Result<(AuthorizationCode, CsrfToken)> {
    let accept_result = tokio::time::timeout(timeout, listener.accept()).await;
    let (stream, _) = match accept_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(Error::oidc(format!("accept callback: {e}"))),
        Err(_) => {
            return Err(Error::oidc(format!(
                "timed out waiting for login callback after {}s — \
                 complete the login in your browser within this window, \
                 and ensure the authorization URL was opened (if it did not \
                 open automatically, copy and paste it into a browser). \
                 If the IdP redirected to a non-loopback URL, check the \
                 redirect_uri in your relay config",
                timeout.as_secs()
            )));
        }
    };

    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let mut stream = stream;
    let mut buf = Vec::with_capacity(4096);
    // Read only the HTTP request head (the request line + headers), NOT the
    // whole body. `read_to_end` would block until the peer closes the
    // connection, but a well-behaved browser keeps the callback connection
    // alive until it receives our response — so `read_to_end` would always
    // burn the full read timeout before we respond. The authorize-code
    // callback is a GET with no meaningful body, so the request head is all
    // we need. On timeout or I/O error we parse whatever head we have.
    let head = tokio::time::timeout(Duration::from_secs(10), async {
        while !buf.ends_with(b"\r\n\r\n") && buf.len() < 4096 {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 {
                break; // peer closed; parse whatever head we have
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    let _ = head; // best-effort read; parse the head we collected regardless

    // The length of the request head (up to and including the blank line).
    let head_len = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(buf.len());

    // `head_len` is bounded above by `buf.len()`, so this slice is always
    // in-bounds; use `get(..)` to satisfy the `indexing_slicing` lint.
    let request_str = String::from_utf8_lossy(buf.get(..head_len).unwrap_or(&buf));
    // The first line looks like: GET /callback?code=...&state=... HTTP/1.1
    let request_line = request_str
        .lines()
        .next()
        .ok_or_else(|| Error::oidc("empty callback request"))?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::oidc("malformed callback request line"))?;

    // Parse the query string.
    let query = path.split('?').nth(1).unwrap_or("");
    let params: std::collections::HashMap<&str, &str> = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .collect();

    // Check for an error response from the IdP.
    if let Some(err) = params.get("error") {
        let desc = params.get("error_description").copied().unwrap_or("");
        return Err(Error::oidc(format!("IdP returned error: {err} {desc}")));
    }

    let code = params
        .get("code")
        .ok_or_else(|| Error::oidc("callback missing 'code' parameter"))?;
    let state = params
        .get("state")
        .ok_or_else(|| Error::oidc("callback missing 'state' parameter"))?;

    // Write a minimal HTML response.
    let body = "<!DOCTYPE html><html><body><h1>Login complete</h1>\
                 <p>You can close this window and return to your terminal.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    Ok((
        AuthorizationCode::new((*code).to_string()),
        CsrfToken::new((*state).to_string()),
    ))
}

/// Attempts to open the given URL in the user's default browser.
///
/// Tries `open` (macOS), `xdg-open` (Linux), and `start` (Windows). Logs a
/// warning on failure; the caller has already printed the URL as a fallback.
fn open_browser(url: &str) {
    use std::process::Command;
    #[cfg(target_os = "macos")]
    let (cmd, args) = ("open", vec![url]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (cmd, args) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args) = ("cmd", vec!["/C", "start", "", url]);

    #[cfg(not(any(target_os = "macos", target_os = "windows", unix)))]
    {
        let _ = url;
        tracing::warn!("unsupported platform for browser launch; open the URL manually");
        return;
    }

    match Command::new(cmd).args(&args).spawn() {
        Ok(_) => tracing::info!("opened browser for OIDC login"),
        Err(e) => tracing::warn!(error = %e, "failed to open browser; open the URL manually"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KeyStore;

    async fn setup_test_db() -> KeyStore {
        let url = oidc_agent_common::persistence::temp_sqlite_url("login");
        let db = crate::db::setup(&url).await.expect("db setup");
        KeyStore::new(db)
    }

    fn test_config() -> RelayConfig {
        RelayConfig {
            listen_addr: "127.0.0.1:8787".parse().expect("valid addr"),
            database_url: "sqlite://test.db".into(),
            oidc: oidc_agent_common::config::OidcConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "test".into(),
                client_secret_env: "TEST_SECRET".into(),
                redirect_uri: "http://127.0.0.1:0/callback".into(),
                scopes: vec!["openid".into()],
            },
            central: oidc_agent_common::config::CentralConnectionConfig {
                url: "https://central.example.com".into(),
                ca_cert_path: "/ca.pem".into(),
                client_cert_path: "/client.pem".into(),
                client_key_path: "/client.key".into(),
            },
            dev_mode: false,
        }
    }

    // --- complete_login tests ---
    //
    // These tests exercise the full `complete_login` flow, which now calls
    // the central proxy's POST /v1/tokens endpoint. They require a running
    // central server and are marked #[ignore] so they don't run in the
    // normal test suite. Run them manually with:
    //   cargo test -p oac-relay -- --ignored complete_login

    /// Verifies that `complete_login` persists the identity and mints a
    /// central token. Requires a live central server at `config.central.url`.
    #[tokio::test]
    #[ignore = "requires a live central server with POST /v1/tokens endpoint"]
    async fn complete_login_persists_identity_and_mints_key() {
        let store = setup_test_db().await;
        let config = test_config();
        let client = crate::proxy::forward::build_client(&config).expect("client");
        let result = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            None,
        )
        .await
        .expect("login");

        assert_eq!(result.subject, "user123");
        assert_eq!(result.email.as_deref(), Some("user@example.com"));

        // Verify the identity was persisted.
        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].subject, "user123");
    }

    /// Verifies that `complete_login` applies the requested TTL. Requires a
    /// live central server.
    #[tokio::test]
    #[ignore = "requires a live central server with POST /v1/tokens endpoint"]
    async fn complete_login_applies_session_ttl() {
        let store = setup_test_db().await;
        let config = test_config();
        let client = crate::proxy::forward::build_client(&config).expect("client");

        let _ = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            Some(3600),
        )
        .await
        .expect("login");

        // The central server is responsible for the token's TTL. We verify
        // the identity was persisted.
        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
    }

    /// Verifies that `complete_login` is idempotent for the same identity.
    /// Requires a live central server.
    #[tokio::test]
    #[ignore = "requires a live central server with POST /v1/tokens endpoint"]
    async fn complete_login_is_idempotent_for_same_identity() {
        let store = setup_test_db().await;
        let config = test_config();
        let client = crate::proxy::forward::build_client(&config).expect("client");

        // First login.
        let _ = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            None,
        )
        .await
        .expect("login 1");

        // Second login with the same identity.
        let _ = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            None,
        )
        .await
        .expect("login 2");

        // Should have one identity (upsert), but two central tokens.
        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1, "same identity must not be duplicated");
    }

    /// Verifies that `complete_login` persists groups. Requires a live
    /// central server.
    #[tokio::test]
    #[ignore = "requires a live central server with POST /v1/tokens endpoint"]
    async fn complete_login_persists_groups() {
        let store = setup_test_db().await;
        let config = test_config();
        let client = crate::proxy::forward::build_client(&config).expect("client");
        let groups_json = r#"["engineering","ai-users"]"#;
        let _ = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            None,
        )
        .await
        .expect("login");

        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0].groups.as_deref(),
            Some(groups_json),
            "groups must be persisted in the identities table"
        );
    }

    #[tokio::test]
    async fn run_login_no_longer_returns_placeholder() {
        // Against a fake issuer, run_login must fail with a real discovery
        // error rather than the old implementation placeholder.
        let store = setup_test_db().await;
        let config = test_config();
        let err = run_login(&config, &store, None).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("not yet implemented"),
            "run_login must no longer return the placeholder error: {msg}"
        );
        assert!(
            msg.contains("discovery") || msg.contains("issuer"),
            "expected a discovery/issuer error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn wait_for_callback_parses_code_and_state() {
        // Bind a listener, then connect and send a crafted callback request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn a client that sends the callback.
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?code=abc123&state=xyz789 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            // Read the response (discard).
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let (code, state) = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .expect("callback");
        assert_eq!(code.secret(), "abc123");
        assert_eq!(state.secret(), "xyz789");
    }

    #[tokio::test]
    async fn wait_for_callback_rejects_missing_code() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?state=xyz789 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing 'code'"), "{err}");
    }

    #[tokio::test]
    async fn wait_for_callback_surfaces_idp_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GET /callback?error=access_denied&error_description=user+cancelled HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("access_denied"), "{err}");
    }

    // --- Callback failure UX: every way a login can go wrong must produce
    // an actionable error, never a hang or a panic. ---

    #[tokio::test]
    async fn wait_for_callback_times_out_with_guidance() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");

        // Nobody connects; the short timeout must fire with a message that
        // tells the user what to do (open the URL / check the redirect URI).
        let err = wait_for_callback(listener, Duration::from_millis(100))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("timed out") && msg.contains("browser"),
            "the timeout error must guide the user: {msg}"
        );
    }

    #[tokio::test]
    async fn wait_for_callback_rejects_missing_state() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req =
                "GET /callback?code=abc HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing 'state'"), "{err}");
    }

    #[tokio::test]
    async fn wait_for_callback_rejects_empty_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Connect and immediately close the write side: the server reads
        // zero bytes (a scanner or a half-open browser tab).
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let _ = stream.shutdown().await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("empty callback request")
                || err.to_string().contains("malformed"),
            "a connection with no request must fail cleanly: {err}"
        );
    }

    #[tokio::test]
    async fn wait_for_callback_rejects_malformed_request_line() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::AsyncWriteExt;
            let req = "GARBAGE-NO-SPACES-NO-PATH\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        });

        let err = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    #[tokio::test]
    async fn wait_for_callback_writes_a_friendly_html_response() {
        // The browser tab the user lands on must show a completion page,
        // not a blank/error screen.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let req = "GET /callback?code=c&state=s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req.as_bytes()).await;
            let _ = stream.flush().await;
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            let _ = tx.send(buf);
        });

        let (code, state) = wait_for_callback(listener, Duration::from_secs(5))
            .await
            .expect("callback");
        assert_eq!(code.secret(), "c");
        assert_eq!(state.secret(), "s");

        let response = rx
            .await
            .expect("server must write a response before returning");
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 200 OK"),
            "the callback must answer 200: {text}"
        );
        assert!(
            text.contains("Login complete"),
            "the user's browser tab must confirm success: {text}"
        );
        assert!(
            text.contains("text/html"),
            "content-type must be text/html: {text}"
        );
    }

    /// Verifies that `complete_login` persists the display name. Requires a
    /// live central server.
    #[tokio::test]
    #[ignore = "requires a live central server with POST /v1/tokens endpoint"]
    async fn complete_login_persists_display_name() {
        let store = setup_test_db().await;
        let config = test_config();
        let client = crate::proxy::forward::build_client(&config).expect("client");
        let _ = complete_login(
            &store,
            &config,
            &client,
            AuthorizationCodeGrant {
                authorization_code: "test-code",
                pkce_verifier: "test-verifier",
                redirect_uri: "http://127.0.0.1:7777/callback",
                nonce: "test-nonce",
            },
            None,
        )
        .await
        .expect("login");

        use crate::entity::identity;
        use sea_orm::EntityTrait;
        let identities = identity::Entity::find().all(&store.db).await.expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0].display_name.as_deref(),
            Some("Alice Doe"),
            "display name must survive login so admins see real names"
        );
    }

    /// The callback reader must return as soon as the request head (request
    /// line + headers) has arrived — it must NOT wait for the peer to close
    /// the connection. A well-behaved browser keeps the connection open until
    /// it receives the response, so the old `read_to_end` implementation
    /// always burned the full read timeout and made interactive login hang.
    #[tokio::test]
    async fn wait_for_callback_returns_promptly_without_awaiting_eof() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio::net::TcpStream;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Client connects and sends only the request head, then deliberately
        // KEEPS the connection open (no EOF), a buffer response is written.
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let head =
                b"GET /callback?code=abc123&state=xyz HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: test\r\n\r\n";
            stream.write_all(head).await.expect("write head");
            // Do NOT close the stream here — the server must not need EOF.
            stream.flush().await.expect("flush");

            // Read the server's response; then the server has replied and we
            // can close. This also proves the response was written promptly.
            let mut resp = [0u8; 512];
            let _n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut resp))
                .await
                .expect("response within timeout")
                .expect("read response");
            stream.shutdown().await.expect("shutdown");
        });

        // The server must respond well before the full 10s read timeout,
        // even though the client never closes its end.
        let got = tokio::time::timeout(
            Duration::from_secs(3),
            wait_for_callback(listener, Duration::from_secs(10)),
        )
        .await
        .expect("wait_for_callback must return without awaiting client EOF")
        .expect("valid callback");

        assert_eq!(got.0.secret(), "abc123");
        assert_eq!(got.1.secret(), "xyz");
        client.await.expect("client task");
    }

    /// A callback whose head contains no blank line (e.g. a truncated/malformed
    /// request) must not panic; `head_len` falls back to the whole buffer.
    /// The client shuts down its write half after sending so the server's
    /// read loop sees EOF and proceeds to parse what it has.
    #[tokio::test]
    async fn wait_for_callback_tolerates_missing_blank_line() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;
        use tokio::net::TcpStream;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let junk = b"GET /callback?code=only&state=ss HTTP/1.1\r\n";
            stream.write_all(junk).await.expect("write");
            stream.flush().await.expect("flush");
            stream.shutdown().await.expect("shutdown write half (EOF)");
            let mut resp = [0u8; 512];
            let _n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut resp))
                .await
                .expect("response within timeout")
                .expect("read response");
        });

        let got = tokio::time::timeout(
            Duration::from_secs(3),
            wait_for_callback(listener, Duration::from_secs(10)),
        )
        .await
        .expect("must not hang on malformed head")
        .expect("valid callback");

        assert_eq!(got.0.secret(), "only");
        assert_eq!(got.1.secret(), "ss");
        client.await.expect("client task");
    }

    // --- parse_ttl_to_seconds tests ---

    #[test]
    fn parse_ttl_days() {
        assert_eq!(parse_ttl_to_seconds("1d").expect("1d"), Some(86_400));
        assert_eq!(parse_ttl_to_seconds("7d").expect("7d"), Some(604_800));
    }

    #[test]
    fn parse_ttl_hours() {
        assert_eq!(parse_ttl_to_seconds("12h").expect("12h"), Some(43_200));
        assert_eq!(parse_ttl_to_seconds("1h").expect("1h"), Some(3_600));
    }

    #[test]
    fn parse_ttl_minutes() {
        assert_eq!(parse_ttl_to_seconds("30m").expect("30m"), Some(1_800));
        assert_eq!(parse_ttl_to_seconds("1m").expect("1m"), Some(60));
    }

    #[test]
    fn parse_ttl_seconds() {
        assert_eq!(parse_ttl_to_seconds("3600s").expect("3600s"), Some(3_600));
        assert_eq!(parse_ttl_to_seconds("1s").expect("1s"), Some(1));
    }

    #[test]
    fn parse_ttl_years() {
        assert_eq!(parse_ttl_to_seconds("1y").expect("1y"), Some(31_536_000));
    }

    #[test]
    fn parse_ttl_bare_integer() {
        assert_eq!(parse_ttl_to_seconds("3600").expect("3600"), Some(3_600));
        assert_eq!(parse_ttl_to_seconds("60").expect("60"), Some(60));
    }

    #[test]
    fn parse_ttl_empty_returns_none() {
        assert_eq!(parse_ttl_to_seconds("").expect("empty"), None);
        assert_eq!(parse_ttl_to_seconds("   ").expect("whitespace"), None);
    }

    #[test]
    fn parse_ttl_invalid_format_returns_err() {
        assert!(
            parse_ttl_to_seconds("abc").is_err(),
            "non-numeric must error"
        );
        assert!(parse_ttl_to_seconds("0d").is_err(), "zero must error");
        assert!(parse_ttl_to_seconds("-1h").is_err(), "negative must error");
        assert!(
            parse_ttl_to_seconds("1.5d").is_err(),
            "fractional must error"
        );
        assert!(parse_ttl_to_seconds("d").is_err(), "bare suffix must error");
    }

    #[test]
    fn parse_ttl_whitespace_around_value() {
        assert_eq!(
            parse_ttl_to_seconds("  1d  ").expect("trimmed"),
            Some(86_400)
        );
    }
}
