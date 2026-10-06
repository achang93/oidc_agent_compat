//! Token API endpoints for the central proxy.
//!
//! These endpoints implement the zero-trust token lifecycle:
//! - `POST /v1/tokens` — mint a token. In the login flow (no `Authorization`
//!   header), central exchanges a one-time OIDC authorization code and derives
//!   identity from the validated ID token or userinfo response. In the
//!   token-create flow (`oac-relay token create`), a valid bearer is present
//!   and identity is copied from the verified token record.
//! - `DELETE /v1/tokens/current` — revoke the token in the `Authorization:
//!   Bearer` header.
//! - `DELETE /v1/tokens/{id}` — revoke a specific token by its row id
//!   (bearer-authenticated; lets a user revoke any of their tokens).
//! - `GET /v1/tokens` — list tokens for the subject in the `Authorization:
//!   Bearer` header (metadata only; never the hash or plaintext).
//!
//! # Security
//!
//! - The login mint endpoint is authenticated twice: mTLS authenticates the
//!   relay transport, then central performs the OIDC authorization-code
//!   exchange and validates the ID token. Caller-supplied identity fields are
//!   never accepted.
//! - The revoke and list endpoints authenticate via the bearer token itself
//!   (verified against the central token store with constant-time hash
//!   comparison).
//! - The plaintext token is never logged.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use time::Duration;

use oidc_agent_common::identity;
use oidc_agent_common::keys::extract_bearer;
use oidc_agent_common::time_util;

use crate::oidc_bootstrap::BootstrapGrant;
use crate::token_store::MintRequest;

use super::AppState;

/// Request body for `POST /v1/tokens` (mint a token).
#[derive(Deserialize)]
pub struct MintTokenRequest {
    /// One-time OIDC authorization code. Required when no bearer is present.
    #[serde(default)]
    pub authorization_code: String,
    /// PKCE verifier paired with the authorization request's S256 challenge.
    #[serde(default)]
    pub pkce_verifier: String,
    /// Exact loopback redirect URI used for the authorization request.
    #[serde(default)]
    pub redirect_uri: String,
    /// OIDC nonce generated for the authorization request.
    #[serde(default)]
    pub nonce: String,
    /// Human-readable label. Required (validated in handler).
    #[serde(default)]
    pub label: String,
    /// Requested token lifetime in seconds. `None` = never expires. Clamped
    /// to the admin token-TTL backstop (`max_token_ttl_seconds`) if set.
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// Response body for `POST /v1/tokens`.
#[derive(Debug, Serialize)]
pub struct MintTokenResponse {
    /// The plaintext opaque token (`oac_...`). Returned once; never persisted.
    pub token: String,
    /// The stored token row id (UUID).
    pub token_id: String,
    /// When the token expires (RFC 3339 / log format), or `null` for never.
    pub expires_at: Option<String>,
    /// The issuer validated by central.
    pub issuer: String,
    /// The subject validated by central or copied from the verified bearer.
    pub subject: String,
    /// The email validated by central, if supplied by the IdP.
    pub email: Option<String>,
    /// The display name validated by central, if supplied by the IdP.
    pub display_name: Option<String>,
    /// The group/role snapshot validated by central, if supplied by the IdP.
    pub groups: Option<String>,
}

/// A single token's metadata in the list response. Never includes the hash or
/// plaintext.
#[derive(Debug, Serialize)]
pub struct TokenListItem {
    /// The token row id (UUID).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// When the token was minted (log format).
    pub created_at: String,
    /// When the token expires (log format), or `null` for never.
    pub expires_at: Option<String>,
    /// When the token was last used (log format), or `null`.
    pub last_used_at: Option<String>,
}

/// `POST /v1/tokens` — mints a new opaque token.
///
/// Called by the relay over mTLS during login. Central exchanges and validates
/// the one-time OIDC grant, resolves the verified groups' policy, clamps the
/// requested TTL, and returns the plaintext token. The plaintext and OIDC
/// grant are never logged.
///
/// # Dual authentication modes
///
/// This endpoint serves two callers:
///
/// 1. **Login flow** (relay during OIDC login): no `Authorization` header is
///    present. The body carries a one-time authorization code, PKCE verifier,
///    loopback redirect URI, and nonce. Central exchanges the code and derives
///    identity only from the validated IdP response.
/// 2. **Token-create flow** (`oac-relay token create`): a valid bearer token
///    is present in the `Authorization` header. The identity is taken from
///    the verified token record (subject, issuer, email, display name, groups,
///    identity ID), and the body fields are used only for `label` and
///    `ttl_seconds`. This lets an authenticated user mint additional labeled
///    tokens for themselves without re-running the OIDC flow.
pub async fn mint_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MintTokenRequest>,
) -> Result<(StatusCode, Json<MintTokenResponse>), (StatusCode, String)> {
    // Read the device fingerprint from the X-OAC-Device-Fingerprint header
    // (set by the relay from its mTLS client cert). None in dev mode.
    let device_fingerprint = headers
        .get(identity::HEADER_DEVICE_FINGERPRINT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Validate non-secret fields before consuming the one-time OIDC code.
    if body.label.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "label is required".into()));
    }
    if body.ttl_seconds.is_some_and(|t| t <= 0) {
        return Err((
            StatusCode::BAD_REQUEST,
            "ttl_seconds must be a positive integer".into(),
        ));
    }

    // Determine the identity source: a verified existing bearer or a fresh
    // central-validated OIDC code exchange. Never accept identity from JSON.
    let (subject, issuer, email, display_name, groups, identity_id) =
        match extract_bearer_from_headers(&headers) {
            Some(bearer) => {
                let verification = state
                    .token_store
                    .verify_token(bearer)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                    .ok_or((StatusCode::UNAUTHORIZED, "invalid bearer token".into()))?;
                let id = &verification.identity;
                (
                    id.subject.clone(),
                    id.issuer.clone(),
                    id.email.clone(),
                    id.display_name.clone(),
                    id.groups.clone(),
                    id.identity_id.clone(),
                )
            }
            None => {
                if body.authorization_code.trim().is_empty()
                    || body.pkce_verifier.trim().is_empty()
                    || body.redirect_uri.trim().is_empty()
                    || body.nonce.trim().is_empty()
                {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "authorization_code, pkce_verifier, redirect_uri, and nonce are required"
                            .into(),
                    ));
                }
                let verified = state
                    .bootstrap_verifier
                    .exchange_and_verify(&BootstrapGrant {
                        authorization_code: body.authorization_code.clone(),
                        pkce_verifier: body.pkce_verifier.clone(),
                        redirect_uri: body.redirect_uri.clone(),
                        nonce: body.nonce.clone(),
                    })
                    .await
                    .map_err(|error| {
                        tracing::warn!(error = %error, "OIDC token bootstrap rejected");
                        (
                            StatusCode::UNAUTHORIZED,
                            "OIDC authorization-code exchange failed".into(),
                        )
                    })?;
                (
                    verified.subject,
                    verified.issuer,
                    verified.email,
                    verified.display_name,
                    verified.groups,
                    None,
                )
            }
        };

    // Resolve the group policy to get the admin token-TTL backstop.
    let groups_vec: Vec<String> = groups
        .as_deref()
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();
    let policy = state
        .policy_store
        .resolve_policy(&groups_vec)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Clamp the requested TTL to the backstop if it exists.
    let effective_ttl: Option<i64> = match (body.ttl_seconds, policy.max_token_ttl_seconds) {
        (None, None) => None,
        (None, Some(cap)) => Some(cap),
        (Some(req), None) => Some(req),
        (Some(req), Some(cap)) => Some(req.min(cap)),
    };

    let expires_at = effective_ttl.map(|s| time_util::now_utc() + Duration::seconds(s));

    let minted = state
        .token_store
        .mint_token(&MintRequest {
            subject: subject.clone(),
            issuer: issuer.clone(),
            email: email.clone(),
            display_name: display_name.clone(),
            groups: groups.clone(),
            identity_id,
            label: body.label.clone(),
            expires_at,
            device_fingerprint,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Return the plaintext to the relay. Never log it.
    Ok((
        StatusCode::CREATED,
        Json(MintTokenResponse {
            token: minted.plaintext.to_string(),
            token_id: minted.token_id,
            expires_at: minted.expires_at.map(|e| time_util::format_time(&e)),
            issuer,
            subject,
            email,
            display_name,
            groups,
        }),
    ))
}

/// `DELETE /v1/tokens/current` — revokes the token in the `Authorization:
/// Bearer` header.
///
/// Returns 204 No Content on success, 401 if no bearer is present, 404 if the
/// token is not found.
pub async fn revoke_current_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let bearer = extract_bearer_from_headers(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let revoked = state
        .token_store
        .revoke_by_token(bearer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// `GET /v1/tokens` — lists tokens for the subject in the `Authorization:
/// Bearer` header.
///
/// Verifies the bearer, then lists all tokens for that subject. Returns
/// metadata only (never the hash or plaintext). Returns 401 if the bearer is
/// invalid.
pub async fn list_tokens_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TokenListItem>>, StatusCode> {
    let bearer = extract_bearer_from_headers(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let verification = state
        .token_store
        .verify_token(bearer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let tokens = state
        .token_store
        .list_for_subject(&verification.identity.subject)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let items: Vec<TokenListItem> = tokens
        .into_iter()
        .map(|t| TokenListItem {
            id: t.id,
            label: t.label,
            created_at: time_util::format_time(&t.created_at),
            expires_at: t.expires_at.as_ref().map(time_util::format_time),
            last_used_at: t.last_used_at.as_ref().map(time_util::format_time),
        })
        .collect();

    Ok(Json(items))
}

/// `DELETE /v1/tokens/{id}` — revokes a specific token by its row id.
///
/// Authenticates via the bearer in the `Authorization` header (same as
/// [`list_tokens_handler`]), then revokes the token with the given id. This
/// allows a user to revoke **any** of their tokens (not just the current
/// one), as long as they hold a valid token for authentication.
///
/// Returns 204 No Content on success, 401 if the bearer is invalid, 500 if
/// the revocation fails.
pub async fn revoke_by_id_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, StatusCode> {
    let bearer = extract_bearer_from_headers(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let _verification = state
        .token_store
        .verify_token(bearer)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    state
        .token_store
        .revoke_by_token_id(&id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Extracts the bearer token from the `Authorization` header, if present.
fn extract_bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(extract_bearer)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use crate::proxy::AppState;
    use crate::proxy::router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    struct TestBootstrapVerifier;

    #[async_trait::async_trait]
    impl crate::oidc_bootstrap::BootstrapIdentityVerifier for TestBootstrapVerifier {
        async fn exchange_and_verify(
            &self,
            grant: &crate::oidc_bootstrap::BootstrapGrant,
        ) -> oidc_agent_common::error::Result<crate::oidc_bootstrap::BootstrapIdentity> {
            let subject = grant
                .authorization_code
                .strip_prefix("valid:")
                .filter(|subject| !subject.is_empty())
                .ok_or_else(|| oidc_agent_common::error::Error::oidc("invalid test grant"))?;
            if grant.pkce_verifier != "test-verifier"
                || grant.redirect_uri != "http://127.0.0.1:7777/callback"
                || grant.nonce != "test-nonce"
            {
                return Err(oidc_agent_common::error::Error::oidc(
                    "invalid test grant binding",
                ));
            }
            Ok(crate::oidc_bootstrap::BootstrapIdentity {
                issuer: "https://idp.example.com".into(),
                subject: subject.into(),
                email: Some(format!("{subject}@example.com")),
                display_name: Some(format!("Test {subject}")),
                groups: Some(r#"["engineering"]"#.into()),
            })
        }
    }

    /// Builds a minimal dev-mode AppState for token-endpoint tests.
    async fn test_state() -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("token-api");
        let db = crate::db::setup(&url).await.expect("db setup");
        let audit = crate::audit::AuditLogger::new(db.clone());
        let mcp_db = db.clone();
        AppState {
            config: oidc_agent_common::config::CentralConfig {
                listen_addr: "127.0.0.1:0".parse().expect("addr"),
                database_url: "sqlite://test.db".into(),
                oidc: oidc_agent_common::config::OidcConfig {
                    issuer: "https://idp.example.com".into(),
                    client_id: "test".into(),
                    client_secret_env: "TEST".into(),
                    redirect_uri: "http://127.0.0.1:0/callback".into(),
                    scopes: vec!["openid".into()],
                },
                mtls: oidc_agent_common::config::MtlsServerConfig {
                    ca_cert_path: "/ca.pem".into(),
                    server_cert_path: "/server.pem".into(),
                    server_key_path: "/server.key".into(),
                },
                admin: None,
                pricing: None,
                dev_mode: true,
                rate_limit_requests: 60,
                rate_limit_window_secs: 60,
            },
            provider_store: crate::provider::ProviderStore::new(
                db.clone(),
                zeroize::Zeroizing::new([7_u8; 32]),
            ),
            client: reqwest::Client::new(),
            audit,
            rate_limiter: None,
            policy_store: crate::policy::PolicyStore::new(db.clone()),
            device_store: crate::device_store::DeviceStore::new(db.clone()),
            usage_tracker: crate::usage::UsageTracker::new(db.clone()),
            price_table: crate::pricing::PriceTable::empty(),
            mcp_manager: crate::mcp::McpManager::new(mcp_db, zeroize::Zeroizing::new([7_u8; 32])),
            token_store: crate::token_store::TokenStore::new(db),
            bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
        }
    }

    fn mint_body(subject: &str, label: &str, ttl: Option<i64>) -> String {
        let ttl_field = match ttl {
            Some(t) => format!(", \"ttl_seconds\": {t}"),
            None => String::new(),
        };
        format!(
            r#"{{"authorization_code":"valid:{subject}","pkce_verifier":"test-verifier","redirect_uri":"http://127.0.0.1:7777/callback","nonce":"test-nonce","label":"{label}"{ttl_field}}}"#
        )
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(resp.into_body(), 65536)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    #[tokio::test]
    async fn post_tokens_mints_and_returns_plaintext_and_id() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token field");
        assert!(token.starts_with("oac_"), "token must have oac_ prefix");
        assert!(
            json["token_id"].as_str().is_some(),
            "token_id must be present"
        );
        assert!(
            json["expires_at"].as_str().is_some(),
            "expires_at must be present for a TTL token"
        );
    }

    #[tokio::test]
    async fn post_tokens_with_ttl_clamped_by_backstop() {
        let state = test_state().await;
        // Set a group policy with max_token_ttl_seconds = 100 for "engineering".
        state
            .policy_store
            .upsert_policy_full(
                "engineering",
                None,
                None,
                None,
                None,
                false,
                None,
                false,
                false,
                Some(100),
            )
            .await
            .expect("upsert policy");

        let app = router(state.clone());
        // Request a 3600s TTL; backstop is 100s → must clamp to 100s.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token field");

        // Verify the token was minted and check its expires_at reflects the
        // clamped TTL (not 3600s).
        let verify = state
            .token_store
            .verify_token(token)
            .await
            .expect("verify")
            .expect("verified");
        let now = time_util::now_utc();
        let expires = verify.identity.expires_at.expect("expires_at set");
        // The clamped TTL is 100s, so expires_at must be ~100s from now.
        // Allow a small margin for scheduling latency between mint and now.
        let age = expires - now;
        assert!(
            age <= Duration::seconds(101) && age >= Duration::seconds(98),
            "expires_at must reflect the clamped 100s backstop, got age {age:?}"
        );
    }

    #[tokio::test]
    async fn delete_tokens_current_revokes() {
        let state = test_state().await;
        let app = router(state.clone());
        // Mint a token.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token").to_string();

        // Revoke it via DELETE /v1/tokens/current with the bearer.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/current")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The token must no longer verify.
        let verify = state
            .token_store
            .verify_token(&token)
            .await
            .expect("verify");
        assert!(verify.is_none(), "revoked token must not verify");
    }

    #[tokio::test]
    async fn get_tokens_lists_for_verified_subject() {
        let state = test_state().await;
        let app = router(state.clone());
        // Mint two tokens for the same subject.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        let token = body_json(resp).await["token"]
            .as_str()
            .expect("token")
            .to_string();
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "desktop", None)))
                    .expect("request"),
            )
            .await
            .expect("router");

        // GET /v1/tokens with the bearer.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/tokens")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let arr = body_json(resp).await;
        let items = arr.as_array().expect("array");
        assert_eq!(items.len(), 2, "both tokens for alice must be listed");
        // Metadata only: no token hash or plaintext fields.
        for item in items {
            assert!(item["id"].as_str().is_some(), "id present");
            assert!(item["label"].as_str().is_some(), "label present");
            assert!(item.get("token_hash").is_none(), "no hash exposed");
            assert!(item.get("token").is_none(), "no plaintext exposed");
        }
    }

    #[tokio::test]
    async fn post_tokens_without_required_fields_returns_400() {
        let state = test_state().await;
        let app = router(state);
        // Missing authorization grant.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"label":"laptop"}"#))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Missing label.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"authorization_code":"valid:alice","pkce_verifier":"test-verifier","redirect_uri":"http://127.0.0.1:7777/callback","nonce":"test-nonce"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_tokens_with_invalid_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/tokens")
                    .header("authorization", "Bearer oac_nonexistent")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_tokens_without_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/tokens")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_tokens_current_not_found_returns_404() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/current")
                    .header("authorization", "Bearer oac_nonexistent")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_tokens_with_non_positive_ttl_returns_400() {
        let state = test_state().await;
        let app = router(state);
        // ttl_seconds = 0 is invalid.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(0))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_tokens_with_negative_ttl_returns_400() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(-1))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_tokens_with_rejected_oidc_grant_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"authorization_code":"forged","pkce_verifier":"test-verifier","redirect_uri":"http://127.0.0.1:7777/callback","nonce":"test-nonce","label":"laptop"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_tokens_ignores_caller_supplied_identity_fields() {
        let state = test_state().await;
        let app = router(state.clone());
        let mut body: serde_json::Value =
            serde_json::from_str(&mint_body("alice", "laptop", Some(3600))).expect("body");
        body["subject"] = serde_json::json!("mallory");
        body["issuer"] = serde_json::json!("https://evil.example.com");
        body["groups"] = serde_json::json!(r#"["oac-admins"]"#);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token");
        let verified = state
            .token_store
            .verify_token(token)
            .await
            .expect("verify")
            .expect("verified");
        assert_eq!(verified.identity.subject, "alice");
        assert_eq!(verified.identity.issuer, "https://idp.example.com");
        assert_eq!(
            verified.identity.groups.as_deref(),
            Some(r#"["engineering"]"#)
        );
    }

    #[tokio::test]
    async fn post_tokens_with_no_ttl_and_no_backstop_never_expires() {
        let state = test_state().await;
        let app = router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", None)))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        // No TTL and no backstop → expires_at is null (never expires).
        assert!(
            json["expires_at"].is_null(),
            "no TTL → never expires (null)"
        );
    }

    #[tokio::test]
    async fn post_tokens_backstop_applies_when_no_ttl_requested() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy_full(
                "engineering",
                None,
                None,
                None,
                None,
                false,
                None,
                false,
                false,
                Some(100),
            )
            .await
            .expect("policy");
        let app = router(state.clone());
        // No ttl_seconds in the request, but the backstop is 100s → the
        // token must expire in ~100s.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", None)))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        assert!(
            json["expires_at"].as_str().is_some(),
            "backstop must set expires_at even without a requested TTL"
        );
    }

    #[tokio::test]
    async fn delete_tokens_current_without_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/current")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_tokens_with_revoked_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state.clone());
        // Mint a token.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        let token = body_json(resp).await["token"]
            .as_str()
            .expect("token")
            .to_string();
        // Revoke it.
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/current")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        // Now GET /v1/tokens with the revoked token → 401.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/tokens")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_tokens_with_device_fingerprint_stores_it() {
        let state = test_state().await;
        let app = router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .header("x-oac-device-fingerprint", "aabb1122ff")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token field").to_string();

        // Verify the token and check the stored device fingerprint.
        let verify = state
            .token_store
            .verify_token(&token)
            .await
            .expect("verify")
            .expect("verified");
        assert_eq!(
            verify.identity.device_fingerprint.as_deref(),
            Some("aabb1122ff"),
            "device fingerprint from header must be stored on the token"
        );
    }

    #[tokio::test]
    async fn post_tokens_without_device_fingerprint_stores_none() {
        let state = test_state().await;
        let app = router(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let token = json["token"].as_str().expect("token field").to_string();

        let verify = state
            .token_store
            .verify_token(&token)
            .await
            .expect("verify")
            .expect("verified");
        assert!(
            verify.identity.device_fingerprint.is_none(),
            "missing fingerprint header must store None"
        );
    }

    #[tokio::test]
    async fn post_tokens_with_authorization_uses_identity_from_token() {
        let state = test_state().await;
        let app = router(state.clone());
        // Mint a token for "alice" via the login flow (no auth header).
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let alice_token = json["token"].as_str().expect("token").to_string();

        // Mint a second token using alice's bearer — body has only label + ttl.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {alice_token}"))
                    .body(Body::from(
                        serde_json::json!({
                            "label": "codex",
                            "ttl_seconds": 3600,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::CREATED);
        let json = body_json(resp).await;
        let new_token = json["token"].as_str().expect("new token").to_string();

        // Verify the new token has alice's identity (subject = alice), even
        // though the body did not include subject/issuer/email/groups.
        let verify = state
            .token_store
            .verify_token(&new_token)
            .await
            .expect("verify")
            .expect("verified");
        assert_eq!(
            verify.identity.subject, "alice",
            "identity must come from the verified bearer, not the body"
        );
        assert_eq!(verify.identity.issuer, "https://idp.example.com");
        assert_eq!(
            verify.identity.groups.as_deref(),
            Some(r#"["engineering"]"#),
            "groups must come from the verified bearer"
        );

        // The new token must verify independently.
        let verify2 = state
            .token_store
            .verify_token(&new_token)
            .await
            .expect("verify2")
            .expect("verified2");
        assert_eq!(verify2.identity.subject, "alice");
    }

    #[tokio::test]
    async fn post_tokens_with_invalid_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        // An invalid bearer → 401 even if body has label.
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer oac_invalid_token")
                    .body(Body::from(
                        serde_json::json!({
                            "label": "codex",
                            "ttl_seconds": 3600,
                        })
                        .to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_tokens_by_id_revokes_specific_token() {
        let state = test_state().await;
        let app = router(state.clone());

        // Mint two tokens for alice.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "laptop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        let json1 = body_json(resp).await;
        let token1 = json1["token"].as_str().expect("token1").to_string();
        let id1 = json1["token_id"].as_str().expect("id1").to_string();

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(mint_body("alice", "desktop", Some(3600))))
                    .expect("request"),
            )
            .await
            .expect("router");
        let json2 = body_json(resp).await;
        let token2 = json2["token"].as_str().expect("token2").to_string();
        let id2 = json2["token_id"].as_str().expect("id2").to_string();

        // Use token1's bearer to revoke token2 by id.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/tokens/{id2}"))
                    .header("authorization", format!("Bearer {token1}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // token2 must no longer verify.
        let verify2 = state
            .token_store
            .verify_token(&token2)
            .await
            .expect("verify2");
        assert!(verify2.is_none(), "revoked-by-id token must not verify");

        // token1 must still verify (only the targeted id was revoked).
        let verify1 = state
            .token_store
            .verify_token(&token1)
            .await
            .expect("verify1")
            .expect("verified1");
        assert_eq!(verify1.identity.token_id, id1);
    }

    #[tokio::test]
    async fn delete_tokens_by_id_without_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/some-uuid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_tokens_by_id_with_invalid_bearer_returns_401() {
        let state = test_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/tokens/some-uuid")
                    .header("authorization", "Bearer oac_nonexistent")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
