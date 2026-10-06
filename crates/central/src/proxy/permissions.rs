//! Permissions middleware for the central proxy.
//!
//! This middleware enforces group-based authorization policies after the
//! relay identity has been verified by [`auth_middleware`]. It:
//!
//! 1. Extracts the `VerifiedRelayIdentity` from request extensions.
//! 2. Parses the user's groups (JSON array string).
//! 3. Resolves the effective policy via [`PolicyStore::resolve_policy`].
//! 4. Checks device revocation and auto-registers the device.
//! 5. Checks the endpoint against the policy's allowlist.
//! 6. Checks the model against the policy's allowlist.
//! 7. Checks the daily request and token quotas against the accumulated
//!    usage counters (pre-flight; a single request may overshoot).
//! 8. On denial, writes an audit entry with `permission_decision="denied"`
//!    and returns `403 Forbidden` (or `429 Too Many Requests` for quotas).
//! 9. On allow, inserts a `PermissionDecision` into extensions for the
//!    forward handler to log.
//!
//! # Dev mode
//!
//! In `dev_mode`, if no policies exist for any of the user's groups, the
//! request is allowed (so the dev stack works without policy config). If
//! policies *do* exist, they are enforced even in dev mode.

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;
use crate::optimizer::TokenSaverConfig;

/// The token-saver config resolved for this request, attached to request
/// extensions by the permissions middleware.
///
/// The forward handler reads this to apply the (admin-controlled) safe
/// optimiser to the request body before forwarding. Attaching it here (a
/// security boundary, after auth) guarantees the config comes from the
/// resolved group policy — never from the client.
#[derive(Debug, Clone, Copy)]
pub struct TokenSaverGrant {
    /// The resolved, admin-controlled token-saver config.
    pub config: TokenSaverConfig,
}

/// The permission decision attached to request extensions after the
/// permissions middleware runs.
#[derive(Debug, Clone)]
pub struct PermissionDecision {
    /// `"allowed"` or `"denied"`.
    pub decision: String,
    /// The reason for denial (set when `decision == "denied"`).
    pub reason: Option<String>,
    /// Whether this request consumed an atomic request-quota reservation.
    /// The forward handler uses this to avoid counting the request twice.
    pub request_reserved: bool,
}

/// The permissions middleware.
///
/// Enforces model allowlists and endpoint restrictions based on the user's
/// group policies. See the module docs for details.
pub async fn permissions_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip permissions for health check.
    if request.uri().path() == "/healthz" {
        return Ok(next.run(request).await);
    }

    let endpoint = request.uri().path().to_string();

    // Extract the verified relay identity.
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();

    let identity = match identity {
        Some(id) => id,
        None => {
            // No identity — the outer auth middleware rejects this in every
            // mode. Allow it to continue outward so auth returns the 401.
            return Ok(next.run(request).await);
        }
    };

    // Parse the user's groups.
    let groups: Vec<String> = identity
        .groups
        .as_deref()
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();

    // Resolve the effective policy.
    let policy = match state.policy_store.resolve_policy(&groups).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to resolve policy");
            // Fail open on policy store errors to avoid locking out all
            // users due to a DB issue. Log loudly.
            return Ok(next.run(request).await);
        }
    };

    // Backstop check: if the verified identity carries a token id and
    // created_at (always present when auth came from the token store),
    // reject tokens older than the policy's max_token_ttl_seconds. This
    // is a harder rejection than device revocation — a backstop-violating
    // token is already stale and must not reach the backend. The token
    // row is deleted by check_backstop so it cannot be replayed.
    if let (Some(token_id), Some(created_at)) = (&identity.token_id, identity.created_at) {
        if crate::token_store::check_backstop(created_at, policy.max_token_ttl_seconds) {
            // Delete the stale token row so it cannot be replayed.
            let _ = state.token_store.revoke_by_token_id(token_id).await;
            tracing::warn!(
                token_id = %token_id,
                "token backstop exceeded: token is older than the maximum allowed lifetime"
            );
            return deny(
                &state,
                &identity,
                &endpoint,
                None,
                "token backstop exceeded: token is older than the maximum allowed lifetime",
                StatusCode::UNAUTHORIZED,
            )
            .await;
        }
    }

    // Check device revocation and auto-register the device. The device is
    // identified by the relay-side identity (identity_id, falling back to
    // the subject). In production (mTLS) the transport layer has already
    // authenticated the relay's client certificate; the identity header
    // (set by the relay, unspoofable over mTLS) identifies the user/device.
    // Auto-registration keeps `devices` populated so admins can revoke;
    // `last_seen_at` is refreshed on every request.
    let device_id = identity
        .identity_id
        .clone()
        .unwrap_or_else(|| identity.subject.clone());
    match state.device_store.is_revoked(&device_id).await {
        Ok(Some(true)) => {
            return deny(
                &state,
                &identity,
                &endpoint,
                None,
                "device_revoked",
                StatusCode::FORBIDDEN,
            )
            .await;
        }
        Ok(Some(false)) | Ok(None) => {
            // Not revoked (or not yet registered) — register/refresh.
            if let Err(e) = state
                .device_store
                .upsert_device(&device_id, &identity.subject, identity.email.as_deref())
                .await
            {
                // Best-effort: a failure to register must not block traffic.
                tracing::warn!(error = %e, "failed to upsert device registration");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to check device revocation; allowing");
        }
    }

    // Check endpoint restriction.
    if !policy.is_endpoint_allowed(&endpoint) {
        return deny(
            &state,
            &identity,
            &endpoint,
            None,
            "endpoint_not_allowed",
            StatusCode::FORBIDDEN,
        )
        .await;
    }

    // Check model restriction. We need to read the body to extract the model,
    // then put it back. For GET requests (e.g. /v1/models), there's no body
    // model to check.
    let method = request.method().clone();
    if method == axum::http::Method::POST {
        let (parts, body) = request.into_parts();
        let body_bytes = to_bytes(body, super::MAX_BODY_SIZE).await.map_err(|e| {
            tracing::error!(error = %e, "permissions: failed to read body");
            StatusCode::BAD_REQUEST
        })?;

        let model = http_util::extract_model(&body_bytes);

        if let Some(ref model_name) = model {
            if !policy.is_model_allowed(model_name) {
                return deny(
                    &state,
                    &identity,
                    &endpoint,
                    model.as_deref(),
                    "model_not_allowed",
                    StatusCode::FORBIDDEN,
                )
                .await;
            }
        }

        // Reassemble the request with the body.
        request = Request::from_parts(parts, Body::from(body_bytes));
    }

    // Check daily quotas (pre-flight). Usage counters accumulate as
    // requests complete, so a single request may overshoot its token quota
    // by up to one request's worth of tokens — the next request is denied.
    let mut request_reserved = false;
    if policy.daily_token_quota.is_some() {
        match state.usage_tracker.get_usage(&identity.subject).await {
            Ok(Some(usage)) => {
                if let Some(daily_token_quota) = policy.daily_token_quota {
                    if usage.token_count >= daily_token_quota {
                        return deny(
                            &state,
                            &identity,
                            &endpoint,
                            None,
                            "token_quota_exceeded",
                            StatusCode::TOO_MANY_REQUESTS,
                        )
                        .await;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "failed to check token usage; allowing");
            }
        }
    }
    if let Some(daily_request_quota) = policy.daily_request_quota {
        match state
            .usage_tracker
            .try_reserve_request(
                &identity.subject,
                identity.groups.as_deref(),
                daily_request_quota,
            )
            .await
        {
            Ok(true) => request_reserved = true,
            Ok(false) => {
                return deny(
                    &state,
                    &identity,
                    &endpoint,
                    None,
                    "quota_exceeded",
                    StatusCode::TOO_MANY_REQUESTS,
                )
                .await;
            }
            Err(e) => {
                // Preserve the existing fail-open behavior for database
                // outages, but make the failure visible to operators.
                tracing::warn!(error = %e, "failed to reserve request quota; allowing");
            }
        }
    }

    // All checks passed — insert the permission decision for the forward
    // handler to log, and the resolved token-saver config for it to apply.
    request.extensions_mut().insert(PermissionDecision {
        decision: "allowed".into(),
        reason: None,
        request_reserved,
    });
    // Only attach the token-saver grant when it is enabled; otherwise the
    // forward handler treats the request as un-optimised (no change).
    if policy.token_saver.enabled {
        request.extensions_mut().insert(TokenSaverGrant {
            config: policy.token_saver,
        });
    }

    Ok(next.run(request).await)
}

/// Records a denied audit entry and returns the given status code.
async fn deny(
    state: &AppState,
    identity: &super::auth::VerifiedRelayIdentity,
    endpoint: &str,
    model: Option<&str>,
    reason: &str,
    status: StatusCode,
) -> Result<Response, StatusCode> {
    tracing::warn!(
        user_subject = %identity.subject,
        endpoint = %endpoint,
        model = ?model,
        reason = %reason,
        "request denied by permissions policy"
    );

    let entry = AuditEntry {
        device_id: identity
            .identity_id
            .clone()
            .unwrap_or_else(|| identity.subject.clone()),
        user_subject: identity.subject.clone(),
        model: model.map(String::from),
        // Provider resolution occurs in the forward handler. Denials in this
        // middleware happen before a provider is selected.
        backend: "unresolved".into(),
        status: status.as_u16() as i32,
        latency_ms: 0,
        stream: false,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        identity_id: identity.identity_id.clone(),
        email: identity.email.clone(),
        groups: identity.groups.clone(),
        endpoint: Some(endpoint.to_string()),
        request_id: identity.request_id.clone(),
        permission_decision: Some("denied".into()),
        denial_reason: Some(reason.to_string()),
        cost_usd: None,
        token_saver_applied: None,
        tokens_saved: None,
        messages_dropped: None,
        saver_reasons: None,
        mcp_server: None,
        mcp_tool: None,
        mcp_method: None,
        mcp_args_preview: None,
    };
    if let Err(e) = state.audit.record(&entry).await {
        tracing::error!(error = %e, "failed to write denied audit entry");
    }

    let body = serde_json::json!({
        "error": {
            "message": format!("access denied: {reason}"),
            "type": "permission_denied",
        }
    });
    let response = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build denial response");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderStore;
    use crate::usage::UsageTracker;
    use axum::Router;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    async fn test_state() -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("perms");
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
            provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
            client: reqwest::Client::new(),
            audit,
            rate_limiter: None,
            policy_store: crate::policy::PolicyStore::new(db.clone()),
            device_store: crate::device_store::DeviceStore::new(db.clone()),
            usage_tracker: UsageTracker::new(db.clone()),
            price_table: crate::pricing::PriceTable::empty(),
            mcp_manager: crate::mcp::McpManager::new(mcp_db, Zeroizing::new([7_u8; 32])),
            token_store: crate::token_store::TokenStore::new(db),
            bootstrap_verifier: std::sync::Arc::new(
                crate::oidc_bootstrap::UnavailableBootstrapVerifier,
            ),
        }
    }

    /// Mints a token with the given subject and groups, returns the plaintext.
    async fn mint_test_token(state: &AppState, subject: &str, groups: &str) -> String {
        let minted = state
            .token_store
            .mint_token(&crate::token_store::MintRequest {
                subject: subject.into(),
                issuer: "https://idp.example.com".into(),
                email: None,
                display_name: None,
                groups: Some(groups.into()),
                identity_id: Some(format!("{subject}-identity")),
                label: "test".into(),
                expires_at: None,
                device_fingerprint: None,
            })
            .await
            .expect("mint token");
        minted.plaintext.to_string()
    }
    fn test_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(())
    }

    fn chat_request(token: &str) -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
            ))
            .expect("build request")
    }

    #[tokio::test]
    async fn token_quota_denies_when_accumulated_usage_exceeds() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(500), None)
            .await
            .expect("policy");
        // User already consumed 500 tokens today.
        state
            .usage_tracker
            .increment("quota-user", None, 1, 500, 0.0)
            .await
            .expect("seed usage");

        let token_quota_user = mint_test_token(&state, "quota-user", r#"["engineering"]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_quota_user))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "accumulated tokens at the quota must deny with 429"
        );
    }

    #[tokio::test]
    async fn token_quota_denial_has_precise_error_audit_and_no_side_effects() {
        use sea_orm::EntityTrait;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(500), None)
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-audit", None, 1, 500, 0.125)
            .await
            .expect("seed usage");

        let downstream_calls = Arc::new(AtomicUsize::new(0));
        let calls = downstream_calls.clone();
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        "must not run"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::super::auth::auth_middleware,
            ))
            .with_state(());

        let token_quota_user_audit =
            mint_test_token(&state, "quota-user-audit", r#"["engineering"]"#).await;
        let response = app
            .oneshot(chat_request(&token_quota_user_audit))
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body_bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("read denial body");
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("JSON denial body");
        assert_eq!(body["error"]["type"], "permission_denied");
        assert_eq!(
            body["error"]["message"],
            "access denied: token_quota_exceeded"
        );
        assert_eq!(downstream_calls.load(Ordering::SeqCst), 0);

        let usage = state
            .usage_tracker
            .get_usage("quota-user-audit")
            .await
            .expect("usage")
            .expect("seed usage remains");
        assert_eq!(
            usage.request_count, 1,
            "denied request must not increment usage"
        );
        assert_eq!(usage.token_count, 500);

        let audits = crate::entity::audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit rows");
        let denial = audits.last().expect("denial audit row");
        assert_eq!(denial.status, 429);
        assert_eq!(denial.permission_decision.as_deref(), Some("denied"));
        assert_eq!(
            denial.denial_reason.as_deref(),
            Some("token_quota_exceeded")
        );
        assert_eq!(denial.user_subject, "quota-user-audit");
    }

    #[tokio::test]
    async fn token_quota_allows_when_under_quota() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, Some(1000), None)
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-2", None, 1, 499, 0.0)
            .await
            .expect("seed usage");

        let token_quota_user_2 =
            mint_test_token(&state, "quota-user-2", r#"["engineering"]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_quota_user_2))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "tokens under the quota must be allowed"
        );
    }

    #[tokio::test]
    async fn token_quota_unset_allows_any_usage() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-3", None, 5, 1_000_000, 0.0)
            .await
            .expect("seed usage");

        let token_quota_user_3 =
            mint_test_token(&state, "quota-user-3", r#"["engineering"]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_quota_user_3))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "no token quota configured means unlimited"
        );
    }

    #[tokio::test]
    async fn request_quota_still_denies_when_exceeded() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, Some(1))
            .await
            .expect("policy");
        state
            .usage_tracker
            .increment("quota-user-4", None, 1, 0, 0.0)
            .await
            .expect("seed usage");

        let token_quota_user_4 =
            mint_test_token(&state, "quota-user-4", r#"["engineering"]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_quota_user_4))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request-count quota must still be enforced"
        );
    }

    #[tokio::test]
    async fn concurrent_requests_cannot_oversubscribe_request_quota() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, Some(1))
            .await
            .expect("policy");
        let usage_tracker = state.usage_tracker.clone();
        let downstream_calls = Arc::new(AtomicUsize::new(0));
        let calls = downstream_calls.clone();
        let token_concurrent_user =
            mint_test_token(&state, "concurrent-user", r#"["engineering"]"#).await;
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(move || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        "allowed"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(());

        // All requests start concurrently. A read-then-forward implementation
        // would let every request observe request_count=0 and reach the
        // handler. The atomic reservation must admit exactly one.
        let requests = (0..16).map(|_| chat_request(&token_concurrent_user));
        let responses =
            futures::future::join_all(requests.map(|request| app.clone().oneshot(request))).await;
        let responses = responses
            .into_iter()
            .map(|response| response.expect("middleware run"))
            .collect::<Vec<_>>();

        let allowed = responses
            .iter()
            .filter(|response| response.status() == StatusCode::OK)
            .count();
        let denied = responses
            .iter()
            .filter(|response| response.status() == StatusCode::TOO_MANY_REQUESTS)
            .count();
        assert_eq!(allowed, 1, "exactly one request may reserve quota=1");
        assert_eq!(denied, 15, "all concurrent excess requests must be denied");
        assert_eq!(downstream_calls.load(Ordering::SeqCst), 1);

        let usage = usage_tracker
            .get_usage("concurrent-user")
            .await
            .expect("usage")
            .expect("reservation row");
        assert_eq!(
            usage.request_count, 1,
            "quota reservation must be counted once"
        );
    }

    #[tokio::test]
    async fn rate_limited_request_does_not_consume_request_quota() {
        let mut state = test_state().await;
        state.config.dev_mode = false;
        state.rate_limiter = Some(crate::proxy::rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(3600),
        ));
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, Some(2))
            .await
            .expect("policy");
        let usage_tracker = state.usage_tracker.clone();
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "allowed" }),
            )
            // This layer order matches proxy::router: rate limiting runs
            // before permissions can reserve request quota.
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::proxy::rate_limit::rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::super::auth::auth_middleware,
            ))
            .with_state(());

        let token_rate_user = mint_test_token(&state, "rate-user", r#"["engineering"]"#).await;
        let first = app
            .clone()
            .oneshot(chat_request(&token_rate_user))
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::OK);

        // Same default client IP exhausts the token bucket. This request is
        // rejected before permissions can reserve the second quota slot.
        let second = app
            .oneshot(chat_request(&token_rate_user))
            .await
            .expect("second request");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        let usage = usage_tracker
            .get_usage("rate-user")
            .await
            .expect("usage")
            .expect("first reservation");
        assert_eq!(usage.request_count, 1);
    }

    #[tokio::test]
    async fn device_auto_registers_on_first_request() {
        let state = test_state().await;
        let device_store = state.device_store.clone();

        let token_device_user = mint_test_token(&state, "device-user", r#"[]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_device_user))
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::OK);

        let devices = device_store.list_devices().await.expect("list devices");
        let device = devices
            .iter()
            .find(|d| d.cert_fingerprint == "device-user-identity")
            .expect("device must be auto-registered keyed by identity_id");
        assert_eq!(device.user_subject, "device-user");
        assert!(!device.revoked);
    }

    #[tokio::test]
    async fn revoked_device_is_denied() {
        let state = test_state().await;
        state
            .device_store
            .upsert_device("device-user-identity", "device-user", None)
            .await
            .expect("register");
        state
            .device_store
            .revoke("device-user-identity")
            .await
            .expect("revoke");

        let token_device_user = mint_test_token(&state, "device-user", r#"[]"#).await;
        let response = test_router(state)
            .oneshot(chat_request(&token_device_user))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a revoked device must be denied"
        );
    }

    // --- Endpoint / model allowlist denials (user-facing UX) ---

    #[tokio::test]
    async fn endpoint_not_allowed_denies_with_reason_and_audit() {
        use sea_orm::EntityTrait;

        let state = test_state().await;
        // Only chat completions is permitted for this group.
        state
            .policy_store
            .upsert_policy(
                "restricted",
                None,
                Some(r#"["/v1/chat/completions"]"#),
                None,
                None,
            )
            .await
            .expect("policy");

        // /v1/embeddings is not on the allowlist → 403 with a JSON body that
        // names the reason so agents surface something actionable.
        let token_endpoint_user =
            mint_test_token(&state, "endpoint-user", r#"["restricted"]"#).await;
        let response = test_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/embeddings")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_endpoint_user}"))
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#.to_string()))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["error"]["type"], "permission_denied");
        assert_eq!(
            json["error"]["message"], "access denied: endpoint_not_allowed",
            "the denial reason must be machine-readable: {json}"
        );

        // The denial is audited with the reason, for admin review.
        let audits = crate::entity::audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit rows");
        let denial = audits.last().expect("denial row");
        assert_eq!(denial.permission_decision.as_deref(), Some("denied"));
        assert_eq!(
            denial.denial_reason.as_deref(),
            Some("endpoint_not_allowed")
        );
        assert_eq!(denial.user_subject, "endpoint-user");
        assert_eq!(denial.endpoint.as_deref(), Some("/v1/embeddings"));
    }

    #[tokio::test]
    async fn allowed_endpoint_passes_and_gets_have_no_model_check() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("restricted", None, Some(r#"["/v1/models"]"#), None, None)
            .await
            .expect("policy");
        let token_list_models_user =
            mint_test_token(&state, "list-models-user", r#"["restricted"]"#).await;

        // A router with both routes so GET /v1/models resolves.
        let app = Router::new()
            .route("/v1/models", axum::routing::get(|| async { "ok" }))
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(());

        // GET /v1/models is allowlisted → passes (and has no body/model to
        // check, exercising the non-POST path).
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::GET)
                    .uri("/v1/models")
                    .header("authorization", format!("Bearer {token_list_models_user}"))
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::OK);

        // POST to an endpoint not on the list → denied.
        let response = app
            .oneshot(chat_request(&token_list_models_user))
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn model_not_allowed_denies_with_reason_and_audit() {
        use sea_orm::EntityTrait;

        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("restricted", Some(r#"["gpt-4o"]"#), None, None, None)
            .await
            .expect("policy");
        let token_model_user = mint_test_token(&state, "model-user", r#"["restricted"]"#).await;

        // Request a model outside the allowlist.
        let response = test_router(state.clone())
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_model_user}"))
                    .body(Body::from(
                        r#"{"model":"o1-preview","messages":[]}"#.to_string(),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            json["error"]["message"], "access denied: model_not_allowed",
            "the denial reason must be machine-readable: {json}"
        );

        // The audit row records WHICH model was requested.
        let audits = crate::entity::audit_log::Entity::find()
            .all(state.audit.db())
            .await
            .expect("audit rows");
        let denial = audits.last().expect("denial row");
        assert_eq!(denial.denial_reason.as_deref(), Some("model_not_allowed"));
        assert_eq!(
            denial.model.as_deref(),
            Some("o1-preview"),
            "the audit row must name the denied model"
        );
    }

    #[tokio::test]
    async fn request_without_identity_passes_permissions_to_auth() {
        // No VerifiedRelayIdentity in extensions (e.g. dev mode without
        // headers): permissions must defer to auth rather than 500.
        let state = test_state().await;
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                permissions_middleware,
            ))
            .with_state(());

        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#.to_string()))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "permissions must pass identity-less requests through to auth"
        );
    }

    #[tokio::test]
    async fn healthz_bypasses_permissions() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy(
                "restricted",
                None,
                Some(r#"[]"#), // nothing allowed
                None,
                None,
            )
            .await
            .expect("policy");

        let app = Router::new()
            .route("/healthz", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                permissions_middleware,
            ))
            .with_state(());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(response.status(), StatusCode::OK);
    }

    // --- Token TTL backstop (admin-controlled max_token_ttl_seconds) ---

    /// Mints a token and backdates its `created_at` so it is older than the
    /// given TTL cap. Returns the plaintext bearer token and the token row
    /// id (so the caller can verify the row was deleted).
    async fn mint_and_backdate(
        state: &AppState,
        subject: &str,
        groups: &str,
        age_secs: i64,
    ) -> (String, String) {
        use sea_orm::{ConnectionTrait, Statement};
        let minted = state
            .token_store
            .mint_token(&crate::token_store::MintRequest {
                subject: subject.into(),
                issuer: "https://idp.example.com".into(),
                email: None,
                display_name: None,
                groups: Some(groups.into()),
                identity_id: Some(format!("{subject}-identity")),
                label: "test".into(),
                expires_at: None,
                device_fingerprint: None,
            })
            .await
            .expect("mint token");
        let token_id = minted.token_id.clone();
        // Backdate created_at by age_secs.
        let old_created =
            oidc_agent_common::time_util::now_utc() - time::Duration::seconds(age_secs);
        let old_str = oidc_agent_common::time_util::format_time(&old_created);
        let sql = "UPDATE tokens SET created_at = $1 WHERE id = $2";
        state
            .audit
            .db()
            .execute(Statement::from_sql_and_values(
                state.audit.db().get_database_backend(),
                sql,
                vec![old_str.into(), token_id.clone().into()],
            ))
            .await
            .expect("backdate");
        (minted.plaintext.to_string(), token_id)
    }

    /// Verifies a token row exists (or not) by id.
    async fn token_row_exists(state: &AppState, token_id: &str) -> bool {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        crate::entity::token::Entity::find()
            .filter(crate::entity::token::Column::Id.eq(token_id))
            .one(state.audit.db())
            .await
            .expect("query")
            .is_some()
    }

    #[tokio::test]
    async fn backstop_denies_token_older_than_max_ttl_and_deletes_token() {
        let state = test_state().await;
        // Policy: max token lifetime 500 seconds.
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
                Some(500),
            )
            .await
            .expect("policy");

        // Mint a token and backdate it to 1000 seconds ago (exceeds 500s cap).
        let (token, token_id) =
            mint_and_backdate(&state, "backstop-user", r#"["engineering"]"#, 1000).await;

        let response = test_router(state.clone())
            .oneshot(chat_request(&token))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a token older than max_token_ttl_seconds must be denied with 401"
        );

        // The stale token row must have been deleted so it cannot be replayed.
        assert!(
            !token_row_exists(&state, &token_id).await,
            "backstop-violating token must be deleted"
        );
    }

    #[tokio::test]
    async fn backstop_allows_token_within_max_ttl() {
        let state = test_state().await;
        // Policy: max token lifetime 5000 seconds.
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
                Some(5000),
            )
            .await
            .expect("policy");

        // Mint a token and backdate it to 100 seconds ago (within 5000s cap).
        let (token, token_id) =
            mint_and_backdate(&state, "backstop-ok-user", r#"["engineering"]"#, 100).await;

        let response = test_router(state.clone())
            .oneshot(chat_request(&token))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a token within max_token_ttl_seconds must be allowed"
        );

        // The token must still exist (not deleted).
        assert!(
            token_row_exists(&state, &token_id).await,
            "a valid token must not be deleted by the backstop check"
        );
    }

    #[tokio::test]
    async fn backstop_no_cap_allows_any_age() {
        // No max_token_ttl_seconds configured → no backstop, any age allowed.
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("policy");

        let (token, _token_id) =
            mint_and_backdate(&state, "backstop-nocap-user", r#"["engineering"]"#, 100_000).await;

        let response = test_router(state)
            .oneshot(chat_request(&token))
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "no max_token_ttl_seconds means no backstop — any age allowed"
        );
    }

    #[tokio::test]
    async fn post_request_without_model_field_is_allowed() {
        // A POST body without a `model` field must pass (no model to check).
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("policy");
        let token = mint_test_token(&state, "nomodel", r#"["engineering"]"#).await;
        let app = Router::new()
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"messages":[]}"#))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "POST without a model field must pass the model check"
        );
    }

    #[tokio::test]
    async fn model_allowlist_with_none_means_all_models_allowed() {
        // A group with allowed_models=None (all allowed) must let any model
        // through the permissions middleware.
        let state = test_state().await;
        state
            .policy_store
            .upsert_policy("open", None, None, None, None)
            .await
            .expect("policy");
        let token = mint_test_token(&state, "open-user", r#"["open"]"#).await;
        let response = test_router(state)
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"model":"any-model","messages":[]}"#.to_string(),
                    ))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "None models allowlist means all models allowed"
        );
    }

    // --- device fingerprint binding enforcement ---

    /// Mints a token with a device fingerprint, returns the plaintext.
    async fn mint_test_token_with_fingerprint(
        state: &AppState,
        subject: &str,
        groups: &str,
        fingerprint: &str,
    ) -> String {
        let minted = state
            .token_store
            .mint_token(&crate::token_store::MintRequest {
                subject: subject.into(),
                issuer: "https://idp.example.com".into(),
                email: None,
                display_name: None,
                groups: Some(groups.into()),
                identity_id: Some(format!("{subject}-identity")),
                label: "test".into(),
                expires_at: None,
                device_fingerprint: Some(fingerprint.into()),
            })
            .await
            .expect("mint token");
        minted.plaintext.to_string()
    }

    #[tokio::test]
    async fn device_fingerprint_match_allows_request() {
        let state = test_state().await;
        let token =
            mint_test_token_with_fingerprint(&state, "alice", r#"["engineering"]"#, "fp-aabb1122")
                .await;
        let app = test_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-oac-device-fingerprint", "fp-aabb1122")
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "matching device fingerprint must allow the request"
        );
    }

    #[tokio::test]
    async fn device_fingerprint_mismatch_rejects_request() {
        let state = test_state().await;
        let token =
            mint_test_token_with_fingerprint(&state, "alice", r#"["engineering"]"#, "fp-correct")
                .await;
        let app = test_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-oac-device-fingerprint", "fp-wrong")
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "device fingerprint mismatch must reject with 401"
        );
    }

    #[tokio::test]
    async fn device_fingerprint_missing_when_stored_rejects_request() {
        let state = test_state().await;
        let token =
            mint_test_token_with_fingerprint(&state, "alice", r#"["engineering"]"#, "fp-stored")
                .await;
        let app = test_router(state);
        // No x-oac-device-fingerprint header on the request.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing fingerprint header with stored fingerprint must reject with 401"
        );
    }

    #[tokio::test]
    async fn device_fingerprint_none_skips_check() {
        let state = test_state().await;
        // Mint a token WITHOUT a device fingerprint (dev mode).
        let token = mint_test_token(&state, "alice", r#"["engineering"]"#).await;
        let app = test_router(state);
        // No fingerprint header — should be allowed because the token has no
        // stored fingerprint (dev mode).
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"model":"gpt-4","messages":[]}"#))
                    .expect("build request"),
            )
            .await
            .expect("middleware run");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "no stored fingerprint → skip device binding check"
        );
    }
}
