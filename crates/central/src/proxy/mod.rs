//! Proxy core for the central proxy.
//!
//! This module implements the Axum router, auth middleware, and forward
//! handler that receives mTLS-authenticated relay requests and forwards
//! them to a runtime-selected OpenAI-compatible provider.
//!
//! # Security
//!
//! - **Master key injection**: the master backend key is loaded from the
//!   secret store into `Zeroizing` memory and injected into upstream
//!   requests. It never appears in logs, errors, or responses.
//! - **Hop-by-hop header stripping** (RFC 7230 §6.1).
//! - **SSRF prevention**: the backend URL comes from config only.
//! - **Raw byte SSE passthrough** for streaming responses.
//! - **Audit logging**: every request is recorded.

use std::sync::Arc;

pub mod auth;
pub mod forward;
pub mod mcp_forward;
pub mod mcp_hub;
pub mod mcp_permissions;
pub mod permissions;
pub mod rate_limit;
pub mod tokens;

use crate::audit::AuditLogger;
use crate::device_store::DeviceStore;
use crate::policy::PolicyStore;
use crate::pricing::PriceTable;
use crate::provider::ProviderStore;
use crate::usage::UsageTracker;
use axum::Router;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::error::Result;
use tower_http::limit::RequestBodyLimitLayer;

/// The shared application state for the central proxy.
#[derive(Clone)]
pub struct AppState {
    /// The central proxy configuration.
    pub config: CentralConfig,
    /// Runtime-managed providers and encrypted API keys.
    pub provider_store: ProviderStore,
    /// The HTTP client for forwarding to the backend.
    pub client: reqwest::Client,
    /// The audit logger.
    pub audit: AuditLogger,
    /// The rate limiter (None in dev mode).
    pub rate_limiter: Option<rate_limit::RateLimiter>,
    /// The group policy store.
    pub policy_store: PolicyStore,
    /// The device store.
    pub device_store: DeviceStore,
    /// The usage tracker (for quota enforcement and reporting).
    pub usage_tracker: UsageTracker,
    /// The pricing table (for cost tracking; empty if no pricing configured).
    pub price_table: PriceTable,
    /// The runtime MCP server registry.
    pub mcp_manager: crate::mcp::McpManager,
    /// The central token store (zero-trust opaque tokens).
    pub token_store: crate::token_store::TokenStore,
    /// Exchanges OIDC authorization codes and returns centrally verified identities.
    pub bootstrap_verifier: Arc<dyn crate::oidc_bootstrap::BootstrapIdentityVerifier>,
}

impl AppState {
    /// Returns the admin group name if the admin API is enabled, or `None`
    /// if the admin config is absent (admin API disabled).
    #[must_use]
    pub fn admin_group(&self) -> Option<&str> {
        self.config.admin.as_ref().map(|a| a.admin_group.as_str())
    }
}

/// The maximum request body size (10 MB).
///
/// Re-exported from [`oidc_agent_common::http_util`] so both proxies share
/// a single source of truth.
pub const MAX_BODY_SIZE: usize = oidc_agent_common::http_util::MAX_BODY_SIZE;

/// Builds the Axum router for the central proxy.
///
/// # Security
///
/// The router applies the auth middleware (validating relay-forwarded
/// identity headers) before the proxy handler. Body size limits are applied
/// globally.
pub fn router(state: AppState) -> Router {
    let mut proxy_router = Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route(
            "/v1/chat/completions",
            axum::routing::post(forward::proxy_handler),
        )
        .route("/v1/responses", axum::routing::post(forward::proxy_handler))
        .route("/v1/models", axum::routing::get(forward::proxy_handler))
        .route(
            "/v1/embeddings",
            axum::routing::post(forward::proxy_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            permissions::permissions_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state.clone());

    // MCP routes: a Streamable-HTTP endpoint per configured server, plus the
    // combined /mcp hub endpoint. Both use the same auth middleware and body
    // limit. Per-tool enforcement runs on the per-server route via the mcp
    // permissions middleware, and inline in the hub handler.
    let mcp_router = Router::new()
        .route(
            "/mcp/{server}",
            axum::routing::any(mcp_forward::mcp_handler),
        )
        .route("/mcp", axum::routing::post(mcp_hub::mcp_hub_handler))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            mcp_permissions::mcp_permissions_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state.clone());
    proxy_router = proxy_router.merge(mcp_router);

    // Token API routes: mint (mTLS-authenticated, no middleware), revoke and
    // list (bearer-token auth, handled in the handlers). These are mounted
    // WITHOUT the existing auth middleware — they use their own auth.
    let token_router = Router::new()
        .route(
            "/v1/tokens",
            axum::routing::post(tokens::mint_token_handler),
        )
        .route(
            "/v1/tokens/current",
            axum::routing::delete(tokens::revoke_current_handler),
        )
        .route(
            "/v1/tokens/{id}",
            axum::routing::delete(tokens::revoke_by_id_handler),
        )
        .route(
            "/v1/tokens",
            axum::routing::get(tokens::list_tokens_handler),
        )
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE))
        .with_state(state.clone());
    proxy_router = proxy_router.merge(token_router);

    // Merge the admin API router if an admin config is present.
    if let Some(admin_group) = state.admin_group() {
        let admin_state = crate::admin::AdminState {
            policy_store: state.policy_store.clone(),
            provider_store: state.provider_store.clone(),
            device_store: state.device_store.clone(),
            audit: state.audit.clone(),
            usage_tracker: state.usage_tracker.clone(),
            mcp_manager: state.mcp_manager.clone(),
            token_store: state.token_store.clone(),
            admin_group: admin_group.to_string(),
        };
        proxy_router = proxy_router.merge(crate::admin::router(admin_state));
    }

    proxy_router
}

/// Starts the central proxy server.
///
/// # Security
///
/// In production mode (`dev_mode = false`), the server binds with mTLS
/// (TLS 1.3) using the company CA, requiring relay client certificates. In
/// dev mode, it serves plain HTTP (for the containerized dev stack where
/// mTLS is not needed).
///
/// # Errors
///
/// Returns [`Error`] if the server fails to bind or start.
pub async fn serve(
    config: CentralConfig,
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
    audit: AuditLogger,
) -> Result<()> {
    let bootstrap_verifier =
        Arc::new(crate::oidc_bootstrap::OidcBootstrapVerifier::discover(&config.oidc).await?);
    serve_with_bootstrap_verifier(config, encryption_key, audit, bootstrap_verifier).await
}

async fn serve_with_bootstrap_verifier(
    config: CentralConfig,
    encryption_key: zeroize::Zeroizing<[u8; 32]>,
    audit: AuditLogger,
    bootstrap_verifier: Arc<dyn crate::oidc_bootstrap::BootstrapIdentityVerifier>,
) -> Result<()> {
    let client = forward::build_client()?;
    let rate_limiter = if config.dev_mode {
        None
    } else {
        Some(rate_limit::RateLimiter::new(
            config.rate_limit_requests,
            std::time::Duration::from_secs(config.rate_limit_window_secs),
        ))
    };
    let policy_store = PolicyStore::new(audit.db().clone());
    let device_store = DeviceStore::new(audit.db().clone());
    let provider_store = ProviderStore::new(audit.db().clone(), encryption_key.clone());
    let mcp_manager = crate::mcp::McpManager::new(audit.db().clone(), encryption_key);
    let usage_tracker = UsageTracker::new(audit.db().clone());
    let token_store = crate::token_store::TokenStore::new(audit.db().clone());
    let price_table = config
        .pricing
        .as_ref()
        .map(PriceTable::from_config)
        .unwrap_or_else(PriceTable::empty);

    // Periodically auto-fetch model prices from each enabled provider's
    // /v1/models endpoint (e.g. OpenRouter's pricing catalog). Manual
    // pricing entries act as overrides and are never overwritten. An
    // interval of 0 disables auto-fetch; each cycle re-lists providers so
    // runtime-managed changes are picked up within one interval.
    let fetch_interval_secs = config
        .pricing
        .as_ref()
        .map(|p| p.fetch_interval_secs)
        .unwrap_or(0);
    if fetch_interval_secs > 0 {
        price_table.spawn_provider_price_refresh(
            provider_store.clone(),
            client.clone(),
            std::time::Duration::from_secs(fetch_interval_secs),
        );
        tracing::debug!(
            interval_secs = fetch_interval_secs,
            "periodic provider price refresh enabled"
        );
    }

    let state = AppState {
        config: config.clone(),
        provider_store,
        client,
        audit,
        rate_limiter,
        policy_store,
        device_store,
        usage_tracker,
        price_table,
        mcp_manager,
        token_store,
        bootstrap_verifier,
    };
    let app = router(state);

    if config.dev_mode {
        // Dev mode: plain HTTP (for containerized dev stack).
        let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
        tracing::info!(
            "central proxy listening on {} (dev HTTP)",
            config.listen_addr
        );
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(oidc_agent_common::shutdown::shutdown_signal())
        .await?;
        return Ok(());
    }

    // Production mode: mTLS (TLS 1.3, client cert required).
    let server_config = oidc_agent_common::mtls::build_server_config(
        &config.mtls.ca_cert_path,
        &config.mtls.server_cert_path,
        &config.mtls.server_key_path,
    )?;

    // Set ALPN protocols for HTTP/1.1 (axum-server requires this when
    // building from a raw ServerConfig).
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        let _ = oidc_agent_common::shutdown::shutdown_signal().await;
        shutdown_handle.shutdown();
    });

    tracing::info!("central proxy listening on {} (mTLS)", config.listen_addr);
    axum_server::bind_rustls(config.listen_addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogger;
    use crate::device_store::DeviceStore;
    use crate::policy::PolicyStore;
    use crate::provider::ProviderStore;
    use crate::usage::UsageTracker;
    use axum::http::StatusCode;
    use oidc_agent_common::config::{AdminConfig, CentralConfig};
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    /// Builds a minimal dev-mode AppState for middleware-level tests.
    async fn test_state(admin: Option<AdminConfig>) -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("proxy-mod");
        let db = crate::db::setup(&url).await.expect("db setup");
        let audit = AuditLogger::new(db.clone());
        let mcp_db = db.clone();
        AppState {
            config: CentralConfig {
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
                admin,
                pricing: None,
                dev_mode: true,
                rate_limit_requests: 60,
                rate_limit_window_secs: 60,
            },
            provider_store: ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32])),
            client: reqwest::Client::new(),
            audit,
            rate_limiter: None,
            policy_store: PolicyStore::new(db.clone()),
            device_store: DeviceStore::new(db.clone()),
            usage_tracker: UsageTracker::new(db.clone()),
            price_table: crate::pricing::PriceTable::empty(),
            mcp_manager: crate::mcp::McpManager::new(mcp_db, Zeroizing::new([7_u8; 32])),
            token_store: crate::token_store::TokenStore::new(db),
            bootstrap_verifier: Arc::new(crate::oidc_bootstrap::UnavailableBootstrapVerifier),
        }
    }

    fn admin_group_config() -> AdminConfig {
        AdminConfig {
            admin_group: "oac-admins".into(),
        }
    }

    #[tokio::test]
    async fn router_mounts_admin_api_when_admin_config_present() {
        let state = test_state(Some(admin_group_config())).await;
        // Mint an admin token (subject in the admin group).
        let minted = state
            .token_store
            .mint_token(&crate::token_store::MintRequest {
                subject: "alice".into(),
                issuer: "https://idp.example.com".into(),
                email: None,
                display_name: None,
                groups: Some(r#"["oac-admins"]"#.into()),
                identity_id: None,
                label: "test".into(),
                expires_at: None,
                device_fingerprint: None,
            })
            .await
            .expect("mint token");
        let admin_token = minted.plaintext.to_string();
        let app = router(state);

        // Without a bearer token the admin API must refuse (401), proving
        // the routes + auth middleware are mounted.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/admin/v1/group-policies")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With an admin bearer token the same route answers 200.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/admin/v1/group-policies")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_omits_admin_api_when_admin_config_absent() {
        let state = test_state(None).await;
        let app = router(state);

        // No admin config → the admin routes must not exist at all (404,
        // not 401/403), so operators cannot probe a disabled surface.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/admin/v1/group-policies")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_group_helper_reflects_config() {
        let with = test_state(Some(admin_group_config())).await;
        assert_eq!(with.admin_group(), Some("oac-admins"));
        let without = test_state(None).await;
        assert_eq!(without.admin_group(), None);
    }

    // --- rate-limit middleware UX ---

    /// Wraps the rate-limit middleware around an always-OK handler. The
    /// caller controls `dev_mode`/`rate_limiter` on the state.
    fn rate_limited_app(state: AppState) -> axum::Router {
        axum::Router::new()
            .route("/v1/models", axum::routing::get(|| async { "ok" }))
            .route("/healthz", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                rate_limit::rate_limit_middleware,
            ))
            .with_state(())
    }

    #[tokio::test]
    async fn rate_limit_returns_429_with_retry_after_and_json_body() {
        let mut state = test_state(None).await;
        state.config.dev_mode = false;
        state.rate_limiter = Some(rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        let app = rate_limited_app(state);

        let first = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("first");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("second");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        // The Retry-After header must be present and numeric so agents can
        // back off for the exact refill time.
        let retry_after = second
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .expect("retry-after header");
        let secs: u64 = retry_after.parse().expect("numeric retry-after");
        assert!(secs >= 1, "retry-after must be at least 1s, got {secs}");
        let body = axum::body::to_bytes(second.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"]["type"], "rate_limit_error");
        assert_eq!(json["error"]["retry_after_secs"], secs);
    }

    #[tokio::test]
    async fn rate_limit_skips_healthz_even_when_limiter_engaged() {
        let mut state = test_state(None).await;
        state.config.dev_mode = false;
        state.rate_limiter = Some(rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        let app = rate_limited_app(state);

        // Exhaust the bucket on the API route…
        let _ = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("exhaust");
        // …health checks must still succeed so orchestrators don't kill the
        // pod over a rate-limited data plane.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("healthz");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rate_limit_disabled_in_dev_mode_and_without_limiter() {
        // Dev mode: middleware is a no-op even with a 1-request limiter.
        let mut state = test_state(None).await;
        state.config.dev_mode = true;
        state.rate_limiter = Some(rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        let app = rate_limited_app(state);
        for _ in 0..3 {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/models")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("request");
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Production mode but no limiter configured: also a no-op.
        let mut state = test_state(None).await;
        state.config.dev_mode = false;
        state.rate_limiter = None;
        let app = rate_limited_app(state);
        for _ in 0..3 {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/v1/models")
                        .body(axum::body::Body::empty())
                        .expect("request"),
                )
                .await
                .expect("request");
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    /// Verifies the rate-limit middleware keys on the `ConnectInfo<SocketAddr>`
    /// extension (injected by `into_make_service_with_connect_info`) rather
    /// than falling back to `0.0.0.0`. Two distinct client IPs must get
    /// independent buckets even when the global capacity is 1.
    #[tokio::test]
    async fn rate_limit_keys_on_connect_info_not_global_bucket() {
        let mut state = test_state(None).await;
        state.config.dev_mode = false;
        state.rate_limiter = Some(rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        let app = rate_limited_app(state);

        let ip1: std::net::SocketAddr = "203.0.113.1:1234".parse().expect("addr");
        let ip2: std::net::SocketAddr = "203.0.113.2:5678".parse().expect("addr");

        // First request from ip1 — consumes the single token in ip1's bucket.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .extension(axum::extract::ConnectInfo(ip1))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ip1 first");
        assert_eq!(resp.status(), StatusCode::OK);

        // Second request from ip1 — same bucket, now exhausted → 429.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .extension(axum::extract::ConnectInfo(ip1))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ip1 second");
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // First request from ip2 — independent bucket, must succeed even
        // though ip1 is exhausted. If the middleware fell back to 0.0.0.0
        // (the pre-fix bug), this would share ip1's bucket and fail.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/models")
                    .extension(axum::extract::ConnectInfo(ip2))
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("ip2 first");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "distinct client IP must get an independent bucket"
        );
    }

    #[test]
    fn too_many_requests_response_is_well_formed() {
        let resp = rate_limit::too_many_requests_response(7);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("7"),
            "the header must echo the computed refill time, not a constant"
        );
    }

    // --- serve() boot + graceful shutdown ---
    //
    // NOTE: exactly ONE test in this binary may send a signal to the test
    // process - the handler is process-wide, so a SIGTERM resolves every
    // concurrent shutdown_signal() future. Both serve modes are therefore
    // exercised inside a single test.

    /// Boots the real `serve()` in BOTH modes (dev HTTP and production
    /// mTLS), verifies the mTLS listener rejects certless clients, then
    /// SIGTERMs the process and asserts both shut down cleanly.
    #[cfg(unix)]
    #[tokio::test]
    async fn serve_boots_dev_and_mtls_then_shuts_down_gracefully() {
        let dev_url = oidc_agent_common::persistence::temp_sqlite_url("serve-dev");
        let dev_db = crate::db::setup(&dev_url).await.expect("db setup");
        let dev_audit = AuditLogger::new(dev_db);

        let base_config = CentralConfig {
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
        };

        // Dev-mode serve().
        let dev_config = base_config.clone();
        let dev_task = tokio::spawn(async move {
            super::serve_with_bootstrap_verifier(
                dev_config,
                Zeroizing::new([7_u8; 32]),
                dev_audit,
                Arc::new(crate::oidc_bootstrap::UnavailableBootstrapVerifier),
            )
            .await
        });

        // Production mTLS serve().
        use oidc_agent_common::test_certs::generate_test_certs;
        let certs = generate_test_certs();
        let dir = std::env::temp_dir().join(format!(
            "oac-serve-mtls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let ca = dir.join("ca.crt");
        let server_cert = dir.join("server.crt");
        let server_key = dir.join("server.key");
        std::fs::write(&ca, &certs.ca_cert).expect("ca");
        std::fs::write(&server_cert, &certs.server_cert).expect("cert");
        std::fs::write(&server_key, &certs.server_key).expect("key");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }

        let mtls_url = oidc_agent_common::persistence::temp_sqlite_url("serve-mtls");
        let mtls_db = crate::db::setup(&mtls_url).await.expect("db setup");
        let mtls_audit = AuditLogger::new(mtls_db);

        // serve() does not return the bound address, so reserve a port,
        // release it, and pin the config to it.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe bind");
        let mtls_port = probe.local_addr().expect("addr").port();
        drop(probe);

        let mut mtls_config = base_config;
        mtls_config.listen_addr = format!("127.0.0.1:{mtls_port}").parse().expect("addr");
        mtls_config.mtls = oidc_agent_common::config::MtlsServerConfig {
            ca_cert_path: ca.clone(),
            server_cert_path: server_cert.clone(),
            server_key_path: server_key.clone(),
        };
        mtls_config.dev_mode = false;

        let mtls_task = tokio::spawn(async move {
            super::serve_with_bootstrap_verifier(
                mtls_config,
                Zeroizing::new([7_u8; 32]),
                mtls_audit,
                Arc::new(crate::oidc_bootstrap::UnavailableBootstrapVerifier),
            )
            .await
        });

        // Wait for the mTLS listener to accept TCP connections.
        let mut tls_up = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", mtls_port))
                .await
                .is_ok()
            {
                tls_up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(tls_up, "mTLS listener must come up");

        // A plain HTTPS client WITHOUT a client certificate must fail the
        // handshake - this is the mTLS guarantee serve() configures.
        let certless = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("certless client");
        let refused = certless
            .get(format!("https://127.0.0.1:{mtls_port}/healthz"))
            .send()
            .await;
        assert!(
            refused.is_err(),
            "a certless client must not complete the TLS handshake"
        );

        // Both servers must still be running.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !dev_task.is_finished() && !mtls_task.is_finished(),
            "both serve() tasks must run until signalled"
        );

        // One SIGTERM shuts both down gracefully (the handler is
        // process-wide, matching real operator behaviour).
        let pid = std::process::id().to_string();
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("send SIGTERM");
        assert!(status.success(), "kill -TERM must succeed");

        let dev_result = tokio::time::timeout(std::time::Duration::from_secs(10), dev_task)
            .await
            .expect("dev serve() must return after SIGTERM")
            .expect("join dev serve task");
        assert!(
            dev_result.is_ok(),
            "dev shutdown must be clean: {dev_result:?}"
        );

        let mtls_result = tokio::time::timeout(std::time::Duration::from_secs(10), mtls_task)
            .await
            .expect("mTLS serve() must return after SIGTERM")
            .expect("join mTLS serve task");
        assert!(
            mtls_result.is_ok(),
            "mTLS shutdown must be clean: {mtls_result:?}"
        );
    }
}
