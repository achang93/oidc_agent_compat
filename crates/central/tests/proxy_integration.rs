//! Integration tests for the central proxy.
//!
//! These tests spin up a mock OpenAI-compatible backend and the central
//! proxy, then verify:
//! - Non-streaming forwarding with master key injection
//! - SSE streaming passthrough
//! - Hop-by-hop header stripping
//! - Audit log recording
//! - Master key never appears in responses or logs

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::provider::{ProviderInput, ProviderStore};
use oac_central::proxy;
use zeroize::Zeroizing;

struct TestBootstrapVerifier;

#[async_trait::async_trait]
impl oac_central::oidc_bootstrap::BootstrapIdentityVerifier for TestBootstrapVerifier {
    async fn exchange_and_verify(
        &self,
        grant: &oac_central::oidc_bootstrap::BootstrapGrant,
    ) -> oidc_agent_common::error::Result<oac_central::oidc_bootstrap::BootstrapIdentity> {
        if grant.pkce_verifier != "integration-verifier"
            || grant.redirect_uri != "http://127.0.0.1:7777/callback"
            || grant.nonce != "integration-nonce"
        {
            return Err(oidc_agent_common::error::Error::oidc(
                "invalid integration grant binding",
            ));
        }
        let claims: serde_json::Value = serde_json::from_str(&grant.authorization_code)
            .map_err(|error| oidc_agent_common::error::Error::oidc(error.to_string()))?;
        let subject = claims["subject"]
            .as_str()
            .filter(|subject| !subject.is_empty())
            .ok_or_else(|| oidc_agent_common::error::Error::oidc("missing test subject"))?;
        Ok(oac_central::oidc_bootstrap::BootstrapIdentity {
            issuer: "https://idp.example.com".into(),
            subject: subject.into(),
            email: None,
            display_name: None,
            groups: claims["groups"].as_str().map(String::from),
        })
    }
}

/// Sets up a test central proxy with a mock backend.
async fn setup_test_central() -> (SocketAddr, reqwest::Client) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // Set up a mock OpenAI-compatible backend.
    let mock_backend = Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async {
                r#"{"data": [{"id": "gpt-4"}]}"#
            }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"choices": [{"message": {"content": "hello"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#,
                )
            }),
        );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Set up the central DB.
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-integ-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    let anonymous = reqwest::Client::new();
    let token = mint_token_via_api(&anonymous, "http", &addr, "integration-user", None, None).await;
    (addr, client_with_bearer(&token))
}

/// Builds a client that authenticates every request with the supplied token.
fn client_with_bearer(token: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("valid bearer header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("authenticated client")
}

/// Mints a token via the central proxy's token API endpoint.
/// Returns the plaintext bearer token.
async fn mint_token_via_api(
    client: &reqwest::Client,
    scheme: &str,
    addr: &std::net::SocketAddr,
    subject: &str,
    groups: Option<&str>,
    identity_id: Option<&str>,
) -> String {
    let url = format!("{scheme}://127.0.0.1:{}/v1/tokens", addr.port());
    let body = serde_json::json!({
        "authorization_code": serde_json::json!({
            "subject": subject,
            "groups": groups,
        }).to_string(),
        "pkce_verifier": "integration-verifier",
        "redirect_uri": "http://127.0.0.1:7777/callback",
        "nonce": "integration-nonce",
        "label": "integration-test",
    });
    let _ = identity_id;
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("mint token request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "token mint must succeed"
    );
    let json: serde_json::Value = resp.json().await.expect("json response");
    json["token"].as_str().expect("token field").to_string()
}

#[tokio::test]
async fn healthz_returns_ok() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn forwards_get_request_to_backend() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["data"].is_array(), "response must contain data array");
}

#[tokio::test]
async fn forwards_post_request_with_master_key() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp_body: serde_json::Value = resp.json().await.expect("json");
    assert!(
        resp_body["choices"].is_array(),
        "response must contain choices"
    );
    assert_eq!(resp_body["usage"]["total_tokens"], 15);
}

#[tokio::test]
async fn master_key_not_in_response_body() {
    let (addr, client) = setup_test_central().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({"model": "gpt-4", "messages": []});
    let resp = client.post(&url).json(&body).send().await.expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-test-master-key-12345"),
        "master key must never appear in response body"
    );
}

// ─── Streaming usage accounting tests ──────────────────────────────────────

#[tokio::test]
async fn streaming_response_records_token_usage_after_stream_completes() {
    use std::sync::{Arc, Mutex};

    // Capture the request bodies received by the mock backend so the test
    // can assert the include_usage injection reached the upstream.
    let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();

    let sse_body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n",
        "data: [DONE]\n\n",
    );

    let mock_backend = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: String| {
            let captured = captured.clone();
            async move {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
                    captured.lock().expect("lock").push(value);
                }
                ([("content-type", "text/event-stream")], sse_body)
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-stream-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");

    let usage_tracker = oac_central::usage::UsageTracker::new(audit.db().clone());
    let state = proxy::AppState {
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
        provider_store,
        client: proxy::forward::build_client().expect("client"),
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: usage_tracker.clone(),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    // Mint a token before moving state into the router.
    let minted = state
        .token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "stream-user-1".into(),
            issuer: "https://idp.example.com".into(),
            email: None,
            display_name: None,
            groups: None,
            identity_id: Some("stream-user-1-identity".into()),
            label: "stream-test".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint");
    let stream_token = minted.plaintext.to_string();
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Send a streaming request with a bearer token (required for the
    // usage counters to be incremented).
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "stream": true,
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = reqwest::Client::new()
        .post(&url)
        .header("authorization", format!("Bearer {stream_token}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "text/event-stream"
    );
    // Consume the entire stream (the deferred accounting task runs after
    // the stream completes).
    let resp_text = resp.text().await.expect("stream body");
    assert!(resp_text.contains("[DONE]"));
    assert!(resp_text.contains("\"total_tokens\":15"));

    // The upstream must have received the include_usage injection.
    {
        let bodies = received.lock().expect("lock");
        let upstream_body = bodies
            .first()
            .expect("mock backend must have received the request");
        assert_eq!(
            upstream_body["stream_options"]["include_usage"],
            serde_json::Value::Bool(true),
            "central must inject stream_options.include_usage for streaming requests"
        );
    }

    // The usage counters must reflect the streamed usage (deferred task).
    let mut usage = None;
    for _ in 0..50 {
        usage = usage_tracker
            .get_usage("stream-user-1")
            .await
            .expect("usage");
        if usage.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let usage = usage.expect("usage must be recorded after the stream completes");
    assert_eq!(usage.request_count, 1);
    assert_eq!(
        usage.token_count, 15,
        "streamed token usage must be recorded"
    );
}

// ─── Auth middleware tests (non-dev-mode) ──────────────────────────────────

/// Sets up a central proxy in **production mode** (`dev_mode = false`) so the
/// auth middleware enforces the bearer token.
async fn setup_prod_central() -> (SocketAddr, reqwest::Client) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mock_backend = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-prod-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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
        dev_mode: false,
        rate_limit_requests: 60,
        rate_limit_window_secs: 60,
    };

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    (addr, reqwest::Client::new())
}

#[tokio::test]
async fn prod_mode_rejects_request_without_identity_headers() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    // No Authorization bearer token → must be rejected.
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "prod-mode central must reject requests without a bearer token"
    );
}

#[tokio::test]
async fn prod_mode_accepts_request_with_identity_headers() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    // Mint a token via the token API.
    let token = mint_token_via_api(&client, "http", &addr, "user-123", None, Some("id-456")).await;
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "prod-mode central must accept requests with valid identity headers"
    );
}

#[tokio::test]
async fn prod_mode_healthz_bypasses_auth() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "healthz must bypass auth even in prod mode"
    );
}

#[tokio::test]
async fn prod_mode_rejects_empty_subject() {
    let (addr, client) = setup_prod_central().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "missing bearer token must be rejected"
    );
}

// ─── mTLS integration tests ────────────────────────────────────────────────

/// Writes test certs to temp files and returns the paths.
fn write_test_certs_to_temp() -> (
    std::path::PathBuf, // ca_cert
    std::path::PathBuf, // server_cert
    std::path::PathBuf, // server_key
    std::path::PathBuf, // client_cert
    std::path::PathBuf, // client_key
) {
    use oidc_agent_common::test_certs::generate_test_certs;

    let certs = generate_test_certs();
    let dir = std::env::temp_dir().join(format!(
        "oac-mtls-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let ca_path = dir.join("ca.crt");
    let server_cert_path = dir.join("server.crt");
    let server_key_path = dir.join("server.key");
    let client_cert_path = dir.join("client.crt");
    let client_key_path = dir.join("client.key");

    std::fs::write(&ca_path, &certs.ca_cert).expect("write ca");
    std::fs::write(&server_cert_path, &certs.server_cert).expect("write server cert");
    std::fs::write(&server_key_path, &certs.server_key).expect("write server key");
    std::fs::write(&client_cert_path, &certs.client_cert).expect("write client cert");
    std::fs::write(&client_key_path, &certs.client_key).expect("write client key");

    // Set 0600 on private keys (required by mtls::enforce_secure_perms).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&server_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod server key");
        std::fs::set_permissions(&client_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod client key");
    }

    (
        ca_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    )
}

/// Builds a reqwest client with mTLS using the test certs.
fn build_mtls_client(
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> reqwest::Client {
    let client_config =
        oidc_agent_common::mtls::build_client_config(ca_path, client_cert_path, client_key_path)
            .expect("build mTLS client config");

    reqwest::Client::builder()
        .use_preconfigured_tls(client_config)
        .https_only(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("build mTLS client")
}

/// Starts a central proxy with mTLS (production mode) and returns its address.
async fn setup_mtls_central() -> SocketAddr {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let (ca_path, server_cert_path, server_key_path, client_cert_path, client_key_path) =
        write_test_certs_to_temp();

    // Mock backend.
    let mock_backend = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Central DB.
    let tmp = std::env::temp_dir().join(format!(
        "oac-mtls-central-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let config = oidc_agent_common::config::CentralConfig {
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
            ca_cert_path: ca_path.clone(),
            server_cert_path: server_cert_path.clone(),
            server_key_path: server_key_path.clone(),
        },
        admin: None,
        pricing: None,
        dev_mode: false,
        rate_limit_requests: 60,
        rate_limit_window_secs: 60,
    };

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-mtls-test-master-key", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("central client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);

    // Build the mTLS server config.
    let server_config =
        oidc_agent_common::mtls::build_server_config(&ca_path, &server_cert_path, &server_key_path)
            .expect("build server config");
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(server_config));

    let handle = axum_server::Handle::new();
    let listen_handle = handle.clone();

    tokio::spawn(async move {
        axum_server::bind_rustls(config.listen_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .expect("serve mTLS central");
    });

    // Wait for the server to start listening.
    let addr = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(a) = listen_handle.listening().await {
                return a;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not start in time");

    // Return the cert paths too (via a static — hacky but works for tests).
    // Actually, we need the client cert paths for the test. Let's store them.
    MTLS_CERT_PATHS.with(|p| {
        *p.borrow_mut() = Some((ca_path, client_cert_path, client_key_path));
    });

    addr
}

thread_local! {
    static MTLS_CERT_PATHS: std::cell::RefCell<Option<(
        std::path::PathBuf, // ca
        std::path::PathBuf, // client_cert
        std::path::PathBuf, // client_key
    )>> = const { std::cell::RefCell::new(None) };
}

#[tokio::test]
async fn mtls_accepts_valid_client_cert() {
    let addr = setup_mtls_central().await;
    let (ca_path, client_cert_path, client_key_path) =
        MTLS_CERT_PATHS.with(|p| p.borrow().clone().expect("cert paths set"));

    let client = build_mtls_client(&ca_path, &client_cert_path, &client_key_path);
    let url = format!("https://127.0.0.1:{}/v1/models", addr.port());
    // Mint a token for the mTLS test (over the mTLS channel, since the
    // production-mode central server only accepts HTTPS/mTLS).
    let token = mint_token_via_api(&client, "https", &addr, "mtls-test-user", None, None).await;
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "mTLS connection with valid client cert should succeed"
    );
}

#[tokio::test]
async fn mtls_rejects_connection_without_client_cert() {
    let addr = setup_mtls_central().await;

    // A plain HTTPS client without a client cert should fail the TLS handshake.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("build plain client");

    let url = format!("https://127.0.0.1:{}/v1/models", addr.port());
    let result = client.get(&url).send().await;

    assert!(
        result.is_err(),
        "connection without client cert must fail the TLS handshake"
    );
}

// ─── Provider routing & key selection integration tests ───────────────────

use std::sync::Arc;
use tokio::sync::Mutex;

/// A recording mock backend: captures Authorization headers and returns a
/// marker in the body. If `accept_key` is set, requests whose Authorization
/// header doesn't match get a 401 (to exercise key fallback).
async fn spawn_recording_backend(
    marker: &'static str,
    accept_key: Option<&'static str>,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_clone = seen.clone();
    let accept = accept_key.map(String::from);

    let app = Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(
            move |headers: axum::http::HeaderMap,
                  _body: axum::body::Bytes| {
                let seen = seen_clone.clone();
                let accept = accept.clone();
                let marker = marker;
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    seen.lock().await.push(auth.clone());
                    if let Some(good) = &accept {
                        if &auth != good {
                            return (
                                axum::http::StatusCode::UNAUTHORIZED,
                                [("content-type", "application/json")],
                                r#"{"error": {"message": "bad key"}}"#.to_string(),
                            );
                        }
                    }
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        format!(
                            r#"{{"choices": [{{"message": {{"content": "{marker}"}}}}], "usage": {{"total_tokens": 1}}}}"#
                        ),
                    )
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording backend");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, seen)
}

/// A configured provider for the multi-provider test helper.
struct TestProvider {
    id: &'static str,
    models: Option<Vec<&'static str>>,
    is_default: bool,
    keys: Vec<(&'static str, i32, Vec<&'static str>)>, // (secret, priority, groups)
}

/// Spins up central (dev mode) with recording backends per provider and
/// returns the central address plus the captured-auth handles per provider.
async fn setup_multi_provider_central(
    providers: Vec<TestProvider>,
) -> (SocketAddr, Vec<Arc<Mutex<Vec<String>>>>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut seen_handles = Vec::new();
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-routing-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);

    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    for provider in providers {
        // Each provider gets its own backend so routing is observable by
        // which marker comes back.
        let (backend_addr, seen) =
            spawn_recording_backend(Box::leak(provider.id.to_string().into_boxed_str()), None)
                .await;
        seen_handles.push(seen);
        provider_store
            .upsert_provider(&ProviderInput {
                id: provider.id.into(),
                name: provider.id.into(),
                base_url: format!("http://{backend_addr}"),
                enabled: true,
                is_default: provider.is_default,
                models: provider
                    .models
                    .map(|models| models.into_iter().map(String::from).collect()),
            })
            .await
            .expect("provider");
        for (secret, priority, groups) in provider.keys {
            let groups: Vec<String> = groups.into_iter().map(String::from).collect();
            provider_store
                .add_key(provider.id, "test-key", secret, priority, &groups)
                .await
                .expect("provider key");
        }
    }

    let config = oidc_agent_common::config::CentralConfig {
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
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, seen_handles)
}

/// POSTs a chat completion and returns (status, body).
async fn post_completion(
    client: &reqwest::Client,
    addr: &SocketAddr,
    model: &str,
    groups: &[&str],
) -> (reqwest::StatusCode, String) {
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let groups_json = serde_json::json!(groups).to_string();
    // Mint a token with the given groups.
    let token = mint_token_via_api(
        client,
        "http",
        addr,
        "routing-test-user",
        Some(&groups_json),
        None,
    )
    .await;
    let req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "model": model,
            "messages": [{"role": "user", "content": "hi"}],
        }));
    let resp = req.send().await.expect("request");
    let status = resp.status();
    (status, resp.text().await.expect("body"))
}

#[tokio::test]
async fn routes_request_to_provider_matching_model() {
    let (addr, _seen) = setup_multi_provider_central(vec![
        TestProvider {
            id: "provider-alpha",
            models: Some(vec!["model-a"]),
            is_default: false,
            keys: vec![("sk-alpha", 0, vec![])],
        },
        TestProvider {
            id: "provider-beta",
            models: Some(vec!["model-b"]),
            is_default: false,
            keys: vec![("sk-beta", 0, vec![])],
        },
    ])
    .await;

    let client = reqwest::Client::new();
    let (status, body) = post_completion(&client, &addr, "model-b", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("provider-beta"),
        "model-b must be served by provider-beta, got: {body}"
    );
    assert!(
        !body.contains("provider-alpha"),
        "model-b must not hit provider-alpha, got: {body}"
    );
}

#[tokio::test]
async fn unknown_model_falls_back_to_default_provider() {
    let (addr, _seen) = setup_multi_provider_central(vec![
        TestProvider {
            id: "provider-alpha",
            models: Some(vec!["model-a"]),
            is_default: false,
            keys: vec![("sk-alpha", 0, vec![])],
        },
        TestProvider {
            id: "provider-default",
            models: None,
            is_default: true,
            keys: vec![("sk-default", 0, vec![])],
        },
    ])
    .await;

    let client = reqwest::Client::new();
    let (status, body) = post_completion(&client, &addr, "totally-unknown", &[]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert!(
        body.contains("provider-default"),
        "unknown model must fall back to the default provider, got: {body}"
    );
}

#[tokio::test]
async fn group_restricted_key_serves_only_matching_groups() {
    let (addr, seen) = setup_multi_provider_central(vec![TestProvider {
        id: "restricted",
        models: None,
        is_default: true,
        keys: vec![("sk-eng-only", 0, vec!["engineering"])],
    }])
    .await;

    let client = reqwest::Client::new();

    // Matching group → key is used.
    let (status, body) = post_completion(&client, &addr, "any-model", &["engineering"]).await;
    assert_eq!(status, reqwest::StatusCode::OK, "body: {body}");
    assert_eq!(
        seen[0].lock().await.len(),
        1,
        "authorized group must reach the backend exactly once"
    );

    // Non-matching group → no authorized key → upstream failure surfaced.
    let (status, body) = post_completion(&client, &addr, "any-model", &["sales"]).await;
    assert_ne!(status, reqwest::StatusCode::OK);
    assert!(
        !body.contains("sk-eng-only"),
        "key material must never appear in error responses: {body}"
    );
    assert_eq!(
        seen[0].lock().await.len(),
        1,
        "unauthorized group must not reach the backend"
    );
}

#[tokio::test]
async fn missing_identity_groups_cannot_use_restricted_keys() {
    // No X-OAC-User-Groups header at all in dev mode → empty group set →
    // restricted keys are unavailable.
    let (addr, seen) = setup_multi_provider_central(vec![TestProvider {
        id: "restricted",
        models: None,
        is_default: true,
        keys: vec![("sk-eng-only", 0, vec!["engineering"])],
    }])
    .await;

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let client = reqwest::Client::new();
    // Mint a token without groups → empty group set → restricted keys
    // are unavailable.
    let token = mint_token_via_api(&client, "http", &addr, "groupless-user", None, None).await;
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_ne!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        seen[0].lock().await.len(),
        0,
        "no groups + restricted key must not reach the backend"
    );
}

#[tokio::test]
async fn key_falls_back_on_upstream_401() {
    // One provider whose backend rejects the primary key and accepts the
    // secondary. Central must retry with the next authorized key.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let (backend_addr, seen) = spawn_recording_backend("fallback-ok", Some("sk-good")).await;
    let tmp = std::env::temp_dir().join(format!(
        "oac-central-fallback-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "fallback".into(),
            name: "fallback".into(),
            base_url: format!("http://{backend_addr}"),
            enabled: true,
            is_default: true,
            models: None,
        })
        .await
        .expect("provider");
    provider_store
        .add_key("fallback", "bad", "sk-bad", 0, &[])
        .await
        .expect("bad key");
    provider_store
        .add_key("fallback", "good", "sk-good", 1, &[])
        .await
        .expect("good key");

    let config = oidc_agent_common::config::CentralConfig {
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
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let token = mint_token_via_api(&http, "http", &addr, "fallback-user", None, None).await;
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("fallback-ok"), "body: {body}");

    // Both keys were tried, in priority order.
    let seen = seen.lock().await;
    assert_eq!(&*seen, &["sk-bad".to_string(), "sk-good".to_string()]);
}

#[tokio::test]
async fn no_provider_configured_returns_error_without_key_leak() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    let tmp = std::env::temp_dir().join(format!(
        "oac-central-noprovider-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db);
    let provider_store = ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));

    let config = oidc_agent_common::config::CentralConfig {
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
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config,
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: oac_central::policy::PolicyStore::new(audit.db().clone()),
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let anonymous = reqwest::Client::new();
    let token = mint_token_via_api(&anonymous, "http", &addr, "no-provider-user", None, None).await;
    let http = client_with_bearer(&token);
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "model": "any-model",
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "no provider configured must fail closed"
    );
    let body = resp.text().await.expect("body");
    assert!(
        !body.contains("sk-"),
        "error responses must not leak key material: {body}"
    );
}

/// End-to-end test of the token saver:
/// - Admin enables the token saver (via the policy store) for a group.
/// - A request from that group containing an exact duplicate + an empty
///   content message is forwarded.
/// - The mock backend receives a DEDUPLICATED body (the duplicate and empty
///   messages removed).
/// - The audit log records the applied saver, tokens saved, and reason tags.
/// - A request from a non-saver group is untouched (saver applies only to
///   groups/admin-enabled).
#[tokio::test]
async fn token_saver_deduplicates_and_audits() {
    use std::sync::{Arc, Mutex};

    // Capturing mock backend that records the forwarded request body.
    let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let mock_backend = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: String| {
            let captured = captured.clone();
            async move {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    captured.lock().expect("lock").push(v);
                }
                (
                    [("content-type", "application/json")],
                    r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                )
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Central DB + stores.
    let tmp = std::env::temp_dir().join(format!(
        "oac-saver-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let policy_store = oac_central::policy::PolicyStore::new(db.clone());
    // Admin enables the token saver for the `engineering` group, with a
    // budget large enough that only dedup/empty removal applies.
    policy_store
        .upsert_policy_full(
            "engineering",
            None,
            None,
            None,
            None,
            true,
            Some(100_000),
            true,
            false,
            None,
        )
        .await
        .expect("enable saver for engineering");

    let config = oidc_agent_common::config::CentralConfig {
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
    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: policy_store.clone(),
        device_store: oac_central::device_store::DeviceStore::new(db.clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(db.clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    // Request from the `engineering` group with one exact duplicate + one
    // empty-content message. These are semantically lossless to remove.
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "fix the bug"},
            {"role": "user", "content": ""},
            {"role": "user", "content": "fix the bug"},
            {"role": "user", "content": "and add tests"}
        ]
    });
    let token = mint_token_via_api(
        &http,
        "http",
        &addr,
        "alice",
        Some(r#"["engineering"]"#),
        None,
    )
    .await;
    let resp = http
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            addr.port()
        ))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // The backend must have received a body without the duplicate or the
    // empty message.
    let captured = received.lock().expect("lock").clone();
    assert_eq!(captured.len(), 1, "backend received one request");
    let upstream_msgs = captured[0]["messages"].as_array().expect("messages");
    let contents: Vec<&str> = upstream_msgs
        .iter()
        .map(|m| m["content"].as_str().unwrap())
        .collect();
    assert!(
        !contents.contains(&""),
        "empty-content message must be removed upstream"
    );
    // Exactly one occurrence of "fix the bug" survives (the other was an
    // exact-verbatim duplicate).
    let dedup_count = contents.iter().filter(|c| **c == "fix the bug").count();
    assert_eq!(dedup_count, 1, "exact duplicate must be removed upstream");
    assert_eq!(
        contents.len(),
        2,
        "four messages -> two after dedup + empty removal"
    );

    // The audit log must record the saver application + savings.
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit");
    let entry = entries
        .iter()
        .find(|e| e.user_subject == "alice")
        .expect("audit entry for alice exists");
    assert_eq!(entry.token_saver_applied, Some(true));
    assert_eq!(entry.messages_dropped, Some(2));
    assert!(entry.tokens_saved.unwrap_or(0) > 0, "tokens saved > 0");
    let reasons: Vec<String> =
        serde_json::from_str(entry.saver_reasons.as_deref().unwrap_or("[]")).expect("reasons json");
    assert!(
        reasons.contains(&"dedup".to_string()),
        "reason: {reasons:?}"
    );
    assert!(
        reasons.contains(&"empty_removed".to_string()),
        "reason: {reasons:?}"
    );

    // A request from a NON-saver group must pass through untouched.
    let token_sales =
        mint_token_via_api(&http, "http", &addr, "bob", Some(r#"["sales"]"#), None).await;
    let resp2 = http
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            addr.port()
        ))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token_sales}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    let captured2 = received.lock().expect("lock").clone();
    assert_eq!(captured2.len(), 2, "second request received");
    assert_eq!(
        captured2[1]["messages"].as_array().expect("messages").len(),
        4,
        "non-saver group must not be optimised"
    );
}

/// End-to-end test of the opt-in ANSI-stripping pass:
/// - Admin enables the token saver WITH `strip_ansi` for a group.
/// - A request from that group carries message content with terminal ANSI
///   colour codes (as an agent pastes from a colourising terminal).
/// - The mock backend receives the content with ANSI control codes removed.
/// - The audit log records `ansi_strip` in `saver_reasons`.
#[tokio::test]
async fn ansi_strip_end_to_end() {
    use std::sync::{Arc, Mutex};

    let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let mock_backend = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: String| {
            let captured = captured.clone();
            async move {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    captured.lock().expect("lock").push(v);
                }
                (
                    [("content-type", "application/json")],
                    r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                )
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-ansi-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let policy_store = oac_central::policy::PolicyStore::new(db.clone());
    // Admin enables the token saver WITH `strip_ansi` for `engineering`.
    policy_store
        .upsert_policy_full(
            "engineering",
            None,
            None,
            None,
            None,
            true,
            Some(100_000),
            false,
            true,
            None,
        )
        .await
        .expect("enable ansi for engineering");

    let config = oidc_agent_common::config::CentralConfig {
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
    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: policy_store.clone(),
        device_store: oac_central::device_store::DeviceStore::new(db.clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(db.clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "\u{1b}[31mError\u{1b}[0m in parse"},
            {"role": "user", "content": "plain line"}
        ]
    });
    let token = mint_token_via_api(
        &http,
        "http",
        &addr,
        "alice",
        Some(r#"["engineering"]"#),
        None,
    )
    .await;
    let resp = http
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            addr.port()
        ))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let captured = received.lock().expect("lock").clone();
    assert_eq!(captured.len(), 1, "backend received one request");
    let upstream_msgs = captured[0]["messages"].as_array().expect("messages");
    let contents: Vec<&str> = upstream_msgs
        .iter()
        .map(|m| m["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents[0], "Error in parse", "ANSI codes must be removed");
    assert_eq!(contents[1], "plain line", "non-ANSI message untouched");

    // Audit must record the `ansi_strip` reason.
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit");
    let entry = entries
        .iter()
        .find(|e| e.user_subject == "alice")
        .expect("audit entry for alice exists");
    assert_eq!(entry.token_saver_applied, Some(true));
    let reasons: Vec<String> =
        serde_json::from_str(entry.saver_reasons.as_deref().unwrap_or("[]")).expect("reasons json");
    assert!(
        reasons.contains(&"ansi_strip".to_string()),
        "reason: {reasons:?}"
    );
}

/// End-to-end test of the RTK-adapted repeated-line collapse pass:
/// - Admin enables the token saver WITH `collapse_repeated_lines` for a
///   group.
/// - A request from that group carries a single message whose content has a
///   run of consecutive verbatim-repeated lines (as a multi-turn agent often
///   accumulates in editors/logs).
/// - The mock backend receives the SAME message with the repeated lines
///   folded into `[×N]` markers; the representative first line survives.
/// - The audit log records `rtk_collapse` in `saver_reasons`.
/// - A group that enabled the saver but NOT collapse keeps its content
///   byte-identical (collapse is independent of the budget pass).
#[tokio::test]
async fn rtk_collapse_repeated_lines_end_to_end() {
    use std::sync::{Arc, Mutex};

    // Capturing mock backend that records the forwarded request body.
    let received: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let mock_backend = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: String| {
            let captured = captured.clone();
            async move {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    captured.lock().expect("lock").push(v);
                }
                (
                    [("content-type", "application/json")],
                    r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                )
            }
        }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    // Central DB + stores.
    let tmp = std::env::temp_dir().join(format!(
        "oac-rtk-collapse-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let policy_store = oac_central::policy::PolicyStore::new(db.clone());

    let config = oidc_agent_common::config::CentralConfig {
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
    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-test-master-key-12345", 0, &[])
        .await
        .expect("provider key");
    let client = proxy::forward::build_client().expect("client");
    let state = proxy::AppState {
        config: config.clone(),
        provider_store,
        client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: policy_store.clone(),
        device_store: oac_central::device_store::DeviceStore::new(db.clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(db.clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();

    // --- Group A: collapse enabled. The request body has a single message
    // whose content contains a long run of verbatim-repeated lines, as an
    // editor/log heavy multiturn session would produce.
    policy_store
        .upsert_policy_full(
            "group-collapse",
            None,
            None,
            None,
            None,
            true,
            Some(50_000),
            true,
            false,
            None,
        )
        .await
        .expect("enable collapse for group-collapse");
    let repeated_content = "refactor the parser module\nwarning: unused import detected in src/main.rs\nwarning: unused import detected in src/main.rs\nwarning: unused import detected in src/main.rs\nfinished refactor\nnext: tweak config tests\nwarning: cache miss retriggering build step\nwarning: cache miss retriggering build step";
    let token = mint_token_via_api(
        &http,
        "http",
        &addr,
        "alice",
        Some(r#"["group-collapse"]"#),
        None,
    )
    .await;
    let resp = http
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            addr.port()
        ))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": repeated_content}]
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let collapsed_body = {
        let guard = received.lock().expect("lock");
        guard.last().expect("captured").clone()
    };
    let upstream_content = collapsed_body["messages"][0]["content"]
        .as_str()
        .expect("content string");
    // Consecutive exact-verbatim duplicates are folded into `[×N]` markers,
    // keeping the representative first line.
    let expected = "refactor the parser module\n[×3] warning: unused import detected in src/main.rs\nfinished refactor\nnext: tweak config tests\n[×2] warning: cache miss retriggering build step";
    assert_eq!(
        upstream_content, expected,
        "repeated lines must collapse to [×N] markers"
    );
    // The collapse never rewrites the surrounding structure: the message
    // survives as a single user turn with the same role/model fields.
    assert_eq!(collapsed_body["model"], serde_json::json!("gpt-4"));

    // Audit must record the collapse reason tag.
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit");
    let entry = entries
        .iter()
        .find(|e| e.user_subject == "alice")
        .expect("audit entry for alice exists");
    assert_eq!(entry.token_saver_applied, Some(true));
    assert!(entry.tokens_saved.unwrap_or(0) > 0, "tokens saved > 0");
    let reasons: Vec<String> =
        serde_json::from_str(entry.saver_reasons.as_deref().unwrap_or("[]")).expect("reasons json");
    assert!(
        reasons.contains(&"rtk_collapse".to_string()),
        "reason: {reasons:?}"
    );

    // --- Group B: saver enabled but collapse OFF. The exact same content
    // must pass through byte-identical — collapse is an independent opt-in.
    policy_store
        .upsert_policy_full(
            "group-nocollapse",
            None,
            None,
            None,
            None,
            true,
            Some(50_000),
            false,
            false,
            None,
        )
        .await
        .expect("enable saver (no collapse) for group-nocollapse");
    let token_nocollapse = mint_token_via_api(
        &http,
        "http",
        &addr,
        "bob",
        Some(r#"["group-nocollapse"]"#),
        None,
    )
    .await;
    let resp2 = http
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            addr.port()
        ))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {token_nocollapse}"))
        .json(&serde_json::json!({
            "model": "gpt-4",
            "messages": [{"role": "user", "content": repeated_content}]
        }))
        .send()
        .await
        .expect("request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
    let nocollapse_body = {
        let guard = received.lock().expect("lock");
        guard.last().expect("captured").clone()
    };
    assert_eq!(
        nocollapse_body["messages"][0]["content"].as_str(),
        Some(repeated_content),
        "collapse-disabled group must keep content verbatim"
    );
}

// ─── Quota fairness: reservation released when upstream fails ─────────────
//
// A user whose request dies at the provider (dead upstream, network
// partition) must NOT have their daily request quota consumed by the
// failure. This test pins that behaviour end-to-end through the real
// router, middlewares, and forwarder.
#[tokio::test]
async fn upstream_failure_releases_request_quota_reservation() {
    use oac_central::usage::UsageTracker;

    // A provider pointing at a dead port: connection refused on send.
    let tmp = std::env::temp_dir().join(format!(
        "oac-quota-release-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let policy_store = oac_central::policy::PolicyStore::new(db.clone());
    // One request per day for this group — every failure counts.
    policy_store
        .upsert_policy("engineering", None, None, None, Some(1))
        .await
        .expect("policy");

    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "dead".into(),
            name: "dead".into(),
            // Port 1 is reserved and nothing listens there.
            base_url: "http://127.0.0.1:1".into(),
            enabled: true,
            is_default: true,
            models: None,
        })
        .await
        .expect("provider");
    provider_store
        .add_key("dead", "test-key", "sk-dead-upstream-key", 0, &[])
        .await
        .expect("provider key");

    let usage_tracker = UsageTracker::new(db.clone());
    let state = proxy::AppState {
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
        provider_store,
        client: proxy::forward::build_client().expect("client"),
        audit: audit.clone(),
        rate_limiter: None,
        policy_store: policy_store.clone(),
        device_store: oac_central::device_store::DeviceStore::new(db.clone()),
        usage_tracker: usage_tracker.clone(),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(
            audit.db().clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        token_store: oac_central::token_store::TokenStore::new(audit.db().clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let endpoint = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "any-model",
        "messages": [{"role": "user", "content": "hi"}],
    });

    // First request: the forward fails (dead upstream) → 502 with a JSON
    // body that never leaks the provider key.
    let token = mint_token_via_api(
        &http,
        "http",
        &addr,
        "quota-fairness-user",
        Some(r#"["engineering"]"#),
        None,
    )
    .await;
    let resp = http
        .post(&endpoint)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let text = resp.text().await.expect("body");
    let json: serde_json::Value = serde_json::from_str(&text).expect("json error body");
    assert_eq!(
        json["error"]["type"], "central_proxy_error",
        "users get a typed error, not a stack trace: {json}"
    );
    assert!(
        !text.contains("sk-dead-upstream-key"),
        "provider key must never leak in error responses"
    );

    // The failed request must NOT consume the daily quota: the reservation
    // is released (reserved 1 → released 0), so a retry once the upstream
    // recovers still works.
    let usage = usage_tracker
        .get_usage("quota-fairness-user")
        .await
        .expect("usage");
    assert_eq!(
        usage.map(|u| u.request_count),
        Some(0),
        "a failed forward must not permanently consume the request quota"
    );

    // And the next request is still admitted by the permissions middleware
    // (it fails at the forwarder again, but with 502 — NOT quota 429).
    let token = mint_token_via_api(
        &http,
        "http",
        &addr,
        "quota-fairness-user",
        Some(r#"["engineering"]"#),
        None,
    )
    .await;
    let resp = http
        .post(&endpoint)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "the retry must fail as an upstream error, not as quota exhaustion"
    );
}

// ─── Rate limiting through the real router (production mode) ──────────────

#[tokio::test]
async fn rate_limit_429_through_router_carries_retry_after() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // Mock backend so allowed requests succeed.
    let mock_backend = Router::new().route(
        "/v1/models",
        axum::routing::get(|| async { r#"{"data": [{"id": "gpt-4"}]}"# }),
    );
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let mock_addr = mock_listener.local_addr().expect("mock addr");
    tokio::spawn(async {
        let _ = axum::serve(mock_listener, mock_backend).await;
    });

    let tmp = std::env::temp_dir().join(format!(
        "oac-ratelimit-router-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let url = format!("sqlite://{}?mode=rwc", tmp.display());
    let db = oac_central::db::setup(&url).await.expect("db setup");
    let audit = AuditLogger::new(db.clone());
    let provider_store = ProviderStore::new(db.clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&ProviderInput {
            id: "mock".into(),
            name: "mock".into(),
            base_url: format!("http://{mock_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key("mock", "test-key", "sk-ratelimit-test-key", 0, &[])
        .await
        .expect("provider key");

    let state = proxy::AppState {
        // Production mode so the rate limiter engages (dev mode skips it).
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
            dev_mode: false,
            rate_limit_requests: 1,
            rate_limit_window_secs: 60,
        },
        provider_store,
        client: proxy::forward::build_client().expect("client"),
        audit,
        rate_limiter: Some(proxy::rate_limit::RateLimiter::new(
            1,
            std::time::Duration::from_secs(60),
        )),
        policy_store: oac_central::policy::PolicyStore::new(db.clone()),
        device_store: oac_central::device_store::DeviceStore::new(db.clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(db.clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager: oac_central::mcp::McpManager::new(db.clone(), Zeroizing::new([7_u8; 32])),
        token_store: oac_central::token_store::TokenStore::new(db.clone()),
        bootstrap_verifier: std::sync::Arc::new(TestBootstrapVerifier),
    };
    let app = proxy::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let addr = listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(listener, app).await;
    });

    let http = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());

    // Mint a token for the rate-limit test.
    let token = mint_token_via_api(&http, "http", &addr, "rate-user", None, None).await;
    // First request passes (prod mode requires a bearer token).
    let resp = http
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("first");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Second request is rate limited with Retry-After + JSON body so agents
    // can back off instead of hammering.
    let resp = http
        .get(&url)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("second");
    assert_eq!(resp.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .expect("Retry-After header on 429")
        .to_string();
    assert!(
        retry_after.parse::<u64>().is_ok_and(|s| s >= 1),
        "Retry-After must be a positive number of seconds: {retry_after}"
    );
    let json: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(json["error"]["type"], "rate_limit_error");
    assert_eq!(
        json["error"]["retry_after_secs"].as_u64(),
        retry_after.parse().ok()
    );

    // Health checks stay available even while rate limited.
    let resp = http
        .get(format!("http://127.0.0.1:{}/healthz", addr.port()))
        .send()
        .await
        .expect("healthz");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
