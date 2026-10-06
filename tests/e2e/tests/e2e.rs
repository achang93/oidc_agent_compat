//! End-to-end integration tests.
//!
//! These tests verify the full request flow:
//! agent → relay → central → backend, with:
//! - Non-streaming forwarding
//! - SSE streaming passthrough
//! - Master key confined to the central proxy (never in relay responses)
//! - Auth middleware (401 without key, 200 with valid key)
//! - Host header validation (DNS rebinding defense)
//! - Audit log recording on the central proxy

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::proxy as central_proxy;
use oac_relay::keystore::KeyStore;
use oac_relay::proxy as relay_proxy;
use zeroize::Zeroizing;

/// Sets up the full system: mock backend + central proxy + relay.
///
/// Returns the relay address, an HTTP client, a valid local API key, the
/// central proxy's audit logger (for verifying audit entries), and the
/// relay's key store (for verifying relay activity log entries).
async fn setup_full_system() -> (
    SocketAddr,
    reqwest::Client,
    String,
    AuditLogger,
    oac_relay::keystore::KeyStore,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // 1. Mock OpenAI-compatible backend.
    let mock_backend = Router::new()
        .route(
            "/v1/models",
            axum::routing::get(|| async {
                r#"{"data": [{"id": "gpt-4"}, {"id": "gpt-3.5-turbo"}]}"#
            }),
        )
        .route(
            "/v1/chat/completions",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"choices": [{"message": {"content": "hello from backend"}, "index": 0}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#,
                )
            }),
        )
        .route(
            "/v1/embeddings",
            axum::routing::post(|_body: axum::body::Body| async {
                (
                    [("content-type", "application/json")],
                    r#"{"data": [{"embedding": [0.1, 0.2, 0.3]}]}"#,
                )
            }),
        );
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_addr = backend_listener.local_addr().expect("backend addr");
    tokio::spawn(async {
        let _ = axum::serve(backend_listener, mock_backend).await;
    });

    // 2. Central proxy.
    let central_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-central-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let central_url = format!("sqlite://{}?mode=rwc", central_tmp.display());
    let central_db = oac_central::db::setup(&central_url)
        .await
        .expect("central db");
    let audit = AuditLogger::new(central_db);

    let central_config = oidc_agent_common::config::CentralConfig {
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

    let provider_store =
        oac_central::provider::ProviderStore::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));
    provider_store
        .upsert_provider(&oac_central::provider::ProviderInput {
            id: "mock-backend".into(),
            name: "mock-backend".into(),
            base_url: format!("http://{backend_addr}"),
            enabled: true,
            is_default: true,
            models: Some(vec!["gpt-4".into()]),
        })
        .await
        .expect("provider");
    provider_store
        .add_key(
            "mock-backend",
            "test-key",
            "sk-e2e-master-key-secret",
            0,
            &[],
        )
        .await
        .expect("provider key");
    let central_client = central_proxy::forward::build_client().expect("central client");
    let central_state = central_proxy::AppState {
        config: central_config.clone(),
        provider_store,
        client: central_client,
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
        bootstrap_verifier: std::sync::Arc::new(
            oac_central::oidc_bootstrap::UnavailableBootstrapVerifier,
        ),
    };
    let central_app = central_proxy::router(central_state);
    let central_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind central");
    let central_addr = central_listener.local_addr().expect("central addr");
    tokio::spawn(async {
        let _ = axum::serve(central_listener, central_app).await;
    });

    // 3. Relay proxy.
    let relay_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-relay-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let relay_url = format!("sqlite://{}?mode=rwc", relay_tmp.display());
    let relay_db = oac_relay::db::setup(&relay_url).await.expect("relay db");
    let key_store = KeyStore::new(relay_db);

    // Create the relay-side identity first so its database id can be
    // carried in the central token record (the central proxy's audit log
    // records the identity_id from the verified token, not from headers).
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user",
            Some("e2e@example.com"),
            None,
            None,
        )
        .await
        .expect("identity");

    // Mint a central token (carrying the relay identity id) and register
    // it as a local relay key so both the relay (local auth) and the
    // central proxy (token store) accept it.
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "e2e-user".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("e2e@example.com".into()),
            display_name: None,
            groups: None,
            identity_id: Some(ident.id.clone()),
            label: "e2e-test".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token");
    let local_key = minted_central.plaintext.to_string();

    // The relay no longer registers the token as a local key — it forwards
    // the bearer to central, which verifies it via its token store.

    let relay_config = oidc_agent_common::config::RelayConfig {
        listen_addr: "127.0.0.1:0".parse().expect("addr"),
        database_url: "sqlite://test.db".into(),
        oidc: oidc_agent_common::config::OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "test".into(),
            client_secret_env: "TEST".into(),
            redirect_uri: "http://127.0.0.1:0/callback".into(),
            scopes: vec!["openid".into()],
        },
        central: oidc_agent_common::config::CentralConnectionConfig {
            url: format!("http://{}", central_addr),
            ca_cert_path: "/ca.pem".into(),
            client_cert_path: "/client.pem".into(),
            client_key_path: "/client.key".into(),
        },
        dev_mode: true,
    };

    let relay_client = relay_proxy::forward::build_client(&relay_config).expect("relay client");
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay_listener.local_addr().expect("relay addr");
    let relay_state = relay_proxy::AppState {
        config: relay_config.clone(),
        client: relay_client,
        listen_addr: relay_addr,
        activity: oac_relay::activity::ActivityLogger::new(key_store.db.clone()),
        device_fingerprint: None,
    };
    let relay_app = relay_proxy::router(relay_state);
    tokio::spawn(async {
        let _ = axum::serve(relay_listener, relay_app).await;
    });

    (
        relay_addr,
        reqwest::Client::new(),
        local_key,
        audit,
        key_store,
    )
}

#[tokio::test]
async fn e2e_healthz() {
    let (addr, client, _, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/healthz", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn e2e_get_models_through_full_chain() {
    let (addr, client, key, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["data"].is_array(), "response must contain data array");
    assert_eq!(body["data"][0]["id"], "gpt-4");
}

#[tokio::test]
async fn e2e_post_chat_completions_through_full_chain() {
    let (addr, client, key, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp_body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        resp_body["choices"][0]["message"]["content"],
        "hello from backend"
    );
    assert_eq!(resp_body["usage"]["total_tokens"], 15);
}

#[tokio::test]
async fn e2e_post_embeddings_through_full_chain() {
    let (addr, client, key, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/embeddings", addr.port());
    let body = serde_json::json!({
        "model": "text-embedding-ada-002",
        "input": "test text",
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let resp_body: serde_json::Value = resp.json().await.expect("json");
    assert!(resp_body["data"].is_array());
}

#[tokio::test]
async fn e2e_dev_mode_rejects_request_without_key() {
    // The relay skips its presence check in dev mode, but central remains the
    // sole verification authority and must reject a missing bearer in every
    // mode.
    let (addr, client, _, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn e2e_rejects_invalid_key() {
    let (addr, client, _, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Authorization", "Bearer oac_invalid")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn e2e_rejects_non_loopback_host() {
    let (addr, client, _, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Host", "evil.example.com")
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn e2e_master_key_not_in_relay_response() {
    let (addr, client, key, _, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({"model": "gpt-4", "messages": []});
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-e2e-master-key-secret"),
        "master key must never appear in relay response"
    );
}

#[tokio::test]
async fn e2e_master_key_not_in_error_response() {
    let (addr, client, _, _, _) = setup_full_system().await;
    // Send a request without auth to get an error response.
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client.get(&url).send().await.expect("request");
    let resp_text = resp.text().await.expect("body");
    assert!(
        !resp_text.contains("sk-e2e-master-key-secret"),
        "master key must never appear in error responses"
    );
}

#[tokio::test]
async fn e2e_identity_forwarded_and_audited() {
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;

    let (addr, client, key, audit, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Give the audit log a moment to flush (it's async).
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the audit log recorded the real user subject ("e2e-user"),
    // not the placeholder "unknown".
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    assert!(
        !entries.is_empty(),
        "audit log must contain at least one entry"
    );
    let last = entries.last().expect("at least one entry");
    assert_eq!(
        last.user_subject, "e2e-user",
        "audit log must record the relay-forwarded user subject, not 'unknown'"
    );
    assert_eq!(last.model.as_deref(), Some("gpt-4"));
    assert_eq!(last.status, 200);
    // Enrichment columns.
    assert!(
        last.identity_id.is_some(),
        "audit log must record the identity_id"
    );
    assert_eq!(last.email.as_deref(), Some("e2e@example.com"));
    assert_eq!(last.endpoint.as_deref(), Some("/v1/chat/completions"));
    assert!(
        last.request_id.is_some(),
        "audit log must record the request_id"
    );
}

#[tokio::test]
async fn e2e_relay_activity_log_records_request() {
    use oac_relay::entity::relay_activity_log;
    use sea_orm::EntityTrait;

    let (addr, client, key, _, key_store) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Give the activity log a moment to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Verify the relay activity log recorded the request.
    let entries = relay_activity_log::Entity::find()
        .all(&key_store.db)
        .await
        .expect("load relay activity log");
    assert!(
        !entries.is_empty(),
        "relay activity log must contain at least one entry"
    );
    let last = entries.last().expect("at least one entry");
    assert_eq!(last.method, "POST");
    assert_eq!(last.endpoint, "/v1/chat/completions");
    assert_eq!(last.model.as_deref(), Some("gpt-4"));
    assert_eq!(last.central_status, Some(200));
    assert!(
        last.request_id.is_some(),
        "relay activity log must record the request_id"
    );
}

#[tokio::test]
async fn e2e_request_id_correlates_relay_and_central() {
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;

    let (addr, client, key, audit, _) = setup_full_system().await;
    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The central audit log must have a non-null request_id for the request.
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    assert!(!entries.is_empty());
    let last = entries.last().expect("at least one entry");
    assert!(
        last.request_id.is_some(),
        "central audit log must record the request_id forwarded by the relay"
    );
}

#[tokio::test]
async fn e2e_permissions_deny_disallowed_model() {
    // Set up a policy allowing only "gpt-4o" for the "engineering" group,
    // then verify a request for "gpt-4" is denied with 403.
    let (addr, client, key, audit, key_store) = setup_full_system().await;

    // Use a distinct subject so a new identity with groups is created
    // (upsert_identity returns existing rows without updating groups).
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user-eng",
            Some("e2e-eng@example.com"),
            None,
            Some(r#"["engineering"]"#),
        )
        .await
        .expect("upsert with groups");

    // Mint a central token with groups and register it as a local key.
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "e2e-user-eng".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("e2e-eng@example.com".into()),
            display_name: None,
            groups: Some(r#"["engineering"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "e2e-perm-test".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token with groups");
    let key_with_groups = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

    // Create a policy allowing only "gpt-4o" for "engineering".
    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_policy("engineering", Some(r#"["gpt-4o"]"#), None, None, None)
        .await
        .expect("upsert policy");

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key_with_groups}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "request for disallowed model must be denied"
    );

    // Verify the denial was audited.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    let denied = entries
        .iter()
        .find(|e| e.permission_decision.as_deref() == Some("denied"));
    assert!(denied.is_some(), "audit log must contain a denied entry");
    let denied = denied.expect("denied entry");
    assert_eq!(denied.denial_reason.as_deref(), Some("model_not_allowed"));
    assert_eq!(denied.status, 403);

    // The original key (no groups) should still work (no policies match).
    let body2 = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp2 = client
        .post(&url)
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body2)
        .send()
        .await
        .expect("request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn e2e_permissions_allow_allowed_model() {
    // Set up a policy allowing "gpt-4" for the "engineering" group, then
    // verify a request for "gpt-4" succeeds.
    let (addr, client, _, audit, key_store) = setup_full_system().await;

    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user-allow",
            Some("e2e-allow@example.com"),
            None,
            Some(r#"["engineering"]"#),
        )
        .await
        .expect("upsert with groups");
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "e2e-user-allow".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("e2e-allow@example.com".into()),
            display_name: None,
            groups: Some(r#"["engineering"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "e2e-perm-allow".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token with groups");
    let key_with_groups = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_policy("engineering", Some(r#"["gpt-4"]"#), None, None, None)
        .await
        .expect("upsert policy");

    let url = format!("http://127.0.0.1:{}/v1/chat/completions", addr.port());
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hello"}],
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key_with_groups}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn e2e_permissions_deny_disallowed_endpoint() {
    // Set up a policy allowing only /v1/chat/completions for "restricted"
    // group, then verify /v1/embeddings is denied.
    let (addr, client, _, audit, key_store) = setup_full_system().await;

    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user-restricted",
            Some("e2e-restricted@example.com"),
            None,
            Some(r#"["restricted"]"#),
        )
        .await
        .expect("upsert with groups");
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "e2e-user-restricted".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("e2e-restricted@example.com".into()),
            display_name: None,
            groups: Some(r#"["restricted"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "e2e-perm-endpoint".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token with groups");
    let key_with_groups = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_policy(
            "restricted",
            None,
            Some(r#"["/v1/chat/completions"]"#),
            None,
            None,
        )
        .await
        .expect("upsert policy");

    let url = format!("http://127.0.0.1:{}/v1/embeddings", addr.port());
    let body = serde_json::json!({
        "model": "text-embedding-ada-002",
        "input": "test",
    });
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {key_with_groups}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "request to disallowed endpoint must be denied"
    );

    // Verify the denial reason.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    let denied = entries
        .iter()
        .find(|e| e.permission_decision.as_deref() == Some("denied"));
    assert!(denied.is_some(), "audit log must contain a denied entry");
    assert_eq!(
        denied.expect("denied").denial_reason.as_deref(),
        Some("endpoint_not_allowed")
    );
}

#[tokio::test]
async fn e2e_device_revocation_blocks_request() {
    // Register a device (using identity_id as the device identifier),
    // revoke it, then verify subsequent requests are denied with 403.
    let (addr, client, _, audit, key_store) = setup_full_system().await;

    // Create an identity and key.
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "e2e-user-device",
            Some("e2e-device@example.com"),
            None,
            None,
        )
        .await
        .expect("upsert");
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "e2e-user-device".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("e2e-device@example.com".into()),
            display_name: None,
            groups: None,
            identity_id: Some(ident.id.clone()),
            label: "e2e-device-test".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token");
    let key = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

    // Register the device using the identity_id as the device identifier.
    let device_store = oac_central::device_store::DeviceStore::new(audit.db().clone());
    device_store
        .upsert_device(&ident.id, "e2e-user-device", Some("e2e-device@example.com"))
        .await
        .expect("upsert device");

    // Verify the request works before revocation.
    let url = format!("http://127.0.0.1:{}/v1/models", addr.port());
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Revoke the device.
    device_store.revoke(&ident.id).await.expect("revoke");

    // Verify the request is now denied.
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "request from revoked device must be denied"
    );

    // Verify the denial was audited.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    use oac_central::entity::audit_log;
    use sea_orm::EntityTrait;
    let entries = audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("load audit log");
    let denied = entries
        .iter()
        .find(|e| e.denial_reason.as_deref() == Some("device_revoked"));
    assert!(
        denied.is_some(),
        "audit log must contain a device_revoked denial entry"
    );

    // Reinstate the device and verify the request works again.
    device_store.reinstate(&ident.id).await.expect("reinstate");

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "request from reinstated device must succeed"
    );
}
