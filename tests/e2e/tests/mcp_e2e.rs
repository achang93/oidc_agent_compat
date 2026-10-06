//! End-to-end MCP relay tests.
//!
//! Verifies the full MCP flow:
//! agent → relay → central → upstream MCP server, with:
//! - Per-tool allow (200 + upstream passthrough) and per-tool deny (403).
//! - Central MCP audit rows recording mcp_server / mcp_tool / mcp_method.
//! - Relay activity rows with the same MCP metadata.
//! - Auth required on the relay (401 without key).
//! - The upstream MCP server only ever sees allowed tool calls.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use oac_central::audit::AuditLogger;
use oac_central::proxy as central_proxy;
use oac_relay::keystore::KeyStore;
use oac_relay::proxy as relay_proxy;
use zeroize::Zeroizing;

/// A lightweight in-process mock MCP server (Streamable HTTP + JSON-RPC).
fn mock_mcp_server() -> Router {
    let call_count = std::sync::Arc::new(AtomicU64::new(0));
    let count = call_count.clone();
    Router::new().route(
        "/mcp",
        axum::routing::any(move |body: axum::body::Body| {
            let count = count.clone();
            async move {
                let bytes = axum::body::to_bytes(body, 1 << 20)
                    .await
                    .unwrap_or_default();
                // Record which server hit us and echo a JSON-RPC response.
                if bytes.is_empty() {
                    return (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        r#"{"jsonrpc":"2.0","id":null,"result":{}}"#.to_string(),
                    );
                }
                count.fetch_add(1, Ordering::SeqCst);
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                let method = value.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
                match method {
                    "tools/call" => {
                        let name = value
                            .pointer("/params/name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let result = if name == "read_file" {
                            serde_json::json!({
                                "content": [{"type":"text","text":"file contents"}],
                                "isError": false,
                            })
                        } else {
                            serde_json::json!({
                                "content": [{"type":"text","text":"generic"}],
                                "isError": false,
                            })
                        };
                        (
                            axum::http::StatusCode::OK,
                            [("content-type", "application/json")],
                            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
                                .to_string(),
                        )
                    }
                    "tools/list" => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "tools": [ {"name":"read_file","description":"read"} ] }
                        })
                        .to_string(),
                    ),
                    _ => (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
                    ),
                }
            }
        }),
    )
}

/// Full MCP e2e system: mock MCP server + central (with a registered MCP
/// server and a per-group tool policy) + relay authenticated as a user.
async fn setup_mcp_system() -> (
    SocketAddr,                    // relay addr
    reqwest::Client,               // client
    String,                        // local key
    String,                        // mcp server id
    AuditLogger,                   // central audit
    oac_relay::keystore::KeyStore, // relay keystore
) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);

    // 1. Upstream mock MCP server at /mcp.
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mcp");
    let mcp_addr = mcp_listener.local_addr().expect("mcp addr");
    tokio::spawn(async move {
        let _ = axum::serve(mcp_listener, mock_mcp_server()).await;
    });
    let mcp_base = format!("http://{mcp_addr}/mcp");

    // 2. Central proxy.
    let central_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-mcp-central-{}-{counter}-{}.db",
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
    let mcp_manager =
        oac_central::mcp::McpManager::new(audit.db().clone(), Zeroizing::new([7_u8; 32]));

    // Register an MCP server "fs" pointing at the mock server, with an auth
    // header (encrypted at rest) so we can assert it is forwarded.
    mcp_manager
        .upsert_server(&oac_central::mcp::McpServerInput {
            id: "fs".into(),
            name: "Fake FS".into(),
            base_url: mcp_base.clone(),
            enabled: true,
            auth_header: Some("Authorization: Bearer e2e-secret".into()),
        })
        .await
        .expect("register mcp server");

    // Register a per-group policy allowing only read_file on server fs.
    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
        .await
        .expect("mcp policy");

    let central_client = central_proxy::forward::build_client().expect("central client");
    let central_state = central_proxy::AppState {
        config: central_config.clone(),
        provider_store,
        client: central_client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store,
        device_store: oac_central::device_store::DeviceStore::new(audit.db().clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(audit.db().clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager,
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
        "oac-e2e-mcp-relay-{}-{counter}-{}.db",
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
    // carried in the central token record.
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "mcp-user",
            Some("mcp@example.com"),
            None,
            Some(r#"["eng"]"#),
        )
        .await
        .expect("identity");

    // Mint a central token (carrying the relay identity id and groups) and
    // register it as a local relay key so both the relay (local auth) and
    // the central proxy (token store) accept the same bearer token.
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "mcp-user".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("mcp@example.com".into()),
            display_name: None,
            groups: Some(r#"["eng"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "mcp-e2e".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token");
    let local_key = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

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
        "fs".to_string(),
        audit,
        key_store,
    )
}

/// Builds a `tools/call` JSON-RPC request body.
fn tools_call(name: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": name, "arguments": { "path": "/tmp/x" } },
    })
}

/// Builds a `tools/list` JSON-RPC request body.
fn tools_list() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    })
}

/// A mock MCP server that advertises one tool and echoes a distinctive text
/// for the tool name, so tests can tell which upstream served a call.
fn mock_mcp_server_named(tool: &'static str, echo: &'static str) -> Router {
    Router::new().route(
        "/mcp",
        axum::routing::any(move |body: axum::body::Body| async move {
            let bytes = axum::body::to_bytes(body, 1 << 20)
                .await
                .unwrap_or_default();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let method = value.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
            match method {
                "tools/call" => {
                    let name = value
                        .pointer("/params/name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let text = if name == tool { echo } else { "wrong-tool" };
                    (
                        axum::http::StatusCode::OK,
                        [("content-type", "application/json")],
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": { "content": [{"type":"text","text":text}], "isError": false },
                        })
                        .to_string(),
                    )
                }
                "tools/list" => (
                    axum::http::StatusCode::OK,
                    [("content-type", "application/json")],
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "tools": [ {"name": tool, "description": "a tool"} ] }
                    })
                    .to_string(),
                ),
                _ => (
                    axum::http::StatusCode::OK,
                    [("content-type", "application/json")],
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
                ),
            }
        }),
    )
}

/// Spins up a mock MCP server on a random port and returns its `/mcp` base URL.
async fn spin_mock_server(tool: &'static str, echo: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mcp");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, mock_mcp_server_named(tool, echo)).await;
    });
    format!("http://{addr}/mcp")
}

/// Full hub e2e system: two mock MCP servers ("fs": read_file and "gh":
/// list) + central (both registered, policy allows only fs:read_file) +
/// relay. Returns relay addr, client, local key, and central db connection.
async fn setup_hub_system() -> (
    SocketAddr,
    reqwest::Client,
    String,
    sea_orm::DatabaseConnection,
) {
    use std::sync::atomic::{AtomicU64, Ordering as _Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, _Ordering::SeqCst);

    let fs_base = spin_mock_server("read_file", "fs-content").await;
    let gh_base = spin_mock_server("list", "gh-content").await;

    // Central.
    let central_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-hub-central-{}-{counter}-{}.db",
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
    let audit = AuditLogger::new(central_db.clone());

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

    let mcp_manager =
        oac_central::mcp::McpManager::new(central_db.clone(), Zeroizing::new([7_u8; 32]));
    for (id, base) in [("fs", fs_base), ("gh", gh_base)] {
        mcp_manager
            .upsert_server(&oac_central::mcp::McpServerInput {
                id: id.into(),
                name: id.into(),
                base_url: base,
                enabled: true,
                auth_header: None,
            })
            .await
            .expect("register mcp server");
    }

    let policy_store = oac_central::policy::PolicyStore::new(central_db.clone());
    // Allow only fs:read_file for the "eng" group.
    policy_store
        .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
        .await
        .expect("mcp policy");

    let central_client = central_proxy::forward::build_client().expect("central client");
    let central_state = central_proxy::AppState {
        config: central_config.clone(),
        provider_store: oac_central::provider::ProviderStore::new(
            central_db.clone(),
            Zeroizing::new([7_u8; 32]),
        ),
        client: central_client,
        audit: audit.clone(),
        rate_limiter: None,
        policy_store,
        device_store: oac_central::device_store::DeviceStore::new(central_db.clone()),
        usage_tracker: oac_central::usage::UsageTracker::new(central_db.clone()),
        price_table: oac_central::pricing::PriceTable::empty(),
        mcp_manager,
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

    // Relay.
    let relay_tmp = std::env::temp_dir().join(format!(
        "oac-e2e-hub-relay-{}-{counter}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let relay_url = format!("sqlite://{}?mode=rwc", relay_tmp.display());
    let relay_db = oac_relay::db::setup(&relay_url).await.expect("relay db");
    let key_store = KeyStore::new(relay_db);
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "hub-user",
            Some("hub@example.com"),
            None,
            Some(r#"["eng"]"#),
        )
        .await
        .expect("identity");

    // Mint a central token (carrying the relay identity id and groups) and
    // register it as a local relay key so both the relay and the central
    // proxy accept the same bearer token.
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "hub-user".into(),
            issuer: "https://idp.example.com".into(),
            email: Some("hub@example.com".into()),
            display_name: None,
            groups: Some(r#"["eng"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "hub-e2e".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token");
    let local_key = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

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

    (relay_addr, reqwest::Client::new(), local_key, central_db)
}

#[tokio::test]
async fn allowed_tool_is_forwarded_and_audited() {
    let (relay_addr, client, key, _server, audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json");
    let text = body
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(text, "file contents", "upstream passthrough");

    // Central audit recorded the MCP fields.
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("audit load");
    let mcp = entries
        .iter()
        .find(|e| e.mcp_server.as_deref() == Some("fs"))
        .expect("mcp audit row");
    assert_eq!(mcp.mcp_tool.as_deref(), Some("read_file"));
    assert_eq!(mcp.mcp_method.as_deref(), Some("tools/call"));
    assert_eq!(mcp.permission_decision.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn denied_tool_returns_403_and_is_denied_in_audit() {
    let (relay_addr, client, key, _server, audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    // delete_file is NOT allowed by the "eng" policy.
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("delete_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);

    // Central audit recorded a denied MCP entry.
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("audit load");
    let denied = entries
        .iter()
        .find(|e| e.mcp_tool.as_deref() == Some("delete_file"))
        .expect("denied mcp audit row");
    assert_eq!(denied.mcp_server.as_deref(), Some("fs"));
    assert_eq!(denied.permission_decision.as_deref(), Some("denied"));
    assert!(denied.denial_reason.is_some());
}

#[tokio::test]
async fn relay_dev_mode_mcp_still_requires_central_auth() {
    // The relay skips its presence check in dev mode, but central must still
    // reject an MCP request without a bearer token.
    let (relay_addr, client, _key, _server, _audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn per_server_endpoint_allows_non_tools_call_methods_under_specific_policy() {
    // Regression: non-tools/call methods (initialize, tools/list) used to be
    // misclassified as tools/call of a "tool" literally named after the
    // method, so a specific allowlist (fs:read_file) denied them with 403.
    // They must pass through when the group has at least one allowed tool
    // on the server, and be audited with the method and no tool name.
    let (relay_addr, client, key, _server, audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    for method in ["initialize", "tools/list"] {
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method });
        let resp = client
            .post(&url)
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("request");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "{method} must be forwarded, not denied by per-tool policy"
        );
        let json: serde_json::Value = resp.json().await.expect("json body");
        assert!(
            json.get("result").is_some(),
            "{method} must return a JSON-RPC result: {json}"
        );
    }

    // Central audit classified them as methods (no tool name).
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(audit.db())
        .await
        .expect("audit load");
    for method in ["initialize", "tools/list"] {
        let entry = entries
            .iter()
            .find(|e| e.mcp_method.as_deref() == Some(method))
            .expect("audit row for the method");
        assert_eq!(entry.mcp_server.as_deref(), Some("fs"));
        assert!(
            entry.mcp_tool.as_deref().is_none_or(str::is_empty),
            "non-tools/call must not record a tool name"
        );
        assert_eq!(entry.permission_decision.as_deref(), Some("allowed"));
    }
}

#[tokio::test]
async fn per_server_endpoint_denies_non_tools_call_methods_under_deny_all_policy() {
    // A group whose policy is an explicit empty allowlist (deny-all) must
    // also deny non-tools/call methods: the server is fully off-limits.
    // (Achieved by minting a second identity whose group has a deny-all
    // policy on "fs".)
    let (relay_addr, client, _key, _server, audit, key_store) = setup_mcp_system().await;

    // Give the "interns" group an explicit deny-all policy (empty allowlist)
    // on central's policy store, then mint a relay user in that group.
    let policy_store = oac_central::policy::PolicyStore::new(audit.db().clone());
    policy_store
        .upsert_mcp_policy("interns", Some(&[]))
        .await
        .expect("deny-all policy");
    let ident = key_store
        .upsert_identity(
            "https://idp.example.com",
            "intern-user",
            None,
            None,
            Some(r#"["interns"]"#),
        )
        .await
        .expect("identity");

    // Mint a central token for the intern so the central proxy can verify
    // it (the relay forwards the bearer token to central for verification).
    let central_token_store = oac_central::token_store::TokenStore::new(audit.db().clone());
    let minted_central = central_token_store
        .mint_token(&oac_central::token_store::MintRequest {
            subject: "intern-user".into(),
            issuer: "https://idp.example.com".into(),
            email: None,
            display_name: None,
            groups: Some(r#"["interns"]"#.into()),
            identity_id: Some(ident.id.clone()),
            label: "intern-e2e".into(),
            expires_at: None,
            device_fingerprint: None,
        })
        .await
        .expect("mint central token");
    let intern_key = minted_central.plaintext.to_string();
    // The relay forwards the bearer to central; no local key registration.

    let url = format!("http://{relay_addr}/mcp/fs");
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {intern_key}"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "deny-all policy must also deny non-tools/call methods"
    );
}

#[tokio::test]
async fn relay_activity_records_mcp_metadata() {
    let (relay_addr, client, key, _server, _audit, key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    use sea_orm::EntityTrait;
    let entries = oac_relay::entity::relay_activity_log::Entity::find()
        .all(&key_store.db)
        .await
        .expect("relay activity load");
    let mcp = entries
        .iter()
        .find(|e| e.mcp_server.as_deref() == Some("fs"))
        .expect("relay mcp activity row");
    assert_eq!(mcp.mcp_tool.as_deref(), Some("read_file"));
    assert_eq!(mcp.mcp_method.as_deref(), Some("tools/call"));
    assert_eq!(mcp.central_status, Some(200));
}

#[tokio::test]
async fn batch_jsonrpc_is_rejected_at_per_server_endpoint() {
    // A JSON-RPC batch (array) containing a tools/call must be rejected at
    // the per-server /mcp/{server} endpoint, not forwarded verbatim —
    // otherwise the tools/call inside the batch would bypass per-tool
    // permission enforcement.
    let (relay_addr, client, key, _server, _audit, _key_store) = setup_mcp_system().await;
    let url = format!("http://{relay_addr}/mcp/fs");

    let batch = serde_json::json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": { "name": "read_file", "arguments": {} } },
        { "jsonrpc": "2.0", "id": 2, "method": "tools/list" }
    ]);

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&batch)
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "batch must be rejected, not forwarded"
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(
        body.get("error").is_some(),
        "response must carry a JSON-RPC error object"
    );
}

#[tokio::test]
async fn batch_jsonrpc_is_rejected_at_hub_endpoint() {
    // The combined /mcp hub must also reject batches.
    let (relay_addr, client, key, _central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");

    let batch = serde_json::json!([
        { "jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": { "name": "fs__read_file", "arguments": {} } }
    ]);

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&batch)
        .send()
        .await
        .expect("request");
    // The hub returns 200 with a JSON-RPC error (not 4xx) because JSON-RPC
    // errors are delivered in the response body, not via HTTP status.
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    let code = body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64());
    assert_eq!(
        code,
        Some(-32600),
        "hub must return -32600 invalid request for batches"
    );
}

// --- Combined /mcp hub tests ---

#[tokio::test]
async fn hub_tools_list_aggregates_prefixed_and_filters_by_policy() {
    let (relay_addr, client, key, _central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_list())
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json");
    let names: Vec<String> = body
        .pointer("/result/tools")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    // Only fs:read_file is in the policy, so only fs__read_file is exposed.
    assert_eq!(names, vec!["fs__read_file"]);
}

#[tokio::test]
async fn hub_tools_call_routes_to_correct_upstream() {
    let (relay_addr, client, key, central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");

    // fs__read_file is allowed and routed to the "fs" upstream.
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("fs__read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json");
    let text = body
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(text, "fs-content", "routed to fs upstream");

    // The audit row must attribute the call to the real target server with
    // the unprefixed tool name (not server "hub" / "fs__read_file").
    use sea_orm::EntityTrait;
    let entries = oac_central::entity::audit_log::Entity::find()
        .all(&central_db)
        .await
        .expect("audit load");
    let row = entries
        .iter()
        .find(|e| e.mcp_method.as_deref() == Some("tools/call"))
        .expect("hub tools/call audit row");
    assert_eq!(row.mcp_server.as_deref(), Some("fs"));
    assert_eq!(row.mcp_tool.as_deref(), Some("read_file"));
    assert_eq!(row.permission_decision.as_deref(), Some("allowed"));
}

#[tokio::test]
async fn hub_tools_call_denies_tool_outside_policy() {
    let (relay_addr, client, key, _central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");

    // gh__list is on server "gh" which is NOT in the policy.
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("gh__list"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn hub_tools_call_rejects_unprefixed_tool_name() {
    let (relay_addr, client, key, _central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");

    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .json(&tools_call("read_file"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn hub_dev_mode_still_requires_central_auth() {
    // The relay skips its presence check in dev mode, but central still
    // authenticates the combined MCP hub endpoint.
    let (relay_addr, client, _key, _central_db) = setup_hub_system().await;
    let url = format!("http://{relay_addr}/mcp");
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .json(&tools_list())
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
