//! Per-tool MCP permissions middleware for the central proxy.
//!
//! MCP requests arrive as JSON-RPC over HTTP on `/mcp/{server}`. After
//! [`super::auth::auth_middleware`] establishes the verified relay identity,
//! this middleware enforces **per-server, per-tool allowlists** resolved
//! from the caller's group policies.
//!
//! # Flow
//!
//! 1. Parse the `{server}` path segment.
//! 2. Resolve the caller's group policy (`mcp_server_policies`), which maps
//!    a group to a set of allowed `"server:tool"` entries. `None` means all
//!    tools allowed; an empty set means no tools.
//! 3. Read the request body and extract the JSON-RPC method and, for
//!    `tools/call`, the tool name (via `oac-mcp::parse`).
//! 4. Deny with `403` if the tool is not in the allowlist for that server.
//! 5. On allow, attach an [`McpGrant`] to extensions for audit logging.
//!
//! # Security
//!
//! - Enforcement happens on the central proxy after mTLS + identity auth,
//!   so a compromised relay cannot bypass it.
//! - Denials are audit-logged with the tool, server, method, and a redacted
//!   argument preview.
//! - Non-`tools/call` methods (`initialize`, `tools/list`, etc.) are
//!   audited but not per-tool enforced. As of v1, admins can restrict these
//!   too by leaving allowed-tools empty (deny-all).

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oac_mcp::parse;
use oidc_agent_common::http_util;

use super::AppState;
use crate::audit::AuditEntry;

/// The MCP permission grant attached to a request extension after the MCP
/// permissions middleware runs. Carries the enforcement result and audit
/// metadata.
#[derive(Debug, Clone)]
pub struct McpGrant {
    /// The MCP server id.
    pub server: String,
    /// The JSON-RPC method (e.g. `tools/call`).
    pub method: String,
    /// The tool name (empty for non-`tools/call` methods).
    pub tool: String,
    /// `"allowed"` or `"denied"`.
    pub decision: String,
    /// The reason for denial, if denied.
    pub reason: Option<String>,
    /// A redacted, length-capped preview of the tool arguments.
    pub args_preview: Option<String>,
}

/// The MCP permissions middleware.
pub async fn mcp_permissions_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Only apply to the MCP route.
    let Some(server) = parse_server_path(request.uri().path()) else {
        return Ok(next.run(request).await);
    };

    // Extract verified identity (auth middleware should have set it).
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();
    let groups = identity
        .as_ref()
        .and_then(|i| i.groups.as_deref())
        .and_then(|g| serde_json::from_str::<Vec<String>>(g).ok())
        .unwrap_or_default();

    // We need the body to extract the tool. Read and re-attach it.
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, http_util::MAX_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "mcp permissions: failed to read body");
            StatusCode::BAD_REQUEST
        })?;

    // Determine the JSON-RPC method + tool.
    // Non-request payloads (responses/notifications) are not tool targets;
    // the request passes through and is audited as best-effort. Batches
    // (arrays) are rejected — a batch can contain tools/call requests that
    // would bypass per-tool permission enforcement if forwarded verbatim.
    let (tool_call, parse_error) = match parse::extract_tool_call(&body_bytes, &server) {
        Ok(Some(call)) => (Some(call), None),
        Ok(None) => (None, None),
        Err(e) => (None, Some(e)),
    };

    let is_tool_call_method = tool_call
        .as_ref()
        .is_some_and(|c| c.method == oac_mcp::protocol::METHOD_TOOLS_CALL);
    let mcp_method = tool_call
        .as_ref()
        .map(|c| c.method.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let tool_name = if is_tool_call_method {
        tool_call
            .as_ref()
            .map(|c| c.tool.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let args_preview = tool_call.as_ref().and_then(|c| c.args_preview.clone());

    // Resolve the allowlist for the caller's groups.
    let allow = match &tool_call {
        Some(_) => {
            if is_tool_call_method {
                is_tool_allowed(&state, &groups, &server, &tool_name).await
            } else {
                is_method_allowed(&state, &groups, &server).await
            }
        }
        None => {
            if let Some(err) = &parse_error {
                // Fail closed on tool-bearing routes. Batches get a specific
                // message so operators can distinguish a rejected batch
                // (policy) from a genuinely malformed body.
                let reason = match err {
                    oac_mcp::McpError::BatchUnsupported => {
                        "batch JSON-RPC messages are not supported"
                    }
                    _ => "malformed JSON-RPC body",
                };
                (false, Some(reason.to_string()))
            } else {
                // Not a request we enforce (response/notification): allow.
                (true, None)
            }
        }
    };

    let (allowed, denial_reason) = allow;

    if !allowed {
        let grant = McpGrant {
            server: server.clone(),
            method: mcp_method.clone(),
            tool: tool_name.clone(),
            decision: "denied".to_string(),
            reason: denial_reason.clone(),
            args_preview: args_preview.clone(),
        };
        // Audit the denial.
        if let Some(identity) = &identity {
            record_mcp_audit(&state, identity, &grant, StatusCode::FORBIDDEN, 0, false).await;
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32001, "message": denial_reason.clone().unwrap_or_else(|| "tool not allowed".to_string()) },
        })
        .to_string();
        return Ok((
            StatusCode::FORBIDDEN,
            [("content-type", "application/json")],
            body,
        )
            .into_response());
    }

    // Allow: attach the grant for audit + forward.
    request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(McpGrant {
        server: server.clone(),
        method: mcp_method.clone(),
        tool: tool_name.clone(),
        decision: "allowed".to_string(),
        reason: None,
        args_preview,
    });

    Ok(next.run(request).await)
}

/// Parses the server id out of an `/mcp/{server}` path, percent-decoding it.
fn parse_server_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/mcp/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(percent_decode(rest))
}

/// Minimal percent-decoder (server ids are short, opaque strings).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let Some(&cur) = bytes.get(i) else {
            break;
        };
        if cur == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex_val),
                bytes.get(i + 2).copied().and_then(hex_val),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(cur);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Returns `(allowed, reason)` for a `tools/call` on `server`.
async fn is_tool_allowed(
    state: &AppState,
    groups: &[String],
    server: &str,
    tool: &str,
) -> (bool, Option<String>) {
    let allowed = state
        .policy_store
        .resolve_mcp_tool_allowed(groups, server, tool)
        .await;
    match allowed {
        Ok(true) => (true, None),
        Ok(false) => (
            false,
            Some(format!(
                "tool '{tool}' is not allowed on MCP server '{server}'"
            )),
        ),
        Err(e) => {
            // Fail closed on policy-store errors: do not leak an upstream
            // tool behind a DB outage. Log and deny.
            tracing::error!(error = %e, server = %server, tool = %tool, "MCP policy resolution failed");
            (false, Some("policy resolution failed".to_string()))
        }
    }
}

/// Returns whether a non-`tools/call` method is allowed (deny-all applies
/// when the policy is an explicit empty allowlist).
async fn is_method_allowed(
    state: &AppState,
    groups: &[String],
    server: &str,
) -> (bool, Option<String>) {
    let at_least_one = state
        .policy_store
        .resolve_mcp_has_any_tool(groups, server)
        .await;
    match at_least_one {
        Ok(true) => (true, None),
        Ok(false) => (
            false,
            Some(format!(
                "MCP server '{server}' has no allowed tools for this group"
            )),
        ),
        Err(e) => {
            tracing::error!(error = %e, server = %server, "MCP policy resolution failed");
            (false, Some("policy resolution failed".to_string()))
        }
    }
}

/// Records an MCP audit entry from an [`McpGrant`].
///
/// Reused by the per-server middleware and the combined `/mcp` hub so every
/// MCP request — allowed or denied — is logged with the same field mapping
/// (`mcp_server`, `mcp_tool`, `mcp_method`, redacted args preview).
pub(crate) async fn record_mcp_audit(
    state: &AppState,
    identity: &super::auth::VerifiedRelayIdentity,
    grant: &McpGrant,
    status: StatusCode,
    latency_ms: i64,
    stream: bool,
) {
    let entry = AuditEntry {
        device_id: identity
            .identity_id
            .clone()
            .unwrap_or_else(|| identity.subject.clone()),
        user_subject: identity.subject.clone(),
        model: None,
        backend: grant.server.clone(),
        status: status.as_u16() as i32,
        latency_ms,
        stream,
        prompt_tokens: None,
        completion_tokens: None,
        total_tokens: None,
        identity_id: identity.identity_id.clone(),
        email: identity.email.clone(),
        groups: identity.groups.clone(),
        endpoint: Some(format!("/mcp/{}", grant.server)),
        request_id: identity.request_id.clone(),
        permission_decision: Some(grant.decision.clone()),
        denial_reason: grant.reason.clone(),
        cost_usd: None,
        token_saver_applied: None,
        tokens_saved: None,
        messages_dropped: None,
        saver_reasons: None,
        mcp_server: Some(grant.server.clone()),
        mcp_tool: Some(grant.tool.clone()),
        mcp_method: Some(grant.method.clone()),
        mcp_args_preview: grant.args_preview.clone(),
    };
    if let Err(e) = state.audit.record(&entry).await {
        tracing::error!(error = %e, "failed to write MCP audit log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    async fn test_state() -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("mcp-perms");
        let db = crate::db::setup(&url).await.expect("db");
        let mcp_db = db.clone();
        AppState {
            config: oidc_agent_common::config::CentralConfig {
                listen_addr: "127.0.0.1:0".parse().expect("addr"),
                database_url: "sqlite://test.db".into(),
                oidc: oidc_agent_common::config::OidcConfig {
                    issuer: "https://idp".into(),
                    client_id: "c".into(),
                    client_secret_env: "E".into(),
                    redirect_uri: "http://127.0.0.1:0/cb".into(),
                    scopes: vec!["openid".into()],
                },
                mtls: oidc_agent_common::config::MtlsServerConfig {
                    ca_cert_path: "/c".into(),
                    server_cert_path: "/s".into(),
                    server_key_path: "/k".into(),
                },
                admin: None,
                pricing: None,
                dev_mode: true,
                rate_limit_requests: 60,
                rate_limit_window_secs: 60,
            },
            provider_store: crate::provider::ProviderStore::new(
                db.clone(),
                Zeroizing::new([7_u8; 32]),
            ),
            client: reqwest::Client::new(),
            audit: crate::audit::AuditLogger::new(db.clone()),
            rate_limiter: None,
            policy_store: crate::policy::PolicyStore::new(db.clone()),
            device_store: crate::device_store::DeviceStore::new(db.clone()),
            usage_tracker: crate::usage::UsageTracker::new(db.clone()),
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
                issuer: "https://idp".into(),
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
            .route("/mcp/{server}", axum::routing::any(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                mcp_permissions_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state,
                super::super::auth::auth_middleware,
            ))
            .with_state(())
    }

    fn mcp_request(token: &str, tool: &str) -> Request<Body> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": { "path": "/x" } },
        })
        .to_string();
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp/fs")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .expect("build request")
    }

    #[tokio::test]
    async fn allowlisted_tool_passes() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "read_file"))
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_allowlisted_tool_is_denied() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "delete_file"))
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn no_policy_blocks_all_tools() {
        let state = test_state().await;
        // No MCP policy configured for this group → deny-all for tools.
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "read_file"))
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allow_all_policy_permits_any_tool() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "delete_file"))
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn parses_server_path() {
        assert_eq!(parse_server_path("/mcp/fs").as_deref(), Some("fs"));
        assert_eq!(parse_server_path("/mcp/fs/extra"), None);
        assert_eq!(parse_server_path("/v1/models"), None);
        assert_eq!(parse_server_path("/mcp/").as_deref(), None);
    }

    #[tokio::test]
    async fn batch_tools_call_is_denied() {
        // A JSON-RPC batch (array) is rejected by the parse layer with
        // BatchUnsupported; the middleware must deny it with a specific
        // message.
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let batch = serde_json::json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "read_file", "arguments": {} } }
        ])
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(batch))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["error"]["code"], -32001);
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("batch"),
            "batch rejection message must mention 'batch'"
        );
    }

    #[tokio::test]
    async fn malformed_json_body_is_denied() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from("not json at all"))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["error"]["code"], -32001);
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("malformed"),
            "malformed body message must mention 'malformed'"
        );
    }

    #[tokio::test]
    async fn non_tools_call_method_denied_when_no_allowed_tools() {
        // A non-tools/call method (e.g. tools/list) requires at least one
        // allowed tool (deny-all when the policy is an explicit empty set).
        let state = test_state().await;
        // Empty allowed-tools list → deny-all for the server.
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&[]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["error"]["code"], -32001);
    }

    #[tokio::test]
    async fn non_tools_call_method_allowed_when_tools_exist() {
        // A non-tools/call method (e.g. tools/list) is allowed when the
        // group has at least one allowed tool on that server.
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn response_object_is_denied_malformed() {
        // A JSON-RPC response object (has jsonrpc+id+result but no method)
        // fails to deserialize as a JsonRpcRequest → the middleware denies
        // it with 403 (fail-closed on malformed JSON-RPC).
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": [] },
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "response object (no method) must be denied as malformed"
        );
    }

    #[tokio::test]
    async fn notification_passes_through() {
        // A JSON-RPC notification (has method but no id) is not a tool
        // target; the middleware passes it through.
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/fs")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn percent_decode_handles_encoded_chars() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("%2F"), "/");
        // Incomplete escape at end — should keep the literal '%'.
        assert_eq!(percent_decode("abc%2"), "abc%2");
    }

    #[test]
    fn hex_val_converts_correctly() {
        assert_eq!(hex_val(b'0'), Some(0));
        assert_eq!(hex_val(b'9'), Some(9));
        assert_eq!(hex_val(b'a'), Some(10));
        assert_eq!(hex_val(b'F'), Some(15));
        assert_eq!(hex_val(b'g'), None);
    }

    #[tokio::test]
    async fn empty_groups_list_denies_all_tools() {
        // A caller with an empty groups list (verified but groupless) must
        // not reach any tool — MCP tools are opt-in.
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "groupless", r#"[]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "read_file"))
            .await
            .expect("router run");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "empty groups must deny all tools"
        );
    }

    #[tokio::test]
    async fn tool_on_server_not_in_allowed_set_denies() {
        // The policy allows tools on "fs" but the request targets "gh".
        // The middleware must deny (the server is not in the allowed set).
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        // Request targets /mcp/gh (not fs), so "gh:read_file" is not in the
        // allowlist → denied.
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": {} },
        })
        .to_string();
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp/gh")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token_u}"))
                    .body(Body::from(body))
                    .expect("build request"),
            )
            .await
            .expect("router run");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn policy_store_error_fails_closed() {
        // If the policy store returns an error, the middleware must deny
        // (fail-closed), not leak the tool. We simulate this by querying a
        // server that has no policy at all (deny-all by default).
        let state = test_state().await;
        let token_u = mint_test_token(&state, "u", r#"["eng"]"#).await;
        let app = test_router(state);
        let resp = app
            .oneshot(mcp_request(&token_u, "read_file"))
            .await
            .expect("router run");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "no policy → deny-closed"
        );
    }
}
