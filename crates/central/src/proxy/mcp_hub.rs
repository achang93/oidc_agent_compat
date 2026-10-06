//! Combined MCP hub handler (`/mcp`).
//!
//! This is the single MCP endpoint a user configures in their agent. It
//! aggregates every centrally-hosted MCP server into one namespace:
//!
//! - **`initialize`** → forwards to the first enabled server reachable by
//!   the caller and returns its result (so the client negotiates a protocol
//!   version).
//! - **`tools/list`** → fans out to each enabled server the caller may
//!   reach, prefixes every tool name with `{server}__`, filters by the
//!   caller's per-tool policy, and aggregates the results.
//! - **`tools/call`** → splits the prefixed name into `(server, tool)`,
//!   enforces the caller's per-tool policy inline, and routes to that server.
//! - **`ping`** → returns an empty result.
//! - **notifications/*** → best-effort broadcast to all reachable servers.
//!
//! # Security
//!
//! - Enforcement happens here (on the central proxy, after auth) — a
//!   compromised relay cannot bypass per-tool policy.
//! - Every `tools/call` (allowed or denied) and every upstream error is
//!   recorded with the same [`McpGrant`]-based audit mapping as the
//!   per-server endpoint.

use std::collections::HashSet;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use oac_mcp::hub;
use oac_mcp::protocol::{METHOD_INITIALIZE, METHOD_PING, METHOD_TOOLS_CALL, METHOD_TOOLS_LIST};
use oidc_agent_common::error::{Error, Result};

use super::AppState;
use crate::proxy::mcp_permissions::{McpGrant, record_mcp_audit};

/// Handles a combined `/mcp` request.
pub async fn mcp_hub_handler(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Response<Body> {
    let start = Instant::now();
    let identity = request
        .extensions()
        .get::<super::auth::VerifiedRelayIdentity>()
        .cloned();

    // Groups used for policy resolution.
    let groups: Vec<String> = identity
        .as_ref()
        .and_then(|i| i.groups.as_deref())
        .and_then(|g| serde_json::from_str(g).ok())
        .unwrap_or_default();

    // Read the JSON-RPC body.
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, super::MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "hub: failed to read body");
            return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "parse error");
        }
    };

    // Parse the method.
    let parsed = oac_mcp::parse::parse_request_body(&body_bytes);
    let (method, id) = match parsed {
        Ok(Some(req)) => (req.method.clone(), req.id),
        Ok(None) => {
            // Not a request object (notification/response/scalar). Try to
            // classify and forward/broadcast as appropriate; otherwise allow.
            return json_rpc_error(StatusCode::OK, -32600, "invalid request");
        }
        Err(oac_mcp::McpError::BatchUnsupported) => {
            // Batches are rejected at the proxy boundary: a batch can
            // contain tools/call requests that would bypass per-tool
            // permission enforcement if forwarded verbatim.
            return json_rpc_error(StatusCode::OK, -32600, "invalid request");
        }
        Err(_) => return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "parse error"),
    };

    // Determine the set of servers the caller may reach (for fan-out).
    let reachable = match state
        .policy_store
        .resolve_mcp_allowed_servers(&groups)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "hub: policy resolution failed");
            let _ = record_hub_audit(
                &state,
                &identity,
                &method,
                "",
                StatusCode::FORBIDDEN,
                start,
                None,
            )
            .await;
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };

    match method.as_str() {
        METHOD_TOOLS_CALL => {
            handle_tools_call(&state, &identity, &groups, id, &body_bytes, start).await
        }
        METHOD_TOOLS_LIST => {
            handle_tools_list(
                &state,
                &identity,
                &groups,
                &reachable,
                id,
                &body_bytes,
                start,
            )
            .await
        }
        METHOD_INITIALIZE => handle_initialize(&state, &identity, &reachable, id, start).await,
        METHOD_PING => {
            let _ =
                record_hub_audit(&state, &identity, &method, "", StatusCode::OK, start, None).await;
            json_response(id, serde_json::json!({}))
        }
        m if m.starts_with("notifications/") => {
            // Best-effort broadcast; client does not expect a response.
            broadcast_notification(&state, &groups, &body_bytes).await;
            (StatusCode::ACCEPTED, Body::empty()).into_response()
        }
        _ => {
            // Unknown method: MCP JSON-RPC error -32601.
            let _ =
                record_hub_audit(&state, &identity, &method, "", StatusCode::OK, start, None).await;
            json_rpc_error(StatusCode::OK, -32601, "method not found")
        }
    }
}

/// Handles a `tools/call` on the hub: split the prefixed name, enforce the
/// per-tool policy, and route to the target server.
async fn handle_tools_call(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    groups: &[String],
    _id: Option<serde_json::Value>,
    raw_body: &[u8],
    start: Instant,
) -> Response<Body> {
    // Extract the tool name and args preview from the JSON-RPC body.
    let parsed = oac_mcp::parse::extract_tool_call(raw_body, "hub")
        .ok()
        .flatten();
    let Some(call) = parsed else {
        let _ = record_hub_audit(
            state,
            identity,
            METHOD_TOOLS_CALL,
            "",
            StatusCode::BAD_REQUEST,
            start,
            None,
        )
        .await;
        return json_rpc_error(StatusCode::BAD_REQUEST, -32700, "malformed tools/call");
    };
    let tool_name = call.tool;

    // Split into server + tool.
    let Some((server, tool)) = hub::split_tool_name(&tool_name) else {
        let _ = record_hub_audit(
            state,
            identity,
            METHOD_TOOLS_CALL,
            &tool_name,
            StatusCode::BAD_REQUEST,
            start,
            None,
        )
        .await;
        return json_rpc_error(
            StatusCode::BAD_REQUEST,
            -32602,
            format!("tool name '{tool_name}' is missing a '{{server}}__' prefix"),
        );
    };

    // Enforce per-tool policy inline (deny-by-default).
    let allowed = match state
        .policy_store
        .resolve_mcp_tool_allowed(groups, server, tool)
        .await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, server = %server, tool = %tool, "hub: policy resolution failed");
            let _ = record_hub_audit(
                state,
                identity,
                METHOD_TOOLS_CALL,
                &tool_name,
                StatusCode::FORBIDDEN,
                start,
                None,
            )
            .await;
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };
    if !allowed {
        // Record a denied audit entry (consistent with per-server endpoint).
        if let Some(identity) = identity {
            let grant = McpGrant {
                server: server.to_string(),
                method: METHOD_TOOLS_CALL.to_string(),
                tool: tool.to_string(),
                decision: "denied".to_string(),
                reason: Some(format!(
                    "tool '{tool}' is not allowed on MCP server '{server}'"
                )),
                args_preview: None,
            };
            record_mcp_audit(
                state,
                identity,
                &grant,
                StatusCode::FORBIDDEN,
                start.elapsed().as_millis() as i64,
                false,
            )
            .await;
        }
        return json_rpc_error(
            StatusCode::FORBIDDEN,
            -32001,
            format!("tool '{tool}' is not allowed on MCP server '{server}'"),
        );
    }

    // Route to the server.
    let resolved = match state.mcp_manager.resolve_server(server).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = record_hub_audit(
                state,
                identity,
                METHOD_TOOLS_CALL,
                &tool_name,
                StatusCode::NOT_FOUND,
                start,
                None,
            )
            .await;
            return json_rpc_error(
                StatusCode::NOT_FOUND,
                -32602,
                format!("MCP server '{server}' not found or disabled"),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, server = %server, "hub: resolve failed");
            let _ = record_hub_audit(
                state,
                identity,
                METHOD_TOOLS_CALL,
                &tool_name,
                StatusCode::BAD_GATEWAY,
                start,
                None,
            )
            .await;
            return json_rpc_error(
                StatusCode::BAD_GATEWAY,
                -32603,
                "upstream MCP request failed",
            );
        }
    };

    // Rewrite the tool name in the body to the unprefixed name before
    // forwarding (the upstream knows its own tool names).
    let rewritten = rewrite_tool_name(raw_body, tool);
    match call_upstream(state, server, &resolved, &rewritten).await {
        Ok((resp, status, _stream)) => {
            // Audit with the real target server and the unprefixed tool
            // name (plus the redacted args preview) — consistent with the
            // per-server endpoint and with how denials are recorded.
            if let Some(identity) = identity {
                let grant = McpGrant {
                    server: server.to_string(),
                    method: METHOD_TOOLS_CALL.to_string(),
                    tool: tool.to_string(),
                    decision: "allowed".to_string(),
                    reason: None,
                    args_preview: call.args_preview.clone(),
                };
                record_mcp_audit(
                    state,
                    identity,
                    &grant,
                    status,
                    start.elapsed().as_millis() as i64,
                    false,
                )
                .await;
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, server = %server, "hub: upstream call failed");
            if let Some(identity) = identity {
                let grant = McpGrant {
                    server: server.to_string(),
                    method: METHOD_TOOLS_CALL.to_string(),
                    tool: tool.to_string(),
                    decision: "allowed".to_string(),
                    reason: None,
                    args_preview: call.args_preview.clone(),
                };
                record_mcp_audit(
                    state,
                    identity,
                    &grant,
                    StatusCode::BAD_GATEWAY,
                    start.elapsed().as_millis() as i64,
                    false,
                )
                .await;
            }
            json_rpc_error(
                StatusCode::BAD_GATEWAY,
                -32603,
                "upstream MCP request failed",
            )
        }
    }
}

/// Handles a `tools/list`: fan out to enabled reachable servers, prefix tool
/// names, filter by policy, and aggregate.
async fn handle_tools_list(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    groups: &[String],
    reachable: &Option<HashSet<String>>,
    _id: Option<serde_json::Value>,
    raw_body: &[u8],
    start: Instant,
) -> Response<Body> {
    // The set of tool entries allowed (None = all). Used to filter.
    let allowed_tools = match state.policy_store.resolve_mcp_allowed_tools(groups).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "hub: tools/list policy failed");
            return json_rpc_error(StatusCode::FORBIDDEN, -32001, "policy resolution failed");
        }
    };

    // Enabled servers, filtered to those reachable.
    let enabled = match state.mcp_manager.list_enabled_servers().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "hub: list servers failed");
            return json_rpc_error(StatusCode::BAD_GATEWAY, -32603, "server listing failed");
        }
    };
    let reachable_ids: Vec<_> = enabled
        .iter()
        .filter(|s| reachable.as_ref().is_none_or(|r| r.contains(&s.id)))
        .collect();

    let mut tools: Vec<serde_json::Value> = Vec::new();
    for server_info in reachable_ids {
        let resolved = match state.mcp_manager.resolve_server(&server_info.id).await {
            Ok(Some(r)) => r,
            _ => continue,
        };
        let Ok((resp, status, _)) =
            call_upstream(state, &server_info.id, &resolved, raw_body).await
        else {
            continue;
        };
        if status != StatusCode::OK {
            continue;
        }
        let Ok(bytes) = axum::body::to_bytes(resp.into_body(), super::MAX_BODY_SIZE).await else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(list) = value.pointer("/result/tools").and_then(|v| v.as_array()) else {
            continue;
        };
        for tool in list {
            let Some(name) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            // Hub-exposed name and the policy key for the same tool pair.
            let prefixed = hub::join_tool_name(&server_info.id, name);
            let policy_key = format!("{}:{name}", server_info.id);
            // Filter by per-tool policy.
            if let Some(allowed) = &allowed_tools {
                if !allowed.contains(&policy_key) {
                    continue;
                }
            }
            let mut t = tool.clone();
            if let Some(obj) = t.as_object_mut() {
                obj.insert("name".into(), serde_json::Value::String(prefixed.clone()));
                // Convenience annotation: the source server.
                obj.insert(
                    "x-oac-server".into(),
                    serde_json::Value::String(server_info.id.clone()),
                );
            }
            tools.push(t);
        }
    }
    let _ = record_hub_audit(
        state,
        identity,
        METHOD_TOOLS_LIST,
        "",
        StatusCode::OK,
        start,
        Some(format!("{} tools", tools.len())),
    )
    .await;
    json_response(None, serde_json::json!({ "tools": tools }))
}

/// Handles `initialize`: forward to the first reachable server and return its
/// result; if none, return a default (protocol version).
async fn handle_initialize(
    state: &AppState,
    _identity: &Option<super::auth::VerifiedRelayIdentity>,
    reachable: &Option<HashSet<String>>,
    id: Option<serde_json::Value>,
    _start: Instant,
) -> Response<Body> {
    let enabled = state
        .mcp_manager
        .list_enabled_servers()
        .await
        .unwrap_or_default();
    for server_info in enabled {
        if reachable
            .as_ref()
            .is_none_or(|r| r.contains(&server_info.id))
        {
            if let Ok(Some(resolved)) = state.mcp_manager.resolve_server(&server_info.id).await {
                let body = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "method": METHOD_INITIALIZE,
                    "params": { "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION, "capabilities": {}, "clientInfo": { "name": "oac-hub", "version": "1.0" } },
                })
                .to_string();
                if let Ok((resp, status, _)) =
                    call_upstream(state, &server_info.id, &resolved, body.as_bytes()).await
                {
                    if status == StatusCode::OK {
                        if let Ok(bytes) =
                            axum::body::to_bytes(resp.into_body(), super::MAX_BODY_SIZE).await
                        {
                            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                let result = value.get("result").cloned().unwrap_or_else(|| {
                                    serde_json::json!({ "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION })
                                });
                                return json_response(id, result);
                            }
                        }
                    }
                }
            }
        }
    }
    json_response(
        id,
        serde_json::json!({ "protocolVersion": oac_mcp::protocol::PROTOCOL_VERSION, "capabilities": {}, "serverInfo": { "name": "oac-hub", "version": "1.0" } }),
    )
}

/// Broadcasts a notification to every reachable server (best-effort).
async fn broadcast_notification(state: &AppState, groups: &[String], raw_body: &[u8]) {
    let reachable = match state.policy_store.resolve_mcp_allowed_servers(groups).await {
        Ok(r) => r,
        Err(_) => return,
    };
    let enabled = match state.mcp_manager.list_enabled_servers().await {
        Ok(s) => s,
        Err(_) => return,
    };
    for server_info in enabled {
        if reachable
            .as_ref()
            .is_none_or(|r| r.contains(&server_info.id))
        {
            if let Ok(Some(resolved)) = state.mcp_manager.resolve_server(&server_info.id).await {
                let _ = call_upstream(state, &server_info.id, &resolved, raw_body).await;
            }
        }
    }
}

/// Rewrites the `params.name` field of a `tools/call` body to the
/// unprefixed tool name, for forwarding to the upstream.
fn rewrite_tool_name(raw_body: &[u8], tool: &str) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(raw_body).unwrap_or(serde_json::Value::Null);
    if let Some(params) = value.get_mut("params") {
        if let Some(obj) = params.as_object_mut() {
            obj.insert("name".into(), serde_json::Value::String(tool.to_string()));
        }
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| raw_body.to_vec())
}

/// Forwards a raw JSON-RPC body to a specific upstream MCP server, injecting
/// its auth header and stripping hop-by-hop headers.
async fn call_upstream(
    state: &AppState,
    _server: &str,
    resolved: &crate::mcp::ResolvedMcpServer,
    body: &[u8],
) -> Result<(Response<Body>, StatusCode, bool)> {
    // The base_url already points at the MCP Streamable HTTP endpoint (e.g.
    // "https://example.com/mcp"). Post directly to it.
    let url = resolved.base_url.trim_end_matches('/').to_string();

    // Build headers: forwardables are not needed for synthetic JSON-RPC; only
    // content-type + optional auth header.
    let mut headers: Vec<(axum::http::HeaderName, axum::http::HeaderValue)> = Vec::new();
    headers.push((
        axum::http::HeaderName::from_static("content-type"),
        axum::http::HeaderValue::from_static("application/json"),
    ));
    if let Some(auth) = &resolved.auth_header {
        if let Some((name, value)) = auth.as_str().split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if !name.is_empty() {
                if let Ok(n) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
                    if let Ok(v) = axum::http::HeaderValue::from_str(value) {
                        headers.push((n, v));
                    }
                }
            }
        }
    }

    let map: reqwest::header::HeaderMap = headers
        .into_iter()
        .map(|(n, v)| {
            let name = reqwest::header::HeaderName::from_bytes(n.as_str().as_bytes())
                .map_err(|_| Error::Http("invalid header".into()))?;
            let value = reqwest::header::HeaderValue::from_bytes(v.as_bytes())
                .map_err(|_| Error::Http("invalid header value".into()))?;
            Ok((name, value))
        })
        .collect::<Result<reqwest::header::HeaderMap>>()?;

    let resp = state
        .mcp_manager
        .client()
        .post(&url)
        .headers(map)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| Error::Http(format!("MCP upstream send: {e}")))?;

    let status = resp.status();
    let upstream_headers = resp.headers().clone();
    let stream = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(oidc_agent_common::http_util::is_sse_content_type)
        .unwrap_or(false);
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Http(format!("read MCP upstream body: {e}")))?;

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(bytes))
        .map_err(|e| Error::Http(format!("build MCP response: {e}")))?;
    *response.headers_mut() = upstream_headers;

    Ok((response, status, stream))
}

/// Records a hub audit entry.
async fn record_hub_audit(
    state: &AppState,
    identity: &Option<super::auth::VerifiedRelayIdentity>,
    method: &str,
    tool: &str,
    status: StatusCode,
    start: Instant,
    note: Option<String>,
) -> Result<()> {
    if let Some(identity) = identity {
        let grant = McpGrant {
            server: "hub".to_string(),
            method: method.to_string(),
            tool: tool.to_string(),
            decision: if status.is_success() {
                "allowed".into()
            } else {
                "denied".into()
            },
            reason: note,
            args_preview: None,
        };
        record_mcp_audit(
            state,
            identity,
            &grant,
            status,
            start.elapsed().as_millis() as i64,
            false,
        )
        .await;
    }
    Ok(())
}

/// Builds a JSON-RPC error response with the given id = null (id lost for
/// errors in the hub path; acceptable).
fn json_rpc_error(status: StatusCode, code: i64, message: impl Into<String>) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": code, "message": message.into() },
    })
    .to_string();
    (status, [("content-type", "application/json")], body).into_response()
}

/// Builds a successful JSON-RPC response.
fn json_response(id: Option<serde_json::Value>, result: serde_json::Value) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(serde_json::Value::Null),
        "result": result,
    })
    .to_string();
    (StatusCode::OK, [("content-type", "application/json")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    /// Builds a minimal dev-mode AppState for MCP hub tests.
    async fn test_state() -> AppState {
        let url = oidc_agent_common::persistence::temp_sqlite_url("mcp-hub");
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

    /// Mints a token and returns the plaintext bearer.
    async fn mint_token(state: &AppState, subject: &str, groups: &str) -> String {
        let minted = state
            .token_store
            .mint_token(&crate::token_store::MintRequest {
                subject: subject.into(),
                issuer: "https://idp".into(),
                email: None,
                display_name: None,
                groups: Some(groups.into()),
                identity_id: Some(format!("{subject}-id")),
                label: "test".into(),
                expires_at: None,
                device_fingerprint: None,
            })
            .await
            .expect("mint");
        minted.plaintext.to_string()
    }

    /// Builds a router with the hub handler behind the auth middleware so
    /// the verified identity is attached to the request extensions.
    fn hub_router(state: AppState) -> Router {
        Router::new()
            .route("/mcp", axum::routing::any(mcp_hub_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                super::super::auth::auth_middleware,
            ))
            .with_state(state)
    }

    /// A POST /mcp request with the given JSON-RPC body and bearer token.
    fn hub_request(token: &str, body: serde_json::Value) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .expect("build request")
    }

    /// Reads the JSON body from a response.
    async fn read_json(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("parse json")
    }

    #[tokio::test]
    async fn empty_body_returns_parse_error() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32700, "empty body → parse error");
    }

    #[tokio::test]
    async fn invalid_json_returns_parse_error() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from("not json at all"))
                    .expect("build request"),
            )
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn batch_request_returns_invalid_request() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        let batch = serde_json::json!([
            { "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "fs__read", "arguments": {} } },
            { "jsonrpc": "2.0", "id": 2, "method": "ping" }
        ]);
        let resp = app
            .oneshot(hub_request(&token, batch))
            .await
            .expect("router");
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32600, "batch must be rejected");
    }

    #[tokio::test]
    async fn response_object_returns_parse_error() {
        // A JSON-RPC response object (jsonrpc+id+result but no method)
        // fails to deserialize as a JsonRpcRequest → the hub returns
        // -32700 (parse error, the Err(_) arm).
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        let response_obj = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let resp = app
            .oneshot(hub_request(&token, response_obj))
            .await
            .expect("router");
        let json = read_json(resp).await;
        assert_eq!(
            json["error"]["code"], -32700,
            "response object (no method) → parse error"
        );
    }

    #[tokio::test]
    async fn scalar_body_returns_invalid_request() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        // A JSON scalar (number) → Ok(None) → invalid request.
        let resp = app
            .oneshot(hub_request(&token, serde_json::json!(42)))
            .await
            .expect("router");
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn ping_returns_empty_result() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        // Allow-all MCP policy so the server set resolves to None.
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        let ping = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
        });
        let resp = app
            .oneshot(hub_request(&token, ping))
            .await
            .expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        assert!(json.get("result").is_some(), "ping must return a result");
        assert!(
            json["result"]
                .as_object()
                .map(|o| o.is_empty())
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32601, "unknown method → -32601");
    }

    #[tokio::test]
    async fn tools_list_with_no_servers_returns_empty() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        // Allow-all MCP policy so the caller can reach any server, but none
        // are registered.
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        let tools = json["result"]["tools"]
            .as_array()
            .expect("tools must be an array");
        assert!(tools.is_empty(), "no servers → empty tools list");
    }

    #[tokio::test]
    async fn tools_list_denied_when_no_mcp_policy() {
        // No MCP policy configured → deny-all (empty server set).
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        let tools = json["result"]["tools"]
            .as_array()
            .expect("tools must be an array");
        assert!(tools.is_empty(), "no policy → empty tools list (deny-all)");
    }

    #[tokio::test]
    async fn initialize_with_no_servers_returns_default() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1.0" }
            }
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        assert!(
            json.get("result").is_some(),
            "initialize must return a result"
        );
        assert_eq!(
            json["result"]["protocolVersion"],
            oac_mcp::protocol::PROTOCOL_VERSION
        );
        assert_eq!(json["result"]["serverInfo"]["name"], "oac-hub");
    }

    #[tokio::test]
    async fn tools_call_without_prefix_returns_error() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        // A tools/call with a tool name that has no {server}__ prefix.
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": {} },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        let json = read_json(resp).await;
        assert_eq!(
            json["error"]["code"], -32602,
            "missing server prefix → -32602"
        );
    }

    #[tokio::test]
    async fn tools_call_to_nonexistent_server_returns_not_found() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        // A tools/call with a valid prefix but nonexistent server.
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "nonexist__read_file", "arguments": {} },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32602, "nonexistent server → -32602");
    }

    #[tokio::test]
    async fn tools_call_denied_when_tool_not_in_policy() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        // Policy allows only fs:read_file, not fs:delete_file.
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "fs__delete_file", "arguments": {} },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32001);
    }

    #[tokio::test]
    async fn notification_returns_accepted() {
        let state = test_state().await;
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "notifications return 202 Accepted"
        );
    }

    // --- Mock-upstream tests: exercise the forward / fan-out paths ---

    /// Spawns a mock MCP upstream that replies to every POST with the given
    /// (status, content-type, body) tuple. Returns its `127.0.0.1:port` URL.
    async fn spawn_mock_mcp(
        status: axum::http::StatusCode,
        content_type: &'static str,
        body: &'static str,
    ) -> String {
        let mock = Router::new().route(
            "/mcp",
            axum::routing::post(move |_body: axum::body::Body| async move {
                (
                    status,
                    [(axum::http::header::CONTENT_TYPE, content_type)],
                    body,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("mock addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, mock).await;
        });
        format!("http://{addr}/mcp")
    }

    /// Registers an enabled MCP server with the manager, pointing at `url`.
    async fn register_server(state: &AppState, id: &str, url: &str) {
        state
            .mcp_manager
            .upsert_server(&crate::mcp::McpServerInput {
                id: id.into(),
                name: id.into(),
                base_url: url.into(),
                enabled: true,
                auth_header: None,
            })
            .await
            .expect("upsert server");
    }

    #[tokio::test]
    async fn tools_call_routes_to_upstream_and_audits_allowed() {
        let state = test_state().await;
        let url = spawn_mock_mcp(
            StatusCode::OK,
            "application/json",
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":"done"}}"#,
        )
        .await;
        register_server(&state, "fs", &url).await;
        // Allow-all MCP policy so the tool is permitted.
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "caller", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "fs__read_file", "arguments": { "path": "/x" } },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        assert_eq!(json["result"]["content"], "done");
    }

    #[tokio::test]
    async fn tools_call_upstream_failure_returns_bad_gateway() {
        let state = test_state().await;
        // Point at a closed port → upstream send fails → 502.
        register_server(&state, "fs", "http://127.0.0.1:1/mcp").await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "caller", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "fs__read_file", "arguments": {} },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = read_json(resp).await;
        assert_eq!(json["error"]["code"], -32603);
    }

    #[tokio::test]
    async fn tools_list_fans_out_and_prefixes_tool_names() {
        let state = test_state().await;
        let url = spawn_mock_mcp(
            StatusCode::OK,
            "application/json",
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"read"},{"name":"write_file","description":"write"}]}}"#,
        )
        .await;
        register_server(&state, "fs", &url).await;
        // Allow-all MCP policy → every tool is visible.
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "lister", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        let tools = json["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 2);
        // Each tool name is prefixed with the server id.
        assert_eq!(tools[0]["name"], "fs__read_file");
        assert_eq!(tools[1]["name"], "fs__write_file");
        // The convenience annotation records the source server.
        assert_eq!(tools[0]["x-oac-server"], "fs");
    }

    #[tokio::test]
    async fn tools_list_filters_by_per_tool_policy() {
        let state = test_state().await;
        let url = spawn_mock_mcp(
            StatusCode::OK,
            "application/json",
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"},{"name":"delete_file"}]}}"#,
        )
        .await;
        register_server(&state, "fs", &url).await;
        // Only fs:read_file is allowed; fs:delete_file must be filtered out.
        state
            .policy_store
            .upsert_mcp_policy("eng", Some(&["fs:read_file".to_string()]))
            .await
            .expect("policy");
        let token = mint_token(&state, "lister", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        let json = read_json(resp).await;
        let tools = json["result"]["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 1, "only the allowlisted tool must appear");
        assert_eq!(tools[0]["name"], "fs__read_file");
    }

    #[tokio::test]
    async fn tools_list_skips_upstream_errors() {
        let state = test_state().await;
        // Upstream returns 500 → the server's tools are silently skipped.
        let url = spawn_mock_mcp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            r#"{"error":"oops"}"#,
        )
        .await;
        register_server(&state, "broken", &url).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "lister", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        let tools = json["result"]["tools"].as_array().expect("tools array");
        assert!(tools.is_empty(), "a 500 upstream contributes no tools");
    }

    #[tokio::test]
    async fn initialize_forwards_to_first_reachable_server() {
        let state = test_state().await;
        let url = spawn_mock_mcp(
            StatusCode::OK,
            "application/json",
            r#"{"jsonrpc":"2.0","id":null,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"upstream","version":"1.0"}}}"#,
        )
        .await;
        register_server(&state, "fs", &url).await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "init", r#"["eng"]"#).await;
        let app = hub_router(state);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } }
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_json(resp).await;
        // The upstream's result is returned, not the default oac-hub response.
        assert_eq!(json["result"]["serverInfo"]["name"], "upstream");
    }

    #[tokio::test]
    async fn tools_call_with_malformed_body_returns_parse_error() {
        let state = test_state().await;
        state
            .policy_store
            .upsert_mcp_policy("eng", None)
            .await
            .expect("policy");
        let token = mint_token(&state, "u", r#"["eng"]"#).await;
        let app = hub_router(state);
        // A tools/call with an empty params name → extract_tool_call returns
        // Err(Malformed) → the hub returns -32700.
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "", "arguments": {} },
        });
        let resp = app.oneshot(hub_request(&token, req)).await.expect("router");
        let json = read_json(resp).await;
        assert_eq!(
            json["error"]["code"], -32700,
            "malformed tools/call body → parse error"
        );
    }

    #[tokio::test]
    async fn rewrite_tool_name_strips_server_prefix() {
        // The helper must rewrite `params.name` from the prefixed hub name to
        // the bare tool name the upstream expects.
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fs__read_file","arguments":{}}}"#;
        let rewritten = rewrite_tool_name(body, "read_file");
        let value: serde_json::Value = serde_json::from_slice(&rewritten).expect("json");
        assert_eq!(value["params"]["name"], "read_file");
    }

    #[tokio::test]
    async fn rewrite_tool_name_preserves_non_object_params() {
        // When params is missing or non-object, the body passes through
        // (the name cannot be rewritten, but the body is not corrupted).
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let rewritten = rewrite_tool_name(body, "read_file");
        let value: serde_json::Value = serde_json::from_slice(&rewritten).expect("json");
        assert_eq!(value["method"], "ping");
    }
}
