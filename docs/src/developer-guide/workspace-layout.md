# Workspace Layout

The project is a Cargo workspace with five crates. This page documents the
full source file tree.

## Crate overview

| **Crate** | **Path** | **Binary** | **Lib** | **Role** |
|---|---|---|---|---|
| `oidc-agent-common` | `crates/common` | — | `oidc_agent_common` | Shared primitives |
| `oac-mcp` | `crates/mcp` | — | `oac_mcp` | MCP/JSON-RPC protocol types & parsing |
| `oac-relay` | `crates/relay` | `oac-relay` | `oac_relay` | Laptop relay |
| `oac-central` | `crates/central` | `oac-central` | `oac_central` | Central proxy |
| `oac-e2e-tests` | `tests/e2e` | — | `oac_e2e_tests` | In-process E2E tests |

## Full source tree

### `crates/common/` — Shared primitives

```
crates/common/src/
├── lib.rs              # Crate root; re-exports all modules
├── config.rs           # RelayConfig / CentralConfig TOML schemas + validation
├── error.rs            # Unified Error enum + Result alias (thiserror)
├── keys.rs             # Local API key gen, SHA-256 hashing, constant-time compare
├── oidc.rs             # OIDC RP client builder + CustomAdditionalClaims
├── mtls.rs             # rustls mTLS client/server config builders
├── logging.rs          # Structured JSON logging + secret-redaction layer
├── shutdown.rs         # Graceful shutdown signal handler
├── http_util.rs        # HTTP forwarding utilities (hop-by-hop, path sanitization, SSE)
├── identity.rs         # X-OAC-* identity header constants
├── persistence.rs      # Shared DB helpers (setup_database, enforce_db_perms)
├── time_util.rs        # Time utilities (now_utc, format_time)
└── test_certs.rs       # Test cert generation (rcgen, behind test-certs feature)
```

### `crates/mcp/` — MCP protocol types & parsing

```
crates/mcp/src/
├── lib.rs              # Crate root; re-exports modules
├── errors.rs           # McpError enum + Result alias
├── jsonrpc.rs          # JSON-RPC 2.0 request/response framing (batches rejected)
├── protocol.rs         # MCP method constants + ToolCall/initialize types
├── hub.rs              # Hub `server__tool` name join/split helpers
└── parse.rs            # extract_tool_call, redaction, validation helpers
```

### `crates/relay/` — Laptop relay

```
crates/relay/src/
├── lib.rs              # Lib exposed for integration tests
├── main.rs             # Binary: CLI dispatch, serve()
├── login.rs            # Browser + PKCE flow, secure grant handoff, agent config injection
├── keystore.rs         # KeyStore: OIDC identity upsert only (no key methods)
├── db.rs               # Relay DB setup
├── migration.rs        # SeaORM migrations (4 migrations)
├── activity.rs         # Relay-side activity logger (append-only)
├── agent_config.rs     # Agent config injection (Codex config.json / ~/.oac/agent-env.sh)
├── proxy/
│   ├── mod.rs          # Router, AppState, serve() (includes token_store)
│   ├── auth.rs         # Pass-through auth (checks Authorization header presence)
│   ├── forward.rs      # Relay→central forwarding (mTLS client, SSE passthrough)
│   ├── mcp_forward.rs  # MCP byte-tunnel (JSON-RPC → central with identity)
│   └── host_guard.rs   # DNS rebinding defense (Host header validation)
└── entity/
    ├── mod.rs
    ├── identity.rs         # identity entity
    └── relay_activity_log.rs  # relay_activity_log entity

crates/relay/tests/
└── proxy_integration.rs    # 12 integration tests
```

### `crates/central/` — Central proxy

```
crates/central/src/
├── lib.rs              # Lib exposed for integration tests
├── main.rs             # Binary: serve and admin CLI
├── db.rs               # Central DB setup
├── migration.rs        # SeaORM migrations (10 migrations)
├── crypto.rs           # encryption_key_from_hex + sha256 helpers (shared by provider/mcp)
├── admin.rs            # Admin API (/admin/v1/) router, handlers, auth middleware
├── policy.rs           # PolicyStore + resolve_policy (group→policy merge) + MCP tool policies
├── device_store.rs     # Device registration + revocation store
├── provider.rs         # Runtime providers; AES-256-GCM encrypted keys
├── mcp.rs              # McpManager (runtime MCP servers; encrypted auth headers)
├── audit.rs            # Audit logger (enriched with identity, groups, endpoint, etc.)
├── usage.rs            # UsageTracker (per-user daily token/request quotas)
├── pricing.rs          # PriceTable (model cost computation, auto-fetch from backend)
├── optimizer.rs        # Token saver (dedupe, empty-message pruning, budget drops, opt-in collapses)
├── token_store.rs      # Central token store (zero-trust): mint, verify, revoke, list
├── oidc_bootstrap.rs   # Confidential-client code exchange + ID-token validation
├── proxy/
│   ├── mod.rs          # Router, AppState, serve() (includes token_store)
│   ├── auth.rs         # Verifies bearer token via TokenStore (zero-trust)
│   ├── forward.rs      # Central→backend forwarding (SSE, provider-key injection)
│   ├── permissions.rs  # Group-based model/endpoint/quota enforcement
│   ├── mcp_forward.rs      # MCP forwarding (auth-header injection, SSE passthrough)
│   ├── mcp_hub.rs          # Combined /mcp hub (aggregates all servers, prefixes tools)
│   ├── mcp_permissions.rs  # Per-server/per-tool MCP enforcement
│   ├── tokens.rs           # Token API: POST /v1/tokens, DELETE /v1/tokens/current, GET /v1/tokens
│   └── rate_limit.rs   # Per-IP token bucket rate limiter
└── entity/
    ├── mod.rs
    ├── audit_log.rs        # audit_log entity (append-only)
    ├── usage_counter.rs    # usage_counter entity
    ├── device.rs           # device entity
    ├── admin_audit_log.rs  # admin_audit_log entity (append-only)
    ├── group_policy.rs     # group_policy entity
    ├── provider.rs         # provider entity
    ├── provider_key.rs     # provider_key entity (AES-256-GCM ciphertext)
    ├── provider_key_access.rs # provider_key_access entity (group ACL on keys)
    ├── mcp_server.rs       # mcp_server entity (encrypted auth)
    ├── mcp_server_policy.rs# mcp_server_policy entity
    └── token.rs              # token entity (central token store)

crates/central/tests/
├── proxy_integration.rs    # 22 integration tests (dev + prod + mTLS modes)
├── provider_admin_api.rs   # 13 provider/key admin API tests
└── mcp_admin_api.rs        # 5 MCP server/policy admin API tests
```

### `tests/e2e/` — In-process E2E tests

```
tests/e2e/
├── Cargo.toml
├── src/
│   └── lib.rs          # Lint allows only
└── tests/
    ├── e2e.rs          # 16 E2E tests (full chain + permissions + device revocation)
    └── mcp_e2e.rs      # 13 MCP E2E tests (hub, per-server, batches, relay auth, audit)
```

## Workspace `Cargo.toml`

Key workspace settings:

```toml
[workspace]
resolver = "2"
members = ["crates/common", "crates/mcp", "crates/relay", "crates/central", "tests/e2e"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
indexing_slicing = "warn"
todo = "warn"
dbg_macro = "warn"
```

## Toolchain

Pinned via `rust-toolchain.toml`:

```toml
[toolchain]
# Pinned to match the Docker builder images (rust:1.98-slim).
channel = "1.98"
components = ["rustfmt", "clippy"]
```

Minimum Rust 1.85; edition 2024. The channel is pinned (not `stable`) so
local builds match the `rust:1.98-slim` Docker builders — bump in lockstep
with the Dockerfiles when upgrading.
