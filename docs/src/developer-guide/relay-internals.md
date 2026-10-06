# Relay Internals

The `oac-relay` crate (`crates/relay`) is the laptop relay. This page
documents the internal architecture. For full type signatures, run
`cargo doc -p oac-relay --open`.

## CLI dispatch (`main.rs`)

Entry point: `oac-relay [OPTIONS] [COMMAND]`. Built with `clap` derive.

- If no subcommand is given, `serve` is assumed.
- `serve` calls `db::setup()` and starts the proxy. The relay is a dumb
  forwarder — it does not seed a dev key. `dev_mode` skips auth checks
  (central rejects unauthenticated requests via its token store).
- `login` calls `login::run_login()`.
- `logout` calls `DELETE {central}/v1/tokens/current` (revokes at central).
  `list-keys` calls `GET {central}/v1/tokens` (lists tokens at central).
  `print-key` reads the agent config file and needs no config file loaded.
  The `revoke-key` command is removed (central manages tokens).
- `activity { --limit }` prints recent `relay_activity_log` entries
  (newest first; default 20, capped at 1000).

See [CLI Reference](../user-guide/cli-reference.md) for the user-facing
command docs.

## OIDC login flow (`login.rs`)

The `run_login()` function implements the full auth-code + PKCE flow.
See [OIDC Security](./oidc-security.md) for the RFC citations.

### Steps

1. `oidc::validate_loopback_redirect(&config.oidc.redirect_uri)` — RFC 8252.
2. `oidc::build_http_client()` — rustls, no redirects (SSRF), timeouts.
3. OIDC discovery via `CustomProviderMetadata::discover_async`.
4. Binds one-shot loopback listener `127.0.0.1:0` (random port, RFC 8252
   §7.3); substitutes actual port into redirect URI.
5. Builds a public `CustomClient` from provider metadata + `ClientId`; the
   relay does not load or receive the client secret.
6. Generates PKCE S256 (`PkceCodeChallenge::new_random_sha256`),
   `state` (`CsrfToken::new_random`), `nonce` (`Nonce::new_random`).
7. Builds authorize URL with scopes (`openid` always first).
8. Prints URL + calls `open_browser(url)` (macOS `open`, Linux
   `xdg-open`, Windows `cmd /C start`).
9. `wait_for_callback(listener, CALLBACK_TIMEOUT)` —
    `CALLBACK_TIMEOUT = 300s` (5 min).
10. Verifies `state` (CSRF defense).
11. Calls `complete_login()` with the one-time authorization code, PKCE
    verifier, exact redirect URI, and nonce. Central performs the token
    exchange, ID-token validation, `at_hash` check, and userinfo request.

### `complete_login()`

1. `POST {central}/v1/tokens` — sends the short-lived grant over mTLS.
2. Central returns a minted token plus the identity it validated.
3. `key_store.upsert_identity(...)` stores only that verified identity.
4. Builds `AgentConfig { base_url, api_key }` with the minted token.
5. `agent_config::inject(&agent_config)` — writes with `0600` perms.

### `wait_for_callback()`

- `tokio::time::timeout(timeout, listener.accept())`.
- Reads request with `read_to_end` (10s sub-timeout).
- Parses first request line: `GET /callback?code=...&state=... HTTP/1.1`.
- If `error` param present → `Error::oidc`.
- Writes minimal HTML response (`<h1>Login complete</h1>`).

## Proxy pipeline (`proxy/`)

### Router (`proxy/mod.rs`)

Middleware order (outer → inner):

1. `RequestBodyLimitLayer(10 MB)` — `MAX_BODY_SIZE`.
2. `host_guard_middleware` — DNS rebinding defense.
3. `auth_middleware` — pass-through (checks Authorization header presence).
4. Handler (`forward::proxy_handler`).

Routes:

| Method | Path | Auth |
|---|---|---|
| `GET` | `/healthz` | bypassed |
| `POST` | `/v1/chat/completions` | required |
| `POST` | `/v1/responses` | required |
| `GET` | `/v1/models` | required |
| `POST` | `/v1/embeddings` | required |
| any | `/mcp/{server}` | required (byte-tunnel) |
| any | `/mcp` (hub) | required (byte-tunnel) |

### `AppState`

```rust
pub struct AppState {
    pub key_store: KeyStore,
    pub config: RelayConfig,
    pub client: reqwest::Client,        // mTLS client to central
    pub listen_addr: SocketAddr,
    pub activity: ActivityLogger,
}
```

### Host guard (`proxy/host_guard.rs`)

`host_guard_middleware` runs **before** auth. Reads `Host` header,
compares case-insensitively against `allowed_hosts()`:

- Always: `127.0.0.1:{port}`, `localhost:{port}`, `[::1]:{port}`.
- If `dev_mode`: also `relay:{port}` (Docker service name).

Mismatch → `400 Bad Request`. Reference: Jackson et al., Stanford 2007.

### Auth middleware (`proxy/auth.rs`)

`auth_middleware`:

- Skips `/healthz`.
- Extracts `Authorization: Bearer <key>` via `keys::extract_bearer`.
- Missing/invalid → `401 Unauthorized`.
- DB error → `500 Internal Server Error`.
- On success, inserts `VerifiedIdentity` into request extensions.

`VerifiedIdentity`:

```rust
pub struct VerifiedIdentity {
    pub identity_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub groups: Option<String>,   // JSON array string
    pub key_id: String,
}
```

### Forwarding (`proxy/forward.rs`)

`build_client(config)`:

- `use_rustls_tls()`, `redirect(Policy::none())` (SSRF), `timeout(300s)`,
  `connect_timeout(10s)`.
- Production: rustls `ClientConfig` via
  `mtls::build_client_config(ca, cert, key)`, `https_only(true)`.
- Dev: plain HTTP, no mTLS.

`proxy_handler`:

1. Generates `request_id = Uuid::new_v4()`.
2. Extracts `VerifiedIdentity` from extensions.
3. Calls `forward_request()`.
4. Records a `RelayActivityEntry` (best-effort).
5. On error: `502 Bad Gateway`.

`forward_request`:

- Reads body (`to_bytes`, max `MAX_BODY_SIZE`).
- Extracts `model` via `http_util::extract_model`.
- Sanitizes path via `http_util::sanitize_path`.
- Builds upstream URL: `{config.central.url}{sanitized_path}`.
- Builds forward headers via `http_util::build_forward_headers`.
- Forwards the `Authorization` header unchanged (central verifies the
  token). Adds `x-oac-request-id` (per-request correlation UUID).
- Sends request; on response:
  - Strips hop-by-hop + `content-length` headers.
  - If SSE: streams via `bytes_stream()` → `Body::from_stream`.
  - Otherwise: buffers and returns.

### MCP forwarding (`proxy/mcp_forward.rs`)

MCP requests arrive on `/mcp` (the combined hub) and `/mcp/{server}` (a
single server), shown to the agent as `http://127.0.0.1:<relay>/mcp...`. The
relay treats MCP as a raw byte tunnel: it reads the JSON-RPC body once,
best-effort parses the MCP server/tool/method for the activity log, then
forwards the bytes to central with the `Authorization` header, exactly like
the OpenAI path. **The relay never inspects JSON-RPC for policy** — per-tool
enforcement happens on the central proxy. SSE responses pass through
unchanged.

## KeyStore (`keystore.rs`)

```rust
pub struct KeyStore { pub db: DatabaseConnection }
```

Despite the historical name, this type no longer manages API keys. It
persists OIDC identities and exposes the underlying `DatabaseConnection`.

Methods:

- `new(db)` — creates a store.
- `upsert_identity(issuer, subject, email, display_name, groups)` —
  finds by (issuer, subject); inserts with UUID id if absent.

Key minting, verification, and revocation are handled by central's
`TokenStore` (`crates/central/src/token_store.rs`). The relay's `login`
flow calls `POST {central}/v1/tokens` to mint a token; `logout` calls
`DELETE {central}/v1/tokens/current`; `list-keys` calls
`GET {central}/v1/tokens`.

## Activity logger (`activity.rs`)

```rust
pub struct RelayActivityEntry {
    pub identity_id: String,
    pub key_id: String,
    pub method: String,
    pub endpoint: String,
    pub model: Option<String>,
    pub central_status: Option<i32>,
    pub latency_ms: i64,
    pub request_id: Option<String>,
    pub mcp_server: Option<String>,   // set for /mcp* traffic
    pub mcp_tool: Option<String>,
    pub mcp_method: Option<String>,
}
```

`ActivityLogger::record()` inserts into `relay_activity_log` (append-only,
enforced by DB triggers). The `proxy_handler` constructs an entry after
each forwarded request.

## Agent config injection (`agent_config.rs`)

```rust
pub struct AgentConfig {
    pub base_url: String,   // e.g. "http://127.0.0.1:8787/v1"
    pub api_key: String,    // plaintext, written once then dropped
}

pub enum AgentKind { Codex, GenericEnv }
```

- `detect_agent()` — if `CODEX_HOME` env set → Codex at
  `$CODEX_HOME/config.json`. Else if `~/.codex/config.json` exists →
  Codex. Else → GenericEnv at `~/.oac/agent-env.sh`.
- `inject(config)` — detects agent, delegates to `inject_codex` /
  `inject_generic_env`. Writes with `0600` perms.
- `read()` — reads back the injected config.

### Codex format (`~/.codex/config.json`)

JSON object; sets `api_base_url` and `api_key`, preserves all other
existing fields.

### Generic env format (`~/.oac/agent-env.sh`)

```sh
export OPENAI_API_BASE='<base_url>'
export OPENAI_API_KEY='<api_key>'
```

Single-quote escaped via `shell_escape` (replaces `'` with `'\''`).

## Persistence

### `db.rs`

`setup(database_url)` — delegates to
`persistence::setup_database::<Migrator>`. On Unix, tightens the SQLite
file to `0600`.

### `migration.rs`

Four migrations:

- `m000001_initial_schema` — creates the `identities` table. (The
  `api_keys` table has been removed — central manages tokens.)
- `m000002_relay_activity_log` — creates `relay_activity_log` + two
  append-only triggers.
- `m000003_api_key_expiry` — historical migration (added `expires_at` to
  `api_keys`; the table is now removed).
- `m000004_mcp_activity` — adds nullable `mcp_server`, `mcp_tool`,
  `mcp_method` columns to `relay_activity_log`.

### Entities

- `identity::Model` — `id`, `issuer`, `subject`, `email`, `display_name`,
  `groups`, `created_at`.
- `relay_activity_log::Model` — `id`, `identity_id`, `key_id`, `method`,
  `endpoint`, `model`, `central_status`, `latency_ms`, `request_id`,
  `mcp_server`, `mcp_tool`, `mcp_method`, `created_at`.

See [Persistence](./persistence.md) for full schemas.
