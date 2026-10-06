# Central Internals

The `oac-central` crate (`crates/central`) is the central proxy. This page
documents the internal architecture. For full type signatures, run
`cargo doc -p oac-central --open`.

## CLI dispatch (`main.rs`)

Entry point: `oac-central [OPTIONS] [COMMAND]`.

- `serve` (default) — starts the proxy.
- `admin` — manages runtime providers, provider keys, policies, devices, and
   audit data through the relay.

See [CLI Reference](../user-guide/cli-reference.md) for the user-facing
command docs.

## Server (`proxy/mod.rs`)

### `AppState`

```rust
pub struct AppState {
    pub config: CentralConfig,
    pub provider_store: ProviderStore,
    pub client: reqwest::Client,
    pub audit: AuditLogger,
    pub rate_limiter: Option<RateLimiter>,
    pub policy_store: PolicyStore,
    pub device_store: DeviceStore,
    pub usage_tracker: UsageTracker,
    pub price_table: PriceTable,
    pub mcp_manager: McpManager,
    pub token_store: crate::token_store::TokenStore,
}
```

### `serve()`

- Opens the database (runs migrations).
- Loads the provider encryption key and opens the `ProviderStore`; provider
   API keys are decrypted into `Zeroizing` memory only for upstream requests.
- Builds the `reqwest::Client` via `forward::build_client()`.
- Creates `PolicyStore`, `DeviceStore`, `UsageTracker`, `PriceTable`,
   `TokenStore`.
- If `[pricing]` is configured with a non-zero interval, refreshes model
   prices from each enabled provider (best-effort).
- Binds:
  - **Dev mode**: plain HTTP via `axum::serve` + `TcpListener`.
  - **Production**: mTLS via `axum_server::bind_rustls` with
    `mtls::build_server_config`, ALPN `http/1.1`, client cert required.
- Graceful shutdown via `shutdown::shutdown_signal()`.

### Router

Middleware order (outer → inner, as executed — in axum the last
`.layer()` applied is outermost):

1. `RequestBodyLimitLayer(10 MB)`.
2. `auth::auth_middleware` — verifies bearer token via TokenStore.
3. `rate_limit::rate_limit_middleware` — per-IP token bucket (prod only).
4. `permissions::permissions_middleware` — group-based enforcement.
5. Handler (`forward::proxy_handler`).

Note the consequence: rate limiting runs **before** policy resolution,
so a request that will be denied by policy still consumes a rate-limit
token.

The admin API router is merged only if `config.admin` is present.

Routes (OpenAI paths are the same set the relay exposes):

| Method | Path | Auth |
|---|---|---|
| `GET` | `/healthz` | bypassed |
| `POST` | `/v1/chat/completions` | required |
| `POST` | `/v1/responses` | required |
| `GET` | `/v1/models` | required |
| `POST` | `/v1/embeddings` | required |
| `POST` | `/v1/tokens` | OIDC code exchange or existing bearer |
| `GET` | `/v1/tokens` | existing bearer |
| `DELETE` | `/v1/tokens/current`, `/v1/tokens/{id}` | existing bearer |
| any | `/mcp/{server}` | required (per-tool MCP middleware) |
| `POST` only | `/mcp` (hub) | required (hub handler enforces inline) |

## OIDC bootstrap (`oidc_bootstrap.rs`, `proxy/tokens.rs`)

For initial login, the relay sends a one-time authorization code, PKCE
verifier, loopback redirect URI, and nonce to `POST /v1/tokens` over mTLS.
`OidcBootstrapVerifier` uses the client secret held by central to exchange the
code, pins the ID-token algorithm to RS256/ES256, validates issuer, audience,
expiry, nonce, signature, and optional `at_hash`, then requests userinfo with
subject matching. Only this centrally validated identity can be persisted in a
token record; caller-supplied identity or group fields are ignored.

The endpoint's existing-bearer mode copies the complete identity snapshot from
the verified token record and accepts only the new label and TTL from the body.

## Auth middleware (`proxy/auth.rs`)

`VerifiedRelayIdentity`:

```rust
pub struct VerifiedRelayIdentity {
    pub subject: String,
    pub email: Option<String>,
    pub identity_id: Option<String>,
    pub groups: Option<String>,      // JSON array string (from token record)
    pub request_id: Option<String>,
    pub token_id: Option<String>,    // for backstop enforcement
    pub created_at: Option<time::PrimitiveDateTime>,  // for backstop check
}
```

`auth_middleware` — verifies the bearer token via `TokenStore`:

- Skips `/healthz`.
- Extracts the bearer token from the `Authorization` header.
- Verifies it via `state.token_store.verify_token()` (DB lookup,
  constant-time hash comparison, no early return — CWE-208).
- Missing/unverifiable → `401` in every mode. `dev_mode` relaxes transport
  and rate limiting, never bearer verification.
- `X-OAC-*` identity headers are **ignored** — identity comes from the
  token record.
- Inserts `VerifiedRelayIdentity` (with `token_id` and `created_at` for
  backstop enforcement) into extensions.

## Permissions middleware (`proxy/permissions.rs`)

`PermissionDecision`:

```rust
pub struct PermissionDecision {
    pub decision: String,        // "allowed" or "denied"
    pub reason: Option<String>,  // set when denied
    pub request_reserved: bool,  // request-quota reservation held (see below)
}
```

Enforcement order:

1. Skip `/healthz`.
2. Extract `VerifiedRelayIdentity`.
3. Parse groups from JSON array string.
4. `PolicyStore::resolve_policy(&groups)` — on error, **fails open**
   (logs loudly, allows through).
5. **Token-TTL backstop check** — if `max_token_ttl_seconds` is set and
   the token is older than the limit (from `created_at`), the token row
   is deleted and the request is rejected with `401`.
6. **Device revocation check** — uses `identity_id` or `subject` as
   device ID. If revoked → `403` (`"device_revoked"`).
7. **Endpoint check** — `policy.is_endpoint_allowed(&endpoint)`. Deny
   `403` (`"endpoint_not_allowed"`).
8. **Model check** (POST only) — reads body, extracts model, checks
   `policy.is_model_allowed`. Deny `403` (`"model_not_allowed"`).
9. **Quota checks** (both pre-flight):
   - **Token quota** — if `daily_token_quota` set and
     `usage.token_count >= quota` → `429` (`"token_quota_exceeded"`).
   - **Request quota** — an **atomic reservation** via
     `UsageTracker::try_reserve_request` → `429` (`"quota_exceeded"`)
     when it cannot be taken. The reservation is recorded on the
     decision (`request_reserved`) and **released if the upstream
     request ultimately fails**, so failed requests do not consume
     quota.
10. On allow: inserts `PermissionDecision` into extensions.

Denial response:

```json
{"error":{"message":"access denied: {reason}","type":"permission_denied"}}
```

Denials also write an `AuditEntry` with
`permission_decision = "denied"`.

## Forwarding (`proxy/forward.rs`)

`build_client()` — `rustls-tls`, 300s timeout, 10s connect timeout.

`proxy_handler`:

1. Extracts `VerifiedRelayIdentity` and `PermissionDecision`.
2. **Token saver** — if the resolved policy attached a `TokenSaverGrant`,
   applies `optimizer::optimize_prompt` to the request body (dedupe,
   empty-message pruning, budget drops, opt-in collapses) and carries the
   savings report for auditing. For streaming requests,
   `stream_options.include_usage = true` is injected so the backend
   reports token usage in the final SSE chunk (an explicit `false` is
   overridden).
3. Calls `forward_request()`:
   - Reads body (max `MAX_BODY_SIZE`).
   - Extracts model.
   - Sanitizes path.
   - Builds upstream URL: `{provider.base_url}{sanitized_path}`.
   - Builds forward headers (strips hop-by-hop).
   - **Replaces** `Authorization` with the selected provider key
     (priority-ordered, group-ACL-filtered; on upstream `401`/`429` the
     next authorized key is retried).
   - Sends request.
4. If non-streaming: buffers response, extracts token usage from `usage`
   JSON field.
5. If SSE: passes through as raw byte stream, wraps with
   `wrap_stream_with_usage_extraction` to intercept `data:` lines and
   extract `usage` from the final chunk.
6. Computes cost via `PriceTable::compute_cost`; enabled providers are
   refreshed periodically when configured.
7. Records `AuditEntry` (best-effort, including token-saver accounting:
   `token_saver_applied`, `tokens_saved`, `messages_dropped`,
   `saver_reasons`) and increments daily usage. For SSE,
   audit and usage accounting are deferred until the stream completes.
8. On error: `502 Bad Gateway` (and the request-quota reservation, if any,
   is released).

## Policy store (`policy.rs`)

`ResolvedPolicy`:

```rust
pub struct ResolvedPolicy {
    pub allowed_models: Option<HashSet<String>>,      // None = all
    pub allowed_endpoints: Option<HashSet<String>>,    // None = all
    pub daily_token_quota: Option<i64>,                 // None = unlimited
    pub daily_request_quota: Option<i64>,               // None = unlimited
    pub token_saver: TokenSaverConfig,                  // saver settings
    pub max_token_ttl_seconds: Option<i64>,             // admin backstop
}
```

`resolve_policy(&groups)` — **most-permissive-wins** merge:

- **Models**: union. If any group has `None`, result is `None`.
- **Endpoints**: union. If any group has `None`, result is `None`.
- **Quotas**: `max`. If any group has `None`, result is `None`.

If no policies exist for any group, returns `ResolvedPolicy::default()`
(all allowed).

CRUD: `list_policies()`, `get_policy()`, `upsert_policy()`,
`delete_policy()`.

## Device store (`device_store.rs`)

```rust
pub struct DeviceStore { db: DatabaseConnection }
```

- `list_devices()`, `get_device(fingerprint)`.
- `upsert_device(fingerprint, subject, email)` — inserts or updates
  `last_seen_at` + `user_email`.
- `set_revoked(fingerprint, bool)` — returns `true` if updated.
- `revoke(fingerprint)`, `reinstate(fingerprint)`.
- `is_revoked(fingerprint)` — `None` if not registered, `Some(true)` if
  revoked, `Some(false)` if active.

Enforcement: checked in `permissions_middleware` using `identity_id`
(or `subject` as fallback) as the device ID.

## Provider store (`provider.rs`)

`ProviderStore` manages providers and their API keys at runtime through the
admin API. Provider metadata and AES-256-GCM ciphertexts are stored in the
central database; plaintext keys are decrypted into `Zeroizing<String>` only
when selecting an upstream request key. The 32-byte encryption key is loaded
from `OAC_PROVIDER_ENCRYPTION_KEY` or `/run/secrets/provider-encryption-key`.

Each provider can have multiple priority-ordered keys with optional group
access rules. A failed upstream `401` or `429` causes the proxy to try the
next authorized key. Manual prices remain overrides while enabled providers'
`/v1/models` catalogs can be refreshed periodically.

## Audit logger (`audit.rs`)

`AuditEntry`:

```rust
pub struct AuditEntry {
    pub device_id: String,
    pub user_subject: String,
    pub model: Option<String>,
    pub backend: String,
    pub status: i32,
    pub latency_ms: i64,
    pub stream: bool,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub total_tokens: Option<i32>,
    pub identity_id: Option<String>,
    pub email: Option<String>,
    pub groups: Option<String>,
    pub endpoint: Option<String>,
    pub request_id: Option<String>,
    pub permission_decision: Option<String>,
    pub denial_reason: Option<String>,
    pub cost_usd: Option<f64>,
    pub token_saver_applied: Option<bool>,
    pub tokens_saved: Option<i32>,
    pub messages_dropped: Option<i32>,
    pub saver_reasons: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub mcp_method: Option<String>,
    pub mcp_args_preview: Option<String>,
}
```

`AuditLogger::record()` inserts into `audit_log` (append-only, enforced
by DB triggers). Uses parameterized SQL (SQL-injection-safe).

## Usage tracker (`usage.rs`)

`UsageSnapshot`:

```rust
pub struct UsageSnapshot {
    pub user_subject: String,
    pub period_date: String,    // YYYY-MM-DD (UTC)
    pub period_kind: String,    // "daily"
    pub request_count: i64,
    pub token_count: i64,
    pub cost_usd: f64,
}
```

`UsageTracker`:

- `increment(subject, group, request_delta, token_delta, cost_delta)` —
  SQLite UPSERT keyed on `(user_subject, period_date, period_kind)`.
- `get_usage(subject)` — today's usage.
- `get_all_usage()` — all users' usage for today.

## Pricing (`pricing.rs`)

`PriceTable` — thread-safe via `Arc<RwLock<HashMap<String, PricedModel>>>`.

- `from_config(config)` — config entries stored as `Override`.
- `compute_cost(model, prompt_tokens, completion_tokens)` —
  `(prompt/1000) * input_per_1k + (completion/1000) * output_per_1k`.
  Returns `0.0` for unknown models or missing tokens.
- `fetch_from_backend(client, base_url)` — fetches `GET {base_url}/v1/models`,
  parses OpenRouter format. **Overrides are never overwritten**.
- `spawn_provider_price_refresh(provider_store, client, interval)` —
  periodic background refresh across enabled providers.

Precedence: manual config (`Override`) > auto-fetched (`Fetched`).

## Token saver (`optimizer.rs`)

A pure, admin-controlled module — the only code allowed to modify request
bodies. Applied server-side in `forward.rs` when the resolved policy
attaches a `TokenSaverGrant` (from `ResolvedPolicy.token_saver`):

- Deduplicates bit-identical **consecutive** duplicate messages.
- Removes structurally-empty messages and `tools` entries.
- Drops oldest whole turns to fit `max_input_tokens` budgets.
- Opt-in (`collapse_repeated_lines`): collapses consecutive
  exact-verbatim repeated lines inside a single message into `[×N]`
  markers (RTK-adapted, lossless-by-construction).

**Never rewrites kept content** except the opt-in repeated-line collapse.
Savings are reported per request (`tokens_saved`, `messages_dropped`,
`saver_reasons`) into the audit log; a per-group engagement summary is
served by `GET /admin/v1/token-saver`.

## MCP servers (`mcp.rs`)

`McpManager` manages centrally-hosted MCP servers at runtime, mirroring the
`ProviderStore` pattern. A configured server has a `base_url` (the MCP
Streamable HTTP endpoint) and an optional per-server `auth_header` stored as
AES-256-GCM `ciphertext`/`nonce` encrypted at rest with the provider
encryption key (`OAC_PROVIDER_ENCRYPTION_KEY` — the same key used for
provider API keys; canonical parsing lives in `crypto.rs`).

- `upsert_server` / `get_server` / `list_servers` / `delete_server`.
- `resolve_server(id)` — returns a `ResolvedMcpServer` with the decrypted
  auth header in `Zeroizing` memory (only for the forwarding path).
- Server ids must be non-empty and must not contain `__` (the hub
  separator).

## MCP forwarding + permissions (`proxy/mcp_forward.rs`, `proxy/mcp_permissions.rs`, `proxy/mcp_hub.rs`)

MCP traffic uses the Streamable HTTP transport (JSON-RPC 2.0 over HTTP). The
relay tunnels raw bytes to central on `/mcp` (combined hub) and
`/mcp/{server}` (a single server).

- `mcp_permissions_middleware` (runs after auth) reads the JSON-RPC body,
  extracts the tool name via `oac-mcp::parse`, and resolves the caller's
  per-group, per-server, per-tool policy
  (`PolicyStore::resolve_mcp_tool_allowed`) on `/mcp/{server}`. Denials return
  `403` and are audit-logged with the tool, server, method, and a redacted
  argument preview.
- `mcp_hub::mcp_hub_handler` handles the combined `/mcp`: `initialize`,
  `tools/list` (fans out to enabled reachable servers, prefixes tools as
  `server__tool`, filters by per-tool policy, aggregates), `tools/call`
  (splits the prefixed name, enforces the policy inline, routes to the target
  server), `ping`, and `notifications/*` (best-effort broadcast).
- `mcp_forward::mcp_handler` resolves the upstream server, injects its auth
  header, strips hop-by-hop headers, forwards the bytes, and passes SSE
  responses through. Records an `AuditEntry` with `mcp_server`, `mcp_tool`,
  `mcp_method`, and `mcp_args_preview`.

**Naming consistency:** policy keys are the colon form `server:tool` (what
admins write); the hub exposes the underscore form `server__tool` (what
agents see). `oac-mcp::hub` owns the join/split so both representations and
the two endpoints stay in sync. Server ids must not contain `__`.

MCP policy resolution (`policy.rs`) treats tools as **deny-by-default**:
`resolve_mcp_allowed_tools` returns `None` only for an explicit allow-all
(`allowed_tools = NULL`) policy; otherwise it returns the union of
`"server:tool"` entries across the user's groups, or an empty set (deny
all) when none exist — and also when the caller has **no groups at all**
(a malformed or missing groups claim must never reach an MCP tool).
`resolve_mcp_allowed_servers` derives the reachable server ids for the
hub's `tools/list` fan-out.

## Rate limiting (`proxy/rate_limit.rs`)

`RateLimiter` — token bucket per IP.

- `DEFAULT_RATE_LIMIT = 60` requests per window.
- `DEFAULT_WINDOW = 60s`.
- `try_take(ip)` — returns `Err(retry_after_secs)` if exceeded.

`rate_limit_middleware` — skips `/healthz` and dev mode. On limit
exceeded: `429 Too Many Requests` with `Retry-After` header.

## Admin API (`admin.rs`)

See [Admin API](../user-guide/admin-api.md) for the user-facing endpoint
docs.

`AdminState`:

```rust
pub struct AdminState {
    pub policy_store: PolicyStore,
    pub device_store: DeviceStore,
    pub provider_store: ProviderStore,
    pub mcp_manager: McpManager,
    pub audit: AuditLogger,
    pub usage_tracker: UsageTracker,
    pub token_store: crate::token_store::TokenStore,
    pub admin_group: String,
}
```

`admin_auth_middleware`:

- Verifies the bearer token via `TokenStore` → else `401`.
- Parses groups from the token record → if `admin_group` not in
  groups → `403`.

All mutations write to `admin_audit_log` (append-only).

## Persistence

### Migrations

1. `m000001_initial_schema` — `devices`, `audit_log` + append-only
   triggers.
2. `m000002_audit_enrichment` — adds nullable columns to `audit_log`.
3. `m000003_group_policies` — `group_policies`, `admin_audit_log` +
   triggers.
4. `m000004_usage_counters` — `usage_counters` with unique index on
   `(user_subject, period_date, period_kind)`.
5. `m000005_providers` — `providers`, `provider_keys` (encrypted),
   `provider_key_access`.
6. `m000006_token_saver` — token-saver + budget columns on `group_policies`;
   saver accounting columns on `audit_log`.
7. `m000007_collapse_repeated_lines` — RTK collapse toggle.
8. `m000008_strip_ansi` — ANSI-strip toggle.
9. `m000009_mcp` — `mcp_servers` (encrypted auth), `mcp_server_policies`,
   and MCP audit columns.
10. `m0000010_tokens` — `tokens` table (central token store) +
    `max_token_ttl_seconds` on `group_policies`.

See [Persistence](./persistence.md) for full schemas.
