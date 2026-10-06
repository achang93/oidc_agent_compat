# Admin API

The central proxy exposes an admin API at `/admin/v1/` for managing group
policies, providers, provider API keys, MCP servers, MCP policies, devices,
audit logs, usage, and quotas. The admin API is only mounted if `[admin]` is
present in the central config.

## Authentication

Admin API requests are authenticated via the **same OIDC flow as regular
users** — there is no static admin token. The admin CLI sends requests
through the relay, which forwards the `Authorization` header (the user's
central-minted token) to the central proxy.

Authorization is enforced by the `admin_auth_middleware`:

1. Verifies the bearer token via `TokenStore` → else `401 Unauthorized`.
2. Parses the user's groups from the token record → if the configured
   `admin_group` is not in the user's groups → `403 Forbidden`.

This means the user must:
- Log in via `oac-relay login` (to get a central-minted token).
- Belong to the IdP group configured as `admin_group` (e.g. `oac-admins`).

## Endpoints

### Providers

Providers are runtime-managed. No provider URL or provider key is stored in
the central TOML configuration.

#### `GET /admin/v1/providers`

List providers. The response contains provider metadata and never contains
API-key material.

#### `POST /admin/v1/providers`

Create or update (upsert) a provider. `id`, `name`, and `base_url` are
required; `enabled` is optional (default `true`) and `is_default` is
optional (default `false`). **Response:** `200` — the stored provider JSON
(not `201`). Missing required fields → `422`; invalid input (empty
`id`/`name`, invalid `base_url`) → `400`.

```json
{
  "id": "openai",
  "name": "OpenAI",
  "base_url": "https://api.openai.com",
  "enabled": true,
  "is_default": true,
  "models": ["gpt-4o", "gpt-4o-mini"]
}
```

`models` is an exact model-name list. A provider with `models: null` is a
catch-all fallback. Model-specific providers take precedence over catch-all
providers. At most one provider is marked as the default.

#### `GET|PUT|DELETE /admin/v1/providers/{id}`

Get, update, or delete a provider. Unlike `POST`, `PUT` requires `name`,
`base_url`, `enabled`, and `is_default` (all mandatory; missing → `422`) and
returns `404` when the provider does not exist (`POST` upserts instead).
`PUT` uses the same fields as provider creation, except `id` is taken from
the path. `DELETE` → `204` (`404` if missing); deleting a provider also
deletes its keys.

#### `POST /admin/v1/providers/{id}/default`

Mark an enabled provider as the default fallback. **Response:** `204` on
success; `400` when the provider is unknown or disabled (not `404`).

### Provider keys

#### `GET /admin/v1/providers/{id}/keys`

List key metadata. Each entry has `id`, `provider_id`, `label`, `priority`,
`key_digest`, `enabled`, and `allowed_groups`. Plaintext and encrypted key
material are never returned. `404` when the provider is unknown.

#### `GET /admin/v1/providers/{id}/keys/{key_id}`

Get a single key's metadata (same shape as the list entries), or `404` when
the provider or key is unknown.

#### `POST /admin/v1/providers/{id}/keys`

Add a key. The plaintext is accepted once and encrypted with AES-256-GCM
before it is stored. **Response:** `200` — key metadata JSON (not `201`);
`404` when the provider is unknown; invalid input (empty key/label) → `400`.

```json
{
  "key": "sk-provider-key",
  "label": "production-primary",
  "priority": 0,
  "allowed_groups": ["engineering"]
}
```

Keys are selected by ascending priority and creation time. An empty
`allowed_groups` list permits any authenticated user; otherwise at least one
of the user's IdP groups must match. On upstream `401` or `429`, central
tries the next authorized enabled key.

#### `PUT|DELETE /admin/v1/providers/{id}/keys/{key_id}`

Update key metadata/access rules or delete a key. Key plaintext cannot be
changed by `PUT`; add a replacement key for rotation. `PUT` body:

```json
{
  "label": "production-primary",
  "priority": 0,
  "enabled": true,
  "allowed_groups": ["engineering"]
}
```

`label`, `priority`, and `enabled` are required (missing → `422`);
`allowed_groups` is optional (default `[]`). **Responses:** `PUT` → `200`
with key metadata; `DELETE` → `204` (`404` when the provider or key is
unknown).

### Group policies

#### `GET /admin/v1/group-policies`

List all group policies.

**Response:** `200` — JSON array of [`GroupPolicyResponse`](#grouppolicyresponse).

#### `GET /admin/v1/group-policies/{name}`

Get a single policy by group name.

**Response:** `200` — [`GroupPolicyResponse`](#grouppolicyresponse), or
`404` if not found.

#### `PUT /admin/v1/group-policies/{name}`

Create or update a policy.

**Request body** ([`UpsertPolicyRequest`](#upsertpolicyrequest)):

```json
{
  "allowed_models": ["gpt-4o", "gpt-4o-mini"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": false,
  "max_input_tokens": null,
  "collapse_repeated_lines": false,
  "strip_ansi": false
}
```

All fields are optional (`null` means "all allowed" / "unlimited").
`token_saver_enabled` defaults to `false`; `max_input_tokens` must be a
positive integer when set. `collapse_repeated_lines` (default `false`)
enables the RTK-adapted pass that folds consecutive exact-verbatim repeated
lines inside a single message into `[×N]` markers. `strip_ansi` (default
`false`) enables removal of terminal ANSI colour/control codes from message
content.

**Response:** `200` — [`GroupPolicyResponse`](#grouppolicyresponse).

#### `DELETE /admin/v1/group-policies/{name}`

Delete a policy.

**Response:** `204` (no content), or `404` if not found.

### Devices

#### `GET /admin/v1/devices`

List all registered devices.

**Response:** `200` — JSON array of [`DeviceResponse`](#deviceresponse).

#### `POST /admin/v1/devices/{fingerprint}/revoke`

Revoke a device.

**Response:** `204` (no content), or `404` if not found.

#### `POST /admin/v1/devices/{fingerprint}/reinstate`

Reinstate a revoked device.

**Response:** `204` (no content), or `404` if not found.

### Audit

#### `GET /admin/v1/audit`

Query the audit log.

**Query parameters:**

| Param | Type | Default | Max |
|---|---|---|---|
| `subject` | `Option<String>` | — | — |
| `limit` | `Option<u32>` | `100` | `1000` (clamped) |
| `offset` | `Option<u32>` | `0` | — |

Results are ordered newest first. `offset` skips that many newest entries;
pagination is applied in the database rather than loading the entire audit
table.

**Response:** `200` — JSON array of audit entries with fields: `id`,
`user_subject`, `identity_id`, `email`, `groups`, `model`, `backend`,
`endpoint`, `request_id`, `status`, `latency_ms`, `stream`,
`prompt_tokens`, `completion_tokens`, `total_tokens`,
`permission_decision`, `denial_reason`, `cost_usd`,
`token_saver_applied`, `tokens_saved`, `messages_dropped`, `saver_reasons`,
`created_at` (formatted `YYYY-MM-DD HH:MM:SS`). The four token-saver fields
are present in **every** entry (`null` when the saver did not run on that
request).

### Token saver

#### `GET /admin/v1/token-saver`

Aggregate token-saver engagement so admins can observe what the saver is
doing across groups.

**Response:** `200` — an object with:

```json
{
  "groups": [
    {
      "group": "engineering",
      "enabled": true,
      "max_input_tokens": 8000,
      "requests_optimized": 12,
      "tokens_saved": 3400,
      "messages_dropped": 24
    }
  ],
  "total_requests_optimized": 12,
  "total_tokens_saved": 3400,
  "total_messages_dropped": 24
}
```

`requests_optimized` counts audit rows where the saver applied; `tokens_saved`
and `messages_dropped` are sums across those rows. Each optimized request is
attributed to the **first** group in its audit row's `groups` array (or
`"unknown"` when unset), and a group that has a policy but zero optimized
requests still gets a row (with zeroed counters). The `enabled` and
`max_input_tokens` fields reflect the *current* policy configuration. This
endpoint returns metrics only — never prompt content.

### Usage

#### `GET /admin/v1/usage`

Query usage counters. Returns **only today's (UTC)** usage rows; there are
no date-range or pagination parameters.

**Query parameters:**

| Param | Type | Default |
|---|---|---|
| `subject` | `Option<String>` | — (all users) |

**Response:** `200` — JSON array of [`UsageResponse`](#usageresponse).

### Quotas

#### `GET /admin/v1/quotas/{subject}`

Get quota status for a user.

**Response:** `200` — [`QuotaResponse`](#quotaresponse).

The response includes the groups snapshot from the user's most recent usage
record and resolves `daily_request_quota` and `daily_token_quota` using the
same most-permissive-wins policy merge used for enforcement. `groups` is the
raw JSON array **string** from the usage snapshot (e.g.
`"[\"engineering\"]"`), not a parsed array. If the user has not made a
request today, `groups` and both quotas are `null` and the counters are
`request_count: 0`, `token_count: 0`, `cost_usd: 0.0`.

---

### MCP servers

MCP (Model Context Protocol) servers are runtime-managed, like providers.
No MCP server URL or auth header is stored in the central TOML configuration.

#### `GET /admin/v1/mcp/servers`

List configured MCP servers. Response bodies contain metadata only — never
any auth header value; each entry carries a `has_auth: bool` instead.

#### `POST /admin/v1/mcp/servers`

Create an MCP server (an existing `id` is replaced). The body must carry
its own non-empty `id` (`400` when missing or empty); `name` and `base_url`
are required, `enabled` defaults to `true`, and `auth_header` is optional.
**Response:** `200` — `{ "id", "name", "base_url", "enabled",
"has_auth" }`.

```json
{
  "id": "github",
  "name": "GitHub",
  "base_url": "https://mcp.example.com/mcp",
  "enabled": true,
  "auth_header": "Authorization: Bearer <token>"
}
```

`auth_header` is an optional `"Header: value"` pair. When present it is
attached to every request that central forwards to this server and is
**encrypted at rest** (AES-256-GCM) with the provider encryption key
(`OAC_PROVIDER_ENCRYPTION_KEY` / `/run/secrets/provider-encryption-key`).
It is never returned by any API (only `has_auth`) and never logged.

> **Naming constraints:** a server `id` must be non-empty and must not
> contain `__`, `/`, or spaces (`400`); `name` must be non-empty (`400`).
> The hub reserves `__` as the separator between a server id and a tool
> name (`github__list_files`).

#### `GET|PUT|DELETE /admin/v1/mcp/servers/{id}`

Get, update, or delete an MCP server. `GET` returns `404` when the id is
unknown. `PUT` creates or replaces the server identified by the **path**
`{id}` — the path id always wins and a body `id` is ignored — with the same
body otherwise as `POST`. `DELETE` returns `200` with `{"deleted": <bool>}`
and never `404` (`"deleted": false` means the id was unknown). Deleting a
server removes it from the registry; existing per-group policies that
reference it become inert.

### MCP policies

MCP policies grant a group permission to call specific tools on specific
MCP servers. Policy entries are written as **`"server:tool"`** (colon form).
When a user's agent uses the combined `/mcp` hub, the same tool is exposed
with a **`server__tool`** prefix; an admin's policy key and the agent's tool
name refer to the same pair.

#### `GET /admin/v1/mcp/policies/{group}`

Get a group's MCP policy.

**Response body:**
```json
{ "group_name": "engineering", "allowed_tools": ["github:list_files"] }
```

`allowed_tools: []` means **no tools allowed**.

> **Ambiguity warning:** `allowed_tools: null` is returned both for an
> explicit **allow-all** policy *and* for a group with **no policy row at
> all** — but enforcement differs: an allow-all policy permits every tool,
> while no policy means deny-all. To tell them apart, check whether the group
> was ever configured: an allow-all policy was explicitly `PUT` with
> `allowed_tools` omitted, whereas no row at all means the group was never
> configured and gets deny-all enforcement.

#### `PUT /admin/v1/mcp/policies/{group}`

Set (replace) a group's MCP policy. Omitting `allowed_tools` entirely stores
an **allow-all** policy; an explicit `[]` stores a **deny-all** policy.

```json
{ "allowed_tools": ["fs:read_file"] }
```

Entries are exact `"server:tool"` string matches — no wildcards or
prefixes.

#### `DELETE /admin/v1/mcp/policies/{group}`

Delete the group's policy. **Response:** `200` with `{"deleted": <bool>}`
(never `404`). A group with no policy **cannot call any tools** — unless
another of the caller's groups grants them — because tools are
deny-by-default.

---

## Token API

Central exposes a token API for minting, revoking, and listing opaque
bearer tokens. These endpoints are separate from the admin API and do not
use the admin auth middleware.

### `POST /v1/tokens`

Mint a new opaque token. This endpoint serves two authentication modes:

1. **Login flow** (relay during OIDC login, no `Authorization` header): the
   request carries the one-time authorization code, PKCE verifier, exact
   loopback redirect URI, and nonce. Central exchanges the code with the IdP,
   validates the ID token, and derives identity and groups itself. Supplied
   identity fields are ignored.
2. **Token-create flow** (`oac-relay token create`, with `Authorization:
   Bearer`): a valid bearer is verified against the token store, and the
   identity is taken from the verified token record. The body carries only
   `label` and `ttl_seconds` (subject/issuer/etc. in the body are ignored).

**Request body (login flow):**

```json
{
  "authorization_code": "one-time-code-from-idp",
  "pkce_verifier": "pkce-verifier",
  "redirect_uri": "http://127.0.0.1:49152/callback",
  "nonce": "authorization-request-nonce",
  "label": "default",
  "ttl_seconds": null
}
```

**Request body (token-create flow — body has only label + ttl):**

```json
{
  "label": "codex",
  "ttl_seconds": 31536000
}
```

The authorization code and PKCE verifier are short-lived secrets and must not
be logged. `ttl_seconds` is optional (`null` = never expires). The requested
TTL is clamped to the admin `max_token_ttl_seconds` backstop if set. The
plaintext token is returned once and never persisted or logged.

**Response:** `201 Created`

```json
{
  "token": "oac_...",
  "token_id": "uuid",
  "expires_at": "2026-09-05 12:00:00",
  "issuer": "https://idp.example.com",
  "subject": "user-123",
  "email": "user@example.com",
  "display_name": "User Name",
  "groups": "[\"engineering\"]"
}
```

### `DELETE /v1/tokens/current`

Revoke the token in the `Authorization: Bearer` header. The token
row is deleted from central's database.

**Response:** `204 No Content` (or `404` if not found).

### `DELETE /v1/tokens/{id}`

Revoke a specific token by its row ID (UUID). Bearer-authenticated — the
caller must hold a valid token (any of their tokens) for authentication. This
lets a user revoke any of their tokens, not just the current one.

**Response:** `204 No Content` (401 if the bearer is invalid, 500 if the
revocation fails).

### `GET /v1/tokens`

List all tokens for the verified subject (from the `Authorization: Bearer`
header). Returns metadata only — never the hash or plaintext.

**Response:** `200` — JSON array of:

```json
[
  {
    "id": "uuid",
    "label": "default",
    "created_at": "2026-09-04 12:00:00",
    "expires_at": null,
    "last_used_at": "2026-09-04 14:30:00"
  }
]
```

---

## Response shapes

### `GroupPolicyResponse`

```json
{
  "group_name": "engineering",
  "allowed_models": ["gpt-4o", "gpt-4o-mini"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": false,
  "max_input_tokens": null,
  "collapse_repeated_lines": false,
  "strip_ansi": false,
  "max_token_ttl_seconds": null
}
```

| Field | Type | Notes |
|---|---|---|
| `group_name` | `String` | Group name |
| `allowed_models` | `Vec<String>` or `null` | `null` = all models allowed |
| `allowed_endpoints` | `Vec<String>` or `null` | `null` = all endpoints allowed |
| `daily_token_quota` | `i64` or `null` | `null` = unlimited |
| `daily_request_quota` | `i64` or `null` | `null` = unlimited |
| `token_saver_enabled` | `bool` | Whether the safe token saver is enabled |
| `max_input_tokens` | `i64` or `null` | Per-request budget; `null` = no trimming |
| `collapse_repeated_lines` | `bool` | RTK-adapted repeated-line collapse; `false` = off |
| `strip_ansi` | `bool` | ANSI colour/control-code stripping; `false` = off |
| `max_token_ttl_seconds` | `i64` or `null` | Admin token-TTL backstop (seconds); `null` = no backstop |

### `UpsertPolicyRequest`

```json
{
  "allowed_models": ["gpt-4o"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": true,
  "max_input_tokens": 8000,
  "collapse_repeated_lines": true,
  "strip_ansi": true,
  "max_token_ttl_seconds": 86400
}
```

All fields are optional (`null` = all/unlimited). `max_token_ttl_seconds`
sets the admin backstop; `null` means no backstop.

### `DeviceResponse`

```json
{
  "cert_fingerprint": "ab:cd:...",
  "user_subject": "user-123",
  "user_email": "user@example.com",
  "revoked": false
}
```

### `UsageResponse`

```json
{
  "user_subject": "user-123",
  "period_date": "2026-08-25",
  "request_count": 42,
  "token_count": 15000,
  "cost_usd": 0.0375
}
```

### `QuotaResponse`

```json
{
  "user_subject": "user-123",
  "groups": null,
  "daily_request_quota": null,
  "daily_token_quota": null,
  "request_count": 42,
  "token_count": 15000,
  "cost_usd": 0.0375
}
```

---

## Policy resolution

When a user makes a request, the central proxy resolves the user's
effective policy by merging all policies for the user's groups. The merge
semantics are **most-permissive-wins**:

- **Models**: union of all groups' allowed models. If any group has `null`
  (all allowed), the result is `null` (all allowed).
- **Endpoints**: union. If any group has `null`, the result is `null`.
- **Quotas**: `max` of all groups' quotas. If any group has `null`
  (unlimited), the result is `null` (unlimited).

If no policies exist for any of the user's groups, the default policy is
**all allowed, unlimited**.

---

## Admin audit logging

All admin mutations are recorded in the `admin_audit_log` table, which is
append-only (enforced by SQLite triggers that abort UPDATE/DELETE). Recorded
actions: `upsert_policy`, `delete_policy`, `revoke_device`,
`reinstate_device`, `upsert_provider` (create and update), `delete_provider`,
`set_default_provider`, `add_provider_key`, `update_provider_key`,
`delete_provider_key`, `upsert_mcp_server`, `delete_mcp_server`,
`upsert_mcp_policy`, `delete_mcp_policy`.

---

## CLI equivalents

Most admin operations are available via the `oac-central admin` CLI:
providers (list/set/delete/default), provider keys (list/add/delete), group
policies (list/get/set/delete), devices (list/revoke/reinstate), audit
queries, usage queries, and quota status. See
[CLI Reference](./cli-reference.md#admin) for the full command list.

Not available via the CLI — use the HTTP API directly (e.g. `curl` through
the relay):

- `GET`/`PUT` a single provider key
  (`/admin/v1/providers/{id}/keys/{key_id}`)
- `GET /admin/v1/token-saver`
- all MCP endpoints (`/admin/v1/mcp/servers`, `/admin/v1/mcp/policies`)

Also note that the CLI `policy-set` cannot set `token_saver_enabled`,
`max_input_tokens`, `collapse_repeated_lines`, or `strip_ansi`; configure
those via `PUT /admin/v1/group-policies/{name}`.
