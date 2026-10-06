# Request Data Flow

This page walks through the full request lifecycle, showing what headers
are added, stripped, and transformed at each hop.

## Overview

```
Agent ──HTTP──► Relay ──mTLS──► Central ──HTTPS──► Backend
                  │                  │
                  │                  ├─ Auth (token verification via TokenStore)
                  │                  ├─ Permissions (policy, device, quota)
                  │                  ├─ Provider-key injection
                  │                  ├─ Audit log
                  │                  └─ Usage tracking
                  │
                  ├─ Host guard (DNS rebinding)
                  ├─ Auth (pass-through — checks Authorization header presence)
                  ├─ Forwards Authorization header unchanged
                  └─ Activity log
```

## Login bootstrap: relay → central → IdP

1. Relay starts the OIDC authorization request as a public native client with
   PKCE S256, `state`, `nonce`, and a random loopback redirect port.
2. Relay receives the authorization code and verifies `state`.
3. Relay sends the one-time code, PKCE verifier, exact redirect URI, and nonce
   to central's `POST /v1/tokens` over mTLS. It does not send identity claims.
4. Central, which alone holds the client secret, exchanges the code with the
   IdP and validates the ID token (`iss`, `aud`, `exp`, nonce, signature,
   RS256/ES256 pin, and optional `at_hash`). Central fetches userinfo with an
   expected-subject check and falls back to the validated ID-token claims.
5. Central resolves policy from those verified groups, stores the identity
   snapshot with the new opaque token, and returns the plaintext once. Relay
   stores the returned identity locally and injects the token into the agent
   config.

Authorization codes and PKCE verifiers are short-lived secrets, are not
`Debug`, and are never logged. JSON fields claiming a subject, issuer, group,
or identity ID cannot influence bootstrap authorization.

## Step 1: Agent → Relay

The agent sends a standard OpenAI-compatible request:

```http
POST /v1/chat/completions HTTP/1.1
Host: 127.0.0.1:8787
Authorization: Bearer oac_abc123...
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

### Relay processing

1. **Host guard** (`host_guard_middleware`):
   - Validates `Host` header is loopback (`127.0.0.1:8787`,
     `localhost:8787`, `[::1]:8787`).
   - Mismatch → `400 Bad Request` (DNS rebinding defense).

2. **Auth** (`auth_middleware`):
   - Extracts `Authorization: Bearer ***` header.
   - Checks for a non-empty bearer (presence check only — the relay is a
     dumb forwarder and does NOT verify the token). Central verifies it
     via its TokenStore.
   - Missing → `401 Unauthorized` (non-dev mode).
   - On success: inserts a minimal `VerifiedIdentity` (all fields `None`)
     into request extensions for the activity logger.

3. **Forward** (`proxy_handler` → `forward_request`):
   - Generates `request_id = Uuid::new_v4()`.
   - Reads body (max 10 MB).
   - Extracts `model` from body (for activity logging).
   - Sanitizes path (`sanitize_path` — rejects `..`, `//`, `\`, absolute
     URLs).
   - Builds upstream URL: `{config.central.url}{sanitized_path}`.
   - Builds forward headers (`build_forward_headers` — allowlist model,
     strips hop-by-hop headers but **forwards the `Authorization` header
     unchanged** — central verifies the token).
   - Adds `x-oac-request-id` (per-request correlation UUID v4).
   - Sends over mTLS (production) or plain HTTP (dev).

4. **Activity log** (best-effort, after response):
   - Records `RelayActivityEntry` (identity_id, key_id, method, endpoint,
     model, central_status, latency_ms, request_id).

## Step 2: Relay → Central (over mTLS)

```http
POST /v1/chat/completions HTTP/1.1
Host: central:8443
Authorization: Bearer oac_...
x-oac-request-id: 660e8400-e29b-41d4-a716-446655440001
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

> Note: The `Authorization` header (the agent's bearer token) is forwarded
> unchanged. Hop-by-hop headers are stripped. The relay does not inject
> identity headers — central extracts identity from the token record.

### Central processing

1. **Auth** (`auth_middleware`):
   - Skips `/healthz`.
   - Extracts the bearer token from the `Authorization` header.
   - Verifies it via `TokenStore::verify_token()` (DB lookup,
     constant-time hash comparison, no early return — prevents timing
     leaks, CWE-208). Expired tokens are deleted.
   - Missing/unverifiable → `401 Unauthorized` in every mode.
   - `X-OAC-*` identity headers are **ignored** — identity comes from the
     token record.
   - Inserts `VerifiedRelayIdentity` (with `token_id` and `created_at` for
     backstop enforcement) into extensions.

2. **Rate limit** (`rate_limit_middleware`, production only):
   - Per-IP token bucket (60 req/min default).
   - Exceeded → `429 Too Many Requests` with `Retry-After`.
   - Runs **before** permission checks, so policy-denied requests still
     consume a rate-limit token.

3. **Permissions** (`permissions_middleware`):
   - Skip `/healthz`.
   - Parse groups from the token record's `groups` field (JSON array).
   - `PolicyStore::resolve_policy(&groups)` — most-permissive-wins merge.
   - **Token-TTL backstop check** — if `max_token_ttl_seconds` is set and
     the token is older than the limit (from `created_at`), the token row
     is deleted and the request is rejected with `401`.
   - **Device revocation check** — if `DeviceStore::is_revoked` → `403`
     (`"device_revoked"`).
   - **Endpoint check** — `policy.is_endpoint_allowed(&endpoint)` →
     `403` (`"endpoint_not_allowed"`).
   - **Model check** (POST) — extract model, check
     `policy.is_model_allowed` → `403` (`"model_not_allowed"`).
   - **Quota checks** (both pre-flight): **token quota** — if
     `daily_token_quota` set and `usage.token_count >= quota` → `429`
     (`"token_quota_exceeded"`); **request quota** — an atomic
     `try_reserve_request` reservation → `429` (`"quota_exceeded"`)
     when it cannot be taken (released again if the upstream request
     fails).
   - On allow: inserts `PermissionDecision` into extensions.
   - If the resolved policy has the token saver enabled, attaches a
     `TokenSaverGrant` (config) to the extensions for the forward handler.

4. **Forward** (`proxy_handler` → `forward_request`):
   - Reads body (max 10 MB).
   - Extracts model.
   - **Token saver** (if a `TokenSaverGrant` is present): applies the safe
     optimizer to the body — removes exact-verbatim duplicate messages and
     structurally-empty messages, drops empty `tools: []`, and, if a budget
     is set, drops the oldest whole turns (never truncates) to fit. If the
     policy enabled `collapse_repeated_lines`, consecutive exact-verbatim
     repeated lines inside a single message are folded into `[×N]` markers
     (RTK-adapted). If the policy enabled `strip_ansi`, terminal ANSI
     colour/control codes are removed from message content. Kept messages are
     otherwise never rewritten, and a final "never-worse" guard reverts to
     the original body if the optimizer would ever increase token usage.
     Records `OptimizationReport`.
   - Sanitizes path.
  - Builds upstream URL: `{provider.base_url}{sanitized_path}`.
   - Builds forward headers (strips hop-by-hop headers).
   - **Replaces** `Authorization` with the selected provider key (held in
     `Zeroizing<String>` memory).
   - Sends to backend.

## Step 3: Central → Backend (over HTTPS)

```http
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
Authorization: Bearer sk-<provider-key>
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

> Note: Identity headers are gone. `Authorization` is now the selected
> provider key; provider keys are never returned to the relay.

## Step 4: Response (Backend → Central → Relay → Agent)

### Non-streaming response

The central proxy:

1. Buffers the response body.
2. Extracts token usage from the `usage` JSON field.
3. Computes cost via `PriceTable::compute_cost`.
4. Records `AuditEntry` (best-effort).
5. Increments usage counters (best-effort, allowed requests only).
6. Strips hop-by-hop + `content-length` headers.
7. Returns the response.

The relay:

1. Strips hop-by-hop + `content-length` headers.
2. Returns the response to the agent.
3. Records `RelayActivityEntry` (best-effort).

### SSE streaming response

When `Content-Type: text/event-stream`:

- **Central**: sets `stream_options.include_usage=true`, then streams via
  `bytes_stream()` → `Body::from_stream` while wrapping with
  `wrap_stream_with_usage_extraction` to intercept `data:` lines and
  extract `usage` from the final chunk (before `data: [DONE]`). Audit and
  usage accounting are deferred until the stream completes; the forwarded
  SSE bytes are not modified.

## MCP request flow

MCP traffic rides a parallel path with per-tool enforcement:

1. The agent POSTs JSON-RPC to `http://127.0.0.1:8787/mcp/{server}`
   (single server) or `/mcp` (combined hub).
2. The relay checks for the `Authorization` header (same pass-through
   as `/v1`), best-effort parses `mcp_server`/`mcp_tool`/`mcp_method` for
   its activity log, and byte-tunnels the body (with the `Authorization`
   header) to central.
   **Batches (JSON-RPC arrays) are rejected** — a batch could smuggle
   `tools/call` requests past per-tool enforcement.
3. Central verifies the bearer token via TokenStore, then:
   - **Per-server endpoint**: `mcp_permissions_middleware` classifies the
     method (`tools/call` vs other), resolves the caller's
     per-group/per-server/per-tool allowlist, and denies with `403`
     (`-32001`) outside it; non-`tools/call` methods require at least one
     allowed tool on that server. Callers with no groups are denied all.
   - **Hub**: the handler splits the `server__tool` prefix, enforces the
     same policy inline, fans `tools/list` out to enabled servers the
     policy can reach, and answers `ping` locally.
4. Central injects the server's encrypted `auth_header` (decrypted into
   `Zeroizing` memory), strips hop-by-hop headers, forwards the bytes,
   and passes SSE responses through unchanged.
5. Every request — allowed or denied — produces an audit entry with
   `mcp_server`, `mcp_tool`, `mcp_method`, the permission decision, and a
   redacted, 512-char-capped args preview; the relay records the same
   metadata in its activity log.

See [MCP Support](../user-guide/mcp.md) for the user-facing behavior and
error codes.
- **Relay**: streams via `bytes_stream()` → `Body::from_stream` (raw
  byte passthrough).

## Header transformation summary

| Header | Agent→Relay | Relay→Central | Central→Backend |
|---|---|---|---|
| `Authorization` | `Bearer oac_...` (central token) | **forwarded unchanged** | `Bearer sk-...` (selected provider key) |
| `Host` | `127.0.0.1:8787` | `central:8443` | `api.openai.com` |
| `x-oac-request-id` | — | **added** (UUID v4) | **stripped** |
| `Content-Type` | forwarded | forwarded | forwarded |
| `Accept` | forwarded | forwarded | forwarded |
| `User-Agent` | forwarded | forwarded | forwarded |
| Hop-by-hop headers | — | **stripped** | **stripped** |
| `content-length` (response) | — | **stripped** (Axum recomputes) | — |
