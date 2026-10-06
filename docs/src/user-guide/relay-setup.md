# Relay Setup

The laptop relay (`oac-relay`) is a thin binary that each employee runs on
their machine. It authenticates the employee via OIDC, requests a central-minted token,
injects it into the agent's config, and forwards agent traffic over mTLS to
the central proxy.

> The relay is a **dumb forwarder**. It holds only a central-minted token
> (256-bit, stored in the agent config file) and an mTLS client certificate.
> The relay does not verify tokens — central is the sole verification
> authority.

## Configuration

Create a config file for the relay. Start from the production reference
config and edit it for your environment:

```sh
cp docker/prod/configs/relay.toml ~/.oac/relay.toml
```

The relay config uses flat top-level fields (no `[relay]` wrapper). A
minimal production config:

```toml
listen_addr = "127.0.0.1:8787"
database_url = "sqlite://~/.oac/relay.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com"
client_id = "oac-relay"
client_secret_env = ""
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid", "email", "profile", "groups"]

[central]
url = "https://central.example.com:8443"
ca_cert_path = "/etc/oac/ca.crt"
client_cert_path = "/etc/oac/client.crt"
client_key_path = "/etc/oac/client.key"
```

Key points:

- `listen_addr` **must** be loopback (`127.0.0.1`) in production. The
  config validator rejects `0.0.0.0` unless `dev_mode = true`.
- `client_secret_env` is ignored by the relay and should be empty. The relay
  is a public native client; the OIDC client secret exists only on central.
- `redirect_uri` uses port `0` (any port); the relay binds a random
  loopback port at login time per RFC 8252.
- `scopes` should include `groups` if you want group-based authorization
  enforced by the central proxy.
- `central.url` must be `https://` in production (mTLS enforced).
- Cert paths (`ca_cert_path`, `client_cert_path`, `client_key_path`) must
  be absolute — `~` is **not** expanded (only `sqlite://` database URLs
  expand `~`).

See [Configuration Reference](./configuration.md) for all fields.

## Lifecycle

### `oac-relay login` — authenticate and configure the agent

```sh
oac-relay --config ~/.oac/relay.toml login
```

This runs the full OIDC authorization-code + PKCE flow:

1. Validates the loopback redirect URI (RFC 8252).
2. Performs OIDC discovery against the IdP.
3. Binds a random loopback port and opens the system browser to the IdP
   login page.
4. After the employee logs in, the IdP redirects back to the loopback
   callback with an authorization code.
5. The relay sends the one-time code, PKCE verifier, redirect URI, and nonce
   to central's `POST /v1/tokens` over mTLS.
6. Central uses its client secret to exchange the code and validates the ID
   token: alg pinned to {RS256, ES256}, verifies iss, aud, exp, nonce,
   signature, and `at_hash`.
7. Central fetches userinfo (or falls back to validated ID-token claims) and
   derives the identity and groups used for policy.
8. Central mints an opaque token, stores only its SHA-256 hash, and returns
   the plaintext token plus the verified identity once.
9. Relay upserts that verified identity in local SQLite and injects the base
   URL + token into the agent config file.

The agent config is written to one of:

| Agent | File | Format |
|---|---|---|
| Codex | `~/.codex/config.json` (or `$CODEX_HOME/config.json`) | JSON: `{"api_base_url": "...", "api_key": "..."}` |
| Generic | `~/.oac/agent-env.sh` | Shell: `export OPENAI_API_BASE='...'` / `export OPENAI_API_KEY='...'` |

The Codex config is used only if `CODEX_HOME` is set or
`~/.codex/config.json` already exists; otherwise the generic env file is
written. The file is created with `0600` permissions.

On success, the relay prints:

```
oac-relay: login successful for alice@example.com (agent config written to /home/alice/.oac/agent-env.sh)
```

### `oac-relay serve` — start the relay server

```sh
oac-relay --config ~/.oac/relay.toml serve
```

- Opens the SQLite DB (runs migrations, enforces `0600` perms).
- If `dev_mode = true`, skips auth checks (central rejects unauthenticated
  requests via its token store).
- Binds `TcpListener` to `listen_addr`.
- Serves the HTTP router with graceful shutdown (SIGINT/SIGTERM).

### `oac-relay logout` — revoke the current central token

```sh
oac-relay --config ~/.oac/relay.toml logout
```

Calls `DELETE /v1/tokens/current` at central to revoke the token. The agent
config file is **not** deleted — the token stays in the file but stops
working; run `login` again to mint a fresh token.

### `oac-relay print-key` — re-print the token

```sh
oac-relay print-key
```

Reads the agent config file (not the DB) and prints the base URL and token.
Useful if you need to copy the token into a tool that doesn't read the
auto-injected config.

### `oac-relay list-keys` — list all tokens

```sh
oac-relay --config ~/.oac/relay.toml list-keys
```

Calls `GET /v1/tokens` at central. Lists all tokens for the current user:
id, label, created_at, expires_at, last_used_at.

## How the agent connects

After `login`, the agent is configured to point at:

- **Base URL:** `http://127.0.0.1:8787/v1`
- **Token:** the central-minted token (e.g. `oac_abc123...`)

The agent sends standard OpenAI-compatible requests. The relay:

1. Validates the `Host` header (DNS rebinding defense — loopback only).
2. Checks for a non-empty `Authorization: Bearer ***` header (pass-through —
   does not verify the token locally).
3. Adds `x-oac-request-id` (per-request correlation UUID).
4. Forwards over mTLS to the central proxy (with the Authorization header
   unchanged — central verifies the token via its TokenStore).
5. Streams the response back (including SSE).

## Dev mode

When `dev_mode = true`:

- The relay can bind `0.0.0.0` (needed for Docker).
- The central URL can be `http://` (no mTLS).
- The relay skips auth checks (central rejects unauthenticated requests).

Dev mode is for testing only. **Never use it in production.**

## Next steps

- [Central Proxy Setup](./central-setup.md)
- [CLI Reference](./cli-reference.md) — all relay commands and flags.
- [Configuration Reference](./configuration.md) — all TOML fields.
