# Central Proxy Setup

The central proxy (`oac-central`) is a company-hosted server that manages
multiple OpenAI-compatible providers and forwards mTLS-authenticated relay
requests to the provider selected for each model.

> Provider API keys are encrypted at rest in the central database. Plaintext
> keys exist only briefly in `Zeroizing` memory during forwarding; they are
> never sent to a laptop, logged, or returned by the admin API.

## Configuration

The central proxy config uses flat top-level fields (no `[central]`
wrapper). A minimal production config:

```toml
listen_addr = "0.0.0.0:8443"
database_url = "sqlite:///data/central.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com"
client_id = "oac-relay" # must match the relay's public client_id
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid"]

[mtls]
ca_cert_path = "/etc/oac/ca.crt"
server_cert_path = "/etc/oac/server.crt"
server_key_path = "/etc/oac/server.key"

[admin]
admin_group = "oac-admins"
```

Key points:

- `listen_addr` is `0.0.0.0:8443` (network-accessible) in production.
- `dev_mode = false` enforces mTLS. Bearer-token verification is mandatory
  in both production and development modes.
- Provider and key records are not in the TOML file. Add them with the admin
  API after central starts.
- `[admin]` is optional. If present, the admin API is enabled and
  restricted to users in the `admin_group`.

See [Configuration Reference](./configuration.md) for all fields.

Set the OIDC client secret:

```sh
export OAC_OIDC_CLIENT_SECRET="your-oidc-client-secret"
```

Central uses this confidential-client registration to exchange the one-time
authorization code received from a relay and independently validate the ID
token and userinfo response. Its `client_id`, issuer, and redirect policy must
match the public authorization request configured on the relay; only central
receives the client secret.

Set the provider-key encryption key through your secret manager or Docker
secret. For local development only, an environment variable can be used:

```sh
export OAC_PROVIDER_ENCRYPTION_KEY="$(openssl rand -hex 32)"
```

## Lifecycle

### `oac-central serve` — start the central proxy

```sh
oac-central --config config.toml serve
```

- Opens the database (runs migrations).
- Loads the provider encryption key and opens the runtime provider store.
- Builds the `reqwest` client for talking to the backend.
- Initializes the policy store, device store, audit logger, usage
  tracker, and price table.
- If `[pricing]` is configured, auto-fetches model prices from the backend
  at startup (best-effort) and re-fetches every `fetch_interval_secs`
  (default 3600; set `0` to disable auto-fetch). Without a `[pricing]`
  section, costs are not tracked (`cost_usd` is `0.0`).
- Binds the server:
  - **Dev mode** (`dev_mode = true`): plain HTTP via `axum::serve`.
  - **Production** (`dev_mode = false`): mTLS via
    `axum_server::bind_rustls` with client cert required, ALPN `http/1.1`.
- Serves with graceful shutdown (SIGINT/SIGTERM).

### `oac-central admin` — admin CLI

The admin CLI sends requests **through the relay** (which authenticates the
user via OIDC and forwards the bearer token to central). The user must
belong to the configured `admin_group`.

```sh
# Set the relay URL and API key (from oac-relay login):
export OAC_ADMIN_URL="http://127.0.0.1:8787"
export OAC_API_KEY="oac_..."   # from oac-relay login

# Add a provider and its first key (key is prompted without echo):
oac-central admin provider-set openai --name openai --base-url https://api.openai.com --models gpt-4o,gpt-4o-mini --default
oac-central admin provider-key-add openai --label production --groups engineering

# List providers:
oac-central admin provider-list

# List policies:
oac-central admin policy-list

# Set a policy:
oac-central admin policy-set engineering --models gpt-4o,gpt-4o-mini

# Query the audit log:
oac-central admin audit-query --limit 50
```

See [Admin API](./admin-api.md) for all admin commands and endpoints.

## mTLS certificates

In production, the central proxy requires mTLS. You need:

- A **CA certificate** (`ca.crt`) that signs both the server and client
  certs.
- A **server cert** (`server.crt` + `server.key`) for the central proxy.
- A **client cert** (`client.crt` + `client.key`) distributed to each
  relay.

Generate dev certs with:

```sh
./docker/generate-certs.sh
```

This creates `docker/certs/{ca,server,client}.{crt,key}`. For production,
use your company PKI or a properly signed CA.

Distribute `ca.crt`, `client.crt`, and `client.key` to each employee
laptop for the relay config.

## Docker deployment

The recommended production deployment is via Docker. See
[Docker: Production](./docker-prod.md) for the full setup.

## Next steps

- [Admin API](./admin-api.md) — managing policies, devices, audit.
- [Docker: Production](./docker-prod.md) — container deployment.
- [Configuration Reference](./configuration.md) — all TOML fields.
