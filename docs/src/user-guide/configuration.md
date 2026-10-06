# Configuration Reference

The configuration file is TOML. The relay and central proxy each use a
**separate** config file with **flat top-level fields** — there is no
`[relay]` or `[central]` wrapper section. The relay config is parsed by
`RelayConfig::from_toml()` and the central config by
`CentralConfig::from_toml()` (both in `oidc_agent_common::config`).

See `config.example.toml` at the repo root for commented examples of both
files side by side.

All configs are parsed and validated by
`oidc_agent_common::config::{RelayConfig, CentralConfig}::from_toml()`.

## Relay configuration

### Top-level fields

| Field | Type | Required | Default | Validation |
|---|---|---|---|---|
| `listen_addr` | `SocketAddr` | yes | — | Must be loopback (`127.0.0.0/8` or `::1`) unless `dev_mode = true` |
| `database_url` | `String` | yes | — | SQLite URL, e.g. `sqlite://~/.oac/relay.db` (`~` is expanded in `sqlite://` URLs) |
| `oidc` | table | yes | — | See [OIDC](#oidc) below |
| `central` | table | yes | — | See [Central connection](#central-connection) below |
| `dev_mode` | `bool` | no | `false` | When `true`: allows non-loopback bind, HTTP central URL, skips auth checks |

### OIDC

| Field | Type | Required | Validation |
|---|---|---|---|
| `issuer` | `String` | yes | Non-empty; must start with `http://` or `https://` |
| `client_id` | `String` | yes | Non-empty |
| `client_secret_env` | `String` | yes | Ignored by relay; set to `""` because the relay is a public native client |
| `redirect_uri` | `String` | yes | Must be a loopback `http://127.0.0.1` URL; the host is parsed and verified (e.g. `http://127.0.0.1.evil.com/cb` is rejected) |
| `scopes` | `Vec<String>` | yes | e.g. `["openid", "email", "profile", "groups"]` |

> Include `"groups"` in scopes if you want group-based authorization
> enforced by the central proxy.

### Central connection

| Field | Type | Required | Validation |
|---|---|---|---|
| `url` | `String` | yes | Non-empty; must be `https://` unless `dev_mode = true` |
| `ca_cert_path` | `PathBuf` | yes | Company CA cert (PEM) |
| `client_cert_path` | `PathBuf` | yes | Relay mTLS client cert (PEM) |
| `client_key_path` | `PathBuf` | yes | Relay mTLS client key (PEM, must be `0600`) |

> Cert paths are raw filesystem reads — `~` is **not** expanded. Use
> absolute paths (e.g. `/home/yourname/.oac/certs/ca.crt`). Only
> `sqlite://` database URLs expand `~`.

### Example (production)

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

---

## Central proxy configuration

### Top-level fields

| Field | Type | Required | Default | Validation |
|---|---|---|---|---|
| `listen_addr` | `SocketAddr` | yes | — | e.g. `0.0.0.0:8443` |
| `database_url` | `String` | yes | — | SQLite or Postgres URL |
| `oidc` | table | yes | — | See [OIDC](#oidc-1) below |
| `mtls` | table | yes | — | See [mTLS server](#mtls-server) below |
| `admin` | table | no | `None` (admin API disabled) | See [Admin](#admin) below |
| `pricing` | table | no | `None` (no cost tracking; `cost_usd` always `0.0`) | See [Pricing](#pricing) below |
| `dev_mode` | `bool` | no | `false` | When `true`: plain HTTP and the rate limiter is disabled (`rate_limit_*` ignored); bearer verification remains mandatory |
| `rate_limit_requests` | `u32` | no | `60` | Maximum requests per client IP per rate-limit window; must be greater than zero |
| `rate_limit_window_secs` | `u64` | no | `60` | Token-bucket window in seconds; must be greater than zero |

When the limit is exceeded, central returns `429 Too Many Requests` with a
`Retry-After` header (seconds until one token refills) and a JSON body
(`error.type = "rate_limit_error"`, `error.retry_after_secs`) so agents can
back off for exactly the right duration instead of retrying in a tight loop.

### OIDC

Same serialized shape as the relay's OIDC config, but central requires and
uses the client secret for the authorization-code exchange:

| Field | Type | Required | Validation |
|---|---|---|---|
| `issuer` | `String` | yes | Non-empty; must start with `http://` or `https://` |
| `client_id` | `String` | yes | Non-empty |
| `client_secret_env` | `String` | yes | Non-empty (env var name) |
| `redirect_uri` | `String` | yes | Must be a loopback `http://127.0.0.1` URL (host verified) |
| `scopes` | `Vec<String>` | yes | e.g. `["openid"]` |

### Providers and API keys

Providers are deliberately not configuration fields. They are runtime data
managed through the admin API, allowing administrators to add, remove,
enable, disable, and route between multiple OpenAI-compatible backends without
restarting central. Each provider has a base URL, an optional exact model
allowlist, and an optional default flag.

Provider API keys are encrypted at rest in the central database using
AES-256-GCM. Central loads the encryption key from `OAC_PROVIDER_ENCRYPTION_KEY`
or `/run/secrets/provider-encryption-key`; the value must be 64 hexadecimal
characters (32 bytes). The encryption key is required at startup and must be
backed up securely: losing it makes stored provider keys unrecoverable.

Each provider can have multiple keys. Keys are selected by ascending priority,
then creation time. A key can be restricted to IdP groups; an empty access
list means unrestricted. On upstream `401` or `429`, central tries the next
authorized key. Key plaintext is accepted only when a key is created and is
never returned by the API or written to audit logs.

### mTLS server

| Field | Type | Description |
|---|---|---|
| `ca_cert_path` | `PathBuf` | Company CA cert (PEM) — validates relay client certs |
| `server_cert_path` | `PathBuf` | Server cert (PEM) |
| `server_key_path` | `PathBuf` | Server private key (PEM, must be `0600`) |

### Admin

| Field | Type | Required | Validation |
|---|---|---|---|
| `admin_group` | `String` | yes | Non-empty — the IdP group that grants admin access |

If this section is absent, the admin API (`/admin/v1/`) is not mounted.

### Pricing

| Field | Type | Default | Description |
|---|---|---|---|
| `models` | `Vec<ModelPrice>` | `[]` | Manual price overrides |
| `fetch_interval_secs` | `u64` | `3600` (1 hour) | Auto-fetch interval; `0` disables |

#### `[[pricing.models]]`

| Field | Type | Description |
|---|---|---|
| `model` | `String` | Model name (must match request `model` field) |
| `input_per_1k_usd` | `f64` | Price per 1K prompt tokens (USD) |
| `output_per_1k_usd` | `f64` | Price per 1K completion tokens (USD) |

Manual config overrides take precedence over auto-fetched prices.
Auto-fetch (best-effort, from the backend `/v1/models`) runs at startup and
then every `fetch_interval_secs` — but only when a `[pricing]` section is
present. Without the section, prices are never fetched and `cost_usd` is
always `0.0`.

### Example (production)

```toml
listen_addr = "0.0.0.0:8443"
database_url = "sqlite:///data/central.db"
dev_mode = false
rate_limit_requests = 60
rate_limit_window_secs = 60

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

[pricing]
fetch_interval_secs = 3600

[[pricing.models]]
model = "gpt-4o"
input_per_1k_usd = 0.0025
output_per_1k_usd = 0.01
```

---

## Environment variables

| Variable | Used by | Description |
|---|---|---|
| `OAC_OIDC_CLIENT_SECRET` | Central | OIDC client secret (referenced by central's `client_secret_env`; never needed on a relay laptop) |
| `OAC_PROVIDER_ENCRYPTION_KEY` | Central | 64-hex-character key used to encrypt provider API keys at rest |
| `OAC_RELAY_CONFIG` | Relay | Path to config file (alternative to `--config`) |
| `OAC_CENTRAL_CONFIG` | Central | Path to config file (alternative to `--config`) |
| `OAC_API_KEY` | Central admin CLI | Local API key from `oac-relay login` |
| `OAC_ADMIN_URL` | Central admin CLI | Relay URL (default `http://127.0.0.1:8787`) |
| `RUST_LOG` | Both | Log level (default `info`) |
