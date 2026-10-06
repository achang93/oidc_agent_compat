# Quickstart

This guide walks you through setting up a **production** deployment from
scratch: a central proxy in Docker on a company server, and a relay binary
on an employee laptop. It takes about 10 minutes once prerequisites are
in place.

> Want to try the dev stack first (bundled Keycloak + mock backend)?
> See [Docker: Dev Stack](./docker-dev.md).

## Prerequisites

- **Rust 1.85+** (stable) — for building the relay binary. Install via
  [rustup](https://rustup.rs/).
- **Docker** and **Docker Compose** — for running the central proxy
  container.
- **An OIDC Identity Provider** — Okta, Entra ID, Keycloak, Auth0, or any
  OIDC-compliant IdP. You need: an issuer URL, a client ID, a client
  secret, and the ability to register a loopback redirect URI
  (`http://127.0.0.1:*`).
- **An OpenAI-compatible backend** — OpenAI, Azure OpenAI, OpenRouter,
  Ollama, vLLM, etc. You need: the base URL and a master API key.
- **curl** — for test requests.

## Step 1: Generate mTLS certificates

The relay and central proxy communicate over mutual TLS. You need a CA,
server cert, and client cert.

> **⚠️ Production security:** `./docker/generate-certs.sh` creates
> **self-signed test certs** (CN=`OAC Test CA`). These are fine for getting
> started, but for real production you should use your **company PKI** or a
> properly signed CA. Never use the test certs in a production deployment
> that handles real API keys.

For initial testing:

```sh
./docker/generate-certs.sh
```

This creates `docker/certs/{ca,server,client}.{crt,key}`. Copy them into
the production cert directory:

```sh
mkdir -p docker/prod/certs
cp docker/certs/{ca,server,client}.{crt,key} docker/prod/certs/
```

Distribute `ca.crt`, `client.crt`, and `client.key` to each employee
laptop for the relay config. For production, distribute certs via your
internal PKI — do not email them or store them in git.

## Step 2: Configure the central proxy

Edit the reference config for your environment:

```sh
$EDITOR docker/prod/configs/central.toml
```

The production compose file mounts this config directly into the
container. Set the `issuer` and TLS paths. Providers and their keys are
configured through the admin API after startup:

```toml
listen_addr = "0.0.0.0:8443"
database_url = "sqlite:///data/central.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com/realms/your-realm"   # ← your IdP
# Must match the public client_id configured on every relay.
client_id = "oac-relay"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid"]

[mtls]
ca_cert_path = "/certs/ca.crt"
server_cert_path = "/certs/server.crt"
server_key_path = "/certs/server.key"

[admin]
admin_group = "oac-admins"   # ← your admin group (optional)
```

## Step 3: Provide secrets

Set the OIDC client secret via an `.env` file:

```sh
echo "OAC_OIDC_CLIENT_SECRET=your-oidc-client-secret" > docker/prod/.env
```

Generate a 64-hex-character provider encryption key and store it as a Docker
secret (preferred). With Docker Swarm:

```sh
openssl rand -hex 32 | docker secret create oac_provider_encryption_key -
```

Without Swarm, edit `docker/prod/docker-compose.yml` `secrets:` section to
use a `file:` source instead of `external: true`. After central starts, add
providers and provider keys through the admin API; provider keys are
encrypted at rest and are never sent to relays.

## Step 4: Deploy the central proxy

```sh
cd docker/prod
docker compose up -d --build
docker compose logs -f central
```

The central proxy serves mTLS on `:8443` with client cert required. Verify
it's running:

```sh
docker compose ps
```

## Step 5: Install the relay on a laptop

Build the relay binary:

```sh
cargo build --release -p oac-relay
# → target/release/oac-relay
```

Copy the binary, config, and certs to the laptop:

```sh
# Binary:
cp target/release/oac-relay /usr/local/bin/oac-relay

# Config:
mkdir -p ~/.oac
cp docker/prod/configs/relay.toml ~/.oac/relay.toml

# mTLS certs (distributed by your admin; Step 1 put them in
# docker/prod/certs/ — run from the repo root):
mkdir -p ~/.oac/certs
cp docker/prod/certs/ca.crt ~/.oac/certs/
cp docker/prod/certs/client.crt ~/.oac/certs/
cp docker/prod/certs/client.key ~/.oac/certs/
chmod 600 ~/.oac/certs/client.key
```

Edit `~/.oac/relay.toml` to point at your central proxy:

```toml
listen_addr = "127.0.0.1:8787"
database_url = "sqlite://~/.oac/relay.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com/realms/your-realm"
client_id = "oac-relay"
client_secret_env = ""
redirect_uri = "http://127.0.0.1:0/callback"
# "groups" is REQUIRED for group-based policy enforcement and admin access.
scopes = ["openid", "email", "profile", "groups"]

[central]
url = "https://central.example.com:8443"   # ← your central proxy
# Cert paths must be ABSOLUTE — "~" is not expanded (only sqlite:// URLs
# expand "~"). Replace /home/you with your actual home directory:
ca_cert_path = "/home/you/.oac/certs/ca.crt"
client_cert_path = "/home/you/.oac/certs/client.crt"
client_key_path = "/home/you/.oac/certs/client.key"
```

## Step 6: Log in and start the relay

```sh
# Log in (opens browser, runs OIDC auth-code + PKCE flow):
oac-relay --config ~/.oac/relay.toml login

# Source the agent config (if using generic env format):
source ~/.oac/agent-env.sh

# Start the relay server:
oac-relay --config ~/.oac/relay.toml serve
```

After `login`, the relay writes the base URL + central-minted token directly
into the agent's config file (`~/.codex/config.json` or `~/.oac/agent-env.sh`).
The employee never sees or copies a token.

## Step 7: Make a request

The agent should now point at `http://127.0.0.1:8787/v1` with the
auto-injected API key. Test with curl:

```sh
# List models (laptop → relay → mTLS → central → backend):
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  http://127.0.0.1:8787/v1/models

# Chat completion:
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}'
```

The request flows: agent → relay (loopback) → mTLS → central proxy
(provider-key resolution + policy enforcement) → backend. Provider keys
never touch the laptop.

## Next steps

- [Relay Setup](./relay-setup.md) — full relay lifecycle and commands.
- [Central Proxy Setup](./central-setup.md) — central proxy lifecycle.
- [Configuration Reference](./configuration.md) — all TOML fields.
- [Docker: Production](./docker-prod.md) — production deployment in depth.
- [Admin API](./admin-api.md) — managing policies, devices, audit.
