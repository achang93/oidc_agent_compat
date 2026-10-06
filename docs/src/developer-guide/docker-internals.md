# Docker Internals

This page documents the Docker setup internals. For user-facing Docker
guides, see [Docker: Dev Stack](../user-guide/docker-dev.md) and
[Docker: Production](../user-guide/docker-prod.md).

## Dev Dockerfile (`docker/dev/Dockerfile`)

Multi-stage build:

### Builder stage

- Base: `rust:1.98-slim`
- Installs: `pkg-config libssl-dev ca-certificates`
- Copies: `Cargo.toml`, `Cargo.lock`, `crates/`, `tests/`
- Builds: `cargo build --release -p oac-central -p oac-relay`

### Runtime stage

- Base: `debian:trixie-slim`
- Installs: `ca-certificates libssl3 curl`
- Copies both binaries to `/usr/local/bin/`

> **Critical:** The runtime base **must be `debian:trixie-slim`** (not
> `bookworm-slim`) to match the `rust:1.98-slim` builder's glibc 2.41.
> Using `bookworm-slim` will cause a glibc version mismatch and the
> binaries will fail to run.

## Prod Dockerfile (`docker/prod/Dockerfile.central`)

Multi-stage build, central proxy only:

### Builder stage

- Base: `rust:1.98-slim`
- Installs: `pkg-config libssl-dev ca-certificates`
- Copies: `Cargo.toml`, `Cargo.lock`, `crates/`, `tests/`
- Builds: `cargo build --release -p oac-central` (only central, keeps
  layer small)

### Runtime stage

- Base: `debian:trixie-slim` (same glibc requirement as dev)
- Installs: `ca-certificates libssl3`
- Copies `oac-central` to `/usr/local/bin/`
- Creates non-root user: `useradd --system --no-create-home --shell
  /usr/sbin/nologin oac`
- `USER oac`
- `EXPOSE 8443`
- Entrypoint: `oac-central --config /config/central.toml serve`

> Provider API keys are **never** baked into the image. They are encrypted in
> the central database; the provider encryption key is mounted via Docker
> secret at `/run/secrets/provider-encryption-key`.

## Dev compose (`docker/dev/docker-compose.yml`)

### Services

| Service | Image / Build | Port | Depends on |
|---|---|---|---|
| `keycloak` | `quay.io/keycloak/keycloak:26.0` | `8080:8080` | — |
| `mock-backend` | built from `./mock-backend` | `8090:8080` | — |
| `central` | built from `../..` with `docker/dev/Dockerfile` | `8443:8443` | keycloak (healthy), mock-backend (healthy) |
| `relay` | built from `../..` with `docker/dev/Dockerfile` | `127.0.0.1:8787:8787` | central (healthy) |
| `goose` | `ghcr.io/aaif-goose/goose:latest` | — | relay (healthy) |

The dev central receives its provider encryption key via the
`OAC_PROVIDER_ENCRYPTION_KEY` env var (a fixed dev 64-hex value in the
compose file). After healthchecks pass, `docker/dev.sh up` registers the
mock provider and its key through the admin API. It first invokes the hidden
`oac-central dev-token` command inside the central container; that command
requires `dev_mode = true` and mints directly through local database access,
so the public HTTP bootstrap endpoint never accepts caller-claimed identity.
There is no init container and no key file on disk.

### Volumes

| Volume | Mount | Used by |
|---|---|---|
| `central-data` | `/data` | central |
| `relay-data` | `/data` | relay |
| `goose-config` | `/home/goose/.config/goose` | goose |
| `./workspace` | `/workspace` | goose (working_dir) |

### Healthchecks

| Service | Check | Interval | Retries | Start period |
|---|---|---|---|---|
| keycloak | TCP port 8080 | 5s | 30 | 20s |
| mock-backend | Python urllib `/v1/models` | 5s | 10 | — |
| central | `curl -sf http://localhost:8443/healthz` | 5s | 10 | — |
| relay | `curl -sf http://localhost:8787/healthz` | 5s | 10 | — |

## Prod compose (`docker/prod/docker-compose.yml`)

Only the `central` service:

- Build: `../..` with `docker/prod/Dockerfile.central`
- Image: `oac-central:prod`
- Restart: `unless-stopped`
- Env: `OAC_OIDC_CLIENT_SECRET` (required), `RUST_LOG` (default `info`)
- Ports: `8443:8443`
- Volumes: `./configs/central.toml` → `/config/central.toml:ro`,
  `./certs` → `/certs:ro`, `central-data` → `/data`
- Secrets: `oac_provider_encryption_key` → `provider-encryption-key` (at
  `/run/secrets/provider-encryption-key`; the env var
  `OAC_PROVIDER_ENCRYPTION_KEY` is an equivalent non-Docker fallback)
- Healthcheck: `pgrep -x oac-central` (process alive check — plain curl
  would fail TLS handshake with client cert required)
- Logging: `json-file`, max-size 10m, max-file 3

## Cert generation (`docker/generate-certs.sh`)

Uses openssl to generate:

1. **CA** — RSA 4096, SHA-256, 3650 days, `CA:TRUE`,
   `keyCertSign,cRLSign`.
2. **Server cert** — RSA 2048, 365 days, CN=`central`, SAN:
   `DNS:central,DNS:localhost,IP:127.0.0.1`.
3. **Client cert** — RSA 2048, 365 days, CN=`relay`, SAN:
   `DNS:relay,DNS:localhost,IP:127.0.0.1`.

Keys are set to `0600`. CSRs and `.srl` files are cleaned up.

## Mock backend (`docker/dev/mock-backend/app.py`)

Python Flask server, OpenAI-compatible:

- `GET /v1/models` → returns `mock-gpt-4` and `mock-gpt-4o`.
- `POST /v1/chat/completions` → supports `stream` field:
  - Non-streaming: returns `chat.completion` with content
    `"Mock response to: {user_msg}"`, usage `{prompt_tokens: 10,
    completion_tokens: 20, total_tokens: 30}`.
  - Streaming: returns `text/event-stream`, splits response into word
    chunks, terminates with `data: [DONE]`.
- `POST /v1/embeddings` → returns embedding `[0.1, 0.2, 0.3]`, model
  `mock-embedding`.

Listens on `0.0.0.0:8080`.

## Keycloak realm (`docker/dev/keycloak/realm-export.json`)

Realm `oac-dev`:

- `sslRequired: "none"`, `loginWithEmailAllowed: true`.
- Client `oac-relay`: `publicClient: false`, `secret: "oac-relay-secret"`,
  `redirectUris: ["http://127.0.0.1:*", "http://localhost:*"]`,
  `standardFlowEnabled: true`, `implicitFlowEnabled: false`,
  `directAccessGrantsEnabled: true`, `serviceAccountsEnabled: false`,
  `pkce.code.challenge.method: "S256"`.
- 4 test users: `alice`, `bob`, `charlie`, `admin` (see
  [Docker: Dev Stack](../user-guide/docker-dev.md#test-users)).
