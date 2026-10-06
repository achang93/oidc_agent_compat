# Docker: Dev Stack

The dev stack runs the entire system in Docker: Keycloak (IdP), mock
backend, central proxy, relay, and Goose (AI agent). It's the fastest way
to get a working end-to-end setup.

## Architecture

```
Goose (Docker) → relay (Docker, :8787) → central (Docker, :8443) → mock-backend (Docker, :8080)
                                       ↑ encrypted provider key (dev secret)
                    ↑ OIDC (browser)
              Keycloak (Docker, :8080)
```

(Ports shown are the in-network container ports. The mock backend is
published to the host on `localhost:8090`; the relay is published on
`127.0.0.1:8787`.)

## Services

| Service | Container | Port | Description |
|---|---|---|---|
| Keycloak | `keycloak` | `localhost:8080` | OIDC IdP with pre-configured realm `oac-dev` |
| Mock backend | `mock-backend` | `localhost:8090` | OpenAI-compatible Flask server |
| Central proxy | `central` | `localhost:8443` | Resolves the encrypted mock provider key, forwards to mock-backend |
| Relay | `relay` | `127.0.0.1:8787` | Forwards to central; Goose connects here |
| Goose | `goose` | — | AI agent (headless CLI, connects to relay) |

## Test users

All users are in the `oac-dev` Keycloak realm:

| Username | Password | Email | Last name |
|---|---|---|---|
| `alice` | `alice-pass-123` | alice@example.com | Engineer |
| `bob` | `bob-pass-456` | bob@example.com | Senior |
| `charlie` | `charlie-pass-789` | charlie@example.com | Intern |
| `admin` | `admin-pass-000` | admin@example.com | User |

> The dev realm defines **no groups or roles** — the last-name column is
> just profile data. Group-based policies cannot be exercised through real
> OIDC logins in this stack; `dev.sh` performs admin operations directly
> with a token minted by central's dev-mode-only local `dev-token` command.

Keycloak admin console: `http://localhost:8080/admin` (admin / admin).

## Commands

The `docker/dev.sh` script orchestrates the dev stack:

| Command | Description |
|---|---|
| `./docker/dev.sh up` | Generate certs (if missing), build and start all containers, wait for healthchecks, register the mock provider + its key via the admin API, print service URLs + test users |
| `./docker/dev.sh down` | Stop all containers |
| `./docker/dev.sh status` | Show container status |
| `./docker/dev.sh logs` | Tail logs from all services |
| `./docker/dev.sh shell` | Open a shell in the relay container |
| `./docker/dev.sh goose` | Show Goose usage info |
| `./docker/dev.sh goose-run "prompt"` | Run a headless Goose prompt through the full chain |
| `./docker/dev.sh test` | Send test requests through the full chain (infra + full chain + SSE + provider-key-leak check) |

## Quick start

```sh
# Start everything:
./docker/dev.sh up

# Run a Goose prompt:
./docker/dev.sh goose-run "Hello from Goose!"

# Run the test suite:
./docker/dev.sh test

# Interactive Goose session:
docker compose -f docker/dev/docker-compose.yml run --rm goose session
```

## Manual requests

`docker/dev.sh up` executes central's hidden, dev-mode-only `dev-token`
command inside the central container after the stack starts, then writes the
result to `/tmp/oac-dev-token`. The public HTTP token endpoint never accepts
caller-supplied identity claims. Central requires a valid bearer even in dev
mode. Use the token for manual curl:

```sh
# List models:
curl -H 'Authorization: Bearer $DEV_TOKEN' \
  http://127.0.0.1:8787/v1/models

# Chat completion (non-streaming):
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H 'Authorization: Bearer $DEV_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'

# Chat completion (SSE streaming):
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H 'Authorization: Bearer $DEV_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}],"stream":true}'
```

## Direct mock-backend access

```sh
curl http://localhost:8090/v1/models
curl -X POST http://localhost:8090/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## OIDC login (real auth flow)

The containerized relay can't open a host browser or receive a loopback
callback, so to test the real OIDC login flow, run the relay binary **on
the host** against the dev Keycloak:

```sh
# Build the relay:
cargo build --release -p oac-relay

# Run login (the relay needs no OIDC client secret):
./target/release/oac-relay \
  --config docker/dev/configs/relay-login-test.toml login
```

A browser opens to the Keycloak login page. Sign in as a test user. The
relay passes the one-time authorization code and PKCE verifier to central via
`POST /v1/tokens`. Central exchanges the code, validates the ID token and
userinfo, then returns a central-minted token for injection into
`~/.oac/agent-env.sh`.

The login-test config uses `dev_mode = true`, a separate SQLite DB
(`/tmp/oac-relay-login-test.db`), and listens on `127.0.0.1:8788` to
avoid port conflicts with the Docker relay on `:8787`.

## Admin API

The dev central config enables the admin API with
`admin_group = "oac-admins"`. The dev Keycloak realm defines no groups, so
no real login can satisfy that check — instead, `dev.sh up` invokes the
dev-mode-only `oac-central dev-token` command through container-local database
access with the `oac-admins` group, then uses it as a bearer token for admin
API calls to register the mock provider and its key.
To exercise group-based admin access end-to-end, add groups and a group
mapper to the realm first.

For reference, the admin CLI form (against a stack where your login's
groups include the admin group — note `--key` precedes the subcommand):

```sh
export OAC_API_KEY="<key from oac-relay login>"
./target/release/oac-central admin --key $OAC_API_KEY policy-list
./target/release/oac-central admin --key $OAC_API_KEY policy-set engineering --models gpt-4o
./target/release/oac-central admin --key $OAC_API_KEY audit-query
```

In the stock dev stack, `dev.sh` uses the central container's local
dev-mode-only command to mint the token with the `oac-admins` group, so admin
API calls succeed without weakening the HTTP bootstrap endpoint.

See [Admin API](./admin-api.md) for all endpoints.

## `dev.sh test` scenarios

The test command verifies:

1. Relay healthz → 200.
2. Central healthz → 200.
3. Mock backend `/v1/models` → 200.
4. Relay `/v1/models` without Authorization → 401.
5. Relay `/v1/models` with invalid token → 401.
6. Relay with non-loopback Host header → 400 (DNS rebinding defense).
7. Full chain `GET /v1/models` with dev token → 200, contains `mock-gpt-4`.
8. Full chain `POST /v1/chat/completions` (non-streaming) → 200, contains
   `Mock response to: hello`.
9. Full chain `POST /v1/chat/completions` (SSE streaming) →
   `content-type: text/event-stream` and `data: [DONE]` terminator.
10. Provider key leak check: the relay's `/v1/models` response body must
    NOT contain `sk-mock-backend-master-key`.

## Files

```
docker/
├── dev.sh                    # Orchestration script
├── generate-certs.sh         # Generates mTLS CA + server + client certs
├── certs/                    # Generated certs (gitignored)
└── dev/
    ├── docker-compose.yml     # Keycloak + mock-backend + central + relay + goose
    ├── Dockerfile             # Builds oac-central + oac-relay binaries
    ├── configs/
    │   ├── central.toml
    │   ├── relay.toml
    │   └── relay-login-test.toml
    ├── keycloak/
    │   └── realm-export.json  # Pre-configured realm with 4 test users
    ├── mock-backend/
    │   ├── Dockerfile         # Python Flask image
    │   └── app.py            # OpenAI-compatible mock API
    └── workspace/             # Goose working directory
```
