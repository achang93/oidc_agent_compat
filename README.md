# OIDC Agent Compatibility Server

An enterprise-grade OIDC-to-AI-agent forwarder that lets employees use any
OpenAI-compatible AI agent (Codex, Goose, etc.) through company-approved
backends — **without provider API keys ever touching an employee's
laptop**.

## Architecture

```
Agent → [127.0.0.1 relay] → mTLS → [central proxy] → [OpenAI-compatible backend]
                                   ↑ encrypted provider keys (central DB)
```

- **Central proxy** (company-hosted) — manages encrypted provider keys,
  enforces group policies and quotas, and forwards approved requests to
  the AI backend with SSE streaming. Trusts the relay-verified employee
  identity forwarded over mTLS (the relay is the OIDC relying party).
- **Laptop relay** (thin, per-employee) — listens on `127.0.0.1`,
  authenticates the employee via OIDC, relays agent traffic to the central
  proxy over mTLS. Holds **no provider API keys**.

## Documentation

Full documentation is in the [`docs/`](docs/) mdBook. To preview it:

```sh
cargo install mdbook   # one-time
mdbook serve docs/ --open
```

Or read the source files directly:

- **[User Guide](docs/src/user-guide/README.md)** — setup, configuration,
  CLI, Docker deployment, troubleshooting.
- **[Developer Guide](docs/src/developer-guide/README.md)** — architecture,
  internals, conventions, testing, contributing.
- **[Reference](docs/src/reference/architecture.md)** — system diagrams,
  threat model, request data flow.

**New here?** Start with the
[Quickstart](docs/src/user-guide/quickstart.md).

**Prefer downloads over building?** Every release publishes prebuilt,
binaries-only `.zip` archives for macOS (Apple Silicon), Linux (x86_64 +
ARM64), and Windows (x86_64) on the
[**GitHub Releases**](https://github.com/Isaac-To/oidc_agent_compat/releases)
page. See [Installation](docs/src/user-guide/installation.md#download-prebuilt-binaries).

For full Rust API type signatures, run `cargo doc --workspace --open`.

## Quickstart

Production setup in 7 steps (central proxy in Docker + relay on laptop):

```sh
# 1. Generate mTLS certs (use your company PKI for real production):
./docker/generate-certs.sh   # ⚠️ self-signed test certs — dev only
mkdir -p docker/prod/certs   # gitignored, create it first
cp docker/certs/{ca,server,client}.{crt,key} docker/prod/certs/

# 2. Configure the central proxy:
#    Edit docker/prod/configs/central.toml — set issuer and TLS settings
#    for your environment.

# 3. Provide secrets:
echo "OAC_OIDC_CLIENT_SECRET=your-secret" > docker/prod/.env
openssl rand -hex 32 | docker secret create oac_provider_encryption_key -
# ⚠️ `docker secret create` requires Swarm; without it, edit
# docker/prod/docker-compose.yml to use a `file:` secret source instead
# (see docs/src/user-guide/docker-prod.md).

# 4. Deploy the central proxy:
cd docker/prod && docker compose up -d --build

# 5. Install the relay on a laptop:
cargo build --release -p oac-relay
cp target/release/oac-relay /usr/local/bin/oac-relay
cp docker/prod/configs/relay.toml ~/.oac/relay.toml
# Copy ca.crt, client.crt, client.key to ~/.oac/certs/

# 6. Log in and start the relay (the client secret remains on central):
oac-relay --config ~/.oac/relay.toml login
oac-relay --config ~/.oac/relay.toml serve

# 7. Make a request:
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  http://127.0.0.1:8787/v1/models
```

See [Quickstart](docs/src/user-guide/quickstart.md) for the full
walkthrough. For the dev stack (bundled Keycloak + mock backend), see
[Docker: Dev Stack](docs/src/user-guide/docker-dev.md).

## Development

```sh
cargo test --workspace          # all tests
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo build --release
```

See [Build, Test & Lint](docs/src/developer-guide/build-test-lint.md) for
details.

