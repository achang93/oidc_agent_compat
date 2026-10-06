# AGENTS.md — OIDC Agent Compatibility Server

Guidance for AI coding agents working in this repo. Read this file before
making any change. Keep it concise; link to existing docs rather than
duplicating them.

---

## What this project is

An enterprise OIDC-to-AI-agent forwarder. Employees run a thin **laptop
relay** (`oac-relay`) that authenticates them via OIDC and forwards agent
traffic over mTLS to a company-hosted **central proxy** (`oac-central`),
which manages encrypted provider keys and forwards to an OpenAI-compatible
backend. Provider keys never touch any laptop.

```
Agent → 127.0.0.1 relay → mTLS → central proxy → OpenAI-compatible backend
                                  ↑ encrypted provider keys (central DB)
```

See `README.md` for the user-facing overview and `docs/threat-model.md` for
the security design.

---

## Agent operating principles

These principles govern **every** change an agent makes in this repo. They
are non-negotiable.

### 1. Be responsible

- You are accountable for the correctness and safety of your changes.
  Review your own diff before committing as if a human reviewer would
  reject anything sloppy.
- Never disable a security control to make a test pass or unblock a build.
  If a test fails because of a security check, the code is wrong, not the
  check.
- Never commit secrets, credentials, tokens, or private keys. The repo is
  public-equivalent; assume anything you push will be read by an attacker.
- When in doubt about whether a change is safe, **stop and ask** rather
  than guessing. Security-sensitive areas (mTLS, OIDC, provider-key encryption,
  auth, key handling) warrant extra caution.
- Do not "fix" pre-existing advisories or policy files without explicit
  user approval (see [Known caveats](#known-caveats-do-not-fix-without-asking)).

### 2. Always work in a branch

- Create a dedicated branch from `master` before making any change:
  `git checkout -b <type>/<short-description>` (e.g. `feat/refresh-tokens`,
  `docs/redesign-agents-md`, `fix/relay-host-guard`).
- Keep branches focused — one logical change per branch. If a task spans
  multiple unrelated changes, split into separate branches and PRs.
- Never commit directly to `main` or `master`. Never force-push to shared
  branches.
- Squash-merge or rebase-merge into `master` when the work is complete and
  verified.
- **CI/CD is a hard gate before merge.** Never merge (or ask a human to
  merge) a branch into `master` until all CI checks on that branch pass:
  formatting, clippy, tests, release build, and `./docker/dev.sh test` (if
  Docker-relevant code changed). If CI is blocked on a pre-existing
  failure or an environment issue, say so explicitly in the merge summary
  rather than merging with red checks. Do not use "skip CI" or force
  workflows as a workaround.

### 3. Test comprehensively

- Run the full quality gate before considering work done:
  ```sh
  cargo fmt --all -- --check      # formatting clean (fix with: cargo fmt --all)
  cargo clippy --workspace --all-targets  # no warnings
  cargo test --workspace          # unit + integration + in-process e2e
  cargo build --release           # release build succeeds
  ```
- If you changed Docker-relevant code and Docker is available, also run:
  ```sh
  ./docker/dev.sh test            # full chain + SSE + provider-key-leak check
  ```
- If you changed documentation, run `mdbook build docs/` and confirm no
  warnings.
- Do not mark a task complete until every gate above passes. If a gate
  fails and you cannot fix it, report the failure honestly rather than
  claiming success.
- Write tests for new behavior. Security-critical code (auth, mTLS, key
  handling) must have negative-path tests (e.g. wrong cert, expired token,
  tampered ID token).

### 4. Update the documentation

Documentation is part of the deliverable, not an afterthought. When you
change behavior, update the relevant docs in the same branch and commit:

| Change type | Update |
|---|---|
| CLI flags / commands | `docs/src/user-guide/cli-reference.md` |
| Config schema / fields | `docs/src/user-guide/configuration.md` |
| Admin API endpoints | `docs/src/user-guide/admin-api.md` |
| MCP behavior / permissions | `docs/src/user-guide/mcp.md` |
| Architecture / data flow | `docs/src/developer-guide/README.md`, `docs/src/reference/architecture.md`, `docs/src/reference/data-flow.md` |
| Conventions / lints | `docs/src/developer-guide/conventions.md` |
| Crate internals | corresponding `docs/src/developer-guide/*-internals.md` |
| Threat model / security | `docs/src/reference/threat-model.md`, `docs/src/user-guide/security.md` |
| Docker dev stack | `docs/src/user-guide/docker-dev.md`, `docker/README.md` |
| Docker production | `docs/src/user-guide/docker-prod.md` |
| New mdBook page | add entry to `docs/src/SUMMARY.md` |

Preview the book while editing:

```sh
mdbook serve docs/ --open
```

Rust API type signatures are delegated to rustdoc (`cargo doc --workspace
--open`), not hand-maintained in the mdBook.

### 5. Follow industry standards

This project implements security-critical protocols. Adhere to the relevant
RFCs and standards; do not invent ad-hoc variants.

- **OIDC**: OIDC Core 1.0 (ID-token validation §3.1.3.7), OIDC Core 1.0
  errata, OAuth 2.0 (RFC 6749), OAuth 2.0 Security Best Practices
  (RFC 9700).
- **PKCE**: RFC 7636 (S256 mandatory), RFC 9700 §2.1.1 (reject plain).
- **Native apps / loopback redirect**: RFC 8252 (loopback redirect, any
  port).
- **mTLS**: RFC 8705 (mutual TLS), RFC 8446 (TLS 1.3).
- **HTTP forwarding**: RFC 7230 §6.1 (strip hop-by-hop headers), RFC 7239
  (`Forwarded` header semantics).
- **JWT**: RFC 7519 (JWT), RFC 7515 (JWS). Pin signing alg to
  `{RS256, ES256}`; reject `none`.
- **Secrets**: NIST SP 800-63B (authenticator handling), OWASP Cryptographic
  Storage Cheat Sheet. Provider encryption key and decrypted provider keys
  held in `Zeroizing` memory, never logged, never sent to a laptop.
- **Constant-time comparison** for secrets (RFC 6151 guidance).

See `/memories/repo/oidc-security-research.md` for the full citation list.

### 6. Commit discipline

- Make regular commits during coding tasks — don't wait until the end to
  commit everything at once. Each commit should be a coherent, reviewable
  unit.
- Commit messages **must** include a description (body), not just a subject.
  The body should explain what changed and why.
- Use Conventional Commits prefixes (`feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`, `security:`).

Example:

```
docs: add mdBook scaffolding and User Guide

Set up mdBook-based documentation suite with tree-based expandable
sidebar navigation. This commit adds:

- docs/book.toml: mdBook configuration
- docs/src/SUMMARY.md: sidebar tree (navigation entry point)
- docs/src/user-guide/: 12 pages covering overview, quickstart, ...

Content is sourced from exhaustive codebase exploration and covers
only implemented features (TODOs excluded to avoid misleading users).
```

---

## Workspace layout

Cargo workspace, edition 2024, resolver 2. Five members:

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC client, mTLS, logging, shutdown |
| `oac-mcp` | `crates/mcp` | MCP protocol types and parsing: JSON-RPC 2.0 parsing, tool-call extraction with redacted args previews, hub `server__tool` name handling |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib (lib exposed for integration tests) |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests (spins up mock backend + central + relay) |

**Documentation:** The project uses an [mdBook](https://rust-lang.github.io/mdBook/)
documentation suite under `docs/`. The sidebar tree (navigation entry point)
is `docs/src/SUMMARY.md`. To preview: `mdbook serve docs/ --open`. Three
sections: User Guide, Developer Guide, Reference. Rust API type signatures
are delegated to `cargo doc --workspace --open` (rustdoc), not hand-maintained
in the mdBook.

Key modules:

- `crates/common/src/config.rs` — `RelayConfig` / `CentralConfig` TOML schemas + validation (relay rejects `0.0.0.0`).
- `crates/common/src/error.rs` — unified `Error` enum + `Result` alias. Use this, not `anyhow`, in library code.
- `crates/common/src/keys.rs` — opaque token generation (256-bit CSPRNG, `oac_` prefix), SHA-256 hashing, constant-time compare, bearer extraction.
- `crates/common/src/oidc.rs` — OIDC RP client builder + `CustomAdditionalClaims` (groups/roles extraction).
- `crates/common/src/mtls.rs` — rustls mTLS client/server builders.
- `crates/relay/src/login.rs` — `oac-relay login`: browser + PKCE flow, loopback callback, secure grant handoff, agent config injection.
- `crates/relay/src/proxy/` — `mod.rs`, `auth.rs` (pass-through — checks Authorization header presence, does not verify), `forward.rs` (relay→central, forwards Authorization header unchanged), `host_guard.rs` (DNS rebinding defense), `mcp_forward.rs` (byte-tunnel for `/mcp` and `/mcp/{server}`).
- `crates/relay/src/keystore.rs` (OIDC identity storage only — `upsert_identity`; no key methods), `agent_config.rs`, `db.rs`, `migration.rs`, `entity/` — persistence + agent config injection.
- `crates/relay/src/activity.rs` — relay-side activity logger (append-only `relay_activity_log`).
- `crates/central/src/proxy/` — `mod.rs`, `auth.rs` (verifies bearer token via TokenStore — zero-trust), `tokens.rs` (token API: mint, revoke, list), `forward.rs` (central→backend, SSE streaming), `permissions.rs` (group-based model/endpoint enforcement), `rate_limit.rs`, `mcp_permissions.rs` (per-tool MCP allowlists), `mcp_hub.rs` (combined `/mcp` hub), `mcp_forward.rs` (per-server `/mcp/{server}` forwarding).
- `crates/central/src/mcp.rs` — MCP server registry; `auth_header` values AES-256-GCM encrypted at rest with the provider encryption key.
- `crates/central/src/admin.rs` — admin API (`/admin/v1/`) for policy/provider/device/audit/MCP management.
- `crates/central/src/proxy/tokens.rs` — token API (`POST /v1/tokens` mint, `DELETE /v1/tokens/current` revoke, `GET /v1/tokens` list).
- `crates/central/src/oidc_bootstrap.rs` — confidential-client code exchange, ID-token validation, and verified bootstrap identity extraction.
- `crates/central/src/policy.rs` — `PolicyStore` + `resolve_policy` (group→policy merge, most-permissive-wins).
- `crates/central/src/device_store.rs` — device registration + revocation store.
- `crates/central/src/provider.rs` — runtime provider/key store; provider keys are AES-256-GCM encrypted at rest with the configured MEK.
- `crates/central/src/audit.rs` — audit logger (enriched with identity, groups, endpoint, request-id, permission decision, token-saver accounting).
- `crates/central/src/optimizer.rs` — the safe, admin-controlled token saver: a pure module that dedupes exact-verbatim messages, removes structurally-empty messages/`tools`, drops oldest whole turns under a budget, and (opt-in via `collapse_repeated_lines`) collapses consecutive exact-verbatim repeated lines inside a single message into `[×N]` markers (RTK-adapted, lossless-by-construction). **Never rewrites kept content except for the opt-in repeated-line collapse.** Driven by `TokenSaverConfig` from the resolved policy; gated server-side only.
- `crates/central/src/token_store.rs` — central token store (zero-trust): mint, verify, revoke, list opaque bearer tokens with constant-time hash comparison.
- `crates/central/src/db.rs`, `migration.rs`, `entity/` — central persistence.

---

## Build, test, lint

```sh
cargo fmt --all -- --check      # fix with: cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace          # full suite: unit + integration + in-process e2e
cargo build --release
```

Rust toolchain is pinned via `rust-toolchain.toml` (channel 1.98 +
rustfmt + clippy, matching the `rust:1.98-slim` Docker builders).
Minimum Rust 1.85; edition 2024.

### Known caveats (do not "fix" without asking)

- `cargo audit` flags 2 **pre-existing** transitive advisories (`rsa 0.9.10`,
  `rustls-pemfile 2.2.0`) — not our code, no fix available.
- `cargo deny check` uses the array form for `allow-build-scripts` in
  `deny.toml` (compatible with cargo-deny 0.20.2). Do not change this to
  `allow-build-scripts = true` (the boolean form is incompatible with
  cargo-deny 0.20.2) or loosen the build-script policy without explicit
  user approval.

---

## Conventions (enforced by workspace lints)

- `#![forbid(unsafe_code)]` in every crate. No `unsafe` anywhere.
- Workspace clippy lints set to warn: `unwrap_used`, `expect_used`, `panic`,
  `indexing_slicing`, `todo`, `dbg_macro`. Use `?`, `get()`/`get_mut()`, and
  explicit error variants instead. Tests `#![allow]` these for brevity.
- `missing_docs` is warn — document public items.
- Library code returns `oidc_agent_common::error::Result` (thiserror-based
  `Error` enum). Reserve `anyhow` for binary `main` glue if needed.
- Secrets are never literals in config: central references the OIDC client
  secret by env-var name (`client_secret_env`), while the public native relay
  never receives it; provider API keys are managed through
  the admin API and encrypted at rest. Provider keys are held in
  `Zeroizing` memory during forwarding, never logged, never sent to a
  laptop.
- Logging is structured JSON via `tracing`/`tracing-subscriber` with a
  secret-redaction layer (`crates/common/src/logging.rs`). Never log raw
  keys/tokens.
- Hop-by-hop headers are stripped (RFC 7230 §6.1); host header is validated
  (DNS rebinding defense) in the relay.

See `docs/src/developer-guide/conventions.md` for the full convention
reference.

---

## OIDC login flow (security-critical)

`crates/relay/src/login.rs` owns the browser, loopback callback, PKCE, and
state check; `crates/central/src/oidc_bootstrap.rs` owns the confidential
code exchange and authorization-relevant claim validation. When editing,
follow RFC 8252 (loopback redirect, any port), RFC 7636/9700 (PKCE S256
mandatory), and OIDC Core §3.1.3.7 (ID-token validation). The ID-token alg is
pinned to {RS256, ES256}; `none` is disallowed. `state` is verified by the
relay; `nonce` and `at_hash` are verified by central. See
`/memories/repo/oidc-security-research.md` for the full RFC citation list.

Manual verification: run `oac-relay login` on the **host** against dev
Keycloak using `docker/dev/configs/relay-login-test.toml` (`dev_mode=true`,
port 8788). The containerized relay cannot do login (no host browser /
loopback callback).

---

## Docker dev stack

Everything runs in Docker; Goose runs headless in a container.

```sh
./docker/dev.sh up|down|status|logs|shell|goose|goose-run|test
```

- Central proxy serves **mTLS on :8443** in production mode (`dev_mode=false`),
  using `axum_server::bind_rustls` with client cert required. In dev mode
  (`dev_mode=true`), it serves plain HTTP for the containerized dev stack.
  Never probe a prod central proxy over plain HTTP.
- Relay is a dumb forwarder — it does not auto-mint a dev key. `docker/dev.sh`
  mints a dev token via `POST /v1/tokens` at central after the stack starts, then
  writes it to the Goose agent config.
- `dev.sh test` exercises the full chain + SSE + provider-key-leak check.
- Mock provider key `sk-mock-backend-master-key` is registered at runtime by
  `docker/dev.sh` `cmd_up()` via the admin API (`POST /admin/v1/providers` +
  `POST /admin/v1/providers/mock-backend/keys`) using the dev token for
  bearer auth. It must never appear in relay responses.
- Dockerfile runtime base **must be `debian:trixie-slim`** (not
  `bookworm-slim`) to match the `rust:1.98-slim` builder's glibc 2.41.
- Keycloak realm `oac-dev` allows `http://127.0.0.1:*` and
  `http://localhost:*` (any port) for client `oac-relay`. Test users:
  `alice`/`alice-pass-123`, `bob`/`bob-pass-456`,
  `charlie`/`charlie-pass-789`, `admin`/`admin-pass-000`.

See `docker/README.md` for the full service table and quick start.

---

## Out of scope (deferred features — don't assume implemented)

- External KMS backends for the provider encryption key.
- Distributed Redis-backed rate limiting for horizontally scaled central
  instances (the current limiter is in-memory per IP).
- Refresh-token handling: v1 intentionally stores no OIDC refresh tokens;
  central-minted tokens expire according to the `--ttl` flag (default: never
  expires), clamped by the admin `max_token_ttl_seconds` backstop.

---

## Definition of done

A change is complete only when **all** of the following are true:

- [ ] Work was done on a dedicated branch (not `main`/`master`).
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --workspace --all-targets` is warning-free.
- [ ] `cargo test --workspace` passes (unit + integration + e2e).
- [ ] `cargo build --release` succeeds.
- [ ] No secrets, keys, or tokens in the diff.
- [ ] No `unsafe` code added.
- [ ] No `unwrap()` / `expect()` / `panic!()` in library code.
- [ ] Public items have doc comments.
- [ ] New behavior has tests (including negative paths for security code).
- [ ] Documentation updated for any user-facing or architectural change.
- [ ] `mdbook build docs/` is warning-free (if docs changed).
- [ ] Commits are regular, focused, and include a descriptive body.
- [ ] PR is ready for review (or a clear summary of remaining work if
      blocked).
