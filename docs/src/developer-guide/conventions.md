# Conventions

These conventions are enforced by workspace lints and code review.

## `#![forbid(unsafe_code)]`

Every crate has `#![forbid(unsafe_code)]` at the crate root. There is no
`unsafe` code anywhere in the project. This is non-negotiable.

## Clippy lints

Workspace clippy lints (set to `warn`):

| Lint | What to do instead |
|---|---|
| `unwrap_used` | Use `?`, `match`, or `ok_or_else` |
| `expect_used` | Use `?` or explicit error variants |
| `panic` | Return an `Error` variant |
| `indexing_slicing` | Use `.get()` / `.get_mut()` |
| `todo` | Implement it or return `Error::Internal` |
| `dbg_macro` | Remove it |

Tests `#![allow]` these for brevity (test code may use `unwrap`/`expect`).

## `missing_docs`

All public items must have doc comments (`///`). This is set to `warn` at
the workspace level.

## Error handling

Library code returns `oidc_agent_common::error::Result<T>`, which is
`std::result::Result<T, oidc_agent_common::error::Error>`. The `Error`
enum is `thiserror`-based and wraps every error kind across both
components:

```rust
pub enum Error {
    Config(String),
    Oidc(String),
    Database(String),
    Db(sea_orm::DbErr),
    Http(String),
    Reqwest(reqwest::Error),
    Crypto(String),
    Tls(String),
    // Provider-key encryption failures are represented as Crypto errors.
    Auth(String),
    Forbidden(String),
    Io(std::io::Error),
    Serde(serde_json::Error),
    Internal(String),
}
```

Reserve `anyhow` for binary `main` glue if needed. Library code should
never use `anyhow`.

## Secrets

- **Never literal in config**: central references the OIDC client secret by
  env-var name (`client_secret_env`); the relay is a public native client and
  never receives that secret. Provider API keys are managed through the admin
  API and encrypted in the central database; MCP server
  `auth_header` values are likewise admin-API-managed and AES-256-GCM
  encrypted at rest with the provider encryption key.
- **`Zeroizing` memory**: provider keys and decrypted MCP auth headers are
  held in `zeroize::Zeroizing<String>`, which zeros memory on drop.
- **Never logged**: the logging layer (`crates/common/src/logging.rs`)
  redacts sensitive fields (`authorization`, `api_key`, `client_secret`,
  `token`, `master_key`, etc.) to `[REDACTED]`.
- **Never sent to a laptop**: provider keys are only decrypted in central
  proxy memory; the relay never sees them.

## Logging

Structured JSON via `tracing` / `tracing-subscriber`:

- `oidc_agent_common::logging::init()` sets up the global subscriber.
- JSON layer + `EnvFilter` (default `info`).
- `RedactingMakeWriter` wraps stdout and redacts sensitive fields at the
  writer level.

Never log raw keys, tokens, or secrets. The redaction layer is a safety
net, not a license to log secrets.

## File permissions

On Unix, security-sensitive files must have `0600` permissions:

- SQLite database files (relay and central) — enforced by
  `persistence::enforce_db_perms`.
- Agent config file (`~/.codex/config.json` or `~/.oac/agent-env.sh`) —
  enforced by `agent_config::inject`.
- mTLS private key files — enforced by `mtls::enforce_secure_perms`.
- Provider encryption key source — `OAC_PROVIDER_ENCRYPTION_KEY` or the
  Docker secret at `/run/secrets/provider-encryption-key`.

## HTTP forwarding

- **Hop-by-hop headers** are stripped on both requests and responses
  (RFC 7230 §6.1). See `http_util::HOP_BY_HOP_HEADERS`.
- **Forwardable headers** use an allowlist model
  (`http_util::FORWARDABLE_HEADERS`). `Authorization` is intentionally NOT
  forwarded — it is replaced by upstream auth.
- **Path sanitization**: `http_util::sanitize_path` rejects `..`, `//`,
  `\`, and absolute URLs (SSRF defense).
- **`content-length`** is stripped from responses (Axum recomputes it;
  the upstream value is wrong for streaming).

## Identity headers

The relay sets only the `x-oac-request-id` header (per-request
correlation). It forwards the agent's `Authorization` header unchanged —
it does not inject identity headers. Central extracts identity from the
token record (zero-trust). The other `X-OAC-*` header constants still
exist for backward compatibility but are not set by the relay.

Header constants are in `oidc_agent_common::identity`:

| Header | Constant |
|---|---|
| `x-oac-request-id` | `HEADER_REQUEST_ID` (actively used — per-request correlation) |
| `x-oac-user-subject` | `HEADER_USER_SUBJECT` (unused — central extracts identity from token) |
| `x-oac-user-email` | `HEADER_USER_EMAIL` (unused) |
| `x-oac-user-groups` | `HEADER_USER_GROUPS` (unused) |
| `x-oac-identity-id` | `HEADER_IDENTITY_ID` (unused) |

## Append-only logs

The relay activity log and central audit log are enforced append-only at
the database level via SQLite triggers:

```sql
CREATE TRIGGER relay_activity_log_no_update
BEFORE UPDATE ON relay_activity_log
BEGIN
    SELECT RAISE(ABORT, 'relay_activity_log is append-only');
END;

CREATE TRIGGER relay_activity_log_no_delete
BEFORE DELETE ON relay_activity_log
BEGIN
    SELECT RAISE(ABORT, 'relay_activity_log is append-only');
END;
```

Same pattern for `audit_log` and `admin_audit_log` on the central side.

## Commit conventions

- Make regular commits during coding tasks.
- Commit messages should include a description (body), not just a
  subject.
- See [Contributing](./contributing.md) for the full PR checklist.
