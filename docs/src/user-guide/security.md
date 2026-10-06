# Security for Users

This page is a user-facing summary of the security properties of the OIDC
Agent Compatibility Server. For the full technical threat model, see
[Threat Model](../reference/threat-model.md). For a consolidated, ordered
set of deployment checks, see the
[Production Hardening Checklist](./production-checklist.md).

## Provider keys never touch your laptop

Provider API keys (e.g. an OpenAI API key) are encrypted at rest in the
central database and decrypted **only** in the central proxy's process
memory. They are:

- Never sent to any laptop.
- Never logged.
- Never in a config file or admin API response.
- Never in an error response.

The relay holds only a **central-minted opaque token** — a 256-bit random
value (`oac_` prefix) that is SHA-256 hashed at rest in central's database and
verified by the central proxy on every request. The relay is a dumb forwarder;
it does not verify tokens locally.

## OIDC authentication

You authenticate via the standard OIDC authorization-code + PKCE flow
against your enterprise IdP (Okta, Keycloak, etc.):

- **PKCE S256** (RFC 7636/9700) — prevents authorization code
  interception.
- **Loopback redirect** (RFC 8252) — the IdP redirects to
  `http://127.0.0.1:<random-port>/callback`, which only your local relay
  can receive.
- **Central validation** — the relay sends the one-time authorization code,
  PKCE verifier, redirect URI, and nonce to central over mTLS. Central performs
  the token exchange and verifies the ID token signature (alg pinned to RS256
  or ES256), issuer, audience, expiry, nonce, and `at_hash`.
- **No laptop client secret** — the relay is a public native client. The OIDC
  client secret is configured only on central.
- **No caller-claimed identity** — central ignores subject, issuer, email,
  group, and identity-ID fields supplied by callers. Policies use only claims
  obtained from central's validated IdP response.
- **Token lifetime** — central-minted tokens have a lifetime set by the
  `--ttl` flag on `oac-relay login` (e.g. `--ttl 1d`, `--ttl 1y`). Default:
  never expires. An admin can set `max_token_ttl_seconds` on group policies as
  a backstop that rejects tokens older than the limit at request time.

## mTLS between relay and central

All relay-to-central traffic is mutually authenticated with TLS 1.3 and a
company CA:

- The relay presents a client cert to the central proxy.
- The central proxy presents a server cert to the relay.
- Both are verified against the company CA.
- Private key files must have `0600` permissions.

> **⚠️ Production:** Use your **company PKI** to issue mTLS certificates.
> The `./docker/generate-certs.sh` script creates self-signed test certs
> (CN=`OAC Test CA`) — these are for dev/testing only and must not be used
> in a production deployment that handles real API keys.

## Token security

- **256-bit tokens** generated from the OS CSPRNG (`OsRng`) at central.
- **SHA-256 hashed at rest** — only the hash is stored in central's database,
  never the plaintext.
- **Constant-time comparison** — token verification uses
  `subtle::ConstantTimeEq` with no early return (prevents timing attacks,
  CWE-208).
- **Required in every mode** — central rejects missing or invalid bearer
  tokens even when local Docker development uses `dev_mode = true`.
- **`0600` file permissions** — the agent config file (containing the
  plaintext token) is readable only by you.
- **`Zeroizing` memory** — plaintext tokens are held in `Zeroizing` wrappers
  that zero memory on drop.

## DNS rebinding defense

The relay validates the `Host` header on every request. Only loopback
hosts (`127.0.0.1`, `localhost`, `[::1]`) are accepted. This prevents DNS
rebinding attacks where a malicious website could trick your browser into
sending requests to your local relay.

## Hop-by-hop header stripping

The relay and central proxy strip hop-by-hop headers (RFC 7230 §6.1) on
both requests and responses. This prevents connection-level header leakage
across proxy hops.

## Audit trail

Every request is logged in an **append-only** audit log:

- **Relay activity log** — records method, endpoint, model, central status,
  latency, request ID.
- **Central audit log** — records user subject, identity, email, groups,
  model, backend, endpoint, status, latency, stream flag, token usage,
  cost, permission decision, denial reason, request ID.

Both logs are enforced append-only at the database level (SQLite triggers
abort any UPDATE or DELETE).

## Group-based authorization

The central proxy enforces per-group policies:

- **Model allowlists** — restrict which models each group can use.
- **Endpoint restrictions** — restrict which API endpoints each group can
  access.
- **Daily quotas** — per-user daily token and request limits.

Policies are resolved by merging all policies for the user's groups, with
**most-permissive-wins** semantics.

## No `unsafe` code

All crates have `#![forbid(unsafe_code)]`. There is no `unsafe` code
anywhere in the project.

## Secret redaction in logs

All logs are structured JSON with a secret-redaction layer. Sensitive
fields (`authorization`, `api_key`, `client_secret`, `token`,
`master_key`, etc.) are automatically replaced with `[REDACTED]`.

## What you should do

- **Keep your laptop secure** — the central token in your agent config is
  only as safe as your laptop. Use disk encryption and screen lock.
- **Log out when done** — run `oac-relay logout` to revoke your token at
  central (`DELETE /v1/tokens/current`).
- **Don't share your agent config file** — `~/.codex/config.json` or
  `~/.oac/agent-env.sh` contains your central token.
- **Report suspicious activity** — check the audit log via the admin API
  if you suspect unauthorized use.
