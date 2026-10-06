# System Architecture

## System overview

```
Agent (Codex, Goose, etc.)
  │  Authorization: Bearer *** token>
  ▼
[127.0.0.1 relay]  ── mTLS (TLS 1.3) ──►  [central proxy]  ──►  [OpenAI-compatible backend]
  │                                        │
  │ OIDC (browser, auth-code + PKCE)       │ encrypted provider keys
  ▼                                        │
[Enterprise IdP]                           ▼
                                  [Audit log (append-only)]
```

## Components

| Component | Where it runs | Role |
|---|---|---|
| Agent | Employee laptop | Sends OpenAI-compatible API requests to `127.0.0.1:8787/v1` or MCP JSON-RPC to `127.0.0.1:8787/mcp/{server}` |
| Relay (`oac-relay`) | Employee laptop | Starts OIDC auth-code + PKCE as a public native client, hands the one-time grant to central, and forwards agent traffic over mTLS |
| Central proxy (`oac-central`) | Company-hosted server | Holds the OIDC client secret, exchanges login codes, validates identity and groups, manages encrypted provider keys, enforces policies and quotas, and forwards backend/MCP traffic |
| IdP | Company infrastructure | Authenticates employees via OIDC auth-code + PKCE |
| Backend | External | OpenAI-compatible API called with a selected provider key |
| MCP servers | Company/centrally-hosted | Exposed tools called by agents through central (per-server, per-tool policy) |

## Trust boundaries

1. **Agent → relay** (loopback HTTP — same host, low trust).
2. **Relay → central proxy** (mTLS over network — medium trust).
3. **Central proxy → backend** (HTTPS — external, low trust).
4. **Relay/central → IdP** (OIDC — external, low trust).
5. **Central proxy → MCP servers** (HTTPS — external, medium trust) — policy
   enforcement happens on central before this hop.

## Assets

| Asset | Location | Sensitivity |
|---|---|---|
| Provider API keys | Central DB ciphertext → `Zeroizing` memory during forwarding | **CRITICAL** — never on laptop |
| MCP server auth headers | Central DB ciphertext (`mcp_servers`) → `Zeroizing` memory during forwarding | **CRITICAL** — never on laptop, never returned by any API |
| Central-minted tokens (plaintext) | Agent config file (`0600`) | Medium — loopback-only, revocable at central |
| Token hashes | Central DB | Low — SHA-256 hashes, constant-time compare |
| OIDC authorization codes, PKCE verifiers, ID/access tokens | In transit only between relay, central, and IdP; never stored | Medium — short-lived; never logged |
| User identity (subject, email) | Relay + central DB, audit log | Medium — PII |
| Audit log | Central DB (append-only) | Medium — tamper-evident |

## Crate map

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC, mTLS, logging, HTTP utilities |
| `oac-mcp` | `crates/mcp` | MCP/JSON-RPC protocol types and parsing (tool-call extraction, redacted previews, hub name handling) |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests |

See [Workspace Layout](../developer-guide/workspace-layout.md) for the full
file tree.

## Related

- [Threat Model](./threat-model.md) — STRIDE analysis.
- [Request Data Flow](./data-flow.md) — request lifecycle with header
  table.
- [Developer Guide: Architecture](../developer-guide/README.md).
