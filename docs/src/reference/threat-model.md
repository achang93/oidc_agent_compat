# Threat Model

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege).

**Scope:** v1 MVP — relay (laptop), central proxy (company-hosted), and
the communication channels between them, the IdP, the backend, MCP
servers, and the agent.

## System overview

```
Agent (Codex, etc.)
  │  Authorization: Bearer *** token>
  ▼
[127.0.0.1 relay]  ── mTLS (TLS 1.3) ──►  [central proxy]  ──►  [OpenAI-compatible backend]
  │                                        │
  │ OIDC (browser, auth-code + PKCE)       │ encrypted provider keys
  ▼                                        │
[Enterprise IdP]                           ▼
                                  [Audit log (append-only)]
```

**Trust boundaries:**

1. Agent → relay (loopback HTTP — same host, low trust).
2. Relay → central proxy (mTLS over network — medium trust).
3. Central proxy → backend (HTTPS — external, low trust).
4. Relay/central → IdP (OIDC — external, low trust).
5. Central proxy → MCP servers (HTTPS — external, medium trust);
   per-tool policy enforcement happens on central before this hop.

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

## STRIDE analysis

### S — Spoofing

| Threat | Control | Status |
|---|---|---|
| Attacker spoofs a central token | 256-bit `OsRng` token, SHA-256 hash, constant-time compare (`subtle::ConstantTimeEq`), central DB lookup | ✅ Implemented |
| Attacker spoofs the relay to the central proxy | mTLS with company CA (client cert required) | ✅ Implemented |
| Attacker spoofs the IdP | OIDC discovery + JWKS signature verification + alg pin {RS256, ES256} | ✅ Implemented |
| Attacker spoofs the central proxy to the relay | mTLS with company CA (server cert verification) | ✅ Implemented |
| Attacker spoofs the user identity to the central proxy | Initial bootstrap identity is derived by central from its own authorization-code exchange and ID-token/userinfo validation; later requests use the central token record; caller identity fields and `X-OAC-*` identity headers are ignored | ✅ Implemented |
| Attacker spoofs the Host header (DNS rebinding) | Host header validation middleware (loopback only) | ✅ Implemented |
| Attacker spoofs the OIDC redirect (mix-up) | `state` (CSRF) + `nonce` (replay) + loopback redirect only | ✅ Implemented |
| Stolen or replayed authorization code is exchanged | PKCE S256 binds the one-time code to the verifier; central supplies the exact loopback redirect URI and consumes the code at the IdP token endpoint | ✅ Implemented |

### T — Tampering

| Threat | Control | Status |
|---|---|---|
| Attacker tampers with the request in transit (relay → central) | mTLS (TLS 1.3 integrity) | ✅ Implemented |
| Attacker tampers with the audit log | Append-only triggers (SQLite `BEFORE UPDATE/DELETE` → `RAISE(ABORT)`) | ✅ Implemented |
| Attacker tampers with the central token store | Parameterized SQL (no injection); relay no longer stores key hashes | ✅ Implemented |
| Attacker tampers with the agent config file | `0600` permissions, written by relay only | ✅ Implemented |
| Attacker tampers with the request path (SSRF/path traversal) | Path sanitization (rejects `..`, `//`, `\`, absolute URLs) | ✅ Implemented |

### R — Repudiation

| Threat | Control | Status |
|---|---|---|
| User denies making a request | Audit log records user subject, model, status, latency, tokens | ✅ Implemented |
| Attacker deletes/modifies audit entries | Append-only DB triggers | ✅ Implemented |
| Attacker forges audit entries | Parameterized SQL, server-side only (no client API to write audit) | ✅ Implemented |

### I — Information Disclosure

| Threat | Control | Status |
|---|---|---|
| Provider key leaks to laptop | Provider key never leaves central proxy process; relay never sees it | ✅ By design |
| Provider key leaks in logs/responses | `Zeroizing` memory, never logged, never in error responses, redaction layer | ✅ Implemented |
| Provider key leaks in relay response | E2E + dev-stack tests verify the provider key is not in relay responses | ✅ Tested |
| Token leaks to other local users | `0600` on agent config file (relay no longer stores hashes) | ✅ Implemented |
| Token leaks in logs | Never logged; `Zeroizing` wrapper; secret redaction layer | ✅ Implemented |
| PII (email, subject) leaks in logs | Structured logging, no body logging, redaction layer | ✅ Implemented |
| Secrets in MCP tool-call arguments leak into audit log | `redact_args` replaces values for known-sensitive keys (`api_key`, `token`, `password`, `secret`, etc.) with `[REDACTED]` before serialization, then truncates to 512 chars as a second line of defense | ✅ Implemented |
| Hop-by-hop header leakage | RFC 7230 §6.1 hop-by-hop stripping on forward + response | ✅ Implemented |
| ID token alg downgrade (`none`/HS*) | Alg pin {RS256, ES256} before signature verification | ✅ Implemented |

### D — Denial of Service

| Threat | Control | Status |
|---|---|---|
| Large request body exhausts memory | 10 MB body limit (`RequestBodyLimitLayer`) | ✅ Implemented |
| Slow client ties up connections | Connect timeout (10s) + request timeout (300s) | ✅ Implemented |
| OIDC callback hangs forever | 5-minute callback timeout | ✅ Implemented |
| Attacker floods relay with requests | Loopback-only binding (not network-accessible) | ✅ Implemented |
| Attacker floods central proxy | Per-IP token-bucket rate limiter (60 req/min default, production only) | ✅ Implemented |
| Rate-limiter memory grows unbounded from unique IPs | Amortized eviction: every 128th request sweeps buckets idle for ≥10 window periods | ✅ Implemented |

### E — Elevation of Privilege

| Threat | Control | Status |
|---|---|---|
| Unauthenticated user accesses relay | Auth middleware (401 without Authorization header; central verifies token) | ✅ Implemented |
| Unauthenticated request reaches backend | Central auth middleware requires a valid TokenStore bearer in every mode, including `dev_mode` | ✅ Implemented |
| Attacker bypasses auth via healthz | `/healthz` exempt from auth (returns only "ok", no data) | ✅ Implemented |
| Attacker uses revoked token | Token row deleted on logout/revoke; `verify_token` checks current tokens only | ✅ Implemented |
| Attacker exploits `unsafe` code | `#![forbid(unsafe_code)]` across all crates | ✅ Implemented |
| Authenticated user calls disallowed model | Permissions middleware enforces group-based model allowlists (403) | ✅ Implemented |
| Authenticated user calls disallowed endpoint | Permissions middleware enforces group-based endpoint restrictions (403) | ✅ Implemented |
| Authenticated user exceeds quota | Per-user daily request and token quotas enforced pre-flight against accumulated daily usage (429) | ✅ Implemented (a request may overshoot by its own completed usage) |
| Attacker spoofs group membership | Central ignores request-body group fields and stores only groups from its validated ID token or subject-bound TLS userinfo response | ✅ Implemented |
| Admin API accessed without authorization | Admin auth middleware verifies bearer token via TokenStore, checks group membership from token record; 403 if not in admin group | ✅ Implemented |
| Admin API mutations go unlogged | All mutations recorded in append-only `admin_audit_log` | ✅ Implemented |
| Revoked device continues to access | Devices auto-register on first verified request; revocation checked in `permissions_middleware` (uses `identity_id` or `subject` as device ID) | ✅ Implemented |
| Expired token continues to access | Central-minted tokens expire per `--ttl` flag (default: never); admin `max_token_ttl_seconds` backstop rejects old tokens at request time; expired rows deleted | ✅ Implemented |
| MCP `tools/call` bypasses per-tool policy via JSON-RPC batch | Batches (arrays) are rejected at the proxy boundary with `BatchUnsupported`; per-server endpoint returns 403, hub returns `-32600` | ✅ Implemented |
| MCP `tools/call` to denied tool via per-server endpoint | `mcp_permissions` middleware enforces per-tool allowlist (403 on denial, fail-closed on policy-store errors) | ✅ Implemented |
| MCP `tools/call` to denied tool via hub endpoint | Hub splits prefixed tool name, enforces policy inline, routes only to allowed servers | ✅ Implemented |

## Token-saver trust model

The token-saver is a safe, admin-controlled request optimizer on the central
proxy. Its threat model deliberately *accepts* a small, well-defined content
risk rather than pretending it can "understand" requests:

| Behaviour | Control / rationale | Status |
|---|---|---|
| Saver enabled/disables & budget scope | Admin-only, per-group via the admin API; resolved server-side from the policy store (never client-controlled) | ✅ Implemented |
| Exact-verbatim duplicate messages removed | Only *bit-identical* duplicates removed; cannot drop information not already present verbatim | ✅ Implemented (lossless) |
| Structurally-empty messages removed | Only empty-string `content` removed; contributes nothing to the backend | ✅ Implemented (lossless) |
| Empty `tools: []` removed | Empty definition list; no behavioural change | ✅ Implemented (lossless) |
| Oldest whole turns dropped under budget | The single acknowledged case where content is dropped: the admin-opted-in budget trims the **oldest** whole turns (never truncates a message), always keeping the newest turn and any system prompt | ✅ Implemented (bounded, admin-opted-in) |
| Request meaning preserved | Kept messages are never rewritten/re-ordered; the optimizer only drops, never rewrites text | ✅ Implemented |
| Content never logged | Audit records metrics and reason tags only, never prompt content (consistent with secret-redaction conventions) | ✅ Implemented |
| Saver bypass via direct client flag | There is no client-facing "enable" control; the saver config is attached by the permissions middleware only after auth | ✅ Implemented |

**Accepted residual risk:** budget trimming can drop old context a developer
still needs. This is a deliberate, admin-controlled trade-off (matching the
industry-wide "drop oldest whole turns / keep newest" consensus for token
saving) and is fully audited per request.

| Standard | Requirement | Status |
|---|---|---|
| RFC 8252 (Native Apps) | Loopback redirect, random port, PKCE | ✅ |
| RFC 7636 (PKCE) | S256, 32-octet verifier | ✅ |
| RFC 9700 (OAuth Security BCP) | S256 mandatory, state, exact redirect, no token storage v1 | ✅ |
| OIDC Core §3.1.3.7 | ID token validation (iss, aud, exp, nonce, sig, alg pin) | ✅ |
| RFC 7230 §6.1 | Hop-by-hop header stripping | ✅ |
| NIST SP 800-90A | OS CSPRNG for key generation | ✅ |
| NIST SP 800-131A | 256-bit minimum key length | ✅ |
| OWASP ASVS V2/V3 | Auth, session, federated auth controls | ✅ |
| CWE-208 | Constant-time comparison (timing attack prevention) | ✅ |
