# CLI Reference

## `oac-relay`

The laptop relay binary.

### Usage

```
oac-relay [OPTIONS] [COMMAND]
```

If no subcommand is given, `serve` is assumed.

### Options

| Flag | Short | Long | Env var | Default | Description |
|---|---|---|---|---|---|
| config | `-c` | `--config` | `OAC_RELAY_CONFIG` | `config.toml` | Path to the TOML config file |

`--config` is a top-level flag: it must appear **before** the subcommand
(`oac-relay --config relay.toml login` works; `oac-relay login --config
relay.toml` fails). `print-key` is the only subcommand that does not need
a config file.

### Subcommands

#### `serve` (default)

Start the relay HTTP server.

```sh
oac-relay --config config.toml serve
# or simply:
oac-relay --config config.toml
```

- Opens the SQLite DB (runs migrations, enforces `0600` perms).
- If `dev_mode = true`, skips auth checks (central rejects unauthenticated
  requests via its token store).
- Binds to `listen_addr` and serves with graceful shutdown.

#### `login`

Run the OIDC auth-code + PKCE flow, request a central-minted token, and
inject it into the agent config.

```sh
oac-relay --config config.toml login [--ttl <DURATION>]
```

The `--ttl` flag sets the token lifetime (e.g. `--ttl 1d`, `--ttl 12h`,
`--ttl 1y`, `--ttl 3600s`). Default: never expires (unless the admin
`max_token_ttl_seconds` backstop clamps it).

Opens a browser to the IdP login page. After successful authentication,
the relay sends the one-time authorization code, PKCE verifier, redirect URI,
and nonce to `POST /v1/tokens` over mTLS. Central exchanges and validates the
grant, derives the identity from verified OIDC claims, and returns a minted
token. The relay writes the agent config file with `0600` perms. The Codex
config (`$CODEX_HOME/config.json`, or
`~/.codex/config.json`) is used only if `CODEX_HOME` is set or
`~/.codex/config.json` already exists; otherwise the generic env file
`~/.oac/agent-env.sh` is written.

#### `logout`

Revoke the current central token.

```sh
oac-relay --config config.toml logout
```

Calls `DELETE /v1/tokens/current` at central to revoke the token. The agent
config file is **not** deleted — the token stays in the file but stops
working; run `login` again to mint a fresh token.

#### `print-key`

Re-print the base URL and token from the agent config file (not the DB).
The only subcommand that runs without loading a config file.

```sh
oac-relay print-key
```

#### `list-keys`

List all tokens for the current user (via the central token API).

```sh
oac-relay --config config.toml list-keys
```

Calls `GET /v1/tokens` at central with the current bearer token. Output:
id, label, created_at, expires_at, last_used_at. Never includes the hash
or plaintext.

#### `activity`

Show recent relay request activity from the append-only local activity log.

```sh
oac-relay --config config.toml activity --limit 20
```

Entries are displayed newest first. `--limit` defaults to `20` and is capped
at `1000`. The output contains request metadata only; API keys and provider
key material are never printed.

#### `token`

Manage central tokens: create a new labeled token, list all tokens, or
revoke a specific token by ID. This subcommand group requires a valid
current token (from `oac-relay login`) for authentication.

##### `token create`

Mint a new labeled token using the current token as authentication. The
identity is inherited from the verified bearer — the body carries only
`label` and `ttl_seconds`. The returned plaintext token is printed for
manual copy into an agent config file.

```sh
oac-relay --config config.toml token create --label codex --ttl 1y
```

- `--label` (required): human-readable label for the token (e.g. `codex`).
- `--ttl` (optional): token lifetime (e.g. `1d`, `12h`, `1y`, `3600s`).
  If omitted, the token never expires (unless the admin `max_token_ttl_seconds`
  backstop clamps it).

Calls `POST /v1/tokens` at central with `Authorization: Bearer <current token>`.
The response includes the new token plaintext, token ID, label, and expiry.

##### `token list`

List all tokens for the current user. Same as [`list-keys`](#list-keys).

```sh
oac-relay --config config.toml token list
```

##### `token revoke`

Revoke a specific token by its row ID (UUID). The current token is used
for authentication; any of the user's tokens can be revoked (including the
current one).

```sh
oac-relay --config config.toml token revoke <token-id>
```

Calls `DELETE /v1/tokens/{id}` at central with `Authorization: Bearer`.
Returns success (204) or an error message.

---

## `oac-central`

The central proxy binary.

### Usage

```
oac-central [OPTIONS] [COMMAND]
```

If no subcommand is given, `serve` is assumed.

### Options

| Flag | Short | Long | Env var | Default | Description |
|---|---|---|---|---|---|
| config | `-c` | `--config` | `OAC_CENTRAL_CONFIG` | `config.toml` | Path to the TOML config file |

`--config` is a top-level flag: it must appear **before** the subcommand
(`oac-central --config central.toml serve` works; `oac-central serve
--config central.toml` fails).

### Subcommands

#### `serve` (default)

Start the central proxy server.

```sh
oac-central --config config.toml serve
# or simply:
oac-central --config config.toml
```

- Opens the database (runs migrations).
- Loads the provider encryption key and opens the runtime provider store.
- Binds the server (dev: plain HTTP; prod: mTLS with client cert required).
- Serves with graceful shutdown.

#### `admin`

Admin API operations (providers, policies, devices, audit). Sends requests
**through the relay** (which authenticates the user via OIDC). The user
must belong to the configured `admin_group`.

```
oac-central admin --key <KEY> [--url <URL>] <SUBCOMMAND>
```

| Flag | Long | Env var | Default | Description |
|---|---|---|---|---|
| url | `--url` | `OAC_ADMIN_URL` | `http://127.0.0.1:8787` | Relay URL |
| key | `--key` | `OAC_API_KEY` | (required) | Central token from `oac-relay login` |

`--key` and `--url` belong to `admin` itself and must appear **before** the
admin subcommand (e.g. `oac-central admin --key K policy-list`). With
`OAC_API_KEY` set, `--key` can be omitted.

##### Admin subcommands

| Subcommand | Args / Flags | Description |
|---|---|---|
| `provider-list` | — | List all configured providers |
| `provider-set <id>` | `id` (positional), `--name <STRING>`, `--base-url <URL>`, `--models <CSV>`, `--default`, `--disabled` | Create or update a provider |
| `provider-delete <id>` | `id` (positional) | Delete a provider and all of its keys |
| `provider-default <id>` | `id` (positional) | Set the default fallback provider |
| `provider-key-list <id>` | `id` (positional) | List a provider's key metadata |
| `provider-key-add <id>` | `id` (positional), `--label <STRING>`, `--priority <I32>` (default 0), `--groups <CSV>` | Add a provider key (secret prompted with hidden input) |
| `provider-key-delete <id> <KEY_ID>` | `id`, `KEY_ID` (positional) | Delete a provider key |
| `policy-list` | — | List all group policies |
| `policy-get <name>` | `name` (positional) | Get a single policy |
| `policy-set <name>` | `name` (positional), `--models <CSV>`, `--endpoints <CSV>`, `--token-quota <I64>`, `--request-quota <I64>` | Create or update a policy |
| `policy-delete <name>` | `name` (positional) | Delete a policy |
| `device-list` | — | List all registered devices |
| `device-revoke <fingerprint>` | `fingerprint` (positional) | Revoke a device |
| `device-reinstate <fingerprint>` | `fingerprint` (positional) | Reinstate a revoked device |
| `audit-query` | `--subject <STRING>`, `--limit <U32>` (default 100), `--offset <U32>` (default 0) | Query the newest-first audit log page |
| `usage-query` | `--subject <STRING>` (optional) | Query usage counters |
| `quota-get <subject>` | `subject` (positional) | Get quota status for a user |

##### Provider administration examples

Provider administration commands operate through the relay and require the
admin IdP group. Provider API keys are never command-line arguments. The
examples assume `OAC_API_KEY` is set.

```sh
oac-central admin provider-list
oac-central admin provider-set openai --name OpenAI --base-url https://api.openai.com --models gpt-4o,gpt-4o-mini --default
oac-central admin provider-default openai
oac-central admin provider-delete openai
oac-central admin provider-key-list openai
oac-central admin provider-key-add openai --label production --priority 0 --groups engineering
oac-central admin provider-key-delete openai KEY_ID
```

`provider-key-add` prompts for the key with input hidden. Key listing returns
metadata only; use a new key for rotation rather than attempting to update
key material. Pass `--disabled` to `provider-set` to disable a provider
without deleting it.

##### `policy-set` examples

```sh
# Allow the "engineering" group to use only gpt-4o and gpt-4o-mini:
oac-central admin --key $OAC_API_KEY policy-set engineering \
  --models gpt-4o,gpt-4o-mini

# Restrict the "limited" group to chat completions only:
oac-central admin --key $OAC_API_KEY policy-set limited \
  --endpoints /v1/chat/completions

# Set a daily request quota of 1000:
oac-central admin --key $OAC_API_KEY policy-set engineering \
  --request-quota 1000
```

See [Admin API](./admin-api.md) for the HTTP endpoint equivalents and
response shapes.
