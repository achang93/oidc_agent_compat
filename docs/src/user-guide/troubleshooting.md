# Troubleshooting

## Relay

### `oac-relay login` — browser doesn't open

The relay tries to open the system browser via:
- macOS: `open <url>`
- Linux: `xdg-open <url>`
- Windows: `cmd /C start <url>`

If it fails, the relay prints the URL. Copy it into a browser manually.

### `oac-relay login` — callback timeout

The relay waits 5 minutes for the OIDC callback. If it times out:

- Ensure the IdP redirect URI allows `http://127.0.0.1:*` (any port).
- Ensure no firewall blocks loopback connections.
- If running the relay in Docker, login won't work — run the relay binary
  on the host instead. See [Docker: Dev Stack](./docker-dev.md#oidc-login-real-auth-flow).

### `oac-relay login` — ID token validation fails

The relay pins the ID token signing algorithm to **{RS256, ES256}**. If
your IdP uses a different algorithm (e.g. HS256, or `none`), login will
fail with an OIDC error. Configure your IdP to sign ID tokens with RS256
or ES256.

Other validation checks that may fail:
- `iss` (issuer) must match the configured `issuer`.
- `aud` (audience) must match the `client_id`.
- `exp` (expiry) must be in the future.
- `nonce` must match the one sent in the authorize request.
- `at_hash` must match the access token (if the IdP includes it).

### `listen_addr` rejected as non-loopback

The config validator rejects `0.0.0.0` (or any non-loopback address) for
the relay unless `dev_mode = true`. In production, always use
`127.0.0.1:8787`.

### Port 8787 already in use

If you see `Address already in use`, another process is bound to port
8787. Either stop it or change `listen_addr` in the config.

### Dev token not found

The dev token is minted by `docker/dev.sh up` through central's hidden,
dev-mode-only local CLI. The public `POST /v1/tokens` endpoint never accepts
caller-supplied identity claims. If you're running in production mode, you
must run `oac-relay login` to complete OIDC and get a central-minted token.

## Central proxy

### `oac-central serve` — provider encryption key not loaded

If central cannot start because the provider encryption key is missing:

- Ensure `OAC_PROVIDER_ENCRYPTION_KEY` contains exactly 64 hexadecimal
  characters, or that `/run/secrets/provider-encryption-key` is mounted.
- Restore the original key from secure backup; generating a replacement
  makes existing encrypted provider keys unrecoverable.

### mTLS handshake failure

If the relay can't connect to the central proxy:

- Ensure the CA cert in the relay config matches the CA that signed the
  central proxy's server cert.
- Ensure the relay's client cert is signed by the same CA.
- Ensure the central proxy's `ca_cert_path` points to the CA that signed
  the relay's client cert.
- Ensure private key files have `0600` permissions.
- In dev mode (`dev_mode = true`), mTLS is not used — the central proxy
  serves plain HTTP.

### `401 Unauthorized` from the central proxy (production)

In production mode (`dev_mode = false`), the central proxy verifies the
bearer token via its TokenStore. If you see 401:

- Ensure the relay is running and the agent is pointing at
  `http://127.0.0.1:8787/v1`.
- Ensure the relay has a valid central-minted token (run `oac-relay login`).
- Ensure the token has not expired or been revoked.
- Ensure the relay is forwarding to the correct central URL.

### `403 Forbidden` — model not allowed

The central proxy enforces group-based model allowlists. If a user gets
`403` with `denial_reason: "model_not_allowed"`:

- Check the user's group membership in the IdP.
- Check the group policy with `oac-central admin policy-get <group>`.
- Update the policy with `oac-central admin policy-set <group> --models <csv>`.

### `403 Forbidden` — device revoked

If a user gets `403` with `denial_reason: "device_revoked"`:

- Check device status: `oac-central admin device-list`.
- Reinstate the device: `oac-central admin device-reinstate <fingerprint>`.

### `429 Too Many Requests`

The central proxy enforces per-IP rate limiting (60 requests/minute by
default, production only). If you hit this:

- Reduce request frequency.
- The response includes a `Retry-After` header.

## Docker dev stack

### `./docker/dev.sh up` — containers won't start

- Ensure Docker is running: `docker info`.
- Ensure ports 8080, 8090, 8443, 8787 are free.
- Check logs: `./docker/dev.sh logs`.

### `./docker/dev.sh up` — healthcheck timeout

- Keycloak can take 30-60 seconds to start. The script waits up to 60s.
- If it still fails, check Keycloak logs:
  `docker compose -f docker/dev/docker-compose.yml logs keycloak`.

### Goose can't connect to relay

- Ensure the relay container is healthy:
  `docker compose -f docker/dev/docker-compose.yml ps relay`.
- Goose connects to `http://relay:8787` over the Docker network. Ensure
  both containers are on the same network.

## Logging

All logs are structured JSON via `tracing`/`tracing-subscriber` with a
secret-redaction layer. Sensitive fields (`authorization`, `api_key`,
`client_secret`, `token`, `master_key`, etc.) are replaced with
`[REDACTED]`.

Set the log level with `RUST_LOG`:

```sh
RUST_LOG=debug oac-relay serve --config config.toml
RUST_LOG=info oac-central serve --config config.toml   # default
```
