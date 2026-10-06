#!/bin/bash
# Dev environment orchestration for the OIDC Agent Compatibility Server.
#
# Everything runs in Docker containers, including Goose (headless).
# The relay is exposed to the host on 127.0.0.1:8787 for direct tests.
#
# Usage:
#   ./docker/dev.sh up         — generate certs, start all containers,
#                                register the mock provider + key
#   ./docker/dev.sh down       — stop all containers
#   ./docker/dev.sh status     — show status
#   ./docker/dev.sh logs       — tail logs from all services
#   ./docker/dev.sh goose      — configure Goose to use the relay
#   ./docker/dev.sh goose-run  — run a headless Goose prompt
#   ./docker/dev.sh test       — send test requests through the full chain
#   ./docker/dev.sh shell      — open a shell in the relay container

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/dev/docker-compose.yml"
CERT_DIR="$SCRIPT_DIR/certs"

# ─── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*" >&2; }

# ─── Commands ────────────────────────────────────────────────────────────

cmd_up() {
    info "Generating mTLS certificates..."
    if [ -f "$CERT_DIR/ca.crt" ]; then
        ok "Certificates already exist (delete $CERT_DIR to regenerate)"
    else
        bash "$SCRIPT_DIR/generate-certs.sh"
        ok "Certificates generated"
    fi

    info "Building and starting all containers..."
    docker compose -f "$COMPOSE_FILE" up -d --build

    info "Waiting for services to be healthy..."
    wait_for "http://localhost:8080/realms/oac-dev/.well-known/openid-configuration" 60 "Keycloak"
    wait_for "http://localhost:8090/v1/models" 30 "Mock backend"
    wait_for "http://localhost:8443/healthz" 30 "Central proxy"
    wait_for "http://127.0.0.1:8787/healthz" 30 "Relay"

    info "Minting a dev token through direct central database access..."
    # Interactive login bootstraps through OIDC. The non-interactive dev stack
    # instead uses a dev-mode-only CLI inside the central container; the public
    # HTTP token endpoint never accepts caller-supplied identity claims.
    DEV_TOKEN=$(docker compose -f "$COMPOSE_FILE" exec -T central \
        oac-central --config /config/central.toml dev-token \
        --subject dev-alice --groups oac-admins --label dev-stack \
        | tail -n 1)
    ok "Dev token minted"

    info "Registering the mock provider and test key..."
    curl -sfS -X POST http://localhost:8443/admin/v1/providers \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -d '{"id":"mock-backend","name":"mock-backend","base_url":"http://mock-backend:8080","enabled":true,"is_default":true,"models":["mock-gpt-4"]}' \
        >/dev/null
    curl -sfS -X POST http://localhost:8443/admin/v1/providers/mock-backend/keys \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -d '{"key":"sk-moc...-key","label":"dev-mock-key","priority":0}' \
        >/dev/null
    ok "Mock provider and test key registered"

    info "Writing dev token for manual curl..."
    echo "$DEV_TOKEN" > /tmp/oac-dev-token
    ok "Dev token written to /tmp/oac-dev-token"

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    ok "Dev stack is up!"
    echo ""
    echo "  Keycloak:        http://localhost:8080  (admin/admin)"
    echo "  Mock backend:   http://localhost:8090"
    echo "  Central proxy:  http://localhost:8443"
    echo "  Relay:           http://127.0.0.1:8787"
    echo ""
    echo "  Test users (Keycloak realm: oac-dev):"
    echo "    alice   / alice-pass-123   (alice@example.com)"
    echo "    bob     / bob-pass-456     (bob@example.com)"
    echo "    charlie / charlie-pass-789  (charlie@example.com)"
    echo "    admin   / admin-pass-000   (admin@example.com)"
    echo ""
    echo "  Next steps:"
    echo "    ./docker/dev.sh goose   — configure Goose"
    echo "    ./docker/dev.sh test    — send a test request"
    echo "═══════════════════════════════════════════════════════════════════════"
}

cmd_down() {
    info "Stopping all containers..."
    docker compose -f "$COMPOSE_FILE" down
    ok "Everything stopped"
}

cmd_status() {
    docker compose -f "$COMPOSE_FILE" ps
}

cmd_logs() {
    docker compose -f "$COMPOSE_FILE" logs -f --tail=50
}

cmd_shell() {
    docker compose -f "$COMPOSE_FILE" exec relay /bin/bash
}

cmd_goose() {
    info "Goose is now containerized. Usage:"
    echo ""
    echo "  # Run a headless prompt through Goose → relay → central → backend:"
    echo "  ./docker/dev.sh goose-run \"Summarize the files in /workspace\""
    echo ""
    echo "  # Open an interactive Goose session:"
    echo "  docker compose -f docker/dev/docker-compose.yml run --rm goose session"
    echo ""
    echo "  # Goose is configured to use the relay at http://relay:8787"
    echo "  # with a central-minted dev token and model 'mock-gpt-4'."
    echo "  # 'dev.sh up' mints it through central's dev-mode-only local CLI."
    echo ""
    echo "  # To use a different key, edit the OPENAI_API_KEY env var in"
    echo "  # docker/dev/docker-compose.yml under the 'goose' service."
}

cmd_goose_run() {
    local prompt="${2:-Hello from Goose!}"
    info "Running Goose headless: $prompt"
    info "  Goose → relay (relay:8787) → central (central:8443) → mock-backend"
    echo ""
    docker compose -f "$COMPOSE_FILE" run --rm \
        goose run --no-session -t "$prompt"
}

cmd_test() {
    info "Sending test requests through the full chain..."
    info "  Goose → relay (127.0.0.1:8787) → central (8443) → mock-backend (8090)"

    # Read the dev token minted by 'dev.sh up'.
    if [ ! -f /tmp/oac-dev-token ]; then
        err "Dev token not found. Run './docker/dev.sh up' first."
        exit 1
    fi
    DEV_TOKEN=$(cat /tmp/oac-dev-token)

    # The dev token is minted by central's dev-mode-only local CLI.
    # The tests below exercise the full relay → central → backend chain
    # with that token, plus the security negative paths (401/400).

    info "Testing relay healthz..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/healthz)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Relay healthz → 200"
    else
        err "Relay healthz → $HTTP_CODE"
        exit 1
    fi

    info "Testing central proxy healthz..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8443/healthz)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Central healthz → 200"
    else
        err "Central healthz → $HTTP_CODE"
        exit 1
    fi

    info "Testing mock backend directly..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/v1/models)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Mock backend /v1/models → 200"
    else
        err "Mock backend /v1/models → $HTTP_CODE"
        exit 1
    fi

    info "Testing relay rejects unauthenticated request..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "401" ]; then
        ok "Relay /v1/models without key → 401 (correct)"
    else
        err "Relay /v1/models without key → $HTTP_CODE (expected 401)"
        exit 1
    fi

    info "Testing relay rejects invalid key..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer oac_invalid" \
        http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "401" ]; then
        ok "Relay /v1/models with invalid key → 401 (correct)"
    else
        err "Relay /v1/models with invalid key → $HTTP_CODE (expected 401)"
        exit 1
    fi

    info "Testing relay rejects non-loopback Host header..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Host: evil.example.com" \
        http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "400" ]; then
        ok "Relay with non-loopback Host → 400 (DNS rebinding defense works)"
    else
        err "Relay with non-loopback Host → $HTTP_CODE (expected 400)"
        exit 1
    fi

    info "Testing full chain: GET /v1/models with dev token..."
    BODY=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $DEV_TOKEN" \
        http://127.0.0.1:8787/v1/models)
    HTTP_CODE=$(echo "$BODY" | tail -n1)
    RESP_BODY=$(echo "$BODY" | sed '$d')
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Relay /v1/models with dev token → 200"
    else
        err "Relay /v1/models with dev token → $HTTP_CODE (expected 200)"
        exit 1
    fi
    if echo "$RESP_BODY" | grep -q "mock-gpt-4"; then
        ok "Response contains mock-gpt-4 (full chain works)"
    else
        err "Response missing mock-gpt-4: $RESP_BODY"
        exit 1
    fi

    info "Testing full chain: POST /v1/chat/completions (non-streaming)..."
    BODY=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -H "Content-Type: application/json" \
        -X POST http://127.0.0.1:8787/v1/chat/completions \
        -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}')
    HTTP_CODE=$(echo "$BODY" | tail -n1)
    RESP_BODY=$(echo "$BODY" | sed '$d')
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Relay /v1/chat/completions (non-stream) → 200"
    else
        err "Relay /v1/chat/completions (non-stream) → $HTTP_CODE (expected 200)"
        exit 1
    fi
    if echo "$RESP_BODY" | grep -q "Mock response to: hello"; then
        ok "Non-stream response contains backend content"
    else
        err "Non-stream response missing backend content: $RESP_BODY"
        exit 1
    fi

    info "Testing full chain: POST /v1/chat/completions (SSE streaming)..."
    # For streaming, capture headers + body together.
    OUT=$(curl -s -D - \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -H "Content-Type: application/json" \
        -X POST http://127.0.0.1:8787/v1/chat/completions \
        -d '{"model":"mock-gpt-4","stream":true,"messages":[{"role":"user","content":"hello"}]}')
    if echo "$OUT" | grep -qi "content-type: text/event-stream"; then
        ok "Stream response has content-type: text/event-stream"
    else
        err "Stream response missing text/event-stream content-type"
        echo "$OUT"
        exit 1
    fi
    # Check for the SSE stream terminator.
    if echo "$OUT" | grep -q 'data: \[DONE\]'; then
        ok "Stream response contains SSE terminator (data)"
    else
        err "Stream response missing SSE terminator"
        echo "$OUT"
        exit 1
    fi

    info "Verifying master key never leaks into relay responses..."
    # Any response from the relay must not contain the master key.
    LEAK=$(curl -s \
        -H "Authorization: Bearer $DEV_TOKEN" \
        http://127.0.0.1:8787/v1/models)
    if echo "$LEAK" | grep -q "sk-mock-backend-master-key"; then
        err "Master key leaked into relay /v1/models response!"
        exit 1
    else
        ok "Master key not present in relay response"
    fi

    echo ""
    ok "All tests passed (infrastructure + full chain + SSE)!"
    echo ""
    info "The dev token was minted by 'dev.sh up' through central's local"
    info "dev-mode-only CLI. Use it for manual curl, e.g.:"
    echo "  curl -H \"Authorization: Bearer $DEV_TOKEN\" http://127.0.0.1:8787/v1/models"
}

# ─── Helpers ─────────────────────────────────────────────────────────────

wait_for() {
    local url="$1"
    local timeout="${2:-30}"
    local name="${3:-service}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            ok "$name is ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Timeout waiting for $name at $url"
    exit 1
}

# ─── Main ────────────────────────────────────────────────────────────────

case "${1:-}" in
    up)        cmd_up ;;
    down)      cmd_down ;;
    status)    cmd_status ;;
    logs)      cmd_logs ;;
    shell)     cmd_shell ;;
    goose)     cmd_goose ;;
    goose-run) cmd_goose_run "$@" ;;
    test)      cmd_test ;;
    *)
        echo "Usage: $0 {up|down|status|logs|shell|goose|goose-run|test}"
        echo ""
        echo "  up         — generate certs, build and start all containers"
        echo "  down       — stop all containers"
        echo "  status     — show container status"
        echo "  logs       — tail logs from all services"
        echo "  shell      — open a shell in the relay container"
        echo "  goose      — show Goose usage info"
        echo "  goose-run  — run a headless Goose prompt (e.g. ./docker/dev.sh goose-run \"Hello\")"
        echo "  test       — send test requests through the full chain"
        exit 1
        ;;
esac
