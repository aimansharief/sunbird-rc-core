#!/usr/bin/env bash
# vault-identity-token.sh — gives identity-service a sign-only Vault token (create keys, read public keys, sign).
#
# Uses the root token from keys.txt to:
#   * allow tokens to live 10 years (no renewal needed)
#   * write the identity-signer policy
#   * create a token with only that policy
# and writes it to .env as VAULT_TOKEN. The root token stays in keys.txt for admin work; it is never given
# to identity-service. Safe to re-run: an existing identity-signer token in .env is kept; a root token is replaced.
#
# Usage: ./vault-identity-token.sh [--print]
#   --print  print the token instead of writing .env (e.g. to store it as a Kubernetes Secret)
# Env: COMPOSE (default "docker compose"), VAULT_SERVICE (default "vault"), ENV_FILE (default ".env")

set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="${COMPOSE:-docker compose}"
SERVICE="${VAULT_SERVICE:-vault}"
KEYS_FILE="keys.txt"
ENV_FILE="${ENV_FILE:-.env}"
POLICY="identity-signer"
TTL="87600h"
PRINT=false
[[ "${1:-}" == "--print" ]] && PRINT=true

[[ -f "$KEYS_FILE" ]] || { echo "[ERROR] $KEYS_FILE not found" >&2; exit 1; }
ROOT_TOKEN=$(sed -n 's/Initial Root Token: \(.*\)/\1/p' "$KEYS_FILE" | tr -dc '[:print:]')
[[ -n "$ROOT_TOKEN" ]] || { echo "[ERROR] no root token in $KEYS_FILE" >&2; exit 1; }

vault_as() { local token="$1"; shift; $COMPOSE exec -T -e VAULT_TOKEN="$token" "$SERVICE" vault "$@"; }

CURRENT=""
if [[ "$PRINT" == false && -f "$ENV_FILE" ]]; then
  CURRENT=$(sed -n 's/^VAULT_TOKEN=//p' "$ENV_FILE" | tr -dc '[:print:]')
  if [[ -n "$CURRENT" && "$CURRENT" != "$ROOT_TOKEN" ]] \
     && vault_as "$CURRENT" token lookup -format=json 2>/dev/null | grep -q "\"$POLICY\""; then
    echo "[INFO]  VAULT_TOKEN in $ENV_FILE is already a $POLICY token; keeping it."
    exit 0
  fi
fi

vault_as "$ROOT_TOKEN" auth tune -max-lease-ttl="$TTL" token/ >/dev/null
printf '%s\n' \
  'path "transit/keys/+"          { capabilities = ["create", "update", "read"] }' \
  'path "transit/sign/+"          { capabilities = ["update"] }' \
  'path "transit/sign/+/sha2-256" { capabilities = ["update"] }' \
  | vault_as "$ROOT_TOKEN" policy write "$POLICY" - >/dev/null
TOKEN=$(vault_as "$ROOT_TOKEN" token create -policy="$POLICY" -ttl="$TTL" -display-name=identity-service -field=token \
  | tr -dc '[:print:]')
[[ -n "$TOKEN" ]] || { echo "[ERROR] token creation failed" >&2; exit 1; }

if [[ "$PRINT" == true ]]; then
  echo "$TOKEN"
  exit 0
fi

touch "$ENV_FILE"
awk -v t="$TOKEN" '/^VAULT_TOKEN=/ { print "VAULT_TOKEN=" t; done = 1; next } { print } END { if (!done) print "VAULT_TOKEN=" t }' \
  "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"

# Revoke a previous non-root token that is being replaced, so stray tokens do not stay valid.
if [[ -n "$CURRENT" && "$CURRENT" != "$ROOT_TOKEN" ]]; then
  vault_as "$ROOT_TOKEN" token revoke "$CURRENT" >/dev/null 2>&1 || true
fi
echo "[INFO]  identity-service sign-only Vault token written to $ENV_FILE (VAULT_TOKEN)"
