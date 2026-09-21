#!/usr/bin/env bash
# vault-inventory-root.sh
#
# Run with the ADMIN token (issued at root). Documents the root-level view:
#   - the namespace tree
#   - anything left at root after the namespace migration (secret engines, auth methods)
#   - root policies and the paths they grant
# Read-only. Never reads a secret value.
#
# After a clean migration, root should hold only built-in engines and the token/ auth method.
# Anything else shows up in the report as a possible leftover.
#
# Usage:
#   kubectl port-forward -n vault svc/vault 8200:8200 &
#   export VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true
#   export VAULT_TOKEN=<admin token>
#   ./vault-inventory-root.sh > vault-inventory-root.md

set -euo pipefail

: "${VAULT_TOKEN:?export VAULT_TOKEN - the root-namespace admin token}"

export VAULT_CLIENT_TIMEOUT="${VAULT_CLIENT_TIMEOUT:-15s}"
export VAULT_MAX_RETRIES="${VAULT_MAX_RETRIES:-1}"
BUILTIN='IN("cubbyhole","identity","system","ns_cubbyhole","ns_identity","ns_system")'

log() { echo "[root] $*" >&2; }
r()   { env -u VAULT_NAMESPACE vault "$@" </dev/null; }   # always at root

for b in vault jq; do
  command -v "$b" >/dev/null || { log "missing dependency: $b"; exit 1; }
done

# ------------------------------------------------------------------ token
log "checking token at root"
lookup=$(r token lookup -format=json 2>/dev/null) \
  || { log "token not valid at root - is this the admin token? (namespace-issued tokens won't work here)"; exit 1; }

if jq -e '.data.policies | index("root")' >/dev/null <<<"$lookup"; then
  log "WARNING: this is a Vault ROOT token. Prefer the scoped admin identity; revoke root tokens after use."
fi
token_policies=$(jq -r '.data.policies | join(", ")' <<<"$lookup")

echo "# Vault root-level inventory"
echo
echo "_Generated $(date -u +%Y-%m-%dT%H:%MZ) with the admin token (policies: ${token_policies}). Read-only._"

# ------------------------------------------------------------------ namespaces
echo
echo "## Namespaces"
echo
log "listing namespaces"
if top=$(r namespace list -format=json 2>/dev/null); then
  top_list=$(jq -r '.[]?' <<<"$top")
  if [[ -z "$top_list" ]]; then
    echo "_No namespaces under root._"
  else
    while IFS= read -r ns; do
      ns="${ns%/}"
      echo "- \`$ns/\`"
      if children=$(r namespace list -namespace="$ns" -format=json 2>/dev/null); then
        while IFS= read -r child; do
          [[ -n "$child" ]] && echo "  - \`$ns/${child%/}\`"
        done < <(jq -r '.[]?' <<<"$children")
      else
        echo "  - _children not listable with this token_"
      fi
    done <<<"$top_list"
  fi
else
  echo "_Denied - this token cannot list namespaces._"
fi

# ------------------------------------------------------------------ secret engines at root
echo
echo "## Secret engines at root"
echo
log "listing root secret engines"
if mounts=$(r secrets list -format=json 2>/dev/null); then
  leftovers=$(jq -r "to_entries[] | select(.value.type | $BUILTIN | not) | .key" <<<"$mounts")
  echo "| Mount | Engine | Status |"
  echo "|---|---|---|"
  jq -r "to_entries[]
    | \"| \`\(.key)\` | \(.value.type) | \(if (.value.type | $BUILTIN) then \"built-in\" else \"**possible leftover**\" end) |\"" \
    <<<"$mounts"
  echo
  if [[ -z "$leftovers" ]]; then
    echo "Clean - only built-in engines remain at root."
  else
    echo "**Non-built-in engines still at root:** $(paste -sd, <<<"$leftovers" | sed 's/,/, /g') - confirm whether these should have moved into a namespace."
  fi
else
  echo "_Denied - this token cannot list secret engines at root._"
fi

# ------------------------------------------------------------------ auth methods at root
echo
echo "## Auth methods at root"
echo
log "listing root auth methods"
if auths=$(r auth list -format=json 2>/dev/null); then
  leftovers=$(jq -r 'to_entries[] | select(.value.type != "token") | .key' <<<"$auths")
  echo "| Path | Type | Status |"
  echo "|---|---|---|"
  jq -r 'to_entries[]
    | "| `\(.key)` | \(.value.type) | \(if .value.type == "token" then "built-in" else "**possible leftover**" end) |"' \
    <<<"$auths"
  echo
  if [[ -z "$leftovers" ]]; then
    echo "Clean - only \`token/\` remains at root."
  else
    echo "**Auth methods still at root:** $(paste -sd, <<<"$leftovers" | sed 's/,/, /g') - any \`jwt-*\` here means a spoke cluster still authenticates at root."
  fi
else
  echo "_Denied - this token cannot list auth methods at root._"
fi

# ------------------------------------------------------------------ root policies
echo
echo "## Policies at root"
echo
log "listing root policies"
if pols=$(r policy list 2>/dev/null); then
  echo "| Policy | Paths granted |"
  echo "|---|---|"
  while IFS= read -r pol; do
    [[ -z "$pol" ]] && continue
    if [[ "$pol" == "root" ]]; then
      echo "| \`root\` | _built-in, unrestricted_ |"
      continue
    fi
    log "reading policy $pol"
    paths=$( { r policy read "$pol" 2>/dev/null \
        | grep -oE 'path[[:space:]]*"[^"]+"' \
        | sed -E 's/path[[:space:]]*"([^"]+)"/`\1`/' \
        | paste -sd, - | sed 's/,/, /g'; } || true)
    echo "| \`$pol\` | ${paths:-_unreadable_} |"
  done <<<"$pols"
else
  echo "_Denied - this token cannot list policies at root._"
fi

echo
echo "## Notes"
echo
echo "- Secret paths and consumers come from vault-inventory-namespace.sh, run with the dev/ops token inside each namespace."
echo "- \"Possible leftover\" means the mount is not built in and sits at root. After the root to admin/<env> migration, nothing but built-ins and \`token/\` should remain."

log "done"
