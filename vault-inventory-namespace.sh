#!/usr/bin/env bash
# vault-inventory-namespace.sh
#
# Run with the DEV / OPS token. Documents one Vault namespace:
#   mount | engine | path | owner/team | consumers | policies granting access
# Metadata only - never reads or prints a secret value.
#
# Usage:
#   kubectl port-forward -n vault svc/vault 8200:8200 &
#   export VAULT_ADDR=https://localhost:8200 VAULT_SKIP_VERIFY=true
#   export VAULT_TOKEN=$(vault login -method=oidc -namespace=admin/dev -token-only role=ops-readwrite)
#   export KUBECONFIGS="/path/hub.kubeconfig /path/spoke.kubeconfig"   # optional
#   ./vault-inventory-namespace.sh admin/dev > vault-inventory-dev.md
#
# Options:
#   SKIP_OWNER=1       skip per-secret metadata calls (faster; owner inferred from consumers)
#   SKIP_CONSUMERS=1   skip the kubectl scan

set -euo pipefail

NS="${1:?usage: $0 <vault-namespace, e.g. admin/dev>}"
: "${VAULT_TOKEN:?export VAULT_TOKEN - the dev/ops token issued in $NS}"

# Fail fast instead of hanging on a dead port-forward or unreachable cluster
export VAULT_CLIENT_TIMEOUT="${VAULT_CLIENT_TIMEOUT:-15s}"
export VAULT_MAX_RETRIES="${VAULT_MAX_RETRIES:-1}"
KT="--request-timeout=15s"
BUILTIN='IN("cubbyhole","identity","system","ns_cubbyhole","ns_identity","ns_system")'

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { echo "[namespace] $*" >&2; }
v()   { VAULT_NAMESPACE="$NS" vault "$@" </dev/null; }

for b in vault jq; do
  command -v "$b" >/dev/null || { log "missing dependency: $b"; exit 1; }
done

# ------------------------------------------------------------------ token + mounts
log "checking token in $NS"
v token lookup >/dev/null 2>&1 \
  || { log "token not valid in $NS - stale, expired, or issued in another namespace"; exit 1; }

log "listing mounts"
v secrets list -format=json > "$WORK/mounts.json" \
  || { log "cannot list mounts in $NS"; exit 1; }

# ------------------------------------------------------------------ policies
glob_to_re() {  # Vault glob -> regex: '+' = one segment, trailing '*' = prefix
  local g
  g=$(printf '%s' "$1" | sed -e 's/[][\.()^$|?{}]/\\&/g' -e 's/+/[^\/]+/g' -e 's/\*$/.*/')
  printf '^%s$' "$g"
}

HAVE_POL=0
: > "$WORK/policies.tsv"
: > "$WORK/policies_re.tsv"
if v policy list >/dev/null 2>&1; then
  HAVE_POL=1
  while IFS= read -r pol; do
    [[ -z "$pol" || "$pol" == "root" ]] && continue
    log "reading policy $pol"
    { v policy read "$pol" 2>/dev/null \
        | grep -oE 'path[[:space:]]*"[^"]+"' \
        | sed -E 's/path[[:space:]]*"([^"]+)"/\1/' \
        | awk -v p="$pol" '{print p "\t" $0}'; } || true
  done < <(v policy list) >> "$WORK/policies.tsv"
  while IFS=$'\t' read -r pol glob; do
    printf '%s\t%s\n' "$pol" "$(glob_to_re "$glob")"
  done < "$WORK/policies.tsv" > "$WORK/policies_re.tsv"
else
  log "this token cannot read policies in $NS - policy column will say 'unreadable'"
fi

policies_for() {
  (( HAVE_POL )) || { echo "unreadable"; return; }
  local pol re p hits=""
  while IFS=$'\t' read -r pol re; do
    for p in "$@"; do
      if [[ "$p" =~ $re ]]; then hits+="$pol"$'\n'; break; fi
    done
  done < "$WORK/policies_re.tsv"
  if [[ -z "$hits" ]]; then echo "none"; else printf '%s' "$hits" | sort -u | paste -sd, - | sed 's/,/, /g'; fi
}

mount_policies() {
  (( HAVE_POL )) || { echo "unreadable"; return; }
  local r
  r=$(awk -F'\t' -v m="$1/" 'index($2, m) == 1 {print $1}' "$WORK/policies.tsv" | sort -u | paste -sd, - | sed 's/,/, /g')
  echo "${r:-none}"
}

# ------------------------------------------------------------------ consumers
: > "$WORK/consumers.tsv"
: > "$WORK/clusters.txt"
if [[ "${SKIP_CONSUMERS:-0}" != "1" ]] && command -v kubectl >/dev/null; then
  for kc in ${KUBECONFIGS:-${KUBECONFIG:-$HOME/.kube/config}}; do
    ctx=$(KUBECONFIG="$kc" kubectl config current-context 2>/dev/null) || { log "skipping unreadable kubeconfig: $kc"; continue; }
    ctx="${ctx##*/}"; ctx="${ctx##*@}"
    if ! KUBECONFIG="$kc" kubectl $KT get --raw /version >/dev/null 2>&1; then
      log "cannot reach $ctx - skipped (VPN / session / port?)"
      continue
    fi
    log "scanning consumers on $ctx"
    echo "$ctx" >> "$WORK/clusters.txt"

    stores=$(KUBECONFIG="$kc" kubectl $KT get clustersecretstores -o json 2>/dev/null \
      | jq -c '[.items[] | select(.spec.provider.vault) | {(.metadata.name): .spec.provider.vault.path}] | add // {}') || true
    [[ -n "$stores" ]] || stores='{}'

    (KUBECONFIG="$kc" kubectl $KT get externalsecrets -A -o json 2>/dev/null || echo '{"items":[]}') \
      | jq -r --argjson s "$stores" --arg c "$ctx" '
          .items[] | . as $e
          | ($s[$e.spec.secretStoreRef.name] // "?") as $m
          | ([$e.spec.data[]?.remoteRef.key] + [$e.spec.dataFrom[]?.extract.key // empty]) | unique[]
          | "\($m)/\(.)\t\($e.metadata.namespace)/\($e.metadata.name) (ESO) @\($c)"' \
      >> "$WORK/consumers.tsv"

    (KUBECONFIG="$kc" kubectl $KT get vaultstaticsecrets -A -o json 2>/dev/null || echo '{"items":[]}') \
      | jq -r --arg c "$ctx" '.items[]
          | "\(.spec.mount)/\(.spec.path)\t\(.metadata.namespace)/\(.metadata.name) (VSO) @\($c)"' \
      >> "$WORK/consumers.tsv"
  done
else
  log "consumer scan skipped"
fi
HAVE_CONS=0
[[ -s "$WORK/clusters.txt" ]] && HAVE_CONS=1

consumers_for() {
  (( HAVE_CONS )) || return 0
  awk -F'\t' -v k="$1" '$1 == k {print $2}' "$WORK/consumers.tsv" | sort -u | paste -sd, - | sed 's/,/, /g'
}

# ------------------------------------------------------------------ walk
walk() {  # $1 mount  $2 prefix -> leaf paths relative to the mount
  local listing item
  log "  listing $1/$2"
  listing=$(v kv list -format=json "$1/$2" 2>/dev/null) || { log "  cannot list $1/$2 - skipped"; return 0; }
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    if [[ "$item" == */ ]]; then walk "$1" "$2$item"; else printf '%s\n' "$2$item"; fi
  done < <(jq -r '.[]' <<<"$listing")
}

# ------------------------------------------------------------------ report
: > "$WORK/leaves.txt"
: > "$WORK/unlistable.txt"

echo "# Vault secret inventory - \`$NS\`"
echo
echo "_Generated $(date -u +%Y-%m-%dT%H:%MZ) with the namespace (dev/ops) token. Metadata only; no secret values were read._"
echo
echo "## Mounts"
echo
echo "| Mount | Engine | KV version | Description |"
echo "|---|---|---|---|"
jq -r "to_entries[] | select(.value.type | $BUILTIN | not)
  | \"| \`\(.key)\` | \(.value.type) | \(.value.options.version // \"-\") | \(.value.description // \"-\") |\"" \
  "$WORK/mounts.json"

echo
echo "## Secrets"
echo
echo "| Mount | Engine | Path | Owner / team | Consumers | Policies granting access |"
echo "|---|---|---|---|---|---|"

while IFS=$'\t' read -r mount type version; do
  mount="${mount%/}"

  if [[ "$type" != "kv" ]]; then
    echo "| \`$mount/\` | $type | _(non-KV, mount level)_ | - | - | $(mount_policies "$mount") |"
    continue
  fi

  if ! v kv list -format=json "$mount/" >/dev/null 2>&1; then
    log "cannot list $mount/ - recorded as a gap"
    echo "$mount" >> "$WORK/unlistable.txt"
    continue
  fi

  log "walking $mount/ (kv-v$version)"
  while IFS= read -r leaf; do
    echo "$mount/$leaf" >> "$WORK/leaves.txt"
    cons=$(consumers_for "$mount/$leaf")

    owner=""
    if [[ "$version" == "2" && "${SKIP_OWNER:-0}" != "1" ]]; then
      owner=$(v kv metadata get -format=json "$mount/$leaf" 2>/dev/null \
        | jq -r '.data.custom_metadata // {} | (.owner // .team // empty)') || owner=""
    fi
    if [[ -z "$owner" ]]; then
      if [[ -n "$cons" ]]; then
        nss=$(tr ',' '\n' <<<"$cons" | awk -F/ '{gsub(/^ +/, "", $1); if ($1 != "") print $1}' | sort -u | paste -sd, - | sed 's/,/, /g')
        owner="_inferred:_ $nss"
      else
        owner="unknown"
      fi
    fi

    if [[ "$version" == "2" ]]; then
      pols=$(policies_for "$mount/data/$leaf" "$mount/metadata/$leaf")
    else
      pols=$(policies_for "$mount/$leaf")
    fi

    echo "| \`$mount/\` | kv-v$version | \`$leaf\` | $owner | ${cons:--} | $pols |"
  done < <(walk "$mount" "")
done < <(jq -r "to_entries[] | select(.value.type | $BUILTIN | not)
  | \"\(.key)\t\(.value.type)\t\(.value.options.version // \"1\")\"" "$WORK/mounts.json")

if [[ -s "$WORK/unlistable.txt" ]]; then
  echo
  echo "## Mounts this token could not list"
  echo
  while IFS= read -r mount; do
    echo "- \`$mount/\` - policies with grants here: $(mount_policies "$mount")"
  done < "$WORK/unlistable.txt"
fi

if (( HAVE_CONS )); then
  echo
  echo "## Consumer references with no matching secret"
  echo
  echo "_Something reads these paths but the walk didn't find them: a broken reference, another namespace, or an unlistable mount (marked)._"
  echo
  orphans=$(awk -F'\t' '
    FILENAME == ARGV[1] { seen[$0] = 1; next }
    FILENAME == ARGV[2] { gap[$0] = 1; next }
    !($1 in seen) {
      split($1, parts, "/"); note = (parts[1] in gap) ? " _(mount not listable)_" : ""
      print "| `" $1 "`" note " | " $2 " |"
    }' "$WORK/leaves.txt" "$WORK/unlistable.txt" "$WORK/consumers.tsv" | sort -u)
  if [[ -n "$orphans" ]]; then
    echo "| Referenced path | Consumer |"
    echo "|---|---|"
    echo "$orphans"
  else
    echo "None - every consumer reference resolves."
  fi
fi

echo
echo "## Notes"
echo
echo "- **Owner** is KV v2 \`custom_metadata.owner\` or \`.team\` where set; otherwise inferred from consumers' Kubernetes namespaces."
if (( HAVE_CONS )); then
  echo "- **Consumers** cover ESO ExternalSecrets and VSO VaultStaticSecrets on: $(paste -sd, "$WORK/clusters.txt" | sed 's/,/, /g')."
else
  echo "- **Consumers** were not scanned (no reachable cluster, or SKIP_CONSUMERS=1)."
fi
echo "- **Policies** are matched by evaluating each policy's path globs against the secret's data/metadata paths. Capabilities (read vs write) are not broken out."
echo "- The root-level view (namespaces, leftovers at root, root policies) comes from vault-inventory-root.sh, run with the admin token."

log "done: $(wc -l < "$WORK/leaves.txt") secrets, $(wc -l < "$WORK/consumers.tsv") consumer references, $(wc -l < "$WORK/unlistable.txt") unlistable mounts"
