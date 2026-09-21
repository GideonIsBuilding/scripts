#!/usr/bin/env bash
# vault-inventory.sh
#
# Documents the secret engines in one Vault namespace:
#   mount path | engine type | secret path | owner/team | consumer apps | policies granting access
#
# Reads METADATA ONLY. It never reads or prints a secret value.
#
# Requirements: vault, jq, kubectl
#
# Usage:
#   kubectl port-forward -n vault svc/vault 8200:8200 &
#   export VAULT_ADDR=https://localhost:8200
#   export VAULT_SKIP_VERIFY=true
#   export OPS_TOKEN=$(vault login -method=oidc -namespace=admin/dev -token-only role=ops-readwrite)
#   export ADMIN_TOKEN=<root-namespace admin token>          # optional: fallback for reading policies
#   export KUBECONFIGS="hub.kubeconfig spoke-a.kubeconfig"   # optional: clusters to scan for consumers
#   ./vault-inventory.sh admin/dev > vault-inventory-dev.md
#
# Why two tokens:
#   OPS_TOKEN   is issued inside the namespace and can read secret metadata there.
#   ADMIN_TOKEN is issued at root; it can inspect structure (policies, mounts) but not secret paths.

set -euo pipefail

NS="${1:?usage: $0 <vault-namespace, e.g. admin/dev>}"
: "${OPS_TOKEN:?export OPS_TOKEN - a token issued in $NS}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
KUBECONFIGS="${KUBECONFIGS:-${KUBECONFIG:-$HOME/.kube/config}}"

for bin in vault jq kubectl; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
log() { echo "[inventory] $*" >&2; }

# </dev/null stops the vault CLI from consuming the input of surrounding while-loops
ops()   { VAULT_TOKEN="$OPS_TOKEN"   VAULT_NAMESPACE="$NS" vault "$@" </dev/null; }
admin() { VAULT_TOKEN="$ADMIN_TOKEN" VAULT_NAMESPACE="$NS" vault "$@" </dev/null; }

BUILTIN='IN("cubbyhole","identity","system","ns_cubbyhole","ns_identity","ns_system")'

# ---------------------------------------------------------------- 1. Mounts
ops secrets list -format=json > "$WORK/mounts.json" \
  || { log "cannot list mounts in $NS with OPS_TOKEN - check VAULT_ADDR, namespace and token"; exit 1; }

# ---------------------------------------------------------------- 2. Policies
# policies.tsv: <policy name> TAB <path glob>
POLICY_CLI=""
if ops policy list >/dev/null 2>&1; then
  POLICY_CLI=ops
elif [[ -n "$ADMIN_TOKEN" ]] && admin policy list >/dev/null 2>&1; then
  POLICY_CLI=admin
fi

: > "$WORK/policies.tsv"
if [[ -n "$POLICY_CLI" ]]; then
  log "reading policies in $NS with the $POLICY_CLI token"
  while IFS= read -r pol; do
    [[ -z "$pol" || "$pol" == "root" ]] && continue
    { $POLICY_CLI policy read "$pol" 2>/dev/null \
        | grep -oE 'path[[:space:]]*"[^"]+"' \
        | sed -E 's/path[[:space:]]*"([^"]+)"/\1/' \
        | awk -v p="$pol" '{print p "\t" $0}'; } || true
  done < <($POLICY_CLI policy list) >> "$WORK/policies.tsv"
else
  log "no token can read policies in $NS - policy column will say 'unreadable'"
fi

# Vault globs -> regex:  '+' = one path segment, trailing '*' = prefix match
glob_to_re() {
  local g
  g=$(printf '%s' "$1" | sed -e 's/[][\.()^$|?{}]/\\&/g' -e 's/+/[^\/]+/g' -e 's/\*$/.*/')
  printf '^%s$' "$g"
}

: > "$WORK/policies_re.tsv"
while IFS=$'\t' read -r pol glob; do
  printf '%s\t%s\t%s\n' "$pol" "$glob" "$(glob_to_re "$glob")"
done < "$WORK/policies.tsv" > "$WORK/policies_re.tsv"

# Policies whose path globs match any of the candidate paths given
policies_for() {
  [[ -z "$POLICY_CLI" ]] && { echo "unreadable"; return; }
  local pol glob re p hits=""
  while IFS=$'\t' read -r pol glob re; do
    for p in "$@"; do
      if [[ "$p" =~ $re ]]; then hits+="$pol"$'\n'; break; fi
    done
  done < "$WORK/policies_re.tsv"
  if [[ -z "$hits" ]]; then echo "none"; else printf '%s' "$hits" | sort -u | paste -sd, - | sed 's/,/, /g'; fi
}

# Policies with any path under a mount (used for non-KV and unlistable mounts)
mount_policies() {
  [[ -z "$POLICY_CLI" ]] && { echo "unreadable"; return; }
  local r
  r=$(awk -F'\t' -v m="$1/" 'index($2, m) == 1 {print $1}' "$WORK/policies.tsv" | sort -u | paste -sd, - | sed 's/,/, /g')
  echo "${r:-none}"
}

# ---------------------------------------------------------------- 3. Consumers
# consumers.tsv: <mount/path> TAB <k8s-namespace/name (ESO|VSO) @cluster>
: > "$WORK/consumers.tsv"
for kc in $KUBECONFIGS; do
  ctx=$(KUBECONFIG="$kc" kubectl config current-context 2>/dev/null) || { log "skipping unreadable kubeconfig: $kc"; continue; }
  ctx="${ctx##*/}"; ctx="${ctx##*@}"     # arn:.../cluster/name or user@cluster -> cluster name
  log "scanning consumers on $ctx"

  # ClusterSecretStore name -> Vault mount (ESO keys are relative to the store's path)
  stores=$(KUBECONFIG="$kc" kubectl get clustersecretstores -o json 2>/dev/null \
    | jq -c '[.items[] | select(.spec.provider.vault) | {(.metadata.name): .spec.provider.vault.path}] | add // {}') || true
  [[ -n "$stores" ]] || stores='{}'

  (KUBECONFIG="$kc" kubectl get externalsecrets -A -o json 2>/dev/null || echo '{"items":[]}') \
    | jq -r --argjson s "$stores" --arg c "$ctx" '
        .items[] | . as $e
        | ($s[$e.spec.secretStoreRef.name] // "?") as $m
        | ([$e.spec.data[]?.remoteRef.key] + [$e.spec.dataFrom[]?.extract.key // empty]) | unique[]
        | "\($m)/\(.)\t\($e.metadata.namespace)/\($e.metadata.name) (ESO) @\($c)"' \
    >> "$WORK/consumers.tsv"

  (KUBECONFIG="$kc" kubectl get vaultstaticsecrets -A -o json 2>/dev/null || echo '{"items":[]}') \
    | jq -r --arg c "$ctx" '
        .items[]
        | "\(.spec.mount)/\(.spec.path)\t\(.metadata.namespace)/\(.metadata.name) (VSO) @\($c)"' \
    >> "$WORK/consumers.tsv"
done

consumers_for() {
  awk -F'\t' -v k="$1" '$1 == k {print $2}' "$WORK/consumers.tsv" | sort -u | paste -sd, - | sed 's/,/, /g'
}

# ---------------------------------------------------------------- 4. Owner
# custom_metadata owner/team if set; otherwise inferred from consumers' k8s namespaces
owner_for() {  # $1 mount  $2 path  $3 kv-version  $4 consumer string
  local o="" nss=""
  if [[ "$3" == "2" ]]; then
    o=$(ops kv metadata get -format=json "$1/$2" 2>/dev/null \
      | jq -r '.data.custom_metadata // {} | (.owner // .team // empty)') || true
  fi
  if [[ -n "$o" ]]; then echo "$o"; return; fi
  if [[ -n "$4" ]]; then
    nss=$(tr ',' '\n' <<<"$4" | awk -F/ '{gsub(/^ +/, "", $1); if ($1 != "") print $1}' | sort -u | paste -sd, - | sed 's/,/, /g')
    echo "_inferred:_ $nss"; return
  fi
  echo "unknown"
}

# ---------------------------------------------------------------- 5. Walk KV mounts
walk() {  # $1 mount  $2 prefix  -> prints leaf paths relative to the mount
  local listing item
  listing=$(ops kv list -format=json "$1/$2" 2>/dev/null) || return 0
  while IFS= read -r item; do
    if [[ "$item" == */ ]]; then walk "$1" "$2$item"; else printf '%s\n' "$2$item"; fi
  done < <(jq -r '.[]' <<<"$listing")
}

# ---------------------------------------------------------------- 6. Report
: > "$WORK/leaves.txt"
: > "$WORK/unlistable.txt"

echo "# Vault secret inventory - \`$NS\`"
echo
echo "_Generated $(date -u +%Y-%m-%dT%H:%MZ). Metadata only; no secret values were read._"
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

  if ! ops kv list -format=json "$mount/" >/dev/null 2>&1; then
    echo "$mount" >> "$WORK/unlistable.txt"
    echo "| \`$mount/\` | kv-v$version | _not listable with OPS_TOKEN_ | - | - | $(mount_policies "$mount") |"
    log "cannot list $mount/ - access gap, recorded in report"
    continue
  fi

  while IFS= read -r leaf; do
    echo "$mount/$leaf" >> "$WORK/leaves.txt"
    if [[ "$version" == "2" ]]; then
      cands=("$mount/data/$leaf" "$mount/metadata/$leaf")
    else
      cands=("$mount/$leaf")
    fi
    cons=$(consumers_for "$mount/$leaf")
    owner=$(owner_for "$mount" "$leaf" "$version" "$cons")
    pols=$(policies_for "${cands[@]}")
    echo "| \`$mount/\` | kv-v$version | \`$leaf\` | $owner | ${cons:--} | $pols |"
  done < <(walk "$mount" "")
done < <(jq -r "to_entries[] | select(.value.type | $BUILTIN | not)
  | \"\(.key)\t\(.value.type)\t\(.value.options.version // \"1\")\"" "$WORK/mounts.json")

echo
echo "## Consumer references with no matching secret"
echo
echo "_Paths something reads from but the walk did not find. Either a broken reference, a path in another namespace, or a mount OPS_TOKEN cannot list (marked)._"
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

echo
echo "## Notes"
echo
echo "- **Owner** comes from KV v2 \`custom_metadata.owner\` or \`.team\` when set; otherwise it is inferred from the Kubernetes namespaces of consumers and labelled as such."
echo "- **Consumers** cover ESO ExternalSecrets (via ClusterSecretStores) and VSO VaultStaticSecrets on the scanned clusters only: $(for kc in $KUBECONFIGS; do printf '%s ' "$(basename "$kc")"; done)"
echo "- **Policies** are matched by evaluating each policy's path globs (\`+\`, trailing \`*\`) against the secret's data/metadata paths. Capabilities are not broken out; check the policy for read vs write."
echo "- Namespaced SecretStores are not scanned."

log "done: $(wc -l < "$WORK/leaves.txt") secrets, $(wc -l < "$WORK/consumers.tsv") consumer references, $(wc -l < "$WORK/unlistable.txt") unlistable mounts"
