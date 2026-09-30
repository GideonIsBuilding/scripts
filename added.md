## What

VSO's default VaultAuth (`vault/default`) had no Vault Enterprise namespace,
so it authenticated against the root namespace, where the Kubernetes auth
roles don't exist. Vault returned `400 invalid role name
"vault-secrets-operator"` and `vault-license` stopped syncing.

## Why it wasn't caught by the existing replacement

`vault/default` is rendered by the Helm chart from `defaultAuthMethod` in the
ArgoCD Application — labels confirm `managed-by: Helm`,
`helm.sh/chart: vault-secrets-operator-1.1.0`. Kustomize replacements only
apply to resources inside the build, so the existing `VAULT_ENT_NAMESPACE`
replacement (targeting `kind: VaultAuth`) reaches `gitea/default` and nothing
else.

## Changes

- `apps/platform/vault/vault-secrets-operator.yaml` — add
  `namespace: VAULT_ENT_NAMESPACE` to `defaultAuthMethod`, following the
  existing `VAULT_ADDR` placeholder pattern
- dev and nonprod mgmt hub kustomizations — add a replacement targeting the
  `vault-secrets-operator` Application
- revert `spec.vaultNamespace` → `spec.namespace`; that field does not exist
  on the VaultAuth CRD in VSO 1.1.0

## Verification

Rendered both clusters before pushing:

| Cluster | `defaultAuthMethod.namespace` |
| --- | --- |
| dev-aws-ue1-mgmt-hub | `admin/dev` |
| nonprod-aws-ue1-mgmt-hub-1 | `admin/nonprod` |

## After merge

- [ ] `kubectl get vaultauth default -n vault -o jsonpath='{.spec.namespace}'` returns `admin/dev`
- [ ] `invalid role name` gone from VSO logs
- [ ] `vault-license` syncs

Unverified: whether chart 1.1.0 templates `defaultAuthMethod.namespace` into
the VaultAuth. If it ignores the key the sync will look clean and the CR will
still be empty — fallback is `defaultAuthMethod.enabled: false` plus declaring
the VaultAuth in the kustomization as gitea's is.
