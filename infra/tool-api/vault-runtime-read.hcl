# Installed by vault:tool-setup. The runtime record is enrolled separately.
# No real secret values belong here.
path "federated-copilot-tool-secrets/data/runtime" {
  capabilities = ["read"]
}

# Intentionally no list/write/delete, Transit, token creation, policy/mount
# administration or access to the consent authority's signing credential.
