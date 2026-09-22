# source: infra-commons@<ref> hcl/shared/state-plan-encryption.tf
# class: shared
# proven-in: 2 consumers (local backend and S3 backend), last 2026-09-22
# caveats: the passphrase arrives as TF_VAR_state_passphrase from the
#   consumer's wrapper (vault-fetched, process env only) and never sits in a
#   tfvars file; a lost passphrase is an unreadable state — escrow it before
#   `enforced = true`; migrating an EXISTING plaintext state needs a
#   transitional `fallback { method = method.unencrypted.migrate }` on the
#   state block for one no-change apply, then this exact block (enforce in a
#   follow-up commit, once the encrypted state is proven).

terraform {
  required_version = ">= 1.7" # OpenTofu: native state + plan encryption

  # State + plan encryption at rest. `enforced = true` refuses to read or
  # write a plaintext state or plan, so a wrapper that forgot the passphrase
  # fails closed instead of silently writing secrets to disk.
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }

    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }

    state {
      method   = method.aes_gcm.state
      enforced = true
    }

    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}

variable "state_passphrase" {
  type        = string
  sensitive   = true
  description = "State + plan encryption passphrase. Supplied as TF_VAR_state_passphrase by the wrapper; never in a tfvars file."
}
