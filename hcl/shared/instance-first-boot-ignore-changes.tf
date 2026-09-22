# source: infra-commons@<ref> hcl/shared/instance-first-boot-ignore-changes.tf
# class: shared
# proven-in: 2 consumers (3 instances), last 2026-09-22
# caveats: applies to the vultr provider 2.31.x, where `user_data` and
#   `ssh_key_ids` are ForceNew on vultr_instance while vultr_ssh_key.ssh_key
#   updates in place — re-check the ForceNew set at a provider major bump;
#   with this block an edit to cloud-init plans NOTHING for a running
#   instance (it never converged one — the plan gate refused the replacement
#   before) and reaches only a rebuild; the deploy key is rotated over SSH
#   (templates/rotation-log.md), never by an apply.

terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.31"
    }
  }
}

variable "deploy_pubkey_path" {
  type        = string
  description = "Path to the deploy key's PUBLIC half (the private half lives in the vault / ssh-agent)."
}

variable "plan" { type = string }
variable "region" { type = string }
variable "os_id" { type = number }

resource "vultr_ssh_key" "deploy" {
  name    = "example-deploy"
  ssh_key = trimspace(file(var.deploy_pubkey_path))
}

resource "vultr_instance" "app" {
  plan   = var.plan
  region = var.region
  os_id  = var.os_id

  ssh_key_ids = [vultr_ssh_key.deploy.id]

  # NOTE: the vultr provider base64-encodes user_data itself — do NOT wrap it
  # in base64encode() or cloud-init receives still-encoded data and ignores it.
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    deploy_pubkey = trimspace(file(var.deploy_pubkey_path))
  })

  # Both attributes are first-boot delivery, not access control: cloud-init
  # runs once, and the host's authorized_keys is re-keyed by the rotation
  # ceremony, never by an apply. Both are ForceNew in the vultr provider, so
  # after a deploy-key rotation the re-templated user_data made every plan
  # replace the instance (the data on it with it) and the plan gate refused it
  # (2026-09-22, two consumers). vultr_ssh_key.ssh_key itself updates in place;
  # the key object is still ignored here so a re-created key (deleted in the
  # console, tainted) cannot cascade into the same replacement. A REBUILT
  # instance still gets the current key + template at creation —
  # ignore_changes only affects updates.
  lifecycle {
    ignore_changes = [ssh_key_ids, user_data]
  }
}
