# source: infra-commons@<ref> hcl/single-source/cloudflare-cidr-firewall.tf
# class: single-source
# proven-in: 1 consumer (the app consumer), last 2026-09-22
# caveats: RE-DERIVE THE LIST for every copy from
#   https://api.cloudflare.com/client/v4/ips (and again whenever CDN-only
#   reachability breaks) — the ranges below are a dated snapshot of what that
#   endpoint published and are not maintained here; enumerating them yourself
#   keeps the ingress set auditable and pinned rather than delegated to a
#   provider-managed alias; IPv4 only (the consumer runs single-stack — add the
#   v6 ranges if the instance has IPv6); the same list must be enforced on the
#   host firewall too (defense in depth), or a provider-side change silently
#   widens ingress.

terraform {
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.31"
    }
  }
}

resource "vultr_firewall_group" "app" {
  description = "default-deny inbound; 80/443 from the CDN only"
}

# 80/443 only from Cloudflare's published IPv4 ranges, pinned explicitly —
# the same list the on-host firewall enforces. Enumerating them keeps the
# ingress set auditable and under your own change control; a provider-managed
# alias (`source = "cloudflare"` on this provider) is opaque, and if it ever
# stops matching the CDN's real edge addresses the origin simply stops
# receiving traffic, with nothing in the plan to show for it.
locals {
  cloudflare_ipv4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
  ]
}

resource "vultr_firewall_rule" "http_cdn" {
  for_each          = toset(local.cloudflare_ipv4)
  firewall_group_id = vultr_firewall_group.app.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = split("/", each.value)[0]
  subnet_size       = tonumber(split("/", each.value)[1])
  port              = "80"
  notes             = "HTTP from the CDN ${each.value}"
}

resource "vultr_firewall_rule" "https_cdn" {
  for_each          = toset(local.cloudflare_ipv4)
  firewall_group_id = vultr_firewall_group.app.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = split("/", each.value)[0]
  subnet_size       = tonumber(split("/", each.value)[1])
  port              = "443"
  notes             = "HTTPS from the CDN ${each.value}"
}
