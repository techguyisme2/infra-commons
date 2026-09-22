# source: infra-commons@<ref> hcl/single-source/never-send-domain-dns.tf
# class: single-source
# proven-in: 1 consumer (a second-role box with a loopback-only mail server), last 2026-09-22
# caveats: ONLY for a domain that must never send or receive mail on the
#   public internet (a training or sandbox mail domain whose server is
#   loopback-only) — on a real sending domain these records reject your own
#   mail; count-gated on `mail_domain` so the production role, which sets it
#   empty, publishes nothing; MX/TXT cannot be proxied (grey cloud, explicit TTL).

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

variable "cloudflare_zone_id" { type = string }

variable "mail_domain" {
  type        = string
  default     = ""
  description = "Never-send mail domain (e.g. learn.example.com). Non-empty = publish null-MX + SPF -all + DMARC reject. Empty = no records."
}

# Null MX (RFC 7505 — "this domain accepts no mail"), SPF hard-fail for every
# sender, DMARC reject for the domain and its subdomains: the DNS layer of a
# sender-reputation isolation.
resource "cloudflare_dns_record" "mail_null_mx" {
  count    = var.mail_domain == "" ? 0 : 1
  zone_id  = var.cloudflare_zone_id
  name     = var.mail_domain
  type     = "MX"
  content  = "."
  priority = 0
  ttl      = 3600
  proxied  = false
  comment  = "never-send mail domain — null MX, accepts no mail (RFC 7505)"
}

resource "cloudflare_dns_record" "mail_spf" {
  count   = var.mail_domain == "" ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = var.mail_domain
  type    = "TXT"
  content = "v=spf1 -all"
  ttl     = 3600
  proxied = false
  comment = "never-send mail domain — SPF: no sender is authorised"
}

resource "cloudflare_dns_record" "mail_dmarc" {
  count   = var.mail_domain == "" ? 0 : 1
  zone_id = var.cloudflare_zone_id
  name    = "_dmarc.${var.mail_domain}"
  type    = "TXT"
  content = "v=DMARC1; p=reject; sp=reject"
  ttl     = 3600
  proxied = false
  comment = "never-send mail domain — DMARC reject (domain + subdomains)"
}
