# source: infra-commons@<ref> hcl/single-source/s3-object-lock-backup-bucket.tf
# class: single-source
# proven-in: 1 consumer (the mail-stack consumer; create path and adopt path), last 2026-09-22
# caveats: the retention window is a BACKUP-POLICY decision (it must be >= the
#   backup tool's own prune window, or prune and the lock fight) — do not copy
#   the number; the bucket-creating identity must be resource-scoped S3 only
#   (no IAM) and the per-host backup users are created outside this
#   configuration; Object Lock is enable-able post-creation only with
#   versioning Enabled first, and pre-existing objects stay unlocked; the
#   lifecycle configuration takes ~1 minute to create; destroying a locked
#   bucket needs a version-aware `delete-objects --bypass-governance-retention`
#   loop first.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "backup_bucket" { type = string }

variable "object_lock_retention_days" {
  type        = number
  description = "Default retention for every new object version. A backup-policy decision: >= the backup tool's prune window."
}

resource "aws_s3_bucket" "backup" {
  bucket = var.backup_bucket

  # Creation-time flag on the create path; on an adopt path the lock
  # configuration below remediates (versioning must be Enabled first).
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "backup" {
  bucket = aws_s3_bucket.backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

# THE load-bearing rule: Object Lock *enabled* retains nothing — only a default
# retention rule makes the backup packs immutable.
resource "aws_s3_bucket_object_lock_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.backup]
}

# Reclamation pair for the lock: the backup tool's prune turns deletes into
# delete markers over locked noncurrent versions; this rule expires them after
# the window.
resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    id     = "reclaim-after-lock-window"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.object_lock_retention_days + 2 # small buffer
    }
    expiration {
      expired_object_delete_marker = true
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
