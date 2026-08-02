# The capsule tier. This bucket IS the node's `<cache>/modules` directory — Mountpoint for S3
# presents it read-only at that path, so a published `.dig` is served without ever landing on the
# instance's disk, and the cache has no capacity limit other than the bucket itself.
#
# Why this is a SEPARATE bucket from the hub's `dighub-modules`:
#   1. The live retrieval Lambda reads `dighub-modules` right now. Not touching it means this
#      work cannot break the read tier that is currently serving.
#   2. Objects here are keyed `{store_hex}/{root_hex}.module` to match dig-node's `module_path`
#      (dig-node-core lib.rs:760-763); the hub's are `.dig`. Two suffixes, two lifecycles.
#   3. It gives the boundary a real edge: the node's role is read-only here, the hub's publish
#      role is write-only. A shared prefix could not express that.

resource "aws_s3_bucket" "capsules" {
  bucket = var.capsule_bucket
}

# Content-addressed objects: the key contains the root hash, so a given key's bytes never change.
# Versioning would only accumulate cost for a mutation that cannot happen.
resource "aws_s3_bucket_versioning" "capsules" {
  bucket = aws_s3_bucket.capsules.id
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "capsules" {
  bucket = aws_s3_bucket.capsules.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "capsules" {
  bucket                  = aws_s3_bucket.capsules.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "capsules" {
  bucket = aws_s3_bucket.capsules.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Abort stalled multipart uploads. A 135 MiB capsule is uploaded multipart; an interrupted publish
# would otherwise leave billable parts behind forever.
resource "aws_s3_bucket_lifecycle_configuration" "capsules" {
  bucket = aws_s3_bucket.capsules.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 3
    }
  }
}

data "aws_iam_policy_document" "capsules" {
  # Baseline: refuse anything not over TLS.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.capsules.arn, "${aws_s3_bucket.capsules.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # The publish path may write; it may not read back or delete. Writers are named explicitly
  # rather than granted by a wildcard so the set is visible in a diff.
  dynamic "statement" {
    for_each = length(var.capsule_writer_role_arns) > 0 ? [1] : []
    content {
      sid       = "PublishPathMayWriteCapsules"
      effect    = "Allow"
      actions   = ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads"]
      resources = ["${aws_s3_bucket.capsules.arn}/*", aws_s3_bucket.capsules.arn]
      principals {
        type        = "AWS"
        identifiers = var.capsule_writer_role_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "capsules" {
  bucket     = aws_s3_bucket.capsules.id
  policy     = data.aws_iam_policy_document.capsules.json
  depends_on = [aws_s3_bucket_public_access_block.capsules]
}
