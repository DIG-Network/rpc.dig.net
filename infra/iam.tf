# Instance identity for the node host.
#
# The role is READ-ONLY on the capsule bucket. That is the load-bearing line in this file: it is
# what turns "no maximum cache capacity" from a config value anyone could change into a property
# of the deployment. The node physically cannot grow its own capsule store, so an anonymous read
# can never cause an unbounded write. Requirement 4 and the ticket's disk-exhaustion constraint are
# satisfied by the same grant.

data "aws_iam_policy_document" "node_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "rpc-dig-net-node"
  description        = "rpc.dig.net node host: read-only capsule access + SSM management."
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
}

data "aws_iam_policy_document" "capsule_read" {
  statement {
    sid       = "ReadCapsuleObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.capsules.arn}/*"]
  }

  # Mountpoint lists the prefix to resolve directory entries. Scoped to this bucket only.
  statement {
    sid       = "ListCapsuleBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.capsules.arn]
  }
}

resource "aws_iam_role_policy" "capsule_read" {
  name   = "capsule-read-only"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.capsule_read.json
}

# Origin-certificate issuance + renewal via certbot's DNS-01 challenge (#1951).
#
# Scoped as tightly as the challenge allows: record writes are restricted to THIS hosted zone, so
# the instance cannot touch any other DNS in the account. `ListHostedZones` and `GetChange` have no
# resource-level scoping in the Route 53 API — they are read-only and unavoidable for the plugin to
# find the zone and poll for propagation.
#
# `ChangeResourceRecordSets` on the zone is genuinely powerful: it would let a compromised instance
# rewrite records under dig.net, including the peer host's own A/AAAA. That is the cost of DNS-01,
# and it is accepted here over HTTP-01 because HTTP-01 would mean opening another port on a box
# already internet-facing on two peer ports. Worth revisiting if the read tier ever needs a
# narrower blast radius — the exit is the NLB + the existing *.dig.net ACM wildcard, which needs no
# instance credentials at all.
data "aws_iam_policy_document" "certbot_dns01" {
  statement {
    sid       = "FindZoneAndPollPropagation"
    actions   = ["route53:ListHostedZones", "route53:GetChange"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteChallengeRecordsInThisZoneOnly"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:aws:route53:::hostedzone/${data.aws_route53_zone.zone.zone_id}"]
  }
}

resource "aws_iam_role_policy" "certbot_dns01" {
  name   = "certbot-dns01"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.certbot_dns01.json
}

# The durable origin certificate (#2037): read it at boot, write it back after a renewal.
#
# Scoped to that ONE secret ARN — not a prefix, not a wildcard. The instance can read and replace
# its own certificate and has no visibility into any other secret in the account.
#
# THE WRITE GRANT IS THE LOAD-BEARING RISK, AND IT IS NOT MERELY A DISCLOSURE ONE. Renewal happens
# ON this host, so the host is necessarily what publishes the renewed certificate; nothing else is
# in a position to. But that makes the secret an INPUT to a root-privileged unpack on this and
# every future instance. An attacker who reaches the unprivileged `dignode` account can reach the
# instance role, rewrite the payload, and have it restored as root at the next boot — surviving the
# instance replacement that would otherwise be the remediation.
#
# What keeps that from being an escalation is on the consuming side, in dig-origin-cert.sh: the
# archive may contain only certbot's own state directories, no hooks, no setuid bits, no symlink
# leaving the tree; ownership and modes are imposed by the host rather than taken from the archive;
# `*_hook` lines are stripped from restored renewal configs; and certbot is run with
# `--no-directory-hooks`. Weakening any of those turns this grant into root on every future node.
#
# Still open (dig_ecosystem#2039): the secret uses the AWS-managed key with no resource policy, so
# any account principal holding `secretsmanager:GetSecretValue` can read the private key AND the
# ACME account key — enough to revoke the live certificate, not just impersonate the origin.
data "aws_iam_policy_document" "origin_cert_secret" {
  statement {
    sid    = "ReadAndWriteTheOriginCertificate"
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
    ]
    resources = [data.aws_secretsmanager_secret.origin_cert.arn]
  }
}

resource "aws_iam_role_policy" "origin_cert_secret" {
  name   = "origin-cert-secret"
  role   = aws_iam_role.node.id
  policy = data.aws_iam_policy_document.origin_cert_secret.json
}

# SSM Session Manager instead of SSH. No port 22 in the security group, no key pair, no bastion —
# one fewer remotely-reachable service on a host that is deliberately internet-facing.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "node" {
  name = "rpc-dig-net-node"
  role = aws_iam_role.node.name
}
