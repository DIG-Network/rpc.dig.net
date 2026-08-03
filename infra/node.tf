# The node host: a real dig-node, on a real machine, with real ports.
#
# This is what makes rpc.dig.net stop being a simulated node. The gateway (the read tier) is a
# process on this same host talking to the node over loopback — a wrapper, not a reimplementation.

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# Not every default-VPC subnet carries an IPv6 CIDR, and a peer node must have one: CLAUDE.md §5.2
# makes IPv6 the preferred peer transport, and `RunInstances` fails outright with "Subnet does not
# contain any IPv6 CIDR block ranges" if you ask for an IPv6 address in a v4-only subnet. So select
# on the property rather than taking the first subnet and hoping.
data "aws_subnet" "candidate" {
  for_each = toset(data.aws_subnets.default.ids)
  id       = each.value
}

locals {
  dualstack_subnet_ids = sort([
    for s in data.aws_subnet.candidate : s.id if s.ipv6_cidr_block != ""
  ])

  # Deterministic, so a re-apply does not migrate the instance between AZs.
  subnet_id = local.dualstack_subnet_ids[0]

  # Unbounded, expressed exactly: u64::MAX. dig-node reads DIG_NODE_CACHE_CAP into a u64 and
  # `plan_eviction` short-circuits when total <= cap, so this means "never evict"
  # (dig-node-core lib.rs:598-612, lib.rs:939-956). Note 0 does NOT mean unbounded — the `cap > 0`
  # guard makes 0 fall through to the 1 GiB default.
  cache_cap_unbounded = "18446744073709551615"

  cache_root = "/var/lib/dig-node/cache"

  bootstrap = templatefile("${path.module}/user_data.sh.tftpl", {
    capsule_bucket   = aws_s3_bucket.capsules.id
    region           = var.region
    cache_root       = local.cache_root
    cache_cap        = local.cache_cap_unbounded
    gateway_port     = var.gateway_port
    dig_node_version = var.dig_node_version
    dig_node_url     = var.dig_node_artifact_url
    dig_node_sha256  = var.dig_node_sha256
    gateway_url      = var.gateway_artifact_url
    gateway_sha256   = var.gateway_sha256
    peer_host        = var.peer_host

    # The certificate helper is FETCHED, not embedded. It used to be spliced into this template,
    # which was fine until its comments pushed the rendered bootstrap past EC2's 16 KiB user-data
    # ceiling (the precondition below caught it). It now arrives like the two binaries do —
    # downloaded and SHA-256-verified on the host — which is the mechanism this file already
    # trusts for code it runs as root.
    #
    # The digest is taken from the repo file rather than passed in by the workflow, so it is by
    # construction the digest of the exact bytes that were uploaded from this same checkout.
    origin_cert_script_url    = var.origin_cert_script_url
    origin_cert_script_sha256 = filesha256("${path.module}/dig-origin-cert.sh")
    origin_cert_secret        = data.aws_secretsmanager_secret.origin_cert.arn
    origin_cert_san           = var.origin_cert_san_host
  })

  bootstrap_encoded = base64gzip(local.bootstrap)

  # EC2's user-data ceiling is 16 KiB of the bytes it is handed — the COMPRESSED bytes here, since
  # cloud-init decompresses on the instance. base64 inflates by 4/3, so the budget is expressed in
  # the units `base64gzip` returns.
  bootstrap_encoded_limit = 16384 * 4 / 3
}

# Fail the plan with a readable message rather than a RunInstances error part-way through an apply.
check "dualstack_subnet_available" {
  assert {
    condition     = length(local.dualstack_subnet_ids) > 0
    error_message = "No subnet in the default VPC has an IPv6 CIDR. A DIG peer must be dual-stack (CLAUDE.md §5.2); associate an IPv6 CIDR with the VPC and a subnet before applying."
  }
}

resource "aws_instance" "node" {
  ami                    = data.aws_ssm_parameter.al2023_arm64.value
  instance_type          = var.instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.node.id]
  iam_instance_profile   = aws_iam_instance_profile.node.name

  # Dual-stack: IPv6 first per CLAUDE.md 5.2, with a public IPv4 kept as the fallback because a
  # large share of peers are still v4-only.
  ipv6_address_count          = 1
  associate_public_ip_address = true

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only — no SSRF-readable credentials
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data_replace_on_change = true

  # COMPRESSED, and not as an optimisation. EC2 caps user data at 16 KiB and the bootstrap renders
  # to ~24 KiB, so an uncompressed apply is rejected outright — with the entire script quoted back
  # at you in the error, which is how this was found. cloud-init sniffs the gzip magic bytes and
  # decompresses before running, so the cap effectively applies to the compressed size (~8.9 KiB,
  # comfortably inside it). The precondition below keeps that headroom honest.
  user_data_base64 = local.bootstrap_encoded

  lifecycle {
    # The AMI parameter moves whenever AL2023 publishes; that alone should not recycle a serving
    # node. Replace deliberately, by tainting, not as a side effect of an unrelated apply.
    ignore_changes = [ami]

    precondition {
      condition     = length(local.bootstrap_encoded) <= local.bootstrap_encoded_limit
      error_message = "The bootstrap no longer fits in EC2's 16 KiB user-data limit even compressed. Move the long tail of it out of user_data (an S3-hosted script fetched at boot) rather than deleting the comments that explain why the code is the way it is."
    }
  }

  tags = {
    Name    = "rpc-dig-net-node"
    role    = "public-gateway-node"
    purpose = "rpc.dig.net read tier + public peer"
  }

  # Terraform infers no ordering between an instance and the policies on the role it assumes, so
  # without these the instance can boot before its own permissions exist. Every one of them is on
  # the boot path — the capsule mount, certbot's dns-01 challenge, and restoring the certificate —
  # and the last is the expensive one: a first boot that cannot read the secret would fall through
  # to ordering a certificate, spending one of five weekly issuances to re-obtain something it
  # already had.
  depends_on = [
    aws_s3_bucket_policy.capsules,
    aws_iam_role_policy.capsule_read,
    aws_iam_role_policy.certbot_dns01,
    aws_iam_role_policy.origin_cert_secret,
  ]
}

# A stable address for the peer identity. Peers cache addresses, and a node whose address changes
# on every stop/start is a node that keeps falling out of address books.
resource "aws_eip" "node" {
  domain   = "vpc"
  instance = aws_instance.node.id
  tags     = { Name = "rpc-dig-net-node" }
}

# Persistent state volume, surviving instance replacement.
#
# This exists for one reason that is easy to miss: the node's peer identity keypair lives at
# <cache>/peer-net/identity, and peer_id = SHA-256(SPKI DER). On the root volume, every deploy
# would mint a NEW peer_id — the node would arrive as a stranger each time and fall out of every
# address book that had cached it. The non-capsule cache (downloads staging, response cache) rides
# along on the same volume so a deploy does not throw away warm state either.
#
# Capsules are NOT here. They are on the S3 mount; this volume is small on purpose.
# The AZ comes from the SUBNET, not from `aws_instance.node.availability_zone`.
#
# That distinction is the whole reason this volume works. Every release changes the gateway
# binary's SHA, which changes `user_data`, which replaces the instance — that is the intended
# immutable-deploy behaviour. But reading the AZ off the instance makes it "known after apply" the
# moment a replace is planned, which forces the VOLUME to be replaced too, which `prevent_destroy`
# then blocks: a deploy that cannot proceed and a peer identity one `-target` away from being
# deleted. Pinning to the subnet keeps the volume completely still while instances come and go.
resource "aws_ebs_volume" "state" {
  availability_zone = data.aws_subnet.candidate[local.subnet_id].availability_zone
  size              = 8
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "rpc-dig-net-state" }

  lifecycle {
    # The peer identity is in here. Never let a plan quietly destroy it.
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "state" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.state.id
  instance_id = aws_instance.node.id

  # Leave the filesystem intact when the instance is replaced.
  skip_destroy = false
}
