# The node host: a real dig-node, on a real machine, with real ports.
#
# This is what makes rpc.dig.net stop being a simulated node. The gateway (the read tier) is a
# process on this same host talking to the node over loopback — a wrapper, not a reimplementation.

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# One deterministic subnet, so a re-apply does not migrate the instance between AZs.
locals {
  subnet_id = sort(data.aws_subnets.default.ids)[0]

  # Unbounded, expressed exactly: u64::MAX. dig-node reads DIG_NODE_CACHE_CAP into a u64 and
  # `plan_eviction` short-circuits when total <= cap, so this means "never evict"
  # (dig-node-core lib.rs:598-612, lib.rs:939-956). Note 0 does NOT mean unbounded — the `cap > 0`
  # guard makes 0 fall through to the 1 GiB default.
  cache_cap_unbounded = "18446744073709551615"

  cache_root = "/var/lib/dig-node/cache"
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
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
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
  })

  tags = {
    Name    = "rpc-dig-net-node"
    role    = "public-gateway-node"
    purpose = "rpc.dig.net read tier + public peer"
  }

  lifecycle {
    # The AMI parameter moves whenever AL2023 publishes; that alone should not recycle a serving
    # node. Replace deliberately, by tainting, not as a side effect of an unrelated apply.
    ignore_changes = [ami]
  }

  depends_on = [aws_s3_bucket_policy.capsules]
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
resource "aws_ebs_volume" "state" {
  availability_zone = aws_instance.node.availability_zone
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
