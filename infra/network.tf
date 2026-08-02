# The security group IS the boundary invariant, written down.
#
# Exposing 9444/9445 turns this host from a read-only HTTPS endpoint into a real peer with a real
# attack surface. The rule that keeps that safe is not "be careful" — it is that the only ports
# open to the internet are the two PEER protocols, and the read tier is reachable only from
# CloudFront. Three things are deliberately absent and must stay absent:
#
#   * 9778 — the node's own local surface. It also answers wallet JSON-RPC, a wallet WebSocket,
#     and /s/* SERVER-SIDE-DECRYPTED plaintext content. It binds loopback and is never in this
#     group. The gateway is the only thing that talks to it, over 127.0.0.1.
#   * 22 — no SSH. Management is SSM Session Manager (see iam.tf).
#   * the gateway port from 0.0.0.0/0 — it is CloudFront-only, so the read tier cannot be reached
#     around the edge (which is also where the WAF and the cache live).

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# AWS-managed prefix list of CloudFront's origin-facing ranges. Using the managed list means the
# allowance tracks CloudFront's fleet automatically instead of drifting against a hand-copied CIDR
# set — the #1936 failure mode, one layer down.
data "aws_ec2_managed_prefix_list" "cloudfront_origin" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "node" {
  name        = "rpc-dig-net-node"
  description = "rpc.dig.net node host: peer ports open to the world, read tier from CloudFront only."
  vpc_id      = data.aws_vpc.default.id
}

# --- Peer surface: open to the internet, because a peer that nobody can dial is not a peer. ---

resource "aws_vpc_security_group_ingress_rule" "peer_rpc_v6" {
  security_group_id = aws_security_group.node.id
  description       = "9444 peer-RPC + DHT over mTLS (IPv6, preferred per CLAUDE.md 5.2)."
  cidr_ipv6         = "::/0"
  from_port         = 9444
  to_port           = 9444
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "peer_rpc_v4" {
  security_group_id = aws_security_group.node.id
  description       = "9444 peer-RPC + DHT over mTLS (IPv4 fallback)."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 9444
  to_port           = 9444
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "gossip_v6" {
  security_group_id = aws_security_group.node.id
  description       = "9445 gossip (IPv6)."
  cidr_ipv6         = "::/0"
  from_port         = 9445
  to_port           = 9445
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "gossip_v4" {
  security_group_id = aws_security_group.node.id
  description       = "9445 gossip (IPv4 fallback)."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 9445
  to_port           = 9445
  ip_protocol       = "tcp"
}

# STUN is off by default. An open UDP reflector is a reflection/amplification surface, and being a
# peer does not require being a STUN server. Enable only when the node actually serves it.
resource "aws_vpc_security_group_ingress_rule" "stun_v6" {
  count             = var.enable_stun ? 1 : 0
  security_group_id = aws_security_group.node.id
  description       = "3478 STUN (IPv6)."
  cidr_ipv6         = "::/0"
  from_port         = 3478
  to_port           = 3478
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "stun_v4" {
  count             = var.enable_stun ? 1 : 0
  security_group_id = aws_security_group.node.id
  description       = "3478 STUN (IPv4)."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3478
  to_port           = 3478
  ip_protocol       = "udp"
}

# --- Read tier: CloudFront only. ---

resource "aws_vpc_security_group_ingress_rule" "gateway_from_cloudfront" {
  security_group_id = aws_security_group.node.id
  description       = "Read-tier gateway, reachable ONLY from CloudFront origin-facing ranges."
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront_origin.id
  from_port         = var.gateway_port
  to_port           = var.gateway_port
  ip_protocol       = "tcp"
}

# --- Egress: the node dials peers, S3, and the chain. ---

resource "aws_vpc_security_group_egress_rule" "all_v4" {
  security_group_id = aws_security_group.node.id
  description       = "Outbound to peers, S3 and coinset (IPv4)."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_egress_rule" "all_v6" {
  security_group_id = aws_security_group.node.id
  description       = "Outbound to peers, S3 and coinset (IPv6)."
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

# Gateway endpoint for S3: capsule reads leave via the VPC rather than the internet gateway. Free,
# and it keeps the Mountpoint traffic off the public path.
data "aws_route_tables" "default" {
  vpc_id = data.aws_vpc.default.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.default.ids

  tags = { Name = "rpc-dig-net-s3" }
}
