variable "region" {
  description = "AWS region for the node host and its capsule bucket. Must match the bucket's region — an in-region S3 GET from EC2 has no data-transfer charge, which is what makes the S3-backed capsule cache cheap."
  type        = string
  default     = "us-east-1"
}

variable "peer_host" {
  description = <<-EOT
    Public DNS name of the node itself — the address peers dial on the peer ports. Distinct from
    rpc.dig.net, which is the browser read tier in front of the gateway.

    NOT `node.dig.net`. That name already exists in the zone, is owned by the standing P2P fleet
    lane, and currently points at an address that is not the running fleet node — i.e. it is
    contested AND stale. Taking it would put two writers on one DNS record, which is the exact
    failure dig_ecosystem#1938 documents. `node-rpc.dig.net` is the name the committed
    rpc-peer-endpoint design already reserved for this role.
  EOT
  type        = string
  default     = "node-rpc.dig.net"
}

variable "zone_name" {
  description = "Route 53 hosted zone that owns peer_host."
  type        = string
  default     = "dig.net"
}

variable "capsule_bucket" {
  description = "S3 bucket mounted READ-ONLY at <cache>/modules. Holds one object per published capsule, keyed {store_hex}/{root_hex}.module to match dig-node's module_path layout."
  type        = string
  default     = "dig-rpc-node-capsules"
}

variable "capsule_writer_role_arns" {
  description = "Roles allowed to PUT capsules into the bucket — the hub's publish path, and nothing else. The node's own role is deliberately NOT here: the mount is read-only, which is what makes 'unbounded cache' structurally safe rather than a config value."
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = <<-EOT
    Node host size. Default t4g.small (2 vCPU burst, 2 GiB, Graviton).

    2 GiB is the honest floor, not padding: dig-node reads a whole capsule into RAM to serve it
    (`std::fs::read`, dig-node-core lib.rs:1004) and keeps a 256 MiB in-process decoded-capsule LRU
    on top. Capsules run ~135 MiB today. t4g.micro (1 GiB, about half the price) fits only with
    swap, and swapping during a capsule decode is exactly the wrong place to save six dollars.
  EOT
  type        = string
  default     = "t4g.small"
}

variable "root_volume_gb" {
  description = "gp3 root volume. Holds the OS, the binaries, and the NON-capsule half of the node cache (downloads staging, response cache, peer identity, lockfile). Capsules never land here — they are read straight from S3."
  type        = number
  default     = 12
}

variable "enable_stun" {
  description = "Open 3478/udp for STUN. Default false: the node does not need to be a STUN server to be a peer, and an open UDP reflector is a reflection/amplification surface. Turn on only once the node genuinely serves STUN."
  type        = bool
  default     = false
}

variable "gateway_port" {
  description = "Port the read-tier gateway listens on. Reachable ONLY from the CloudFront origin-facing prefix list, never the open internet."
  type        = number
  default     = 8080
}

variable "dig_node_version" {
  description = "dig-node release running on the host (a tag on DIG-Network/dig-node, e.g. v0.65.0). Recorded on the instance for attribution. Pinned rather than 'latest' so a node restart cannot silently change what is running."
  type        = string
}

variable "dig_node_artifact_url" {
  description = "HTTPS URL of the linux-aarch64 dig-node binary (or tarball) for dig_node_version."
  type        = string
}

variable "dig_node_sha256" {
  description = "SHA-256 of dig_node_artifact_url. Verified on the host before install — this box is internet-facing on two peer ports, so an unverified download is not acceptable."
  type        = string
}

variable "gateway_artifact_url" {
  description = "HTTPS URL of the built gateway binary for this release. Supplied by the deploy workflow from the tagged release asset."
  type        = string
}

variable "gateway_sha256" {
  description = "SHA-256 of gateway_artifact_url. Verified on the host before install."
  type        = string
}
