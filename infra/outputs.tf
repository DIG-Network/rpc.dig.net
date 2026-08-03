output "node_instance_id" {
  description = "EC2 instance id of the node host (for SSM sessions)."
  value       = aws_instance.node.id
}

output "peer_host" {
  description = "Public DNS name peers dial."
  value       = var.peer_host
}

output "peer_ipv4" {
  description = "Stable public IPv4 (EIP) of the node."
  value       = aws_eip.node.public_ip
}

output "peer_ipv6" {
  description = "Public IPv6 of the node — the preferred peer address."
  value       = aws_instance.node.ipv6_addresses
}

output "peer_endpoints" {
  description = "The peer ports this node exposes, for the address book and for verification."
  value = {
    peer_rpc_dht = "${var.peer_host}:9444"
    gossip       = "${var.peer_host}:9445"
    stun         = var.enable_stun ? "${var.peer_host}:3478/udp" : "disabled"
  }
}

output "gateway_origin" {
  description = "Origin address CloudFront should point at for the rpc.dig.net read tier."
  value       = "${aws_eip.node.public_ip}:${var.gateway_port}"
}

output "capsule_bucket" {
  description = "Bucket mounted read-only at the node's capsule cache directory."
  value       = aws_s3_bucket.capsules.id
}

output "capsule_key_layout" {
  description = "Key layout the publish path must write, matching dig-node's module_path."
  value       = "{store_hex}/{root_hex}.dig"
}
