data "aws_route53_zone" "zone" {
  name         = "${var.zone_name}."
  private_zone = false
}

# The peer address. Dual-stack: AAAA is what peers should prefer (CLAUDE.md 5.2), A is the
# fallback for v4-only networks.
resource "aws_route53_record" "peer_v4" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = var.peer_host
  type    = "A"
  ttl     = 300
  records = [aws_eip.node.public_ip]
}

resource "aws_route53_record" "peer_v6" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = var.peer_host
  type    = "AAAA"
  ttl     = 300
  records = aws_instance.node.ipv6_addresses
}
