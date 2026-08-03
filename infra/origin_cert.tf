# The durable home of the origin TLS certificate (#2037).
#
# READ, NOT OWNED — and that is deliberate. Terraform replaces the node instance on every deploy;
# if it also owned the certificate, a taint, a destroy, or a resource rename could take the
# certificate with it, and re-creating one is not free: Let's Encrypt allows five per week per
# exact identifier set, and exhausting that took the read tier down for ~21 hours on 2026-08-03.
# The stack is disposable and the certificate is not, so the certificate outlives the stack.
#
# The same reasoning makes a missing secret a hard, immediate plan failure rather than something
# this configuration silently creates: standing up a certificate is a decision about a
# rate-limited external resource, not a side effect of an apply.
#
# BOOTSTRAPPING A NEW ENVIRONMENT is one command, documented in runbooks/deploy.md:
#
#   aws secretsmanager create-secret --name rpc.dig.net/origin-cert \
#     --description "Origin certificate + certbot state for node-rpc.dig.net"
#
# It may be left empty. The first boot finds nothing to restore, orders a certificate, and
# publishes it; every boot after that restores.
data "aws_secretsmanager_secret" "origin_cert" {
  name = var.origin_cert_secret_name
}
