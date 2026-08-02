terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Remote state, configured at init time from CI variables (TF_STATE_BUCKET / TF_LOCK_TABLE),
  # so no bucket name is baked into the repo.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "managed-by" = "dig-loop"
      "service"    = "rpc.dig.net"
      "repo"       = "DIG-Network/rpc.dig.net"
    }
  }
}
