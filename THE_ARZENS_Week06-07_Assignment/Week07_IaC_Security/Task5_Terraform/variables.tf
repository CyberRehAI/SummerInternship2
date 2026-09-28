###############################################################################
# ARZENS Week 06-07 Combined Assignment - Task 5: Secure Terraform Infrastructure
# File: variables.tf
# Description: Configurable inputs with strict type constraints and security defaults
###############################################################################

variable "aws_region" {
  description = "The AWS deployment region for infrastructure resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-\\d{1}$", var.aws_region))
    error_message = "The aws_region variable must follow standard AWS region format (e.g., us-east-1, eu-west-1)."
  }
}

variable "environment" {
  description = "Deployment lifecycle stage (e.g., prod, staging, dev)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be one of: prod, staging, dev."
  }
}

variable "vpc_cidr" {
  description = "Dedicated CIDR block for the custom VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "Must be a valid IPv4 CIDR block notation (e.g., 10.0.0.0/16)."
  }
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public perimeter subnet"
  type        = string
  default     = "10.0.1.0/24"

  validation {
    condition     = can(cidrnetmask(var.public_subnet_cidr))
    error_message = "Must be a valid IPv4 CIDR block notation (e.g., 10.0.1.0/24)."
  }
}

variable "private_subnet_cidr" {
  description = "CIDR block for the private isolated subnet"
  type        = string
  default     = "10.0.2.0/24"

  validation {
    condition     = can(cidrnetmask(var.private_subnet_cidr))
    error_message = "Must be a valid IPv4 CIDR block notation (e.g., 10.0.2.0/24)."
  }
}

variable "allowed_ssh_cidr" {
  description = "Strictly restricted administrative CIDR block authorized for SSH ingress (Port 22). NEVER 0.0.0.0/0."
  type        = string
  default     = "198.51.100.25/32" # Example dedicated bastion or corporate VPN static IP

  validation {
    condition     = var.allowed_ssh_cidr != "0.0.0.0/0"
    error_message = "SECURITY VIOLATION: SSH ingress (Port 22) must NEVER be exposed to 0.0.0.0/0."
  }
}

variable "instance_type" {
  description = "EC2 compute instance sizing"
  type        = string
  default     = "t3.micro"
}

variable "bucket_name" {
  description = "Globally unique name for the hardened enterprise S3 storage bucket"
  type        = string
  default     = "arzens-devsecops-secure-storage-2026-prod"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "S3 bucket names must conform to AWS DNS naming conventions (lowercase, numbers, hyphens, 3-63 chars)."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH public key content used for key-pair authentication (disables passwords & root logins)"
  type        = string
  default     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGd8a+arzensDevSecOpsProductionKeyAdmin2026 admin@arzens.internal"
}

variable "use_localstack" {
  description = "Toggle flag to route provider API calls to LocalStack for zero-overhead, zero-cost offline validation"
  type        = bool
  default     = false
}

variable "localstack_endpoint" {
  description = "Endpoint URL for LocalStack mock AWS emulator"
  type        = string
  default     = "http://localhost:4566"
}
