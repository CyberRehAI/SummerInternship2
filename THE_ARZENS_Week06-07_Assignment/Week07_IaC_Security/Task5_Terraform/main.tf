###############################################################################
# ARZENS Week 06-07 Combined Assignment - Task 5: Secure Terraform Infrastructure
# File: main.tf
# Description: Production-grade, CIS Benchmark aligned AWS Infrastructure as Code.
#              Enforces VPC isolation, least-privilege security groups, hardened S3,
#              and IMDSv2/EBS-encrypted EC2 instances.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # ===========================================================================
  # STATE MANAGEMENT: Remote S3 Backend with DynamoDB State Locking & Encryption
  # ===========================================================================
  # For production deployment, uncomment this block to enable encrypted remote state.
  # For local/mock verification without cloud infrastructure, Terraform defaults
  # safely to local backend (terraform.tfstate).
  #
  # backend "s3" {
  #   bucket         = "arzens-tf-remote-state-production"
  #   key            = "week07/infrastructure/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "arzens-tf-state-lock"
  #   encrypt        = true
  # }
}

# =============================================================================
# AWS PROVIDER CONFIGURATION (With Optional LocalStack Compatibility)
# =============================================================================
provider "aws" {
  region = var.aws_region

  # Mock credentials & flags when operating against LocalStack
  access_key                  = var.use_localstack ? "mock_access_key" : null
  secret_key                  = var.use_localstack ? "mock_secret_key" : null
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  default_tags {
    tags = {
      Project      = "ARZENS-Week06-07"
      Environment  = var.environment
      Provisioner  = "Terraform"
      SecurityTier = "CIS-AWS-Hardened"
    }
  }

  # Dynamically route to LocalStack endpoints when var.use_localstack is true
  dynamic "endpoints" {
    for_each = var.use_localstack ? [1] : []
    content {
      s3  = var.localstack_endpoint
      ec2 = var.localstack_endpoint
      iam = var.localstack_endpoint
      sts = var.localstack_endpoint
    }
  }
}

# =============================================================================
# DATA SOURCES: Latest Hardened AMI Lookup
# =============================================================================
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# =============================================================================
# NETWORK LAYER: Dedicated Custom VPC, Subnets & Route Tables
# =============================================================================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "arzens-${var.environment}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "arzens-${var.environment}-igw"
  }
}

# Public Perimeter Subnet (Web / Bastion tier)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false # Security best practice: explicit IP assignment

  tags = {
    Name = "arzens-${var.environment}-public-subnet-1a"
    Tier = "Public"
  }
}

# Private Isolated Subnet (Application / Data tier)
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false

  tags = {
    Name = "arzens-${var.environment}-private-subnet-1b"
    Tier = "Private"
  }
}

# Public Route Table directing outbound Internet traffic via IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "arzens-${var.environment}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Private Route Table (Isolated from direct ingress)
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "arzens-${var.environment}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# =============================================================================
# PERIMETER SECURITY: Hardened Least-Privilege Security Group
# =============================================================================
resource "aws_security_group" "web_sg" {
  name        = "arzens-${var.environment}-web-sg"
  description = "Strictly filtered security group for web tier - CIS Benchmark aligned"
  vpc_id      = aws_vpc.main.id

  # Ingress Rule: Administrative SSH strictly restricted to authorized admin CIDR
  ingress {
    description = "Administrative SSH access restricted to authorized management subnet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  # Ingress Rule: Encrypted Web Traffic
  ingress {
    description = "Secure HTTPS inbound traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Ingress Rule: Cleartext HTTP (Redirect to HTTPS)
  ingress {
    description = "HTTP inbound for TLS redirection"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress Rule: HTTPS outbound for OS security patches, repository mirrors, and API integrations
  egress {
    description = "Outbound HTTPS for OS updates and trusted external API dependencies"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress Rule: HTTP outbound for package repositories
  egress {
    description = "Outbound HTTP for package repository mirrors"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress Rule: DNS lookup resolution
  egress {
    description = "Outbound DNS resolution (UDP)"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "arzens-${var.environment}-web-sg"
  }
}

# =============================================================================
# STORAGE HARDENING: Enterprise Hardened S3 Bucket
# =============================================================================
resource "aws_s3_bucket" "secure_data" {
  bucket        = var.bucket_name
  force_destroy = false

  tags = {
    Name        = var.bucket_name
    DataClass   = "Confidential"
    Hardened    = "True"
  }
}

# S3 Public Access Block: Explicitly disallow any public read/write exposure
resource "aws_s3_bucket_public_access_block" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Versioning: Protects against accidental deletion and ransomware overwrites
resource "aws_s3_bucket_versioning" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Server-Side Encryption: AES-256 / KMS default encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_data" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket Policy: Strictly enforce HTTPS/TLS 1.2+ (Deny insecure cleartext transports)
resource "aws_s3_bucket_policy" "enforce_tls" {
  bucket = aws_s3_bucket.secure_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_data.arn,
          "${aws_s3_bucket.secure_data.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.secure_data]
}

# =============================================================================
# COMPUTE LAYER: Hardened EC2 Instance with IMDSv2 & Encrypted EBS
# =============================================================================
resource "aws_key_pair" "auth_key" {
  key_name   = "arzens-${var.environment}-keypair"
  public_key = var.ssh_public_key

  tags = {
    Name = "arzens-${var.environment}-keypair"
  }
}

resource "aws_instance" "hardened_web" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web_sg.id]
  key_name                    = aws_key_pair.auth_key.key_name
  associate_public_ip_address = true
  monitoring                  = true # Detailed CloudWatch monitoring enabled

  # CIS Requirement: Strictly enforce IMDSv2 token-based requests (Prevents SSRF metadata attacks)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 enforced
    http_put_response_hop_limit = 1          # Prevents metadata traversal across containers/proxies
    instance_metadata_tags      = "enabled"
  }

  # CIS Requirement: Encrypted root volume with gp3 storage tier
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true

    tags = {
      Name = "arzens-${var.environment}-web-root-ebs"
    }
  }

  # Baseline OS Security Hardening Bootstrapping
  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail

              # Update all system packages with latest security errata
              dnf update -y --security

              # Disable root login over SSH immediately
              sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
              sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
              systemctl restart sshd

              # Deploy secure operational banner
              cat << 'BANNER' > /etc/issue.net
              ==================================================================
              AUTHORIZED ACCESS ONLY - ARZENS SECURE CLOUD INFRASTRUCTURE
              All activities are logged and monitored. Unauthorized access is
              strictly prohibited and prosecuted under applicable federal law.
              ==================================================================
              BANNER
              echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
              systemctl restart sshd
              EOF

  tags = {
    Name        = "arzens-${var.environment}-hardened-web"
    Role        = "SecurityHardenedWebServer"
    Compliance  = "CIS-Benchmark-Level-1"
  }
}
