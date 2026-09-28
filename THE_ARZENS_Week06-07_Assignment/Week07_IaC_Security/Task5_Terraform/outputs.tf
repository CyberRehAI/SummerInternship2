###############################################################################
# ARZENS Week 06-07 Combined Assignment - Task 5: Secure Terraform Infrastructure
# File: outputs.tf
# Description: Exposed resource IDs, networking parameters, and security attributes
###############################################################################

output "vpc_id" {
  description = "Unique identifier of the provisioned custom VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block assigned to the custom VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_id" {
  description = "Subnet ID of the public perimeter subnet"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Subnet ID of the private isolated subnet"
  value       = aws_subnet.private.id
}

output "security_group_id" {
  description = "Security Group ID applied to the hardened EC2 instance"
  value       = aws_security_group.web_sg.id
}

output "s3_bucket_arn" {
  description = "Amazon Resource Name (ARN) of the hardened S3 storage bucket"
  value       = aws_s3_bucket.secure_data.arn
}

output "s3_bucket_id" {
  description = "Name/ID of the hardened S3 storage bucket"
  value       = aws_s3_bucket.secure_data.id
}

output "ec2_instance_id" {
  description = "Instance ID of the provisioned hardened EC2 server"
  value       = aws_instance.hardened_web.id
}

output "ec2_public_ip" {
  description = "Elastic/Public IPv4 address assigned to the hardened EC2 instance"
  value       = aws_instance.hardened_web.public_ip
}

output "ec2_private_ip" {
  description = "Private IPv4 address assigned to the hardened EC2 instance"
  value       = aws_instance.hardened_web.private_ip
}

output "imds_v2_enforced" {
  description = "Confirmation of strict IMDSv2 token requirement"
  value       = aws_instance.hardened_web.metadata_options[0].http_tokens == "required"
}
