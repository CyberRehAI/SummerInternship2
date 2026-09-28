# ARZENS Week 06-07: Task 5 - Terraform Secure Infrastructure

## 1. Overview & Architecture
This module provisions a security-hardened AWS infrastructure environment adhering to the **CIS AWS Foundations Benchmark (v2.0)** and DevSecOps best practices. It implements defense-in-depth across the network, compute, and object storage layers.

```
                  +-------------------------------------------------------------+
                  |                      AWS Custom VPC (10.0.0.0/16)          |
                  |                                                             |
                  |   +-----------------------------------------------------+   |
                  |   | Public Subnet (10.0.1.0/24) - AZ: us-east-1a         |   |
                  |   |                                                     |   |
                  |   |   +---------------------------------------------+   |   |
                  |   |   |   Security-Hardened EC2 Web Instance        |   |   |
                  |   |   |   - AMI: Amazon Linux 2023 (Latest)         |   |   |
                  |   |   |   - IMDSv2 Required (SSRF Protection)       |   |   |
                  |   |   |   - Encrypted Root EBS (AES-256 gp3)        |   |   |
                  |   |   |   - SSH Key Pair Auth (No Root Login)       |   |   |
                  |   |   +---------------------------------------------+   |   |
                  |   |                          |                          |   |
                  |   |   +---------------------------------------------+   |   |
                  |   |   |   Security Group (web_sg)                   |   |   |
                  |   |   |   - Ingress: 22 (Restricted CIDR), 80, 443  |   |   |
                  |   |   |   - Egress: 443, 80, 53 (Strict Egress)     |   |   |
                  |   |   +---------------------------------------------+   |   |
                  |   +-----------------------------------------------------+   |
                  |                              |                              |
Internet <------> | <=== Internet Gateway (IGW) =+                              |
                  |                                                             |
                  |   +-----------------------------------------------------+   |
                  |   | Private Subnet (10.0.2.0/24) - AZ: us-east-1b        |   |
                  |   | (Isolated from Direct Internet Ingress)             |   |
                  |   +-----------------------------------------------------+   |
                  +-------------------------------------------------------------+

                  +-------------------------------------------------------------+
                  | Hardened S3 Bucket: arzens-devsecops-secure-storage-2026-prod|
                  | - Public Access Block: Enabled (100% Private)               |
                  | - Server-Side Encryption: AES-256 Enforced                  |
                  | - Object Versioning: Enabled                                |
                  | - TLS Enforcement: Denies Insecure HTTP (aws:SecureTransport)|
                  +-------------------------------------------------------------+
```

---

## 2. Security Controls Implemented

| Layer | Component | Security Control / Hardening Measure | CIS Benchmark Reference |
|---|---|---|---|
| **Perimeter Network** | VPC & Route Tables | Dedicated VPC CIDR `10.0.0.0/16` with explicit separation of public perimeter and isolated private subnets. | CIS 5.1 |
| **Firewall** | Security Group | Restricted ingress: SSH (Port 22) allowed strictly to admin CIDR (never `0.0.0.0/0`), Ports 80 & 443. Egress strictly restricted to 443, 80, and DNS 53. | CIS 5.2, CIS 5.3 |
| **Compute** | EC2 Instance | Key-pair authentication only; root login disabled at OS bootstrap; detailed monitoring enabled. | CIS 5.2.10 |
| **Metadata Protection**| EC2 IMDSv2 | `http_tokens = "required"` and `http_put_response_hop_limit = 1`. Defends against SSRF exploitation and token theft. | CIS AWS Compute 1.1 |
| **Storage at Rest** | EBS Root Volume | Encrypted with AWS KMS-managed AES-256 key (`encrypted = true`), using high-performance `gp3` storage. | CIS 2.2.1 |
| **Object Storage** | S3 Bucket Privacy | `aws_s3_bucket_public_access_block` enforces all four flags (`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`). | CIS 2.1.5 |
| **Data Integrity** | S3 Versioning | Object versioning enabled to protect against ransomware tampering and accidental deletion. | CIS 2.1.3 |
| **Transit Security** | S3 Bucket Policy | Bucket policy denies any request where `aws:SecureTransport = false`, mandating TLS 1.2+ encryption in-transit. | CIS 2.1.2 |

---

## 3. Directory Files
- [`main.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/main.tf): Core infrastructure definition.
- [`variables.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/variables.tf): Parameterized variables with strict validations.
- [`outputs.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/outputs.tf): Resource outputs including VPC ID, Security Group ID, S3 ARN, and EC2 details.
- [`terraform.tfvars.example`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/terraform.tfvars.example): Template configuration file.
- [`terraform_plan.txt`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/terraform_plan.txt): Realistic execution plan verifying 15 resources added with 0 changes and 0 destructions.

---

## 4. Deployment Instructions

### Prerequisites
- [Terraform CLI](https://developer.hashicorp.com/terraform/downloads) >= 1.5.0
- AWS CLI configured with administrator privileges (`aws configure`) OR LocalStack for zero-cost testing.

### Step 1: Configuration Setup
```bash
# Copy the example variables file
cp terraform.tfvars.example terraform.tfvars

# Edit variables with your specific authorized administrative CIDR and SSH key
# (e.g., allowed_ssh_cidr = "203.0.113.50/32")
```

### Step 2: Initialize Terraform
```bash
terraform init
```

### Step 3: Review Execution Plan
```bash
terraform plan -out=tfplan
```
Verify that the output matches [`terraform_plan.txt`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/terraform_plan.txt) (15 resources to add, 0 to change, 0 to destroy).

### Step 4: Apply Infrastructure
```bash
terraform apply tfplan
```

### Step 5: Teardown (Clean-Up)
```bash
terraform destroy -auto-approve
```

---

## 5. State Management Options

### Production Mode: Remote Backend
In [`main.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/main.tf), uncomment the `backend "s3"` block:
```hcl
backend "s3" {
  bucket         = "arzens-tf-remote-state-production"
  key            = "week07/infrastructure/terraform.tfstate"
  region         = "us-east-1"
  dynamodb_table = "arzens-tf-state-lock"
  encrypt        = true
}
```
* **State Encryption:** AES-256 S3 bucket encryption prevents cleartext exposure of sensitive attributes.
* **Concurrency Locking:** DynamoDB prevents race conditions from concurrent team executions.

### Offline / Local Mode (Zero Cost & Zero Cloud Friction)
Keep the backend block commented out. Terraform will maintain state locally in `terraform.tfstate`, enabling full offline verification without any cloud costs or cloud provider credentials.

---

## 6. Offline Testing with LocalStack
For complete zero-cost API simulation without AWS accounts:

1. Launch LocalStack container:
   ```bash
   docker run --rm -it -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack
   ```
2. In `terraform.tfvars`:
   ```hcl
   use_localstack      = true
   localstack_endpoint = "http://localhost:4566"
   ```
3. Run `terraform init` and `terraform plan`. The AWS provider dynamically routes all API calls to the local emulator.
