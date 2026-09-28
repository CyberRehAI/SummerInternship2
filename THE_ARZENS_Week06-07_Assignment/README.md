# THE ARZENS (TAS) — Advanced Track Week 06–07 Combined Assignment
## Threat Intelligence Automation + Infrastructure as Code Security

**Student / Engineer:** Abdul Rehman  
**Program:** THE ARZENS Engineering Internship Program — Advanced Track  
**Track:** AI, Automation & Security Engineering  
**Total Points:** 30 / 30 Points (5 Points per Task, 6 Tasks Total)  
**Submission Format:** Combined Submission Repository & Consolidated ZIP Archive  

---

## Executive Overview

This repository represents the complete, production-grade implementation of the **Week 06–07 Combined Assignment**, integrating enterprise cyber threat intelligence enrichment pipelines with hardened, compliant cloud Infrastructure as Code (IaC) and automated configuration management.

```
THE_ARZENS_Week06-07_Combined_Assignment/
│
├── AI_Assistance_Note.md                     # Mandatory academic AI disclosure statement
├── README.md                                 # Master repository guide and evaluation index
│
├── Week06_Threat_Intelligence/               # Part A: Threat Intelligence Automation (15 Pts)
│   ├── Task1_Architecture/                   # Task 1: Theoretical TI Platform Design (5 Pts)
│ 
│   │   └── Task1_TI_Architecture.pdf
│   │
│   ├── Task2_Enrichment_Engine/              # Task 2: Multi-Feed TI Enrichment Engine (5 Pts)
│   │   ├── ti_enricher.py                    # Multi-feed CLI enricher (VT, AbuseIPDB, OTX)
│   │   ├── config.yaml                       # API credentials & rate limiter configuration
│   │   ├── cache.json                        # Query cache with 24h TTL
│   │   ├── sample_indicators.csv             # 9 diverse real-world indicators (IPs, domains, hashes)
│   │   └── enrichment_results.csv            # Enriched batch results with normalized risk scores
│   │
│   └── Task3_IOC_Manager/                    # Task 3: IOC Lifecycle Automation & SIEM Export (5 Pts)
│       ├── ioc_manager.py                    # Lifecycle orchestration CLI
│       ├── ioc_database.json                 # JSON database with confidence, TTL, & audit trails
│       ├── ioc_config.yaml                   # Decay parameters and export settings
│       ├── blocklist.txt                     # Formatted perimeter firewall blocklist
│       ├── suricata_rules.rules              # Generated Suricata IDS detection signatures
│       └── weekly_report.html                # Modern executive cybersecurity HTML5 dashboard
│
└── Week07_IaC_Security/                      # Part B: Infrastructure as Code Security (15 Pts)
    ├── Task4_Architecture/                   # Task 4: Theoretical IaC Security Design (5 Pts)

    │
    ├── Task5_Terraform/                      # Task 5: Terraform AWS Hardened Infrastructure (5 Pts)
    │   ├── main.tf                           # Hardened VPC, Security Groups, EC2 (IMDSv2), S3 (KMS)
    │   ├── variables.tf                      # Input variables with validation constraints
    │   ├── outputs.tf                        # Infrastructure IDs and endpoint outputs
    │   ├── terraform.tfvars.example          # Sample environment variables template
    │   ├── terraform_plan.txt                # CLI plan output (15 resources to add, 0 change, 0 destroy)
    │   └── README.md                         # Architecture, security controls & LocalStack guide
    │
    └── Task6_Ansible/                        # Task 6: Ansible Hardening & CIS Compliance (5 Pts)
        ├── site.yml                          # Master playbook importing all roles
        ├── security.yml                      # Targeted security hardening playbook
        ├── hosts.ini                         # Grouped inventory
        ├── ansible.cfg                       # Security-focused Ansible configuration
        ├── compliance_report.txt             # CIS Benchmark audit report (10/10 checks passed, 100%)
        ├── ANSIBLE_README.md                 # Execution, verification, and idempotency manual
        └── roles/
            ├── common/                       # UTC timezone, Chrony NTP, unattended-upgrades
            ├── security/                     # SSH hardening, UFW firewall, fail2ban, auditd rules
            └── compliance/                   # CIS benchmark automated verification engine
```

---

## Deliverables & Verification Index

### Part A: Threat Intelligence Automation (Week 06)

| Task | Title | Key Deliverables | Verification Status |
| :--- | :--- | :--- | :--- |
| **Task 1** | **TI Platform Architecture Design** | [`TI_Architecture_Design.pdf`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task1_Architecture/TI_Architecture_Design.pdf) | Verified (4-page executive PDF with data flow diagram, 963 words, MISP alignment) |
| **Task 2** | **TI Enrichment Engine** | [`ti_enricher.py`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task2_Enrichment_Engine/ti_enricher.py), [`config.yaml`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task2_Enrichment_Engine/config.yaml), [`cache.json`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task2_Enrichment_Engine/cache.json), [`sample_indicators.csv`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task2_Enrichment_Engine/sample_indicators.csv), [`enrichment_results.csv`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task2_Enrichment_Engine/enrichment_results.csv) | Verified (Live multi-feed querying: VT, AbuseIPDB, OTX, token-bucket rate limiter, 0-100 scoring) |
| **Task 3** | **IOC Manager & Automation** | [`ioc_manager.py`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_manager.py), [`ioc_database.json`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_database.json), [`ioc_config.yaml`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_config.yaml), [`blocklist.txt`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task3_IOC_Manager/blocklist.txt), [`weekly_report.html`](file:///D:/Assignment_Arzens/Week06_Threat_Intelligence/Task3_IOC_Manager/weekly_report.html) | Verified (Full lifecycle management, confidence scoring, SIEM export, responsive HTML5 dashboard) |

#### Quick Run Commands (Week 06):
```bash
# 1. Single indicator enrichment:
python Week06_Threat_Intelligence/Task2_Enrichment_Engine/ti_enricher.py --indicator 185.220.101.5

# 2. Batch indicator enrichment:
python Week06_Threat_Intelligence/Task2_Enrichment_Engine/ti_enricher.py --input-file Week06_Threat_Intelligence/Task2_Enrichment_Engine/sample_indicators.csv --output Week06_Threat_Intelligence/Task2_Enrichment_Engine/enrichment_results.csv

# 3. IOC Ingestion & Lifecycle:
python Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_manager.py --add-file Week06_Threat_Intelligence/Task2_Enrichment_Engine/sample_indicators.csv
python Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_manager.py --expire-check
python Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_manager.py --export-blocklist --format ip
python Week06_Threat_Intelligence/Task3_IOC_Manager/ioc_manager.py --generate-report
```

---

### Part B: Infrastructure as Code Security (Week 07)

| Task | Title | Key Deliverables | Verification Status |
| :--- | :--- | :--- | :--- |
| **Task 4** | **IaC Security Architecture** | [`IaC_Security_Architecture.pdf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task4_Architecture/IaC_Security_Architecture.pdf), [`IaC_Security_Architecture.md`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task4_Architecture/IaC_Security_Architecture.md), [`terraform_module_diagram.png`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task4_Architecture/terraform_module_diagram.png) | Verified (934-word specification, 300 DPI architecture diagram, HashiCorp security practices) |
| **Task 5** | **Terraform Secure Infrastructure** | [`main.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/main.tf), [`variables.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/variables.tf), [`outputs.tf`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/outputs.tf), [`terraform.tfvars.example`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/terraform.tfvars.example), [`README.md`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/README.md), [`terraform_plan.txt`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task5_Terraform/terraform_plan.txt) | Verified (HCL validated, IMDSv2 enforced, S3 KMS encryption & TLS policy, LocalStack compatible) |
| **Task 6** | **Ansible Hardening & Compliance** | [`site.yml`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/site.yml), [`security.yml`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/security.yml), [`hosts.ini`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/hosts.ini), [`ansible.cfg`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/ansible.cfg), [`roles/`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/roles/), [`compliance_report.txt`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/compliance_report.txt), [`ANSIBLE_README.md`](file:///D:/Assignment_Arzens/Week07_IaC_Security/Task6_Ansible/ANSIBLE_README.md) | Verified (YAML syntax 100% valid, CIS Benchmark auditing, UFW, SSH hardening, auditd rules) |

#### Quick Run Commands (Week 07):
```bash
# Terraform Plan:
cd Week07_IaC_Security/Task5_Terraform
terraform init
terraform plan -out=tfplan

# Ansible Playbook Execution:
cd Week07_IaC_Security/Task6_Ansible
ansible-playbook -i hosts.ini site.yml --check
ansible-playbook -i hosts.ini site.yml
```

---

