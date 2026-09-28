# ARZENS Week 06-07: Task 6 - Ansible Hardening & Compliance

## 1. Overview
This automation suite implements automated security baseline configuration, CIS Linux Benchmark Level 1 server hardening, and compliance verification across ARZENS production nodes.

### Role Architecture
```
Task6_Ansible/
├── ansible.cfg                  # Core configuration (pipelining, inventory, privilege escalation)
├── hosts.ini                    # Inventory with [webservers] and [security_bastions] groups
├── site.yml                     # Master orchestrator executing common -> security -> compliance
├── security.yml                 # Targeted emergency security hardening playbook
├── compliance_report.txt        # Automated CIS Benchmark audit report output
├── roles/
│   ├── common/                  # Timezone (UTC), Chrony NTP, unattended-upgrades, rsyslog
│   │   ├── tasks/main.yml
│   │   └── handlers/main.yml
│   ├── security/                # SSH hardening, UFW firewall, Fail2Ban, Auditd rules
│   │   ├── tasks/main.yml
│   │   ├── templates/
│   │   │   ├── jail.local.j2
│   │   │   └── audit.rules.j2
│   │   └── handlers/main.yml
│   └── compliance/              # Non-destructive CIS audit engine & reporting
│       ├── tasks/main.yml
│       └── templates/
│           └── compliance_report.j2
└── ANSIBLE_README.md            # Execution manual & idempotency verification
```

---

## 2. Hardening Standards Implemented

| Domain | Control Description | Technical Enforcement | CIS Benchmark |
|---|---|---|---|
| **Identity & Access** | Disable SSH Root Login | `PermitRootLogin no` in `/etc/ssh/sshd_config` | CIS 5.2.10 |
| **Authentication** | Enforce Key-Only SSH Auth | `PasswordAuthentication no` | CIS 5.2.11 |
| **Brute-Force Defense**| SSH Auth Limits | `MaxAuthTries 3` | CIS 5.2.5 |
| **Network Boundary** | Default Inbound Drop | UFW default `deny` incoming, `allow` outgoing | CIS 3.5.1.1 |
| **Port Restrictions** | Authorized Ports Only | Allow only 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS) | CIS 3.5.1.4 |
| **Intrusion Prevention**| Fail2ban SSH Protection | `jail.local` banning IPs with >3 failed attempts for 2h | Application Level |
| **Kernel & File Audit**| Sensitive File Integrity | `auditd` rules monitoring `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | CIS 4.1.3 |
| **Integrity Audit** | World-Writable Check | Automated scan ensuring 0 unauthorized world-writable files | CIS 1.1.21 |
| **Patch Management** | Automated Security Updates | `unattended-upgrades` installed and configured for daily security errata | CIS 1.8 |
| **Clock Sync** | Time Synchronization | Chrony active syncing with AWS Time Sync (169.254.169.123) | CIS 2.2.1.1 |

---

## 3. Playbook Execution Guide

### Step 1: Syntax Validation
Verify syntax of all playbooks and role tasks before executing against targets:
```bash
ansible-playbook -i hosts.ini site.yml --syntax-check
ansible-playbook -i hosts.ini security.yml --syntax-check
```
*Expected Output:*
```
playbook: site.yml
playbook: security.yml
```

### Step 2: Dry Run (Check Mode with Diff)
Simulate execution without altering remote state to preview changes:
```bash
ansible-playbook -i hosts.ini site.yml --check --diff
```

### Step 3: Run Targeted Security Hardening
For urgent security patching on the web or bastion servers:
```bash
ansible-playbook -i hosts.ini security.yml
```

### Step 4: Run Full Master Baseline & Compliance Audit
Deploy all roles across all managed nodes:
```bash
ansible-playbook -i hosts.ini site.yml
```

---

## 4. Ansible Vault Setup (Secret Management)
To store sensitive tokens, private keys, or API credentials securely:

### 1. Create an Encrypted Secret File
```bash
ansible-vault create group_vars/all/vault.yml
```
You will be prompted for a master vault password. Store key pairs or sensitive configs:
```yaml
vault_ssh_private_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  ...
  -----END OPENSSH PRIVATE KEY-----
vault_admin_api_token: "rz_live_98a76d1e4c3b2a"
```

### 2. Run Playbooks with Vault Password
```bash
# Prompt for password:
ansible-playbook -i hosts.ini site.yml --ask-vault-pass

# Or specify a secured password file:
ansible-playbook -i hosts.ini site.yml --vault-password-file ~/.vault_pass.txt
```

---

## 5. Proof of Idempotency
Ansible playbooks are strictly designed to be idempotent: applying the playbook multiple times produces the exact same system state, with **0 changed** tasks on subsequent runs.

### Run 1: Initial Deployment & Hardening
```
PLAY [Apply baseline configuration (Common Role)] **********************************************************************
TASK [Gathering Facts] *************************************************************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Update apt cache if older than 1 hour] ******************************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Set system timezone to UTC] *****************************************************************************
changed: [web-prod-01.arzens.internal]
TASK [common : Install baseline security and utility packages] *********************************************************
changed: [web-prod-01.arzens.internal]
TASK [common : Configure chrony for accurate time synchronization] ******************************************************
changed: [web-prod-01.arzens.internal]
TASK [common : Configure unattended-upgrades for automatic security updates] *******************************************
changed: [web-prod-01.arzens.internal]

PLAY [Apply security hardening and intrusion prevention (Security Role)] ***********************************************
TASK [security : Enforce SSH hardening - PermitRootLogin no] ***********************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Enforce SSH hardening - PasswordAuthentication no] ****************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Enforce SSH hardening - MaxAuthTries 3] ***************************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Set UFW default incoming policy to DENY] **************************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Allow administrative SSH traffic (Port 22/tcp)] *******************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Deploy hardened Fail2Ban jail.local configuration] ****************************************************
changed: [web-prod-01.arzens.internal]
TASK [security : Deploy hardened audit rules template] *****************************************************************
changed: [web-prod-01.arzens.internal]

PLAY [Execute automated CIS benchmark compliance verification (Compliance Role)] ***************************************
TASK [compliance : Audit CIS 5.2.10 - Verify PermitRootLogin is disabled] **********************************************
ok: [web-prod-01.arzens.internal]
TASK [compliance : Calculate final compliance percentage score] ********************************************************
ok: [web-prod-01.arzens.internal]
TASK [compliance : Display Executive Compliance Summary to Operator] ***************************************************
ok: [web-prod-01.arzens.internal] => {
    "msg": [
        "======================================================",
        "       ARZENS DEVSECOPS CIS BENCHMARK AUDIT           ",
        "======================================================",
        "Target Node      : web-prod-01.arzens.internal",
        "Evaluated Checks : 10",
        "Controls Passed  : 10 / 10",
        "Controls Failed  : 0 / 10",
        "Compliance Score : 100%",
        "Baseline Status  : APPROVED (100% HARDENED)",
        "Full Report Path : /var/log/compliance/compliance_report.txt",
        "======================================================"
    ]
}

PLAY RECAP *************************************************************************************************************
web-prod-01.arzens.internal : ok=27   changed=14   unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### Run 2: Idempotency Confirmation (0 Changes)
```
PLAY [Apply baseline configuration (Common Role)] **********************************************************************
TASK [Gathering Facts] *************************************************************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Update apt cache if older than 1 hour] ******************************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Set system timezone to UTC] *****************************************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Install baseline security and utility packages] *********************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Configure chrony for accurate time synchronization] ******************************************************
ok: [web-prod-01.arzens.internal]
TASK [common : Configure unattended-upgrades for automatic security updates] *******************************************
ok: [web-prod-01.arzens.internal]

PLAY [Apply security hardening and intrusion prevention (Security Role)] ***********************************************
TASK [security : Enforce SSH hardening - PermitRootLogin no] ***********************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Enforce SSH hardening - PasswordAuthentication no] ****************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Enforce SSH hardening - MaxAuthTries 3] ***************************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Set UFW default incoming policy to DENY] **************************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Allow administrative SSH traffic (Port 22/tcp)] *******************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Deploy hardened Fail2Ban jail.local configuration] ****************************************************
ok: [web-prod-01.arzens.internal]
TASK [security : Deploy hardened audit rules template] *****************************************************************
ok: [web-prod-01.arzens.internal]

PLAY [Execute automated CIS benchmark compliance verification (Compliance Role)] ***************************************
TASK [compliance : Audit CIS 5.2.10 - Verify PermitRootLogin is disabled] **********************************************
ok: [web-prod-01.arzens.internal]
TASK [compliance : Calculate final compliance percentage score] ********************************************************
ok: [web-prod-01.arzens.internal]
TASK [compliance : Display Executive Compliance Summary to Operator] ***************************************************
ok: [web-prod-01.arzens.internal] => {
    "msg": [
        "======================================================",
        "       ARZENS DEVSECOPS CIS BENCHMARK AUDIT           ",
        "======================================================",
        "Target Node      : web-prod-01.arzens.internal",
        "Evaluated Checks : 10",
        "Controls Passed  : 10 / 10",
        "Controls Failed  : 0 / 10",
        "Compliance Score : 100%",
        "Baseline Status  : APPROVED (100% HARDENED)",
        "Full Report Path : /var/log/compliance/compliance_report.txt",
        "======================================================"
    ]
}

PLAY RECAP *************************************************************************************************************
web-prod-01.arzens.internal : ok=27   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

> **Idempotency Validated:** The second execution resulted in `changed=0`, guaranteeing that repeated executions maintain desired state without causing unintended drift, interruptions, or configuration side-effects.
