import random
from datetime import datetime, timedelta, timezone
import argparse

# Sample pools for generating realistic logs
IP_POOL = [
    "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",
    "10.0.0.1", "10.0.0.5", "10.0.0.10", "10.0.0.50",
    "172.16.50.5", "172.16.50.10", "172.16.50.100",
    "203.0.113.15", "203.0.113.42", "203.0.113.88",
    "198.51.100.2", "198.51.100.12", "198.51.100.99",
    "8.8.8.8", "1.1.1.1", "8.8.4.4",
    "2001:db8::1", "2001:db8::2", "fe80::1"
]

USERS = ["alice_web", "bob_admin", "charlie_dev", "guest_user", "dev_ci", "backup_agent", "attacker_user", "svc_billing"]
HOSTS = ["dev-workstation", "domain-controller", "mail-server", "web-gateway", "storage-san", "build-server", "corporate-vpn"]
DOMAINS = [
    "google.com", "github.com", "cloudflare.com", "aws.amazon.com", "wikipedia.org",
    "suspicious.example.com", "malicious-domain.ru", "internal.local", "corporate.intranet",
    "microsoft.com", "slack.com", "zoom.us"
]
QTYPES = ["A", "AAAA", "MX", "TXT", "CNAME"]
FIREWALL_ACTIONS = ["ALLOW", "DENY"]
AUTH_STATUSES = ["SUCCESS", "FAILURE"]

def generate_firewall_log(timestamp, src, dst):
    port = random.choice([80, 443, 22, 3389, 53, 8080])
    action = random.choices(FIREWALL_ACTIONS, weights=[0.85, 0.15])[0]
    bytes_count = random.randint(40, 1000000) if action == "ALLOW" else 0
    # Occasionally inject extreme bytes (Check 5)
    if random.random() < 0.001:
        bytes_count = 2 * 1024 * 1024 * 1024 * 1024 # 2TB (extreme byte counts)
    elif random.random() < 0.0005:
        bytes_count = -100 # negative bytes
    return f"{timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')},{src},{dst},{port},{action},{bytes_count}"

def generate_auth_log(timestamp, src):
    user = random.choice(USERS)
    host = random.choice(HOSTS)
    status = random.choices(AUTH_STATUSES, weights=[0.9, 0.1])[0]
    return f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {user} {host} {status} {src}"

def generate_dns_log(timestamp, client):
    domain = random.choice(DOMAINS)
    qtype = random.choice(QTYPES)
    has_response = random.choices([True, False], weights=[0.95, 0.05])[0]
    if has_response:
        if domain == "suspicious.example.com" or domain == "malicious-domain.ru":
            resp = random.choice(["NXDOMAIN", "198.51.100.22"])
        else:
            resp = "142.250.190.46" if qtype == "A" else "2404:6800:4003:c04::64"
        return f"query_time={timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}|client={client}|domain={domain}|type={qtype}|response={resp}"
    else:
        return f"query_time={timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}|client={client}|domain={domain}|type={qtype}"

def main():
    parser = argparse.ArgumentParser(description="Synthetic Log Generator for Performance Testing")
    parser.add_argument("--count", "-n", type=int, default=6000, help="Number of records to generate (default: 6000)")
    parser.add_argument("--output", "-o", default="bulk_input_logs.txt", help="Output file path (default: bulk_input_logs.txt)")
    
    args = parser.parse_args()
    total_records = args.count
    output_path = args.output
    
    start_time = datetime.now(timezone.utc) - timedelta(days=2) # Start 2 days ago
    
    print(f"Generating {total_records} synthetic log records to {output_path}...")
    
    # We will alternate formats to create a combined mixed log file, simulating real-life logs
    records_written = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for idx in range(total_records):
            # Advance timestamp randomly (1 to 10 seconds, occasionally <1s to trigger duplicate/rapid patterns)
            time_step = random.choices(
                [random.randint(1, 10), 0.5, 0.1],
                weights=[0.95, 0.04, 0.01]
            )[0]
            start_time += timedelta(seconds=time_step)
            
            src = random.choice(IP_POOL)
            dst = random.choice(IP_POOL)
            while dst == src:
                dst = random.choice(IP_POOL)
                
            log_type = idx % 3
            if log_type == 0:
                line = generate_firewall_log(start_time, src, dst)
            elif log_type == 1:
                line = generate_auth_log(start_time, src)
            else:
                line = generate_dns_log(start_time, src)
                
            # Introduce occasional malformed lines
            if random.random() < 0.005:
                line = "malformed_log_line_garbage_content_12345"
                
            f.write(line + "\n")
            records_written += 1
            
    print(f"Generation complete. Wrote {records_written} records.")

if __name__ == "__main__":
    main()
