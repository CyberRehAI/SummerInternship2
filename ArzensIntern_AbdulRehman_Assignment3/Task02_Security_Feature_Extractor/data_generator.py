import json
import random
import uuid
from datetime import datetime, timedelta

def generate_events():
    events = []
    
    users = [f"user_{str(i).zfill(4)}" for i in range(1, 11)]
    ips = [f"192.168.1.{i}" for i in range(10, 25)]
    
    start_time = datetime(2026, 7, 28, 0, 0, 0)
    end_time = datetime(2026, 7, 30, 23, 59, 59)
    
    total_duration = int((end_time - start_time).total_seconds())
    
    def random_time():
        return start_time + timedelta(seconds=random.randint(0, total_duration))
        
    event_id_counter = 1
    
    # 1. Auth events
    for _ in range(150): # normal auth
        t = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "auth",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "action": "login",
                "status": random.choices(["success", "failure"], weights=[0.8, 0.2])[0],
                "method": "password",
                "geo_location": {"lat": 33.6 + random.random(), "lon": 73.0 + random.random()}
            }
        })
        event_id_counter += 1
        
    # brute force pattern (20 auth failures)
    bf_ip = random.choice(ips)
    bf_user = random.choice(users)
    bf_time = random_time()
    for _ in range(20):
        bf_time += timedelta(seconds=random.randint(1, 5))
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": bf_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "auth",
            "source_ip": bf_ip,
            "user_id": bf_user,
            "details": {
                "action": "login",
                "status": "failure",
                "method": "password",
                "geo_location": {"lat": 33.68, "lon": 73.04}
            }
        })
        event_id_counter += 1
        
    # impossible travel (10 events, 5 pairs)
    for _ in range(5):
        it_user = random.choice(users)
        it_time = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": it_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "auth",
            "source_ip": random.choice(ips),
            "user_id": it_user,
            "details": {
                "action": "login", "status": "success", "method": "password",
                "geo_location": {"lat": 40.71, "lon": -74.00}
            }
        })
        event_id_counter += 1
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": (it_time + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "auth",
            "source_ip": random.choice(ips),
            "user_id": it_user,
            "details": {
                "action": "login", "status": "success", "method": "password",
                "geo_location": {"lat": 51.50, "lon": -0.12}
            }
        })
        event_id_counter += 1
        
    # off-hours access (10 events)
    for _ in range(10):
        t = start_time + timedelta(days=random.randint(0, 2), hours=random.randint(2, 4), minutes=random.randint(0, 59))
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "auth",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "action": "login", "status": "success", "method": "password",
                "geo_location": {"lat": 33.68, "lon": 73.04}
            }
        })
        event_id_counter += 1

    # 2. Network events
    for _ in range(100):
        t = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "network",
            "source_ip": random.choice(ips),
            "user_id": None,
            "details": {
                "dest_ip": f"203.0.113.{random.randint(1, 255)}",
                "dest_port": random.choice([80, 443, 8080, 53]),
                "bytes_sent": random.randint(100, 2000),
                "bytes_received": random.randint(500, 10000),
                "protocol": random.choice(["TCP", "UDP"]),
                "flags": "SYN,ACK"
            }
        })
        event_id_counter += 1
        
    # Port scan
    ps_ip = random.choice(ips)
    ps_time = random_time()
    for port in range(1000, 1020):
        ps_time += timedelta(seconds=1)
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": ps_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "network",
            "source_ip": ps_ip,
            "user_id": None,
            "details": {
                "dest_ip": "10.0.1.50", "dest_port": port,
                "bytes_sent": 60, "bytes_received": 0, "protocol": "TCP", "flags": "SYN"
            }
        })
        event_id_counter += 1
        
    # Data exfiltration
    exfil_ip = random.choice(ips)
    t = random_time()
    events.append({
        "event_id": f"evt_{str(event_id_counter).zfill(5)}",
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "network",
        "source_ip": exfil_ip,
        "user_id": None,
        "details": {
            "dest_ip": "198.51.100.20", "dest_port": 443,
            "bytes_sent": 500000000,
            "bytes_received": 1000, "protocol": "TCP", "flags": "ACK"
        }
    })
    event_id_counter += 1

    # 3. DNS events
    normal_domains = ["api.microsoft.com", "google.com", "github.com", "aws.amazon.com"]
    for _ in range(80):
        t = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "dns",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "query": random.choice(normal_domains), "query_type": "A",
                "response_code": "NOERROR", "response_ip": "13.107.42.14"
            }
        })
        event_id_counter += 1
        
    # DGA
    for _ in range(10):
        t = random_time()
        dga_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20)) + ".com"
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "dns",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "query": dga_domain, "query_type": "A",
                "response_code": "NXDOMAIN", "response_ip": None
            }
        })
        event_id_counter += 1
        
    # DNS tunneling
    for _ in range(10):
        t = random_time()
        tunnel_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=60)) + ".badsite.com"
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "dns",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "query": tunnel_domain, "query_type": "TXT",
                "response_code": "NOERROR", "response_ip": None
            }
        })
        event_id_counter += 1

    # 4. Endpoint events
    for _ in range(70):
        t = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "endpoint",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "process": random.choice(["explorer.exe", "chrome.exe", "svchost.exe"]),
                "action": "process_start", "parent_process": "explorer.exe",
                "command_line": "", "privilege_change": None
            }
        })
        event_id_counter += 1
        
    # Privilege escalation
    for _ in range(5):
        t = random_time()
        events.append({
            "event_id": f"evt_{str(event_id_counter).zfill(5)}",
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "endpoint",
            "source_ip": random.choice(ips),
            "user_id": random.choice(users),
            "details": {
                "process": "powershell.exe",
                "action": "process_start", "parent_process": "cmd.exe",
                "command_line": "Invoke-Mimikatz", "privilege_change": "user_to_admin"
            }
        })
        event_id_counter += 1
        
    # sort by time
    events.sort(key=lambda x: x["timestamp"])
    
    with open("sample_raw_events.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
            
if __name__ == "__main__":
    generate_events()
