import os
import sys
import json
import uuid
import re
from datetime import datetime, timezone
import ipaddress
import argparse

# IP address validation helper
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

# ISO 8601 timestamp normalizer helper
def normalize_timestamp(ts_str):
    """
    Normalizes a timestamp string to YYYY-MM-DDTHH:MM:SSZ format.
    Accepts space-delimited or ISO 8601 styles.
    """
    ts_str = ts_str.strip()
    
    # Try parsing space-separated: YYYY-MM-DD HH:MM:SS
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Try parsing ISO 8601 with Z or offset
    # Remove 'Z' at the end for strptime parsing or use fromisoformat
    clean_ts = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(clean_ts)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ValueError(f"Invalid timestamp format: {ts_str}")

def parse_firewall_line(line):
    # CSV-style: timestamp,src_ip,dst_ip,port,action,bytes
    parts = [p.strip() for p in line.split(",")]
    if len(parts) != 6:
        raise ValueError(f"Firewall log must have exactly 6 fields, got {len(parts)}")
        
    ts, src_ip, dst_ip, port, action, bytes_str = parts
    
    # Normalize timestamp
    norm_ts = normalize_timestamp(ts)
    
    # Validate IPs
    if not is_valid_ip(src_ip):
        raise ValueError(f"Invalid source IP: {src_ip}")
    if not is_valid_ip(dst_ip):
        raise ValueError(f"Invalid destination IP: {dst_ip}")
        
    # Validate Port
    try:
        port_val = int(port)
        if not (0 <= port_val <= 65535):
            raise ValueError(f"Port out of range: {port}")
    except ValueError:
        raise ValueError(f"Invalid port: {port}")
        
    # Validate bytes
    try:
        bytes_val = int(bytes_str)
    except ValueError:
        raise ValueError(f"Invalid bytes count: {bytes_str}")
        
    # Normalize action and status
    norm_action = action.upper()
    if norm_action not in ["ALLOW", "DENY"]:
        raise ValueError(f"Unexpected firewall action: {action}")
        
    status = "success" if norm_action == "ALLOW" else "failure"
    
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": norm_ts,
        "source_ip": src_ip,
        "target_ip": dst_ip,
        "user": None,
        "action": norm_action,
        "status": status,
        "log_type": "firewall",
        "original_line": line,
        "parsed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bytes": bytes_val  # Preserved for the quality validator checks
    }
    return record

def parse_auth_line(line):
    # Space-delimited: date time user host status source_ip
    # e.g., 2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45
    parts = [p.strip() for p in line.split() if p.strip()]
    if len(parts) < 6:
        raise ValueError(f"Auth log must have at least 6 space-separated fields, got {len(parts)}")
        
    # Join date and time
    ts = f"{parts[0]} {parts[1]}"
    user = parts[2]
    host = parts[3]
    status_str = parts[4].upper()
    src_ip = parts[5]
    
    # Normalize timestamp
    norm_ts = normalize_timestamp(ts)
    
    # Validate IP
    if not is_valid_ip(src_ip):
        raise ValueError(f"Invalid source IP: {src_ip}")
        
    if status_str not in ["SUCCESS", "FAILURE"]:
        raise ValueError(f"Unexpected auth status: {parts[4]}")
        
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": norm_ts,
        "source_ip": src_ip,
        "target_ip": None,
        "user": user,
        "action": status_str,
        "status": "success" if status_str == "SUCCESS" else "failure",
        "log_type": "auth",
        "original_line": line,
        "parsed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    return record

def parse_dns_line(line):
    # Key-value style: query_time=...|client=...|domain=...|type=...|response=...
    # e.g., query_time=2026-07-15T10:23:45Z|client=192.168.1.50|domain=suspicious.example.com|type=A|response=NXDOMAIN
    parts = line.split("|")
    kv = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            kv[k.strip()] = v.strip()
            
    required_keys = ["query_time", "client", "domain", "type"]
    missing = [k for k in required_keys if k not in kv]
    if missing:
        raise ValueError(f"DNS log missing required fields: {', '.join(missing)}")
        
    ts = kv["query_time"]
    src_ip = kv["client"]
    domain = kv["domain"]
    qtype = kv["type"]
    response = kv.get("response")
    
    # Normalize timestamp
    norm_ts = normalize_timestamp(ts)
    
    # Validate IP
    if not is_valid_ip(src_ip):
        raise ValueError(f"Invalid client IP: {src_ip}")
        
    # Check action
    if response:
        action = "RESPONSE"
        # Map response status
        if response in ["NXDOMAIN", "SERVFAIL"]:
            status = "failure"
        else:
            status = "success"
    else:
        action = "QUERY"
        status = "unknown"
        
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": norm_ts,
        "source_ip": src_ip,
        "target_ip": None,
        "user": None,
        "action": action,
        "status": status,
        "log_type": "dns",
        "original_line": line,
        "parsed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dns_query": {
            "domain": domain,
            "type": qtype,
            "response": response
        }
    }
    return record

def detect_and_parse_line(line):
    line = line.strip()
    if not line:
        return None
        
    # Try DNS detection
    if "query_time=" in line and "|" in line:
        return parse_dns_line(line)
        
    # Try Firewall detection: contains commas and ALLOW/DENY
    if "," in line and any(act in line.upper() for act in ["ALLOW", "DENY"]):
        return parse_firewall_line(line)
        
    # Try Auth detection: space delimited with SUCCESS/FAILURE
    if any(st in line.upper() for st in ["SUCCESS", "FAILURE"]):
        # Verify it has spaces
        if len(line.split()) >= 6:
            return parse_auth_line(line)
            
    # Fallback/Unknown format
    raise ValueError("Unable to determine log format or line format is invalid.")

def parse_log_file(file_path, ignore_errors=True):
    parsed_records = []
    skipped_count = 0
    
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                record = detect_and_parse_line(line)
                if record:
                    parsed_records.append(record)
            except Exception as e:
                skipped_count += 1
                sys.stderr.write(f"WARNING: Skipping line {idx} in {file_path}: {e}\n")
                if not ignore_errors:
                    raise e
                    
    return parsed_records, skipped_count

def main():
    parser = argparse.ArgumentParser(description="Multi-Format Security Log Parser")
    parser.add_argument("input_files", nargs="+", help="One or more input log files to parse")
    parser.add_argument("--output", "-o", default="output_normalized.jsonl", help="Output JSONL file path")
    parser.add_argument("--strict", action="store_true", help="Raise error and exit on first malformed line")
    
    args = parser.parse_args()
    
    all_records = []
    total_skipped = 0
    
    for file_path in args.input_files:
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
            
        print(f"Parsing file: {file_path}...")
        records, skipped = parse_log_file(file_path, ignore_errors=not args.strict)
        all_records.extend(records)
        total_skipped += skipped
        print(f"Parsed {len(records)} records, skipped {skipped} malformed lines.")
        
    # Write to output JSONL
    output_path = args.output
    try:
        with open(output_path, "w", encoding="utf-8") as out_f:
            for record in all_records:
                out_f.write(json.dumps(record) + "\n")
        print(f"\nSuccessfully wrote {len(all_records)} normalized records to {output_path}")
        if total_skipped > 0:
            print(f"Total skipped malformed lines: {total_skipped}")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
