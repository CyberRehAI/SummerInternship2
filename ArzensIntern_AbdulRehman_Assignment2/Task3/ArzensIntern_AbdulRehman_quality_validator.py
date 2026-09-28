import os
import sys
import json
import csv
from datetime import datetime, timezone
import ipaddress
import argparse

# Helper to check if an IP is private
def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False

# Helper to check if an IP is valid
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

# Determine if a log record is external-facing
def is_external_facing(record):
    source = record.get("source", "") or ""
    original_line = record.get("original_line", "") or ""
    log_type = record.get("log_type", "") or ""
    
    # Check if host/source name implies external facing
    external_keywords = ["web", "gateway", "mail", "external", "vpn"]
    for kw in external_keywords:
        if kw in source.lower() or kw in original_line.lower():
            return True
            
    # DNS queries/responses are often external facing
    if log_type == "dns":
        return True
        
    return False

def run_validation(input_path, csv_path, json_path):
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} does not exist.", file=sys.stderr)
        sys.exit(1)
        
    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))
                
    total_records = len(records)
    
    # Initialize trackers
    issues = [] # List of dict: {line_number, check_type, severity, description, recommended_action}
    event_ids = {} # event_id -> list of line_numbers
    last_event_by_ip = {} # source_ip -> (timestamp_dt, line_number)
    
    # Check status per check
    check_status = {
        "Check 1: Missing Fields": "PASS",
        "Check 2: IP Validation": "PASS",
        "Check 3: Timestamp Anomalies": "PASS",
        "Check 4: Duplicate Detection": "PASS",
        "Check 5: Suspicious Patterns": "PASS"
    }
    
    # Counts per check (for detail reporting)
    check_issues_count = {
        "Check 1: Missing Fields": 0,
        "Check 2: IP Validation": 0,
        "Check 3: Timestamp Anomalies": 0,
        "Check 4: Duplicate Detection": 0,
        "Check 5: Suspicious Patterns": 0
    }
    
    # Detailed line-by-line checks
    records_with_errors = set()
    current_time = datetime.now(timezone.utc)
    
    for idx, record in enumerate(records, 1):
        line_num = idx
        
        # --- Check 1: Missing Critical Fields ---
        missing_fields = []
        for fld in ["event_id", "timestamp", "source_ip", "action", "log_type"]:
            if fld not in record or record[fld] is None or str(record[fld]).strip() == "":
                missing_fields.append(fld)
                
        if missing_fields:
            issues.append({
                "line_number": line_num,
                "check_type": "Check 1: Missing Fields",
                "severity": "ERROR",
                "description": f"Missing critical field(s): {', '.join(missing_fields)}",
                "recommended_action": "Verify upstream log pipeline schema and parsing logic to ensure all core fields are populated."
            })
            records_with_errors.add(line_num)
            check_status["Check 1: Missing Fields"] = "ERROR"
            check_issues_count["Check 1: Missing Fields"] += 1
            
        # --- Check 2: IP Validation ---
        src_ip = record.get("source_ip")
        if src_ip:
            if not is_valid_ip(src_ip):
                issues.append({
                    "line_number": line_num,
                    "check_type": "Check 2: IP Validation",
                    "severity": "ERROR",
                    "description": f"Invalid source IP address format: {src_ip}",
                    "recommended_action": "Sanitize input log data and ensure IP addresses conform to standard IPv4 or IPv6 specifications."
                })
                records_with_errors.add(line_num)
                check_status["Check 2: IP Validation"] = "ERROR"
                check_issues_count["Check 2: IP Validation"] += 1
            elif is_private_ip(src_ip) and is_external_facing(record):
                issues.append({
                    "line_number": line_num,
                    "check_type": "Check 2: IP Validation",
                    "severity": "WARNING",
                    "description": f"Private IP address {src_ip} detected in external-facing log",
                    "recommended_action": "Investigate private IP logging in external-facing systems; check for NAT configuration issues or internal spoofing."
                })
                if check_status["Check 2: IP Validation"] != "ERROR":
                    check_status["Check 2: IP Validation"] = "WARNING"
                check_issues_count["Check 2: IP Validation"] += 1

        # Check target IP for firewall logs
        target_ip = record.get("target_ip")
        if target_ip:
            if not is_valid_ip(target_ip):
                issues.append({
                    "line_number": line_num,
                    "check_type": "Check 2: IP Validation",
                    "severity": "ERROR",
                    "description": f"Invalid target IP address format: {target_ip}",
                    "recommended_action": "Sanitize destination IP field in firewall logs."
                })
                records_with_errors.add(line_num)
                check_status["Check 2: IP Validation"] = "ERROR"
                check_issues_count["Check 2: IP Validation"] += 1
                
        # --- Check 3: Timestamp Anomalies ---
        ts_str = record.get("timestamp")
        if ts_str:
            try:
                # Normalize Z to +00:00 for ISO parsing
                clean_ts = ts_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                
                # Check for future timestamp
                time_diff = (dt - current_time).total_seconds()
                if time_diff > 5: # Allow 5 seconds tolerance for clock skew
                    issues.append({
                        "line_number": line_num,
                        "check_type": "Check 3: Timestamp Anomalies",
                        "severity": "ERROR",
                        "description": f"Future timestamp detected: {ts_str} (current time is {current_time.isoformat()})",
                        "recommended_action": "Sync system clocks via NTP and verify time conversion logic in the log shipper."
                    })
                    records_with_errors.add(line_num)
                    check_status["Check 3: Timestamp Anomalies"] = "ERROR"
                    check_issues_count["Check 3: Timestamp Anomalies"] += 1
                    
                # Check for older than 1 year
                age_days = (current_time - dt).days
                if age_days > 365:
                    issues.append({
                        "line_number": line_num,
                        "check_type": "Check 3: Timestamp Anomalies",
                        "severity": "WARNING",
                        "description": f"Archived log detected: timestamp {ts_str} is older than 1 year ({age_days} days old)",
                        "recommended_action": "Ensure logs are being ingested in real-time or check if backlog reprocessing is expected."
                    })
                    if check_status["Check 3: Timestamp Anomalies"] != "ERROR":
                        check_status["Check 3: Timestamp Anomalies"] = "WARNING"
                    check_issues_count["Check 3: Timestamp Anomalies"] += 1
            except ValueError:
                issues.append({
                    "line_number": line_num,
                    "check_type": "Check 3: Timestamp Anomalies",
                    "severity": "ERROR",
                    "description": f"Unparseable ISO 8601 timestamp format: {ts_str}",
                    "recommended_action": "Enforce ISO 8601 UTC timestamp format standard during ingestion."
                })
                records_with_errors.add(line_num)
                check_status["Check 3: Timestamp Anomalies"] = "ERROR"
                check_issues_count["Check 3: Timestamp Anomalies"] += 1

        # --- Check 4: Duplicate Detection ---
        ev_id = record.get("event_id")
        if ev_id:
            if ev_id in event_ids:
                event_ids[ev_id].append(line_num)
                # First duplicate warning/error
                orig_lines = event_ids[ev_id]
                issues.append({
                    "line_number": line_num,
                    "check_type": "Check 4: Duplicate Detection",
                    "severity": "ERROR",
                    "description": f"Duplicate event_id detected: {ev_id} (previously seen on line(s) {', '.join(map(str, orig_lines[:-1]))})",
                    "recommended_action": "Review duplicate event_ids for log source issues or ingestion pipeline retries."
                })
                records_with_errors.add(line_num)
                check_status["Check 4: Duplicate Detection"] = "ERROR"
                check_issues_count["Check 4: Duplicate Detection"] += 1
            else:
                event_ids[ev_id] = [line_num]
                
        # --- Check 5: Suspicious Patterns ---
        action = record.get("action", "")
        status = record.get("status", "")
        
        # Impossible action/status combinations
        if action == "DENY" and status == "success":
            issues.append({
                "line_number": line_num,
                "check_type": "Check 5: Suspicious Patterns",
                "severity": "WARNING",
                "description": "Impossible action/status combination: DENY action marked as success",
                "recommended_action": "Check line for impossible action/status combination; check firewall rule parser mapping."
            })
            if check_status["Check 5: Suspicious Patterns"] != "ERROR":
                check_status["Check 5: Suspicious Patterns"] = "WARNING"
            check_issues_count["Check 5: Suspicious Patterns"] += 1
        elif action == "FAILURE" and status == "success":
            issues.append({
                "line_number": line_num,
                "check_type": "Check 5: Suspicious Patterns",
                "severity": "WARNING",
                "description": "Impossible action/status combination: FAILURE action marked as success",
                "recommended_action": "Verify authentication parser action-to-status mapping logic."
            })
            if check_status["Check 5: Suspicious Patterns"] != "ERROR":
                check_status["Check 5: Suspicious Patterns"] = "WARNING"
            check_issues_count["Check 5: Suspicious Patterns"] += 1
            
        # Extreme byte counts
        bytes_val = record.get("bytes")
        if bytes_val is not None:
            try:
                b_count = int(bytes_val)
                if b_count < 0:
                    issues.append({
                        "line_number": line_num,
                        "check_type": "Check 5: Suspicious Patterns",
                        "severity": "ERROR",
                        "description": f"Negative byte count detected: {b_count}",
                        "recommended_action": "Investigate system error or integer overflow in firewall log export."
                    })
                    records_with_errors.add(line_num)
                    check_status["Check 5: Suspicious Patterns"] = "ERROR"
                    check_issues_count["Check 5: Suspicious Patterns"] += 1
                elif b_count > 1099511627776: # 1TB
                    issues.append({
                        "line_number": line_num,
                        "check_type": "Check 5: Suspicious Patterns",
                        "severity": "WARNING",
                        "description": f"Extreme byte count detected (>1TB): {b_count} bytes",
                        "recommended_action": "Verify if the high data transfer rate is legitimate or indicates exfiltration / data flood."
                    })
                    if check_status["Check 5: Suspicious Patterns"] != "ERROR":
                        check_status["Check 5: Suspicious Patterns"] = "WARNING"
                    check_issues_count["Check 5: Suspicious Patterns"] += 1
            except ValueError:
                pass # Already handled by parser, but just in case
                
        # Rapid sequential events (<1s apart) from the same source IP
        if src_ip and ts_str:
            try:
                clean_ts = ts_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                if src_ip in last_event_by_ip:
                    last_dt, prev_line = last_event_by_ip[src_ip]
                    diff_seconds = (dt - last_dt).total_seconds()
                    # If events are in order, time difference is >= 0
                    if 0 <= diff_seconds < 1.0:
                        issues.append({
                            "line_number": line_num,
                            "check_type": "Check 5: Suspicious Patterns",
                            "severity": "WARNING",
                            "description": f"Rapid sequential events detected from source IP {src_ip} (<1s apart from line {prev_line}, diff: {diff_seconds:.3f}s)",
                            "recommended_action": "Check line for rapid sequential events; investigate potential brute-force, port scanning, or log flooding."
                        })
                        if check_status["Check 5: Suspicious Patterns"] != "ERROR":
                            check_status["Check 5: Suspicious Patterns"] = "WARNING"
                        check_issues_count["Check 5: Suspicious Patterns"] += 1
                last_event_by_ip[src_ip] = (dt, line_num)
            except ValueError:
                pass
                
    # Summary calculation
    error_count = sum(1 for iss in issues if iss["severity"] == "ERROR")
    warning_count = sum(1 for iss in issues if iss["severity"] == "WARNING")
    valid_records_count = total_records - len(records_with_errors)
    
    # Generate Console Output
    print("=" * 54)
    print("DATA QUALITY VALIDATION REPORT")
    print(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"Input: {os.path.basename(input_path)}")
    print("=" * 54)
    
    for chk, status in check_status.items():
        cnt = check_issues_count[chk]
        if status == "PASS":
            print(f"{chk:<30} PASS ({total_records}/{total_records} records)")
        elif status == "WARNING":
            print(f"{chk:<30} WARNING ({cnt} issue(s) detected)")
        else:
            print(f"{chk:<30} ERROR ({cnt} issue(s) detected)")
            
    print("\nSUMMARY:")
    print(f"Total Records: {total_records:<6} Valid Records: {valid_records_count:<6} Errors: {error_count:<6} Warnings: {warning_count}")
    
    # Gather distinct recommendations
    print("\nRecommendations:")
    recs = []
    for iss in issues:
        rec = f"- {iss['recommended_action']}"
        if rec not in recs:
            recs.append(rec)
            
    if recs:
        for r in recs[:5]: # Show top 5 unique recommendations
            print(r)
    else:
        print("- No issues detected. Pipeline data quality is optimal.")
    print()
    
    # Write CSV report
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_f:
        writer = csv.writer(csv_f)
        writer.writerow(["line_number", "check_type", "severity", "description", "recommended_action"])
        for iss in issues:
            writer.writerow([
                iss["line_number"],
                iss["check_type"],
                iss["severity"],
                iss["description"],
                iss["recommended_action"]
            ])
            
    # Write JSON summary
    summary_data = {
        "total_records": total_records,
        "valid_records": valid_records_count,
        "error_count": error_count,
        "warning_count": warning_count,
        "by_check": {}
    }
    for chk, status in check_status.items():
        summary_data["by_check"][chk] = {
            "status": status,
            "issues_count": check_issues_count[chk]
        }
        
    with open(json_path, "w", encoding="utf-8") as json_f:
        json.dump(summary_data, json_f, indent=2)
        
    print(f"Reports successfully written to:\n- CSV: {csv_path}\n- JSON: {json_path}")
    return error_count, warning_count

def main():
    parser = argparse.ArgumentParser(description="Security Data Quality Validator")
    parser.add_argument("--input", "-i", default="output_normalized.jsonl", help="Input JSONL parsed log file")
    parser.add_argument("--csv", "-c", default="sample_validation_report.csv", help="CSV report file path")
    parser.add_argument("--json", "-j", default="sample_validation_summary.json", help="JSON summary file path")
    
    args = parser.parse_args()
    
    run_validation(args.input, args.csv, args.json)

if __name__ == "__main__":
    main()
