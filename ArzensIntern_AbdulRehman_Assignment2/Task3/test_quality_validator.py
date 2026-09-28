import os
import sys
import json
import pytest
import csv

sys.path.insert(0, os.path.dirname(__file__))

try:
    from ArzensIntern_AbdulRehman_quality_validator import run_validation
except ImportError:
    try:
        from ArzensIntern_Intern_quality_validator import run_validation
    except ImportError:
        from quality_validator import run_validation

@pytest.fixture
def temp_jsonl_file(tmp_path):
    def _create_file(records):
        file_path = tmp_path / "test_records.jsonl"
        with open(file_path, "w", encoding="utf-8") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        return str(file_path)
    return _create_file

def test_check_missing_fields(temp_jsonl_file, tmp_path):
    records = [
        # Missing event_id
        {
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "192.168.1.100",
            "action": "ALLOW",
            "log_type": "firewall"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors > 0
    
    with open(json_file, "r") as f:
        summary = json.load(f)
    assert summary["by_check"]["Check 1: Missing Fields"]["status"] == "ERROR"

def test_check_ip_validation(temp_jsonl_file, tmp_path):
    records = [
        # Invalid IP
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "999.999.999.999",
            "action": "ALLOW",
            "log_type": "firewall"
        },
        # Private IP in external-facing logs (log_type: dns)
        {
            "event_id": "00000000-0000-0000-0000-000000000002",
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "192.168.1.100",
            "action": "QUERY",
            "log_type": "dns"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors > 0   # Due to 999.999.999.999
    assert warnings > 0 # Due to private IP in DNS
    
    with open(json_file, "r") as f:
        summary = json.load(f)
    assert summary["by_check"]["Check 2: IP Validation"]["status"] == "ERROR"

def test_check_timestamp_anomalies(temp_jsonl_file, tmp_path):
    records = [
        # Future timestamp
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2099-12-31T23:59:59Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall"
        },
        # Older than 1 year
        {
            "event_id": "00000000-0000-0000-0000-000000000002",
            "timestamp": "2020-01-01T00:00:00Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors > 0
    assert warnings > 0
    
    with open(json_file, "r") as f:
        summary = json.load(f)
    assert summary["by_check"]["Check 3: Timestamp Anomalies"]["status"] == "ERROR"

def test_check_duplicate_detection(temp_jsonl_file, tmp_path):
    records = [
        {
            "event_id": "same-uuid-1234",
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall"
        },
        {
            "event_id": "same-uuid-1234",
            "timestamp": "2026-07-18T14:30:01Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors > 0
    
    with open(json_file, "r") as f:
        summary = json.load(f)
    assert summary["by_check"]["Check 4: Duplicate Detection"]["status"] == "ERROR"

def test_check_suspicious_patterns(temp_jsonl_file, tmp_path):
    records = [
        # Impossible action/status: DENY action marked as success
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "192.168.1.1",
            "action": "DENY",
            "status": "success",
            "log_type": "firewall"
        },
        # Extreme byte count (>1TB)
        {
            "event_id": "00000000-0000-0000-0000-000000000002",
            "timestamp": "2026-07-18T14:30:01Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall",
            "bytes": 2000000000000 # 2TB
        },
        # Negative bytes
        {
            "event_id": "00000000-0000-0000-0000-000000000003",
            "timestamp": "2026-07-18T14:30:02Z",
            "source_ip": "192.168.1.1",
            "action": "ALLOW",
            "log_type": "firewall",
            "bytes": -500
        },
        # Rapid sequential events (<1s apart from same source IP)
        {
            "event_id": "00000000-0000-0000-0000-000000000004",
            "timestamp": "2026-07-18T14:30:03.000Z",
            "source_ip": "10.0.0.1",
            "action": "ALLOW",
            "log_type": "firewall"
        },
        {
            "event_id": "00000000-0000-0000-0000-000000000005",
            "timestamp": "2026-07-18T14:30:03.500Z",
            "source_ip": "10.0.0.1",
            "action": "ALLOW",
            "log_type": "firewall"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors > 0   # due to negative bytes
    assert warnings > 0 # due to impossible action, extreme bytes, rapid sequential
    
    with open(json_file, "r") as f:
        summary = json.load(f)
    assert summary["by_check"]["Check 5: Suspicious Patterns"]["status"] == "ERROR"

def test_end_to_end_run(temp_jsonl_file, tmp_path):
    records = [
        {
            "event_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-07-18T14:30:00Z",
            "source_ip": "192.168.1.10",
            "action": "ALLOW",
            "status": "success",
            "log_type": "firewall"
        },
        {
            "event_id": "00000000-0000-0000-0000-000000000002",
            "timestamp": "2026-07-18T14:30:01Z",
            "source_ip": "192.168.1.20",
            "action": "SUCCESS",
            "status": "success",
            "log_type": "auth"
        }
    ]
    input_file = temp_jsonl_file(records)
    csv_file = str(tmp_path / "report.csv")
    json_file = str(tmp_path / "summary.json")
    
    errors, warnings = run_validation(input_file, csv_file, json_file)
    assert errors == 0
    assert warnings == 0
    
    # Verify CSV file creation
    assert os.path.exists(csv_file)
    with open(csv_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header == ["line_number", "check_type", "severity", "description", "recommended_action"]
        rows = list(reader)
        assert len(rows) == 0 # no issues
        
    # Verify JSON summary file creation
    assert os.path.exists(json_file)
    with open(json_file, "r", encoding="utf-8") as f:
        summary = json.load(f)
    assert summary["total_records"] == 2
    assert summary["valid_records"] == 2
    assert summary["error_count"] == 0
    assert summary["warning_count"] == 0
