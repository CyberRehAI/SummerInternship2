import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(__file__))

try:
    from ArzensIntern_AbdulRehman_log_parser import (
        parse_firewall_line,
        parse_auth_line,
        parse_dns_line,
        detect_and_parse_line,
        normalize_timestamp,
        is_valid_ip
    )
except ImportError:
    try:
        from ArzensIntern_Intern_log_parser import (
            parse_firewall_line,
            parse_auth_line,
            parse_dns_line,
            detect_and_parse_line,
            normalize_timestamp,
            is_valid_ip
        )
    except ImportError:
        from log_parser import (
            parse_firewall_line,
            parse_auth_line,
            parse_dns_line,
            detect_and_parse_line,
            normalize_timestamp,
            is_valid_ip
        )

def test_firewall_parsing():
    line = "2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234"
    record = parse_firewall_line(line)
    assert record["log_type"] == "firewall"
    assert record["source_ip"] == "192.168.1.100"
    assert record["target_ip"] == "10.0.0.50"
    assert record["action"] == "ALLOW"
    assert record["status"] == "success"
    assert record["bytes"] == 15234

def test_auth_parsing():
    line = "2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45"
    record = parse_auth_line(line)
    assert record["log_type"] == "auth"
    assert record["user"] == "alice_web"
    assert record["action"] == "SUCCESS"
    assert record["status"] == "success"
    assert record["source_ip"] == "203.0.113.45"
    assert record["target_ip"] is None

def test_dns_parsing():
    line = "query_time=2026-07-15T10:23:45Z|client=192.168.1.50|domain=suspicious.example.com|type=A|response=NXDOMAIN"
    record = parse_dns_line(line)
    assert record["log_type"] == "dns"
    assert record["source_ip"] == "192.168.1.50"
    assert record["action"] == "RESPONSE"
    assert record["status"] == "failure"
    assert record["dns_query"]["domain"] == "suspicious.example.com"
    assert record["dns_query"]["type"] == "A"
    assert record["dns_query"]["response"] == "NXDOMAIN"

def test_timestamp_normalization():
    # ISO 8601 with Z
    assert normalize_timestamp("2026-07-15T10:23:45Z") == "2026-07-15T10:23:45Z"
    # Space separated
    assert normalize_timestamp("2026-07-15 10:23:45") == "2026-07-15T10:23:45Z"
    # Invalid format
    with pytest.raises(ValueError):
        normalize_timestamp("invalid-date-format")

def test_ip_validation():
    # Valid IPv4
    assert is_valid_ip("192.168.1.1") is True
    # Valid IPv6
    assert is_valid_ip("2001:db8::1") is True
    # Invalid IPs
    assert is_valid_ip("256.256.256.256") is False
    assert is_valid_ip("not-an-ip") is False

def test_malformed_lines_and_errors():
    # Invalid firewall line (missing field)
    with pytest.raises(ValueError):
        parse_firewall_line("2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW")
    
    # Invalid auth line (missing source IP)
    with pytest.raises(ValueError):
        parse_auth_line("2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS")
        
    # Invalid DNS line (missing client)
    with pytest.raises(ValueError):
        parse_dns_line("query_time=2026-07-15T10:23:45Z|domain=example.com|type=A")

    # detect_and_parse_line fails on unknown format
    with pytest.raises(ValueError):
        detect_and_parse_line("completely random text that does not match any format")
