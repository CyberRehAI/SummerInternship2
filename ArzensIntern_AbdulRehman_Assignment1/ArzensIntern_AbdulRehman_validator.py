import json
import os
import sys
import jsonschema
from jsonschema import validate, ValidationError

def load_schema(schema_path="schema.json"):
    if not os.path.exists(schema_path):
        raise FileNotFoundError(f"Schema file not found at: {schema_path}")
    with open(schema_path, "r") as f:
        return json.load(f)

def validate_event(event_record, schema):
    """
    Validates a single security event record against the JSON Schema.
    Raises ValidationError with detailed message on failure.
    """
    missing_top_level = []
    if "confidence" not in event_record:
        missing_top_level.append("confidence")
    if "approval" not in event_record:
        missing_top_level.append("approval")
    
    if missing_top_level:
        raise ValidationError(
            f"Record is invalid: missing mandatory top-level section(s): {', '.join(missing_top_level)}"
        )
    

    validate(instance=event_record, schema=schema)

SAMPLES = {
    "Fully Valid Record": {
        "event": {
            "event_id": "8f6b0f1a-b32c-47b2-843e-a89cf625ef3b",
            "timestamp": "2026-07-18T14:30:00Z",
            "source": "firewall-01",
            "event_type": "firewall",
            "severity": "high"
        },
        "enrichment": {
            "threat_intel_matches": [
                {
                    "indicator": "198.51.100.42",
                    "source": "ArzensIntel",
                    "threat_type": "botnet-cnc"
                }
            ],
            "asset_context": {
                "owner": "finance_team",
                "environment": "production",
                "criticality": "high"
            },
            "related_events": []
        },
        "confidence": {
            "score": 0.95,
            "scale": "0.0-1.0",
            "applies_to": ["event_type", "threat_intel_matches"]
        },
        "approval": {
            "approval_status": "approved",
            "approver_id": "analyst-42",
            "approval_timestamp": "2026-07-18T14:35:00Z"
        },
        "audit_trail": [
            {
                "actor": {
                    "id": "system-classifier",
                    "type": "system"
                },
                "action": "Threat Intel Match",
                "timestamp": "2026-07-18T14:30:05Z"
            },
            {
                "actor": {
                    "id": "analyst-42",
                    "type": "human"
                },
                "action": "Host Quarantine Approved",
                "timestamp": "2026-07-18T14:35:00Z"
            }
        ]
    },
    
    "Missing Confidence Fields Record": {
        "event": {
            "event_id": "c983a48e-289e-4e6b-b4a1-b8471c26b42b",
            "timestamp": "2026-07-18T14:31:00Z",
            "source": "auth-server",
            "event_type": "auth",
            "severity": "medium"
        },
        # "confidence" is missing here
        "approval": {
            "approval_status": "auto-approved",
            "approver_id": "system-ruleset",
            "approval_timestamp": "2026-07-18T14:31:05Z"
        },
        "audit_trail": [
            {
                "actor": {
                    "id": "system-ruleset",
                    "type": "system"
                },
                "action": "Auto-Approved Triage",
                "timestamp": "2026-07-18T14:31:05Z"
            }
        ]
    },
    
    "Missing Approval Fields Record": {
        "event": {
            "event_id": "a5e8f49b-732a-4a24-814e-b5f6291a13b4",
            "timestamp": "2026-07-18T14:32:00Z",
            "source": "dns-resolver",
            "event_type": "dns",
            "severity": "low"
        },
        "confidence": {
            "score": 0.60,
            "scale": "0.0-1.0",
            "applies_to": ["event_type"]
        },
        # "approval" is missing here
        "audit_trail": [
            {
                "actor": {
                    "id": "system-ingest",
                    "type": "system"
                },
                "action": "Log Ingestion",
                "timestamp": "2026-07-18T14:32:00Z"
            }
        ]
    }
}

def main():
    print("=" * 60)
    print("ARZENS SECURITY EVENT VALIDATOR")
    print("=" * 60)
    
    # Identify schema path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(base_dir, "schema.json")
    
    try:
        schema = load_schema(schema_path)
        print(f"Loaded schema successfully from: {schema_path}\n")
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to load schema. {e}")
        sys.exit(1)
        
    passed_count = 0
    failed_count = 0
    
    for name, record in SAMPLES.items():
        print(f"Testing Record: {name}")
        print("-" * 50)
        try:
            validate_event(record, schema)
            print("Status: PASS (Record is fully compliant with schema.)")
            passed_count += 1
        except ValidationError as ve:
            print("Status: FAIL (Validation Error detected)")
            print(f"Error Message: {ve.message}")
            failed_count += 1
        except Exception as e:
            print(f"Status: ERROR (Unexpected system error: {e})")
            failed_count += 1
        print()
        
    print("=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total Tested: {passed_count + failed_count}")
    print(f"Passed      : {passed_count}")
    print(f"Failed      : {failed_count}")
    print("=" * 60)
    
    if failed_count > 0:
        sys.exit(0)

if __name__ == "__main__":
    main()
