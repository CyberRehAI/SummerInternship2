### Assignment 2: Python Security Automation & Data Pipeline
- [ArzensIntern_AbdulRehman_DesignMemo.docx](file:///Task1/ArzensIntern_AbdulRehman_DesignMemo.docx) (Design Memo Word Doc)
- [ArzensIntern_AbdulRehman_log_parser.py](file:///Task2/ArzensIntern_AbdulRehman_log_parser.py) (Log parser utility)
- [ArzensIntern_AbdulRehman_quality_validator.py](file:///Task3/ArzensIntern_AbdulRehman_quality_validator.py) (Data quality validation utility)
- [generate_bulk_logs.py](file:///Task4/generate_bulk_logs.py) (Synthetic log generator for performance stress test)
- [run_performance_test.py](file:///run_performance_test.py) (Performance benchmarking suite wrapper)
- [test_log_parser.py](file:///Task2/test_log_parser.py) (Pytest unit tests for log parser)
- [test_quality_validator.py](file:///Task3/test_quality_validator.py) (Pytest unit tests for quality validator)
- [PERFORMANCE.md](file:///Task4/PERFORMANCE.md) (Scale stress test performance analysis report)

### Support Files & Run Outputs
- `Task2/sample_firewall_logs.csv` (10+ records + 2 malformed)
- `Task2/sample_auth_logs.txt` (10+ records + 2 malformed)
- `Task2/sample_dns_logs.txt` (10+ records + 2 malformed)
- `Task2/output_normalized.jsonl` (Parsed events from sample logs)
- `Task3/sample_validation_report.csv` (CSV compliance issues list from sample validation)
- `Task3/sample_validation_summary.json` (JSON summary metrics from sample validation)
- `bulk_input_logs.txt` (6,000 generated log records for stress test)
- `output_bulk.jsonl` (Parsed events from bulk stress test)
- `bulk_validation_report.csv` (CSV validation issues list from bulk validation)
- `bulk_validation_summary.json` (JSON summary metrics from bulk validation)

---

## Getting Started

### Prerequisites
Make sure you have Python 3.11+ installed. The pipeline uses the following third-party dependencies:
- `jsonschema` (for event schema validation)
- `python-docx` (for document compilation)
- `pytest` (for unit testing)

To install them, run:
```bash
pip install jsonschema python-docx pytest
```

---

## Assignment 2: Usage Instructions

### Step 1: Parse Security Logs
`log_parser.py` is a command-line interface that auto-detects and parses Firewall, Authentication, and DNS logs.

To parse the provided sample input logs:
```bash
python log_parser.py sample_firewall_logs.csv sample_auth_logs.txt sample_dns_logs.txt --output output_normalized.jsonl
```

### Step 2: Validate Data Quality
`quality_validator.py` validates the parsed JSONL logs against 5 specific quality checks and generates CSV and JSON reports.

To run the validator against the parsed output:
```bash
python quality_validator.py --input output_normalized.jsonl --csv sample_validation_report.csv --json sample_validation_summary.json
```

### Step 3: Run the Performance Stress Test Suite
The benchmarking suite generates a synthetic dataset of 6,000 log records and measures the parsing and validation performance.

To run the complete test:
```bash
python run_performance_test.py
```
This automatically invokes:
1. `generate_bulk_logs.py` to create `bulk_input_logs.txt` (6,000 records).
2. `log_parser.py` to parse them into `output_bulk.jsonl`.
3. `quality_validator.py` to validate and output `bulk_validation_report.csv`.
It profiles runtime, peak memory, and throughput (records/sec) and prints the results in the terminal.

---

## Running Unit Tests
All unit tests are written in Pytest. They cover 100% of the log formats, normalization features, validation rule sets, and error paths.

To run all unit tests in the repository:
```bash
pytest
```
*Expected result: 12 passed tests (6 for log parser, 6 for quality validator).*
