# Task 3: Data Quality Validator

This directory contains the Python data quality validator script that runs 5 distinct checks on normalized logs and generates validation reports (CSV and JSON).

## Deliverables
- `ArzensIntern_AbdulRehman_quality_validator.py`: Main validation script.
- `test_quality_validator.py`: Pytest unit tests covering all five checks plus an end-to-end run.
- `sample_validation_report.csv`: CSV report showing detailed logs of compliance issues.
- `sample_validation_summary.json`: JSON summary metrics from validation.

## Usage Instructions

To run the validator against normalized JSONL log files:
```bash
python ArzensIntern_AbdulRehman_quality_validator.py --input output_normalized.jsonl --csv sample_validation_report.csv --json sample_validation_summary.json
```

### CLI Arguments:
- `--input` / `-i`: Input JSONL parsed log file (default: `output_normalized.jsonl`).
- `--csv` / `-c`: CSV report file path (default: `sample_validation_report.csv`).
- `--json` / `-j`: JSON summary file path (default: `sample_validation_summary.json`).

## Running Unit Tests

To run the unit tests for the quality validator:
```bash
pytest test_quality_validator.py
```
