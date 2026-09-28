# Task 2: Multi-Format Log Parser

This directory contains the Python parser script that auto-detects and converts three different security log formats into a normalized JSONL output.

## Deliverables
- `ArzensIntern_AbdulRehman_log_parser.py`: Main Python script.
- `test_log_parser.py`: Pytest unit tests covering parsing, normalization, and error handling.
- `sample_firewall_logs.csv`: Sample firewall logs (10+ records + 2 malformed).
- `sample_auth_logs.txt`: Sample authentication logs (10+ records + 2 malformed).
- `sample_dns_logs.txt`: Sample DNS logs (10+ records + 2 malformed).
- `output_normalized.jsonl`: Generated normalized output.

## Usage Instructions

To run the parser against the sample logs:
```bash
python ArzensIntern_AbdulRehman_log_parser.py sample_firewall_logs.csv sample_auth_logs.txt sample_dns_logs.txt --output output_normalized.jsonl
```

### CLI Arguments:
- Positional arguments: One or more log files to parse.
- `--output` / `-o`: Output JSONL file path (default: `output_normalized.jsonl`).
- `--strict`: Enable strict mode, which raises an error and terminates execution on the first malformed line. By default, malformed lines are skipped with a warning.

## Running Unit Tests

To run the unit tests for the parser:
```bash
pytest test_log_parser.py
```
