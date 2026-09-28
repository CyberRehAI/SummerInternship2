import time
import tracemalloc
import subprocess
import os

def profile_task(name, command_args):
    print(f"--- Profiling {name} ---")
    tracemalloc.start()
    start_time = time.perf_counter()
    
    # Run the command as a subprocess
    process = subprocess.run(command_args, capture_output=True, text=True, encoding="utf-8")
    
    end_time = time.perf_counter()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    duration = end_time - start_time
    peak_mem_mb = peak_mem / (1024 * 1024)
    
    print(f"Exit Code: {process.returncode}")
    print(f"Duration: {duration:.4f} seconds")
    print(f"Peak Memory: {peak_mem_mb:.4f} MB")
    if process.stderr:
        print(f"Errors/Stderr:\n{process.stderr[:500]}")
    print()
    
    return duration, peak_mem_mb, process.returncode

def main():
    bulk_input = "bulk_input_logs.txt"
    output_bulk = "output_bulk.jsonl"
    report_csv = "bulk_validation_report.csv"
    summary_json = "bulk_validation_summary.json"
    
    if not os.path.exists(bulk_input):
        print(f"Bulk input file '{bulk_input}' not found. Please run generate_bulk_logs.py first.")
        return
        
    print("Starting Performance Stress Test...\n")
    
    # Get initial record count
    with open(bulk_input, "r", encoding="utf-8") as f:
        input_records = sum(1 for line in f if line.strip())
    
    # 1. Profile Log Parser
    parser_candidates = [
        "ArzensIntern_AbdulRehman_log_parser.py",
        os.path.join("Task2", "ArzensIntern_AbdulRehman_log_parser.py"),
        "ArzensIntern_Intern_log_parser.py",
        os.path.join("Task2", "ArzensIntern_Intern_log_parser.py"),
        "log_parser.py",
        os.path.join("Task2", "log_parser.py")
    ]
    parser_script = next((c for c in parser_candidates if os.path.exists(c)), "log_parser.py")
    parser_args = ["python", parser_script, bulk_input, "--output", output_bulk]
    parser_time, parser_mem, parser_code = profile_task(f"Log Parser ({parser_script})", parser_args)
    
    # Get parsed record count
    if os.path.exists(output_bulk):
        with open(output_bulk, "r", encoding="utf-8") as f:
            parsed_records = sum(1 for line in f if line.strip())
    else:
        parsed_records = 0
        
    # 2. Profile Quality Validator
    validator_candidates = [
        "ArzensIntern_AbdulRehman_quality_validator.py",
        os.path.join("Task3", "ArzensIntern_AbdulRehman_quality_validator.py"),
        "ArzensIntern_Intern_quality_validator.py",
        os.path.join("Task3", "ArzensIntern_Intern_quality_validator.py"),
        "quality_validator.py",
        os.path.join("Task3", "quality_validator.py")
    ]
    validator_script = next((c for c in validator_candidates if os.path.exists(c)), "quality_validator.py")
    validator_args = ["python", validator_script, "--input", output_bulk, "--csv", report_csv, "--json", summary_json]
    validator_time, validator_mem, validator_code = profile_task(f"Data Quality Validator ({validator_script})", validator_args)
    
    # Calculate throughputs
    parser_throughput = parsed_records / parser_time if parser_time > 0 else 0
    validator_throughput = parsed_records / validator_time if validator_time > 0 else 0
    
    total_time = parser_time + validator_time
    combined_throughput = parsed_records / total_time if total_time > 0 else 0
    
    print("=" * 60)
    print("PERFORMANCE RESULTS")
    print("=" * 60)
    print(f"Total Input Records    : {input_records}")
    print(f"Successfully Parsed    : {parsed_records}")
    print("-" * 60)
    print(f"Parser Runtime         : {parser_time:.4f} seconds")
    print(f"Parser Throughput      : {parser_throughput:.2f} records/second")
    print(f"Parser Peak Memory     : {parser_mem:.4f} MB")
    print("-" * 60)
    print(f"Validator Runtime      : {validator_time:.4f} seconds")
    print(f"Validator Throughput   : {validator_throughput:.2f} records/second")
    print(f"Validator Peak Memory  : {validator_mem:.4f} MB")
    print("-" * 60)
    print(f"Combined Pipeline Time : {total_time:.4f} seconds")
    print(f"Pipeline Throughput    : {combined_throughput:.2f} records/second")
    print("=" * 60)

if __name__ == "__main__":
    main()
