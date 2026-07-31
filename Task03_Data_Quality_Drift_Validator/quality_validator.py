import argparse
import pandas as pd
import numpy as np
import os
import json
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from scipy.stats import ks_2samp
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("QualityValidator")

@dataclass
class ValidationResult:
    check_name: str
    status: str  # 'PASS', 'WARN', 'FAIL'
    details: str
    affected_records: int
    total_records: int
    recommendation: str

class SchemaValidator:
    def __init__(self, expected_columns: List[str]):
        self.expected_columns = expected_columns

    def validate(self, df: pd.DataFrame) -> List[ValidationResult]:
        results = []
        actual_cols = df.columns.tolist()
        missing_cols = set(self.expected_columns) - set(actual_cols)
        extra_cols = set(actual_cols) - set(self.expected_columns)
        
        status = 'FAIL' if missing_cols else ('WARN' if extra_cols else 'PASS')
        details = ""
        if missing_cols:
            details += f"Missing: {', '.join(missing_cols)}. "
        if extra_cols:
            details += f"Extra: {', '.join(extra_cols)}."
            
        results.append(ValidationResult(
            check_name="Schema Columns",
            status=status,
            details=details.strip() or "All expected columns present.",
            affected_records=0,
            total_records=len(df),
            recommendation="Update data generation if missing columns exist."
        ))
        return results

class MissingValueDetector:
    def validate(self, df: pd.DataFrame) -> List[ValidationResult]:
        results = []
        for col in df.columns:
            missing_count = df[col].isnull().sum()
            total_records = len(df)
            pct_missing = missing_count / total_records if total_records > 0 else 0
            
            if pct_missing > 0.20:
                status = 'FAIL'
            elif pct_missing > 0.05:
                status = 'WARN'
            else:
                status = 'PASS'
                
            results.append(ValidationResult(
                check_name=f"Missing Values: {col}",
                status=status,
                details=f"{missing_count} missing ({pct_missing:.2%})",
                affected_records=missing_count,
                total_records=total_records,
                recommendation="Investigate data source for high missing rates."
            ))
        return results

class RangeValidator:
    def __init__(self):
        self.ranges = {
            'failed_login_ratio': (0.0, 1.0),
            'login_frequency': (0.0, 100.0),
            'geo_velocity': (0.0, 200000.0),
            'session_duration_anomaly': (-10.0, 10.0),
            'port_scan_index': (0.0, 1.0),
            'dns_query_entropy': (0.0, 8.0),
            'data_exfil_ratio': (0.0, 1000000.0),
            'privilege_escalation_score': (0.0, 10.0),
            'off_hours_ratio': (0.0, 1.0),
            'connection_burstiness': (0.0, 1000.0)
        }

    def validate(self, df: pd.DataFrame) -> List[ValidationResult]:
        results = []
        for col, (min_val, max_val) in self.ranges.items():
            if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
                out_of_range = df[(df[col] < min_val) | (df[col] > max_val)]
                count = len(out_of_range)
                total = len(df)
                status = 'FAIL' if count > 0 else 'PASS'
                results.append(ValidationResult(
                    check_name=f"Range: {col}",
                    status=status,
                    details=f"{count} records out of [{min_val}, {max_val}]",
                    affected_records=count,
                    total_records=total,
                    recommendation="Cap outliers or review data ingestion pipeline." if count > 0 else "Values within expected range."
                ))
        return results

class DuplicateDetector:
    def validate(self, df: pd.DataFrame) -> List[ValidationResult]:
        results = []
        total = len(df)
        
        exact_dupes = df.duplicated().sum()
        status_exact = 'FAIL' if exact_dupes > 0 else 'PASS'
        results.append(ValidationResult(
            check_name="Exact Duplicates",
            status=status_exact,
            details=f"{exact_dupes} exact duplicate rows",
            affected_records=exact_dupes,
            total_records=total,
            recommendation="Remove duplicate records from dataset." if exact_dupes > 0 else "No exact duplicates."
        ))
        
        if 'entity_id' in df.columns and 'window_start' in df.columns:
            key_dupes = df.duplicated(subset=['entity_id', 'window_start']).sum()
            status_key = 'FAIL' if key_dupes > 0 else 'PASS'
            results.append(ValidationResult(
                check_name="Key Duplicates (entity_id, window_start)",
                status=status_key,
                details=f"{key_dupes} duplicate keys",
                affected_records=key_dupes,
                total_records=total,
                recommendation="Aggregate or deduplicate by key." if key_dupes > 0 else "No key duplicates."
            ))
            
        return results

class DriftDetector:
    def __init__(self):
        pass

    def calculate_psi(self, expected: pd.Series, actual: pd.Series, buckets: int = 10) -> float:
        try:
            expected_pct = np.histogram(expected.dropna(), bins=buckets)[0] / len(expected.dropna())
            actual_pct = np.histogram(actual.dropna(), bins=buckets)[0] / len(actual.dropna())
            
            # Avoid divide by zero and log(0)
            expected_pct = np.where(expected_pct == 0, 0.0001, expected_pct)
            actual_pct = np.where(actual_pct == 0, 0.0001, actual_pct)
            
            psi_value = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
            return float(psi_value)
        except Exception:
            return 0.0

    def validate(self, current_df: pd.DataFrame, reference_df: pd.DataFrame) -> List[Dict[str, Any]]:
        results = []
        numeric_cols = current_df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if col in reference_df.columns:
                curr_data = current_df[col].dropna()
                ref_data = reference_df[col].dropna()
                
                if len(curr_data) == 0 or len(ref_data) == 0:
                    continue
                    
                # KS Test
                ks_stat, p_value = ks_2samp(curr_data, ref_data)
                
                # PSI
                psi_score = self.calculate_psi(ref_data, curr_data)
                
                status = "Significant" if psi_score >= 0.25 else ("Moderate" if psi_score >= 0.1 else "No Drift")
                
                results.append({
                    "feature": col,
                    "psi": psi_score,
                    "ks_pvalue": p_value,
                    "status": status
                })
        return results

class QualityReportGenerator:
    @staticmethod
    def generate_html_report(validation_results: List[ValidationResult], drift_results: List[Dict[str, Any]], output_path: str):
        pass_count = sum(1 for r in validation_results if r.status == 'PASS')
        warn_count = sum(1 for r in validation_results if r.status == 'WARN')
        fail_count = sum(1 for r in validation_results if r.status == 'FAIL')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }}
                h1, h2, h3 {{ color: #ffffff; }}
                .container {{ max-width: 1200px; margin: auto; }}
                .badge {{ padding: 5px 10px; border-radius: 5px; font-weight: bold; color: #fff; display: inline-block; min-width: 50px; text-align: center; }}
                .PASS {{ background-color: #4CAF50; }}
                .WARN {{ background-color: #FF9800; }}
                .FAIL {{ background-color: #F44336; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; background-color: #1e1e1e; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-radius: 8px; overflow: hidden; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
                th {{ background-color: #2c2c2c; }}
                tr:hover {{ background-color: #2a2a2a; }}
                .summary {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .summary-box {{ flex: 1; padding: 20px; background-color: #1e1e1e; border-radius: 8px; text-align: center; font-size: 24px; font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .footer {{ margin-top: 50px; text-align: center; color: #888; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Data Quality & Drift Validation Report</h1>
                
                <div class="summary">
                    <div class="summary-box" style="border-top: 4px solid #4CAF50;">{pass_count}<br><span style="font-size:14px;color:#888;">PASS</span></div>
                    <div class="summary-box" style="border-top: 4px solid #FF9800;">{warn_count}<br><span style="font-size:14px;color:#888;">WARN</span></div>
                    <div class="summary-box" style="border-top: 4px solid #F44336;">{fail_count}<br><span style="font-size:14px;color:#888;">FAIL</span></div>
                </div>

                <h2>Validation Results</h2>
                <table>
                    <tr>
                        <th>Check Name</th>
                        <th>Status</th>
                        <th>Details</th>
                        <th>Affected Records</th>
                        <th>Recommendation</th>
                    </tr>
        """
        for r in validation_results:
            html_content += f"""
                    <tr>
                        <td>{r.check_name}</td>
                        <td><span class="badge {r.status}">{r.status}</span></td>
                        <td>{r.details}</td>
                        <td>{r.affected_records} / {r.total_records}</td>
                        <td>{r.recommendation}</td>
                    </tr>
            """
            
        html_content += """
                </table>
                
                <h2>Drift Analysis</h2>
                <table>
                    <tr>
                        <th>Feature</th>
                        <th>PSI Score</th>
                        <th>KS p-value</th>
                        <th>Drift Status</th>
                    </tr>
        """
        
        for d in drift_results:
            status_class = "FAIL" if d['status'] == "Significant" else ("WARN" if d['status'] == "Moderate" else "PASS")
            html_content += f"""
                    <tr>
                        <td>{d['feature']}</td>
                        <td>{d['psi']:.4f}</td>
                        <td>{d['ks_pvalue']:.4e}</td>
                        <td><span class="badge {status_class}">{d['status']}</span></td>
                    </tr>
            """
            
        html_content += f"""
                </table>
                <div class="footer">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
    @staticmethod
    def generate_drift_markdown(drift_results: List[Dict[str, Any]], output_path: str):
        md_content = "# Drift Analysis Report\n\n"
        md_content += "| Feature | PSI Score | KS p-value | Drift Status | Recommendation |\n"
        md_content += "|---------|-----------|------------|--------------|----------------|\n"
        
        for d in drift_results:
            rec = "Retrain model / investigate." if d['status'] == "Significant" else ("Monitor." if d['status'] == "Moderate" else "None.")
            md_content += f"| {d['feature']} | {d['psi']:.4f} | {d['ks_pvalue']:.4e} | {d['status']} | {rec} |\n"
            
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

def main():
    parser = argparse.ArgumentParser(description="Data Quality and Drift Validator")
    parser.add_argument('--features', required=True, help="Path to features CSV")
    parser.add_argument('--reference', required=True, help="Path to reference CSV")
    parser.add_argument('--output-dir', default=".", help="Output directory")
    args = parser.parse_args()

    logger.info(f"Loading features from {args.features}")
    current_df = pd.read_csv(args.features)
    
    logger.info(f"Loading reference from {args.reference}")
    reference_df = pd.read_csv(args.reference)
    
    expected_cols = [
        'entity_id', 'window_start', 'event_count', 'failed_login_ratio', 
        'login_frequency', 'geo_velocity', 'session_duration_anomaly', 
        'port_scan_index', 'dns_query_entropy', 'data_exfil_ratio', 
        'privilege_escalation_score', 'off_hours_ratio', 'connection_burstiness', 
        'generalized_ip'
    ]
    
    all_results = []
    
    logger.info("Running Schema Validation")
    sv = SchemaValidator(expected_cols)
    all_results.extend(sv.validate(current_df))
    
    logger.info("Running Missing Value Detection")
    mvd = MissingValueDetector()
    all_results.extend(mvd.validate(current_df))
    
    logger.info("Running Range Validation")
    rv = RangeValidator()
    all_results.extend(rv.validate(current_df))
    
    logger.info("Running Duplicate Detection")
    dd = DuplicateDetector()
    all_results.extend(dd.validate(current_df))
    
    logger.info("Running Drift Analysis")
    drift_detector = DriftDetector()
    drift_results = drift_detector.validate(current_df, reference_df)
    
    html_out = os.path.join(args.output_dir, "sample_quality_report.html")
    md_out = os.path.join(args.output_dir, "drift_analysis.md")
    
    logger.info(f"Generating Reports: {html_out}, {md_out}")
    report_gen = QualityReportGenerator()
    report_gen.generate_html_report(all_results, drift_results, html_out)
    report_gen.generate_drift_markdown(drift_results, md_out)
    
    logger.info("Validation complete.")

if __name__ == "__main__":
    main()
