import pandas as pd
import numpy as np
import random
import uuid
import os

def generate_reference(output_path="sample_reference_features.csv", num_rows=300):
    np.random.seed(42)
    random.seed(42)
    
    data = {
        'entity_id': [str(uuid.uuid4()) for _ in range(num_rows)],
        'window_start': pd.date_range(start="2023-01-01", periods=num_rows, freq="h").astype(str).tolist(),
        'event_count': np.random.normal(50, 10, num_rows).clip(0),
        'failed_login_ratio': np.random.normal(0.01, 0.005, num_rows).clip(0, 1),
        'login_frequency': np.random.normal(5, 2, num_rows).clip(0),
        'geo_velocity': np.random.normal(100, 50, num_rows).clip(0),
        'session_duration_anomaly': np.random.normal(0, 1, num_rows),
        'port_scan_index': np.random.normal(0.05, 0.02, num_rows).clip(0, 1),
        'dns_query_entropy': np.random.normal(4, 0.5, num_rows).clip(0),
        'data_exfil_ratio': np.random.normal(100, 50, num_rows).clip(0),
        'privilege_escalation_score': np.random.normal(0.1, 0.05, num_rows).clip(0, 10),
        'off_hours_ratio': np.random.normal(0.1, 0.05, num_rows).clip(0, 1),
        'connection_burstiness': np.random.normal(10, 5, num_rows).clip(0),
        'generalized_ip': [f"192.168.{random.randint(0,255)}.0/24" for _ in range(num_rows)]
    }
    
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"Generated {num_rows} rows of reference features at {output_path}")

if __name__ == "__main__":
    generate_reference()
