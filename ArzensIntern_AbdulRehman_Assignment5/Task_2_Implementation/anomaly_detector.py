#!/usr/bin/env python3
"""
Anomaly Detection System v1.0
THE ARZENS — AI, Automation & Security Engineering Track
Assignment 5: Isolation Forest Anomaly Detector

This module provides a production-ready unsupervised anomaly detection CLI
using Isolation Forest for network security traffic analysis.
"""

import argparse
import os
import sys
import time
import yaml
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Core features mandated by UNSW-NB15 specification
DEFAULT_FEATURES = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate']


def load_config(config_path="config.yaml"):
    """Load yaml configuration file if available, else return defaults."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {
        "data": {
            "features": DEFAULT_FEATURES,
            "target_column": "label"
        },
        "model": {
            "n_estimators": 100,
            "contamination": 0.1,
            "random_state": 42
        },
        "threshold_tuning": {
            "threshold_grid": [-0.5, -0.3, -0.1, 0.0, 0.1, 0.3]
        },
        "output": {
            "artifact_dir": "model_artifacts",
            "model_file": "model_artifacts/isolation_forest_model.pkl",
            "scaler_file": "model_artifacts/standard_scaler.pkl",
            "plots_dir": "model_artifacts/plots"
        }
    }


def prepare_features(df, features):
    """
    Extract specified numerical features, check for missing features,
    and impute missing values using median imputation.
    """
    missing_cols = [col for col in features if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required feature columns in dataset: {missing_cols}")

    X = df[features].copy()
    # Fill missing values with median
    X = X.fillna(X.median())
    return X


def print_banner():
    """Print standard system header banner."""
    banner = """
+==========================================================+
|               ANOMALY DETECTION SYSTEM v1.0              |
|        Unsupervised Threat Detection via Isolation Forest |
+==========================================================+"""
    print(banner)


def train_mode(data_path, output_model_path, config):
    """
    Train Isolation Forest model on training data.
    """
    print_banner()
    print(f"\n[+] Executing TRAIN Mode...")
    print(f"    Dataset: {data_path}")
    
    if not os.path.exists(data_path):
        print(f"[!] Error: Training data file '{data_path}' not found.")
        sys.exit(1)

    df = pd.read_csv(data_path)
    features = config['data'].get('features', DEFAULT_FEATURES)
    X = prepare_features(df, features)
    
    n_samples, n_features = X.shape
    contamination = config['model'].get('contamination', 0.1)
    n_estimators = config['model'].get('n_estimators', 100)
    random_state = config['model'].get('random_state', 42)

    print("\nTraining Isolation Forest...")
    print(f"  Samples:       {n_samples:,}")
    print(f"  Features:      {n_features} ({', '.join(features)})")
    print(f"  Contamination: {contamination}")
    print(f"  Trees:         {n_estimators}")

    # Feature Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Model Training (Unsupervised)
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_scaled)

    # Ensure output directory exists
    artifact_dir = os.path.dirname(output_model_path) or "model_artifacts"
    os.makedirs(artifact_dir, exist_ok=True)
    scaler_path = os.path.join(artifact_dir, "standard_scaler.pkl")

    # Save model and scaler
    joblib.dump(model, output_model_path)
    joblib.dump(scaler, scaler_path)

    print(f"\n[+] Model trained successfully!")
    print(f"    Saved Model:  {output_model_path}")
    print(f"    Saved Scaler: {scaler_path}")

    # Evaluate on training data / decision function overview
    scores = model.decision_function(X_scaled)
    preds = model.predict(X_scaled)
    anomalies_detected = (preds == -1).sum()
    anomaly_pct = (anomalies_detected / n_samples) * 100

    print(f"\nTraining Set Summary:")
    print(f"  Normal:   {n_samples - anomalies_detected:,} ({(100 - anomaly_pct):.1f}%)")
    print(f"  Anomaly:  {anomalies_detected:,} ({anomaly_pct:.1f}%)")
    print(f"  Score Range: [{scores.min():.4f}, {scores.max():.4f}]")


def predict_mode(data_path, model_path, output_csv_path, config, threshold=0.0):
    """
    Predict anomalies on new/testing data using trained model & scaler.
    """
    print_banner()
    print(f"\n[+] Executing PREDICT Mode...")
    print(f"    Data Path:   {data_path}")
    print(f"    Model Path:  {model_path}")
    
    if not os.path.exists(data_path):
        print(f"[!] Error: Input data file '{data_path}' not found.")
        sys.exit(1)
        
    if not os.path.exists(model_path):
        print(f"[!] Error: Trained model file '{model_path}' not found.")
        sys.exit(1)

    artifact_dir = os.path.dirname(model_path) or "model_artifacts"
    scaler_path = os.path.join(artifact_dir, "standard_scaler.pkl")
    if not os.path.exists(scaler_path):
        print(f"[!] Error: Fitted scaler file '{scaler_path}' not found.")
        sys.exit(1)

    # Load model & scaler
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    df = pd.read_csv(data_path)
    features = config['data'].get('features', DEFAULT_FEATURES)
    X = prepare_features(df, features)
    X_scaled = scaler.transform(X)

    # Compute raw anomaly decision scores
    # sklearn decision_function: lower = more anomalous; threshold < 0 means anomaly in standard setup
    anomaly_scores = model.decision_function(X_scaled)
    
    # Custom thresholding: decision_score < threshold => Anomaly (1), else Normal (0)
    is_anomaly = (anomaly_scores < threshold).astype(int)

    # Construct output dataframe
    results_df = df[features].copy()
    results_df.insert(0, 'timestamp', pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'))
    results_df['anomaly_score'] = anomaly_scores
    results_df['is_anomaly'] = is_anomaly

    # Save to CSV
    output_dir = os.path.dirname(output_csv_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    results_df.to_csv(output_csv_path, index=False)

    total = len(results_df)
    anomalies = is_anomaly.sum()
    normals = total - anomalies

    print(f"\n[+] Prediction Complete!")
    print(f"    Saved Results: {output_csv_path}")
    print(f"\nAnomaly Distribution (Threshold = {threshold}):")
    print(f"  Total Samples: {total:,}")
    print(f"  Normal:        {normals:,} ({(normals/total)*100:.1f}%)")
    print(f"  Anomaly:       {anomalies:,} ({(anomalies/total)*100:.1f}%)")

    # If ground truth 'label' exists, evaluate performance metrics
    target_col = config['data'].get('target_column', 'label')
    if target_col in df.columns:
        y_true = pd.to_numeric(df[target_col], errors='coerce').fillna(0).astype(int).values
        prec = precision_score(y_true, is_anomaly, zero_division=0)
        rec = recall_score(y_true, is_anomaly, zero_division=0)
        f1 = f1_score(y_true, is_anomaly, zero_division=0)

        print(f"\nGround Truth Evaluation (against '{target_col}'):")
        print(f"  Precision: {prec:.4f} ({prec*100:.1f}% of alerts are real)")
        print(f"  Recall:    {rec:.4f} ({rec*100:.1f}% of anomalies caught)")
        print(f"  F1-Score:  {f1:.4f}")


def tune_mode(data_path, config):
    """
    Perform threshold tuning over candidate decision score thresholds.
    """
    print_banner()
    print(f"\n[+] Executing THRESHOLD TUNING Mode...")
    print(f"    Data Path: {data_path}")

    if not os.path.exists(data_path):
        print(f"[!] Error: Data file '{data_path}' not found.")
        sys.exit(1)

    model_path = config['output'].get('model_file', 'model_artifacts/isolation_forest_model.pkl')
    scaler_path = config['output'].get('scaler_file', 'model_artifacts/standard_scaler.pkl')

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print("[!] Model or scaler not found. Training model first...")
        train_mode(data_path, model_path, config)

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    df = pd.read_csv(data_path)
    features = config['data'].get('features', DEFAULT_FEATURES)
    X = prepare_features(df, features)
    X_scaled = scaler.transform(X)

    anomaly_scores = model.decision_function(X_scaled)
    target_col = config['data'].get('target_column', 'label')
    
    if target_col not in df.columns:
        print(f"[!] Target column '{target_col}' not present in dataset. Cannot evaluate metrics for threshold tuning.")
        sys.exit(1)

    y_true = df[target_col].values
    threshold_grid = config['threshold_tuning'].get('threshold_grid', [-0.5, -0.3, -0.1, 0.0, 0.1, 0.3])

    print(f"\nEvaluating Threshold Grid: {threshold_grid}")
    print("-" * 65)
    print(f"{'Threshold':<12}{'Precision':<12}{'Recall':<12}{'F1-Score':<12}{'Anomaly Rate':<12}")
    print("-" * 65)

    results = []
    for th in threshold_grid:
        y_pred = (anomaly_scores < th).astype(int)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        anomaly_rate = (y_pred.sum() / len(y_pred)) * 100

        results.append({
            'threshold': th,
            'precision': prec,
            'recall': rec,
            'f1_score': f1,
            'anomaly_rate': anomaly_rate
        })
        print(f"{th:<12.2f}{prec:<12.4f}{rec:<12.4f}{f1:<12.4f}{anomaly_rate:.1f}%")

    print("-" * 65)

    # Plot Precision-Recall vs Threshold
    plots_dir = config['output'].get('plots_dir', 'model_artifacts/plots')
    os.makedirs(plots_dir, exist_ok=True)
    plot_path = os.path.join(plots_dir, "precision_recall_vs_threshold.png")

    res_df = pd.DataFrame(results)
    plt.figure(figsize=(10, 6))
    plt.plot(res_df['threshold'], res_df['precision'], marker='o', linewidth=2.5, label='Precision', color='#1f77b4')
    plt.plot(res_df['threshold'], res_df['recall'], marker='s', linewidth=2.5, label='Recall', color='#ff7f0e')
    plt.plot(res_df['threshold'], res_df['f1_score'], marker='^', linewidth=2.5, linestyle='--', label='F1-Score', color='#2ca02c')

    plt.axvline(x=0.0, color='gray', linestyle=':', label='Default Threshold (0.0)')
    best_row = res_df.loc[res_df['f1_score'].idxmax()]
    plt.axvline(x=best_row['threshold'], color='red', linestyle='--', label=f"Max F1 Threshold ({best_row['threshold']:.2f})")

    plt.title('Isolation Forest: Precision & Recall vs. Anomaly Score Threshold', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Anomaly Score Threshold (Score < Threshold => Anomaly)', fontsize=12)
    plt.ylabel('Score', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.legend(fontsize=10, loc='best')
    plt.tight_layout()
    plt.savefig(plot_path, dpi=300)
    plt.close()

    print(f"\n[+] Threshold tuning plot saved: {plot_path}")
    print(f"[+] Optimal F1 Threshold: {best_row['threshold']:.2f} (F1 = {best_row['f1_score']:.4f}, Precision = {best_row['precision']:.4f}, Recall = {best_row['recall']:.4f})")


def main():
    parser = argparse.ArgumentParser(description="Isolation Forest Anomaly Detection System v1.0")
    parser.add_argument("--mode", type=str, choices=["train", "predict", "tune"], required=True,
                        help="Execution mode: train, predict, or tune")
    parser.add_argument("--data", type=str, required=True,
                        help="Path to input CSV data file")
    parser.add_argument("--model", type=str, default="model_artifacts/isolation_forest_model.pkl",
                        help="Path to model file (for predict mode)")
    parser.add_argument("--output", type=str, default="results.csv",
                        help="Output path for model or predictions CSV")
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="Path to config yaml file")
    parser.add_argument("--threshold", type=float, default=0.0,
                        help="Decision threshold for predict mode (default: 0.0)")

    args = parser.parse_args()
    config = load_config(args.config)

    if args.mode == "train":
        train_mode(args.data, args.output if args.output != "results.csv" else "model_artifacts/isolation_forest_model.pkl", config)
    elif args.mode == "predict":
        predict_mode(args.data, args.model, args.output, config, threshold=args.threshold)
    elif args.mode == "tune":
        tune_mode(args.data, config)


if __name__ == "__main__":
    main()
