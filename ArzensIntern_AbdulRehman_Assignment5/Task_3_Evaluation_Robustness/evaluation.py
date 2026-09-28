#!/usr/bin/env python3
"""
Model Evaluation & Robustness Analysis Script (Task 3)
THE ARZENS — AI, Automation & Security Engineering Track
Assignment 5: Anomaly Detection System Evaluation

This script performs comprehensive evaluation, confusion matrix rendering,
per-class attack analysis, adversarial evasion robustness testing, and
SOC alert fatigue impact analysis.
"""

import os
import sys
import yaml
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

DEFAULT_FEATURES = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate']


def load_config(config_path="config.yaml"):
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {
        "data": {
            "features": DEFAULT_FEATURES,
            "target_column": "label",
            "attack_cat_column": "attack_cat",
            "test_file": "data/UNSW_NB15_testing-set.csv"
        },
        "evaluation": {
            "events_per_day": 10000,
            "analyst_capacity_per_day": 50
        },
        "output": {
            "model_file": "model_artifacts/isolation_forest_model.pkl",
            "scaler_file": "model_artifacts/standard_scaler.pkl",
            "plots_dir": "model_artifacts/plots"
        }
    }


def print_header(title):
    print("\n" + "=" * 65)
    print(f" {title.upper()}")
    print("=" * 65)


def plot_confusion_matrix(cm, save_path):
    """Plot and save confusion matrix visual graph."""
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    classes = ['Normal (0)', 'Anomaly (1)']
    ax.set(xticks=np.arange(cm.shape[1]),
           yticks=np.arange(cm.shape[0]),
           xticklabels=classes, yticklabels=classes,
           title='Isolation Forest - Confusion Matrix',
           ylabel='Actual Label',
           xlabel='Predicted Label')

    # Format values inside matrix
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, f"{cm[i, j]:,}",
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=12, fontweight='bold')

    plt.tight_layout()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300)
    plt.close()


def run_evaluation(test_file=None, model_path=None, scaler_path=None, threshold=0.0):
    config = load_config()
    test_file = test_file or config['data'].get('test_file', 'data/UNSW_NB15_testing-set.csv')
    model_path = model_path or config['output'].get('model_file', 'model_artifacts/isolation_forest_model.pkl')
    scaler_path = scaler_path or config['output'].get('scaler_file', 'model_artifacts/standard_scaler.pkl')

    if not os.path.exists(test_file):
        print(f"[!] Error: Test data file '{test_file}' not found.")
        sys.exit(1)
    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print(f"[!] Error: Model or Scaler file not found. Train model first.")
        sys.exit(1)

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    df = pd.read_csv(test_file)

    features = config['data'].get('features', DEFAULT_FEATURES)
    target_col = config['data'].get('target_column', 'label')

    X = df[features].fillna(df[features].median())
    X_scaled = scaler.transform(X)

    # Predictions and Anomaly Scores
    scores = np.nan_to_num(model.decision_function(X_scaled), nan=0.0)
    y_pred = (scores < threshold).astype(int)
    y_true = pd.to_numeric(df[target_col], errors='coerce').fillna(0).astype(int).values

    # Metric Calculations
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    total = len(y_true)

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print_header("Part A: Standard Model Evaluation")
    print(f"Dataset:            {test_file} ({total:,} samples)")
    print(f"Decision Threshold: {threshold:.2f}\n")

    print(f"Confusion Matrix:")
    print(f"  True Negatives  (TN): {tn:>8,}  | Correctly identified normal")
    print(f"  False Positives (FP): {fp:>8,}  | Normal flagged as anomaly (False Alarm)")
    print(f"  False Negatives (FN): {fn:>8,}  | Anomaly missed")
    print(f"  True Positives  (TP): {tp:>8,}  | Correctly identified anomaly\n")

    print("Performance Metrics:")
    print(f"  Accuracy:    {acc*100:.2f}%")
    print(f"  Precision:   {prec*100:.2f}%  ({int(prec*100)}% of alerts are real attacks)")
    print(f"  Recall:      {rec*100:.2f}%  (catches {int(rec*100)}% of total anomalies)")
    print(f"  F1-Score:    {f1:.4f}")
    print(f"  FPR:         {fpr*100:.2f}%  ({int(fpr*1000)} false alarms per 1,000 events)")

    # Save Confusion Matrix Plot
    plots_dir = config['output'].get('plots_dir', 'model_artifacts/plots')
    cm_plot_path = os.path.join(plots_dir, "confusion_matrix.png")
    plot_confusion_matrix(cm, cm_plot_path)
    print(f"\n[+] Confusion Matrix plot saved: {cm_plot_path}")

    # Per-Class Attack Breakdown (if attack_cat available)
    attack_cat_col = config['data'].get('attack_cat_column', 'attack_cat')
    if attack_cat_col in df.columns:
        print_header("Per-Class Attack Detection Rate")
        df['y_pred'] = y_pred
        attack_summary = []
        for cat, group in df.groupby(attack_cat_col):
            cat_clean = str(cat).strip()
            total_cat = len(group)
            detected_cat = group['y_pred'].sum()
            det_rate = (detected_cat / total_cat) * 100 if total_cat > 0 else 0
            attack_summary.append({
                'Category': cat_clean,
                'Total Events': total_cat,
                'Detected': detected_cat,
                'Detection Rate (%)': det_rate
            })

        att_df = pd.DataFrame(attack_summary).sort_values(by='Total Events', ascending=False)
        print(f"{'Attack Category':<22}{'Total Events':<15}{'Detected':<12}{'Detection Rate':<15}")
        print("-" * 65)
        for _, row in att_df.iterrows():
            print(f"{row['Category']:<22}{row['Total Events']:<15,}{row['Detected']:<12,}{row['Detection Rate (%)']:<15.1f}%")

    # Part B: Robustness / Evasion Check
    print_header("Part B: Adversarial Evasion Robustness Test")
    anom_mask = (y_true == 1)
    X_anom = X_scaled[anom_mask]
    total_anom = len(X_anom)

    if total_anom == 0:
        print("[!] No anomalies found in test set to run evasion check.")
    else:
        # Test 1: 10% Noise Addition
        np.random.seed(42)
        noise = np.random.normal(0, 0.10, X_anom.shape)
        X_noise = X_anom + noise
        scores_noise = model.decision_function(X_noise)
        preds_noise = (scores_noise < threshold).astype(int)
        detected_noise = preds_noise.sum()
        evasion_noise_rate = (1 - (detected_noise / total_anom)) * 100

        # Test 2: Scaling by 0.9 and 1.1
        X_scale_down = X_anom * 0.9
        preds_scale_down = (model.decision_function(X_scale_down) < threshold).astype(int)
        detected_scale_down = preds_scale_down.sum()

        X_scale_up = X_anom * 1.1
        preds_scale_up = (model.decision_function(X_scale_up) < threshold).astype(int)
        detected_scale_up = preds_scale_up.sum()

        avg_detected = (detected_noise + detected_scale_down + detected_scale_up) / 3.0
        robustness_rate = (avg_detected / total_anom) * 100
        evasion_rate = 100 - robustness_rate

        status = "ROBUST" if robustness_rate >= 80 else ("MODERATE" if robustness_rate >= 50 else "FRAGILE")

        print(f"Total True Anomalies Tested: {total_anom:,}")
        print(f"  Perturbation (+10% Noise):    {detected_noise:,}/{total_anom:,} detected (Evasion: {evasion_noise_rate:.1f}%)")
        print(f"  Scaling (0.9x Feature Scale): {detected_scale_down:,}/{total_anom:,} detected")
        print(f"  Scaling (1.1x Feature Scale): {detected_scale_up:,}/{total_anom:,} detected")
        print(f"  Overall Detection Retention:  {robustness_rate:.1f}%")
        print(f"  Overall Evasion Success Rate: {evasion_rate:.1f}%")
        print(f"  Robustness Status:            [{status}]")

    # Part C: Operational Considerations & Alert Fatigue
    print_header("Part C: Operational Impact & Alert Fatigue Analysis")
    events_per_day = config['evaluation'].get('events_per_day', 10000)
    analyst_capacity = config['evaluation'].get('analyst_capacity_per_day', 50)

    # Anomaly rate at current threshold
    observed_anomaly_rate = y_pred.sum() / total
    expected_alerts_per_day = int(observed_anomaly_rate * events_per_day)

    print(f"Operational Parameters:")
    print(f"  Daily Network Events:     {events_per_day:,}")
    print(f"  SOC Analyst Capacity:     {analyst_capacity} alerts/day")
    print(f"  Model Anomaly Rate:       {observed_anomaly_rate*100:.1f}%")
    print(f"  Expected Daily Alerts:    {expected_alerts_per_day:,} alerts/day")

    if expected_alerts_per_day > analyst_capacity:
        overload_ratio = expected_alerts_per_day / analyst_capacity
        print(f"\n[!] ALERT FATIGUE WARNING: Daily alerts ({expected_alerts_per_day}) exceed analyst capacity by {overload_ratio:.1f}x!")
        print(f"    RECOMMENDATION: Raise anomaly decision threshold to reduce FPR and false alarm rate.")
    else:
        print(f"\n[+] Alert load ({expected_alerts_per_day}/day) is within SOC analyst capacity ({analyst_capacity}/day).")


if __name__ == "__main__":
    run_evaluation()
