#!/usr/bin/env python3
"""
Adversarial Evasion Robustness Test Script (Task 3 Part B)
THE ARZENS — AI, Automation & Security Engineering Track
Assignment 5: Unsupervised Anomaly Detection

This script evaluates how easily an attacker can evade the Isolation Forest
anomaly detector by slightly altering feature values (noise addition, scaling, perturbation).
"""

import os
import sys
import yaml
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

DEFAULT_FEATURES = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate']


def load_config(config_path="config.yaml"):
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {
        "data": {
            "features": DEFAULT_FEATURES,
            "target_column": "label",
            "test_file": "data/UNSW_NB15_testing-set.csv"
        },
        "output": {
            "model_file": "model_artifacts/isolation_forest_model.pkl",
            "scaler_file": "model_artifacts/standard_scaler.pkl",
            "plots_dir": "model_artifacts/plots"
        }
    }


def run_evasion_tests():
    config = load_config()
    test_file = config['data'].get('test_file', 'data/UNSW_NB15_testing-set.csv')
    model_path = config['output'].get('model_file', 'model_artifacts/isolation_forest_model.pkl')
    scaler_path = config['output'].get('scaler_file', 'model_artifacts/standard_scaler.pkl')

    if not os.path.exists(test_file) or not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print(f"[!] Error: Dataset, Model, or Scaler file missing. Train model first.")
        sys.exit(1)

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    df = pd.read_csv(test_file)

    features = config['data'].get('features', DEFAULT_FEATURES)
    target_col = config['data'].get('target_column', 'label')

    X = df[features].fillna(df[features].median())
    X_scaled = scaler.transform(X)
    y_true = df[target_col].values

    # Filter baseline true positive anomalies
    scores_base = model.decision_function(X_scaled)
    baseline_anomalies_mask = (y_true == 1) & (scores_base < 0.0)
    X_anom = X_scaled[baseline_anomalies_mask]
    n_anom = len(X_anom)

    print("=" * 65)
    print(" ADVERSARIAL EVASION ROBUSTNESS TESTING (TASK 3 PART B)")
    print("=" * 65)
    print(f"Total True Baseline Anomalies Tested: {n_anom:,}\n")

    evasion_results = []

    # 1. Additive Noise Attacks (5%, 10%, 20%)
    np.random.seed(42)
    for noise_std in [0.05, 0.10, 0.20]:
        noise = np.random.normal(0, noise_std, X_anom.shape)
        X_perturbed = X_anom + noise
        scores = model.decision_function(X_perturbed)
        detected = (scores < 0.0).sum()
        evaded = n_anom - detected
        evasion_rate = (evaded / n_anom) * 100
        detection_retention = (detected / n_anom) * 100

        evasion_results.append({
            'Attack Type': f'Noise (+-{int(noise_std*100)}%)',
            'Detected': detected,
            'Evaded': evaded,
            'Evasion Rate (%)': evasion_rate,
            'Retention Rate (%)': detection_retention
        })
        print(f"Attack: Additive Noise (+-{int(noise_std*100)}%)")
        print(f"  Detected: {detected:,}/{n_anom:,} ({detection_retention:.1f}%) | Evaded: {evaded:,} ({evasion_rate:.1f}%)\n")

    # 2. Multiplicative Feature Scaling Attacks (0.8x, 0.9x, 1.1x, 1.2x)
    for scale_factor in [0.8, 0.9, 1.1, 1.2]:
        X_scaled_att = X_anom * scale_factor
        scores = model.decision_function(X_scaled_att)
        detected = (scores < 0.0).sum()
        evaded = n_anom - detected
        evasion_rate = (evaded / n_anom) * 100
        detection_retention = (detected / n_anom) * 100

        evasion_results.append({
            'Attack Type': f'Scaling ({scale_factor}x)',
            'Detected': detected,
            'Evaded': evaded,
            'Evasion Rate (%)': evasion_rate,
            'Retention Rate (%)': detection_retention
        })
        print(f"Attack: Feature Scaling ({scale_factor}x)")
        print(f"  Detected: {detected:,}/{n_anom:,} ({detection_retention:.1f}%) | Evaded: {evaded:,} ({evasion_rate:.1f}%)\n")

    # Overall Robustness Assessment
    res_df = pd.DataFrame(evasion_results)
    avg_retention = res_df['Retention Rate (%)'].mean()
    avg_evasion = res_df['Evasion Rate (%)'].mean()

    if avg_retention >= 80.0:
        status = "ROBUST"
        desc = "Model retains >80% detection capability under simple evasion attacks."
    elif avg_retention >= 50.0:
        status = "MODERATE"
        desc = "Model retains 50-80% detection capability. Partially vulnerable to feature tampering."
    else:
        status = "FRAGILE"
        desc = "Model retains <50% detection capability. Highly vulnerable to simple evasion attacks."

    print("=" * 65)
    print(" SUMMARY ROBUSTNESS SCORE")
    print("=" * 65)
    print(f"Average Detection Retention: {avg_retention:.1f}%")
    print(f"Average Evasion Rate:        {avg_evasion:.1f}%")
    print(f"Model Robustness Status:    [{status}]")
    print(f"Verdict: {desc}\n")

    # Plot Robustness Bar Chart
    plots_dir = config['output'].get('plots_dir', 'model_artifacts/plots')
    os.makedirs(plots_dir, exist_ok=True)
    plot_path = os.path.join(plots_dir, "evasion_robustness_test.png")

    plt.figure(figsize=(10, 5))
    bars = plt.bar(res_df['Attack Type'], res_df['Retention Rate (%)'], color='#2b5c8f', width=0.55)
    plt.axhline(y=80, color='green', linestyle='--', label='Robust Threshold (80%)')
    plt.axhline(y=50, color='orange', linestyle='--', label='Fragile Threshold (50%)')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 1.5,
                 f'{height:.1f}%', ha='center', va='bottom', fontweight='bold')

    plt.title('Isolation Forest: Detection Retention Rate Under Adversarial Evasion', fontsize=13, fontweight='bold')
    plt.xlabel('Evasion Attack Vector', fontsize=11)
    plt.ylabel('Detection Retention Rate (%)', fontsize=11)
    plt.ylim(0, 110)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(plot_path, dpi=300)
    plt.close()

    print(f"[+] Evasion test plot saved: {plot_path}")


if __name__ == "__main__":
    run_evasion_tests()
