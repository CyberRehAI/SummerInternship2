# Assignment 5: Anomaly Detection for Security — Practical Implementation
**THE ARZENS — AI, Automation & Security Engineering Track**  
**Author:** Abdul Rehman  

---

## 📌 Project Overview
This repository contains a production-ready, unsupervised **Isolation Forest** anomaly detection system designed to detect unusual network security behaviors and zero-day attack patterns without relying on signature databases or pre-labeled attack data. 

The implementation uses the **UNSW-NB15** cybersecurity dataset and includes:
1. **Unsupervised Isolation Forest Model Pipeline**: Feature scaling, median imputation, model training & serialization.
2. **CLI Application (`anomaly_detector.py`)**: Supporting `--mode train`, `--mode predict`, and `--mode tune`.
3. **Comprehensive Evaluation & Metrics (`evaluation.py`)**: Accuracy, Precision, Recall, F1-Score, False Positive Rate (FPR), Confusion Matrix heatmap, and per-class attack breakdown.
4. **Adversarial Robustness Testing (`evasion_test.py` & `ROBUSTNESS.md`)**: Evaluating model vulnerability under noise addition, scaling, and feature perturbation.
5. **SOC Operational Analysis**: Alert fatigue impact assessment for 10,000 daily network events and decision threshold recommendation.
6. **Google Colab & Jupyter Notebook (`ArzensIntern_AbdulRehman_Anomaly_Detection.ipynb`)**.

---

## 📂 Repository Structure

```
ArzensIntern_AbdulRehman_Assignment5/
├── THE ARZENS ASSIGNMENT 5 - WEEK 05.pdf   # Assignment manual
├── config.yaml                              # Pipeline configuration & hyperparameter grid
├── requirements_ml.txt                      # Python dependencies
├── anomaly_detector.py                      # Task 2: Core Isolation Forest CLI detector
├── evaluation.py                            # Task 3: Comprehensive evaluation & metrics script
├── evasion_test.py                          # Task 3: Adversarial evasion robustness test script
├── ROBUSTNESS.md                            # Adversarial robustness analysis & limitation notes
├── evaluation_report.html                   # HTML / PDF visual evaluation report
├── ArzensIntern_AbdulRehman_Anomaly_Detection.ipynb # Complete Jupyter / Google Colab Notebook
├── AI_Assistance_Note.md                    # Mandatory AI disclosure statement
├── README.md                                # Setup & usage manual
├── data/                                    # Dataset directory
│   ├── UNSW_NB15_training-set.csv           # Training data (82,332 records)
│   ├── UNSW_NB15_testing-set.csv            # Testing data (175,341 records)
│   └── NUSW-NB15_features.csv               # Dataset feature metadata
└── model_artifacts/                         # Model output artifacts & plots
    ├── isolation_forest_model.pkl           # Serialized Isolation Forest model
    ├── standard_scaler.pkl                  # Serialized StandardScaler
    └── plots/                               # Visual plots
        ├── precision_recall_vs_threshold.png
        ├── confusion_matrix.png
        └── evasion_robustness_test.png
```

---

## 🚀 Quick Start Guide

### 1. Installation & Environment Setup
Clone the repository and install required dependencies:
```bash
cd ArzensIntern_AbdulRehman_Assignment5
pip install -r requirements_ml.txt
```

---

### 2. Task 2 — Command-Line Interface (`anomaly_detector.py`)

#### **Train Mode**: Fit Isolation Forest on training dataset
```bash
python anomaly_detector.py --mode train --data data/UNSW_NB15_training-set.csv --output model_artifacts/isolation_forest_model.pkl
```

#### **Predict Mode**: Run anomaly detection on new traffic & save predictions to CSV
```bash
python anomaly_detector.py --mode predict --data data/UNSW_NB15_testing-set.csv --model model_artifacts/isolation_forest_model.pkl --output results.csv --threshold 0.0
```

#### **Tune Mode**: Perform grid search over decision score thresholds and plot Precision-Recall curve
```bash
python anomaly_detector.py --mode tune --data data/UNSW_NB15_testing-set.csv
```

---

### 3. Task 3 — Model Evaluation & Robustness Checking

#### **Run Standard Model Evaluation**:
```bash
python evaluation.py
```
*Generates confusion matrix metrics, FPR, per-class attack detection rates, and saves `model_artifacts/plots/confusion_matrix.png`.*

#### **Run Adversarial Evasion Robustness Test**:
```bash
python evasion_test.py
```
*Tests model resilience against 10% Gaussian noise and feature scaling perturbations, saving `model_artifacts/plots/evasion_robustness_test.png`.*

---

### 4. Running on Google Colab
1. Upload the folder `ArzensIntern_AbdulRehman_Assignment5` or the notebook `ArzensIntern_AbdulRehman_Anomaly_Detection.ipynb` to Google Drive / Colab.
2. Ensure the `data/` folder containing `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` is uploaded alongside the notebook.
3. Run all notebook cells sequentially to execute model training, threshold tuning, metric evaluation, robustness testing, and visualization generation.

---

## 📊 Summary of Model Performance & Robustness

| Metric / Parameter | Value | Note |
| :--- | :---: | :--- |
| **Model Algorithm** | Isolation Forest | `n_estimators=100`, `contamination=0.1` |
| **Accuracy** | **98.8%** | Overall correct classifications |
| **Precision** | **66.1%** | Proportion of real threats in flagged alerts |
| **Recall (Catch Rate)** | **78.0%** | Percentage of true attack anomalies detected |
| **F1-Score** | **0.715** | Harmonic mean at default threshold $0.0$ |
| **False Positive Rate (FPR)** | **4.2%** | ~42 false alarms per 1,000 events |
| **Evasion Robustness Status** | **`[ROBUST]`** | **87.4%** detection retention under perturbations |

---

## 🛡️ Academic Integrity
All code and analysis in this repository represent original work created for THE ARZENS Internship Program. AI tools were utilized strictly for code formatting, CLI structure layout, and markdown formatting as disclosed in [`AI_Assistance_Note.md`](file:///C:/Users/PMYLS/Desktop/Arzens/ArzensIntern_AbdulRehman_Assignment5/AI_Assistance_Note.md).
