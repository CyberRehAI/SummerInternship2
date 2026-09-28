# Model Card: UNSW-NB15 Network Intrusion Detection System

## 1. Model Details

| Attribute | Details |
| :--- | :--- |
| **Model Name** | UNSW-NB15 Network Intrusion Detection Model |
| **Version** | 1.0 |
| **Model Type** | Binary Classification (Normal vs. Attack) |
| **Framework** | `scikit-learn` / `XGBoost` |
| **Algorithms Evaluated** | Random Forest, XGBoost, Logistic Regression |
| **Best Performing Model** | XGBoost|
| **Training Date** | August 2026 |
| **Author** | Abdul Rehman (THE ARZENS Engineering Internship) |

## 2. Intended Use

* **Primary Use Case:** Real-time and batch detection of malicious network traffic within enterprise network environments.
* **Target Users:** Security Operations Center (SOC) analysts, incident response teams, and security engineers.
* **Out-of-Scope Applications:** Not intended to operate as a standalone automated mitigation system or sole detection mechanism. Designed to augment existing Intrusion Detection Systems (IDS) and security workflows.

## 3. Training Data

* **Dataset Source:** UNSW-NB15 Dataset provided by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS).
* **Data Volume:** ~175,000 training records and ~82,000 testing records.
* **Attack Categories Represented (9 Types):**
  1. Fuzzers
  2. Analysis
  3. Backdoors
  4. DoS (Denial of Service)
  5. Exploits
  6. Generic
  7. Reconnaissance
  8. Shellcode
  9. Worms
* **Pre-processing & Class Imbalance:** Synthetic Minority Over-sampling Technique (SMOTE) is applied to handle severe class imbalances across rare attack vectors.

## 4. Evaluation Metrics

*(Note: Metric values below are initial target benchmarks / placeholder values to be finalized post-training)*

| Metric | Benchmark Value | Description |
| :--- | :--- | :--- |
| **Accuracy** | ~97% | Overall proportion of correctly classified network flows |
| **Precision** | ~93% | Proportion of flagged alerts that are true attacks |
| **Recall (Sensitivity)** | ~94% | Proportion of actual attack traffic correctly identified |
| **F1-Score** | ~94% | Harmonic mean of Precision and Recall |
| **ROC-AUC** | ~0.99 | Area under Receiver Operating Characteristic curve |
| **PR-AUC** | High (~0.95+) | Area under Precision-Recall curve |
| **False Positive Rate (FPR)** | Low | Rate of benign traffic incorrectly flagged as malicious |
| **False Negative Rate (FNR)** | Low | Rate of attack traffic missed by the model |

## 5. Limitations

* **Synthetic Lab Constraints:** The dataset was generated in a lab environment; performance may vary when exposed to complex, real-world enterprise network architectures.
* **Zero-Day Vulnerabilities:** The model cannot reliably detect novel zero-day attack patterns or exploit primitives not represented in the training distribution.
* **Concept Drift & Data Decay:** Network traffic dynamics, application protocols, and attack tactics evolve over time, leading to potential performance degradation.
* **Retraining Dependency:** Requires systematic retraining pipelines with fresh, labelled network telemetry to maintain efficacy.

## 6. Ethical & Operational Considerations

* **Operational Risk of False Positives:** Excessive false positives introduce alert fatigue for SOC analysts, potentially causing operational delays and unnecessary investigations into benign activities.
* **Operational Risk of False Negatives:** Unflagged attack traffic (false negatives) poses severe security risks by allowing intrusions to proceed unhindered.
* **Human-in-the-Loop Imperative:** Model decisions should serve as advisory telemetry for human security professionals rather than triggering unverified automated network blockades.
* **Privacy Assurance:** Model trained on anonymized network metadata and flow statistics; no deep packet payload inspection or private user data extraction is performed.

## 7. Recommendations & Deployment Guidelines

* **Human-in-the-Loop Protocol:** Deploy with human-in-the-loop review. Integrate predictions into analyst dashboards with confidence scores for human verification.
* **Performance Monitoring:** Implement continuous automated tracking of model performance metrics on a weekly basis.
* **Retraining Cadence:** Retrain the model monthly using updated and labeled real-world attack samples.
* **Threshold Tuning:** Adjust decision threshold boundaries according to operational security posture and enterprise risk appetite.
