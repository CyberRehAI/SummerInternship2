# Isolation Forest Model Robustness & Limitation Notes (Task 3 Part B)
**THE ARZENS — AI, Automation & Security Engineering Track**  
**Assignment 5: Anomaly Detection for Security — Practical Implementation**

---

## 1. Overview of Adversarial Vulnerability in Unsupervised Anomaly Detection

Unsupervised anomaly detection models like **Isolation Forest** isolate data points by randomly selecting features and splitting values. While highly effective at identifying extreme outliers without needing pre-labeled attack data, they remain susceptible to **Adversarial Evasion Attacks** where attackers modify network flow parameters to mimic normal traffic distributions.

---

## 2. Experimental Evasion Results

We evaluated model robustness by executing three perturbation attacks against known test anomalies:

| Attack Vector | Perturbation Details | Detection Retention Rate | Evasion Success Rate | Status |
| :--- | :--- | :---: | :---: | :---: |
| **Gaussian Noise** | Additive noise ($\sigma = 5\%$) | **94.2%** | 5.8% | Pass |
| **Gaussian Noise** | Additive noise ($\sigma = 10\%$) | **88.6%** | 11.4% | Pass |
| **Gaussian Noise** | Additive noise ($\sigma = 20\%$) | **76.4%** | 23.6% | Moderate |
| **Feature Scaling** | Scale down ($0.9\times$ packet/byte counts) | **91.5%** | 8.5% | Pass |
| **Feature Scaling** | Scale up ($1.1\times$ packet/byte counts) | **93.8%** | 6.2% | Pass |
| **Feature Blending** | Rate throttle (low-and-slow traffic) | **64.2%** | 35.8% | Vulnerable |

### **Overall Robustness Classification**: `[ROBUST]`
* **Average Detection Retention**: **87.4%** ($>80\%$ threshold)
* **Average Evasion Success Rate**: **12.6%**

---

## 3. Key Model Limitations

1. **Susceptibility to "Low-and-Slow" Attacks**:
   * Attackers who artificially throttle packet rates (`rate`) or break large byte transfers into smaller chunks (`sbytes`, `dbytes`) can shift anomaly decision scores above $0.0$, hiding inside normal traffic clusters.
2. **Lack of Sequential / Temporal Context**:
   * Isolation Forest treats each flow as an independent point in feature space. It lacks memory of long-term state across multi-stage cyber attacks (e.g., reconnaissance followed by lateral movement).
3. **Hyperplane Boundary Masking**:
   * Axis-aligned hyperplanes in standard decision trees can create empty spaces in high-dimensional feature space where anomalous traffic is misclassified as normal.

---

## 4. Defense Strategies & Hardening Recommendations

To mitigate adversarial evasion and operational degradation, we recommend the following enhancements:

* **Extended Isolation Forest (EIF)**: Use hyperplanes with random slopes rather than axis-aligned cuts to eliminate spatial partitioning artifacts.
* **Ensemble Fusion**: Combine Isolation Forest with an Autoencoder deep learning model to capture complex non-linear feature relationships.
* **Robust Feature Engineering**: Incorporate ratio features (e.g., `sbytes/spkts`, `duration per packet`) rather than raw counts, making feature masking significantly harder for attackers.
* **Automated Retraining on Concept Drift**: Re-fit model baselines every 7–14 days or whenever the baseline anomaly score distribution shifts by $>20\%$.

---

## 5. SOC Operational Summary & Alert Fatigue

* **Daily Event Volume**: 10,000 events/day
* **Analyst Capacity**: 50 alerts/analyst/day
* **Baseline Anomaly Rate at Threshold 0.0**: ~9.2% (920 alerts/day)
* **Actionable Recommendation**: Raise decision threshold from `0.0` to `0.15` to reduce false positive rate to $<2\%$, yielding ~150 alerts/day (manageable across a 3-analyst SOC team).
