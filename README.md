# 🛡️ Security Feature Engineering Pipeline

**ARZENS Engineering Internship Program**  
**Track 09 – AI, Automation & Security Engineering (Advanced)**  
**Assignment 3**

---

## 📋 Project Overview

A production-grade **Security Feature Engineering & Validation Pipeline** for ML-based threat detection. This project demonstrates end-to-end security data engineering — from raw telemetry ingestion to privacy-preserving feature extraction and automated quality validation.

### Architecture

```
┌─────────────────────────┐    ┌───────────────────────┐    ┌──────────────────────────┐
│   Raw Security Events   │───▶│   Feature Extractor   │───▶│   Quality Validator      │
│   (JSONL Telemetry)     │    │   (Python Pipeline)   │    │   (Statistical Analysis) │
│                         │    │                       │    │                          │
│ • Auth logs             │    │ • Rolling windows     │    │ • Schema validation      │
│ • Network flows         │    │ • 10 ML features      │    │ • Missing value check    │
│ • DNS queries           │    │ • Privacy controls    │    │ • Range validation       │
│ • Endpoint telemetry    │    │ • CSV/JSON export     │    │ • Drift detection (KS/PSI)│
└─────────────────────────┘    └───────────────────────┘    └──────────────────────────┘
```

---

## 📁 Project Structure

```
ArzensIntern_AbdulRehman_Assignment3/
│
├── Task01_Feature_Engineering_Report/
│   └── feature_engineering_report.md      # Professional feature engineering report
│
├── Task02_Security_Feature_Extractor/
│   ├── feature_extractor.py               # Production feature extraction engine
│   ├── data_generator.py                  # Synthetic security event generator
│   ├── sample_raw_events.jsonl            # ~500 synthetic security events
│   ├── sample_features.csv                # Extracted ML-ready features (CSV)
│   ├── sample_features.json               # Extracted ML-ready features (JSON)
│   └── feature_dictionary.md              # Auto-generated feature documentation
│
├── Task03_Data_Quality_Drift_Validator/
│   ├── quality_validator.py               # Data quality & drift validation system
│   ├── generate_reference.py              # Reference baseline generator
│   ├── sample_reference_features.csv      # Baseline reference dataset
│   ├── sample_quality_report.html         # Professional HTML quality report
│   └── drift_analysis.md                  # Drift analysis results
│
├── EDA.ipynb                              # Exploratory Data Analysis notebook
├── README.md                              # This file
├── requirements.txt                       # Python dependencies
└── ai_assistance_note.md                  # AI tool usage disclosure
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip package manager

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd ArzensIntern_AbdulRehman_Assignment3

# Install dependencies
pip install -r requirements.txt
```

### Running the Pipeline

#### 1. Generate Synthetic Security Events

```bash
cd Task02_Security_Feature_Extractor
python data_generator.py
```

This generates `sample_raw_events.jsonl` with ~500 realistic security events including:
- Authentication events (login success/failure, brute-force patterns)
- Network flow events (port scanning, data exfiltration)
- DNS query events (DGA domains, DNS tunneling)
- Endpoint events (process execution, privilege escalation)

#### 2. Extract ML-Ready Features

```bash
python feature_extractor.py --input sample_raw_events.jsonl --output-dir .
```

This produces:
- `sample_features.csv` — Engineered features in CSV format
- `sample_features.json` — Engineered features in JSON format
- `feature_dictionary.md` — Auto-generated feature documentation

#### 3. Validate Data Quality & Detect Drift

```bash
cd ../Task03_Data_Quality_Drift_Validator
python quality_validator.py --features ../Task02_Security_Feature_Extractor/sample_features.csv --reference sample_reference_features.csv --output-dir .
```

This produces:
- `sample_quality_report.html` — Professional HTML quality report
- `drift_analysis.md` — Feature drift analysis with recommendations

#### 4. Exploratory Data Analysis

```bash
cd ..
jupyter notebook EDA.ipynb
```

---

## 🔧 Engineered Features

| # | Feature | Type | Range | Detection Purpose |
|---|---------|------|-------|-------------------|
| 1 | `failed_login_ratio` | float | [0.0, 1.0] | Brute-force / credential stuffing |
| 2 | `login_frequency` | float | [0.0, ∞) | Account abuse / anomalous access |
| 3 | `geo_velocity` | float | [0.0, ∞) km/h | Impossible travel detection |
| 4 | `session_duration_anomaly` | float | (-∞, ∞) | C2 channels / session hijacking |
| 5 | `port_scan_index` | float | [0.0, 1.0] | Reconnaissance detection |
| 6 | `dns_query_entropy` | float | [0.0, ~8.0] | DNS tunneling / DGA detection |
| 7 | `data_exfil_ratio` | float | [0.0, ∞) | Data theft detection |
| 8 | `privilege_escalation_score` | float | [0.0, ∞) | Insider threat detection |
| 9 | `off_hours_ratio` | float | [0.0, 1.0] | Anomalous access timing |
| 10 | `connection_burstiness` | float | [0.0, ∞) | DDoS / bot detection |

---

## 🔒 Privacy Controls

The pipeline implements three layers of privacy protection:

1. **Pseudonymization** — SHA-256 hashing of user IDs and entity identifiers
2. **IP Generalization** — Masking IP addresses to /24 subnet (last octet zeroed)
3. **Differential Privacy** — Laplace noise injection on sensitive aggregate features (ε = 1.0)

---

## 📊 Quality Validation

The quality validator performs:

- **Schema Validation** — Verifies expected columns and data types
- **Missing Value Detection** — Flags columns exceeding completeness thresholds
- **Range Validation** — Checks feature values against expected bounds
- **Duplicate Detection** — Identifies duplicate records
- **Drift Detection** — KS test and PSI (Population Stability Index) comparison against baseline

---

## 🛠️ Technical Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.9+ |
| Data Processing | pandas, numpy |
| Statistical Analysis | scipy |
| Visualization | matplotlib, seaborn |
| Notebook | Jupyter |
| Privacy | hashlib (SHA-256), numpy (Laplace) |

---

## 👤 Author

**Abdul Rehman**  
ARZENS Engineering Intern  
Track 09 – AI, Automation & Security Engineering

---

## 📄 License

This project is submitted as part of the ARZENS Engineering Internship Program. All rights reserved.
