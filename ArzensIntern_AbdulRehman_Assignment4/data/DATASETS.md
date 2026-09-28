# Dataset Documentation

The UNSW-NB15 network intrusion dataset is used for threat detection in this assignment.

## Included Dataset Files
- `UNSW_NB15_training-set.csv` (~175k rows, 14.7 MB): Standardized training set.
- `UNSW_NB15_testing-set.csv` (~82k rows, 30.8 MB): Standardized testing set.
- `NUSW-NB15_features.csv`: Feature dictionary and schema definitions.
- `UNSW-NB15_LIST_EVENTS.csv`: Attack event categorization metadata.

## Note on Excluded Raw Dumps
The unpartitioned raw capture dumps (`UNSW-NB15_1.csv` through `UNSW-NB15_4.csv`) each exceed 100 MB and are excluded from Git repository tracking in accordance with GitHub's file size policies. All model training (`ArzensIntern_AbdulRehman_train_model.py`), evaluation (`ArzensIntern_AbdulRehman_evaluate_model.py`), and Jupyter analysis notebooks directly consume `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`.
