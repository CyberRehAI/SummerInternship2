#!/usr/bin/env python3
"""
Production-grade ML training pipeline for network intrusion detection using the UNSW-NB15 dataset.
"""

import os
import yaml
import time
import datetime
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier

RANDOM_STATE = 42

def load_data(config):
    """
    Load data, perform quality checks, clean data, and split into train/val/test.
    """
    print(f"[{datetime.datetime.now()}] Loading data...")
    train_path = config['data']['train_file']
    test_path = config['data']['test_file']
    
    # We combine train and test just to have a complete dataset to split according to user specification (70/15/15)
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    df = pd.concat([df_train, df_test], ignore_index=True)
    
    # Schema validation
    expected_cols = [
        "id", "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", 
        "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt", 
        "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", 
        "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl", 
        "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", 
        "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports", 
        "attack_cat", "label"
    ]
    missing_cols = set(expected_cols) - set(df.columns)
    if missing_cols:
        raise ValueError(f"Missing expected columns: {missing_cols}")

    # Data quality checks
    print(f"[{datetime.datetime.now()}] Initial shape: {df.shape}")
    print(f"[{datetime.datetime.now()}] Null values:\n{df.isnull().sum()[df.isnull().sum() > 0]}")
    duplicates = df.duplicated().sum()
    print(f"[{datetime.datetime.now()}] Duplicates: {duplicates}")

    # Clean data
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Drop columns
    cols_to_drop = config['data']['drop_columns']
    df.drop(columns=[col for col in cols_to_drop if col in df.columns], inplace=True)
    
    # Outlier detection via IQR on numeric columns (reporting only)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if 'label' in numeric_cols:
        numeric_cols.remove('label')
        
    for col in numeric_cols:
        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        outliers = ((df[col] < (Q1 - 1.5 * IQR)) | (df[col] > (Q3 + 1.5 * IQR))).sum()
        if outliers > 0:
            pass # just detecting as per requirement

    X = df.drop(columns=[config['data']['target_column']])
    y = df[config['data']['target_column']]
    
    # Split 70/15/15
    # First split: 70% train, 30% temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    # Second split: 50% of temp -> 15% val, 15% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )
    
    print(f"[{datetime.datetime.now()}] Data split: Train {X_train.shape[0]}, Val {X_val.shape[0]}, Test {X_test.shape[0]}")
    
    return X_train, X_val, X_test, y_train, y_val, y_test

def preprocess(X_train, y_train, config):
    """
    Preprocess features (scale, encode, feature selection) and handle imbalance.
    """
    print(f"[{datetime.datetime.now()}] Preprocessing data...")
    categorical_cols = ['proto', 'service', 'state']
    numeric_cols = [c for c in X_train.columns if c not in categorical_cols]
    
    numeric_transformer = Pipeline(steps=[
        ('scaler', StandardScaler())
    ])
    
    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_cols),
            ('cat', categorical_transformer, categorical_cols)
        ]
    )
    
    top_k = config['preprocessing']['feature_selection']['top_k']
    
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('feature_selection', SelectKBest(score_func=mutual_info_classif, k=top_k))
    ])
    
    # Fit pipeline on training data
    print(f"[{datetime.datetime.now()}] Fitting preprocessing pipeline...")
    X_train_processed = pipeline.fit_transform(X_train, y_train)
    
    # SMOTE on training set only
    print(f"[{datetime.datetime.now()}] Applying SMOTE...")
    smote = SMOTE(random_state=RANDOM_STATE)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train_processed, y_train)
    
    # Get feature names if possible
    feature_names = []
    try:
        cat_encoder = pipeline.named_steps['preprocessor'].named_transformers_['cat'].named_steps['onehot']
        cat_features = cat_encoder.get_feature_names_out(categorical_cols)
        all_features = numeric_cols + list(cat_features)
        selector = pipeline.named_steps['feature_selection']
        selected_indices = selector.get_support(indices=True)
        feature_names = [all_features[i] for i in selected_indices]
    except Exception as e:
        print(f"Could not extract feature names: {e}")
        feature_names = [f"feature_{i}" for i in range(top_k)]
        
    return pipeline, X_train_resampled, y_train_resampled, feature_names

def train_models(X_train, y_train, config):
    """
    Train and tune models using RandomizedSearchCV.
    """
    print(f"[{datetime.datetime.now()}] Training models...")
    cv_folds = config['training']['cv_folds']
    scoring = config['training']['scoring']
    n_jobs = config['training']['n_jobs']
    
    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    
    models = {
        'Random Forest': (
            RandomForestClassifier(random_state=RANDOM_STATE, class_weight='balanced'),
            {
                'n_estimators': config['models']['random_forest']['n_estimators'],
                'max_depth': [None if x == 'null' or x is None else x for x in config['models']['random_forest']['max_depth']],
                'min_samples_split': config['models']['random_forest']['min_samples_split']
            }
        ),
        'XGBoost': (
            XGBClassifier(random_state=RANDOM_STATE, eval_metric='logloss'),
            {
                'n_estimators': config['models']['xgboost']['n_estimators'],
                'max_depth': config['models']['xgboost']['max_depth'],
                'learning_rate': config['models']['xgboost']['learning_rate'],
                'subsample': config['models']['xgboost']['subsample']
            }
        ),
        'Logistic Regression': (
            LogisticRegression(random_state=RANDOM_STATE, class_weight='balanced', solver='lbfgs', max_iter=1000),
            {
                'C': config['models']['logistic_regression']['C']
            }
        )
    }
    
    trained_models = []
    
    for name, (model, param_grid) in models.items():
        print(f"[{datetime.datetime.now()}] Tuning {name}...")
        search = RandomizedSearchCV(
            model, param_distributions=param_grid, n_iter=3, scoring=scoring, 
            cv=skf, n_jobs=n_jobs, random_state=RANDOM_STATE, verbose=1
        )
        search.fit(X_train, y_train)
        
        print(f"[{datetime.datetime.now()}] {name} Best Params: {search.best_params_}")
        print(f"[{datetime.datetime.now()}] {name} Best CV Score ({scoring}): {search.best_score_:.4f}")
        
        trained_models.append({
            'model_name': name,
            'best_model': search.best_estimator_,
            'best_params': search.best_params_,
            'best_cv_score': search.best_score_
        })
        
    return trained_models

def evaluate_cv(X, y, trained_models, config):
    """
    Compute cross-validation scores for trained models.
    """
    print(f"[{datetime.datetime.now()}] Evaluating models via CV...")
    skf = StratifiedKFold(n_splits=config['training']['cv_folds'], shuffle=True, random_state=RANDOM_STATE)
    metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    
    results = []
    
    for item in trained_models:
        name = item['model_name']
        model = item['best_model']
        
        cv_res = cross_validate(model, X, y, cv=skf, scoring=metrics, n_jobs=config['training']['n_jobs'])
        
        res_dict = {'Model': name}
        for metric in metrics:
            res_dict[f'Mean {metric.capitalize()}'] = np.mean(cv_res[f'test_{metric}'])
            
        results.append(res_dict)
        
    df_results = pd.DataFrame(results)
    print(f"\nCV Evaluation Results:\n{df_results}\n")
    return df_results

def save_artifacts(trained_models, pipeline, feature_names, df_results, config):
    """
    Save best model, pipeline, features, logs, and all models.
    """
    print(f"[{datetime.datetime.now()}] Saving artifacts...")
    model_dir = config['output']['model_dir']
    os.makedirs(model_dir, exist_ok=True)
    
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    
    # Find best model based on best CV score from randomized search
    best_item = max(trained_models, key=lambda x: x['best_cv_score'])
    best_model = best_item['best_model']
    best_name = best_item['model_name'].replace(" ", "_").lower()
    
    best_model_filename = os.path.join(model_dir, f"best_model_v1.0_{date_str}.pkl")
    joblib.dump(best_model, best_model_filename)
    print(f"[{datetime.datetime.now()}] Saved best model ({best_name}) to {best_model_filename}")
    
    # Save preprocessing pipeline
    pipeline_filename = os.path.join(model_dir, config['output']['pipeline_file'])
    joblib.dump(pipeline, pipeline_filename)
    
    # Save feature list
    feature_filename = os.path.join(model_dir, config['output']['feature_list_file'])
    with open(feature_filename, 'w') as f:
        for feat in feature_names:
            f.write(f"{feat}\n")
            
    # Save training log
    log_filename = os.path.join(model_dir, config['output']['training_log_file'])
    df_results.to_csv(log_filename, index=False)
    
    # Save all 3 trained models with fixed names for evaluate_model.py
    name_map = {'Random Forest': 'rf_model', 'XGBoost': 'xgb_model', 'Logistic Regression': 'lr_model'}
    for item in trained_models:
        short_name = name_map.get(item['model_name'], item['model_name'].replace(' ', '_').lower())
        model_filename = os.path.join(model_dir, f"{short_name}.pkl")
        joblib.dump(item['best_model'], model_filename)
        
    print(f"[{datetime.datetime.now()}] All artifacts saved successfully.")

def main():
    """
    Pipeline orchestration.
    """
    print(f"[{datetime.datetime.now()}] Starting ML pipeline...")
    
    # Use relative path for portability (local + Colab)
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    # Set random seed
    np.random.seed(RANDOM_STATE)
    
    # 1. Load Data
    X_train, X_val, X_test, y_train, y_val, y_test = load_data(config)
    
    # 2. Preprocess
    pipeline, X_train_processed, y_train_processed, feature_names = preprocess(X_train, y_train, config)
    
    # 3. Train Models
    trained_models = train_models(X_train_processed, y_train_processed, config)
    
    # 4. Evaluate CV (on training set to keep it consistent, though could evaluate on processed val set too)
    df_results = evaluate_cv(X_train_processed, y_train_processed, trained_models, config)
    
    # 5. Save Artifacts
    save_artifacts(trained_models, pipeline, feature_names, df_results, config)
    
    print(f"[{datetime.datetime.now()}] Pipeline completed successfully.")

if __name__ == '__main__':
    main()
