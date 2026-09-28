import os
import yaml
import time
import base64
import logging
import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, average_precision_score,
                             confusion_matrix, roc_curve, precision_recall_curve)
import shap

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

import joblib

def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def ensure_dir(dir_path):
    os.makedirs(dir_path, exist_ok=True)

def image_to_base64(img_path):
    with open(img_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
    return f"data:image/png;base64,{encoded_string}"

def load_models_and_data(config):
    model_dir = config['output']['model_dir']
    
    # Load data
    test_file = config['data']['test_file']
    df_test = pd.read_csv(test_file)
    y_test = df_test[config['data']['target_column']]
    
    if config['data']['attack_cat_column'] in df_test.columns:
        attack_cat_test = df_test[config['data']['attack_cat_column']]
    else:
        attack_cat_test = None
        
    df_test = df_test.drop(columns=[col for col in config['data']['drop_columns'] if col in df_test.columns])
    if config['data']['target_column'] in df_test.columns:
        df_test = df_test.drop(columns=[config['data']['target_column']])
    
    # Load pipeline with joblib
    pipeline_path = os.path.join(model_dir, config['output']['pipeline_file'])
    pipeline = joblib.load(pipeline_path)
        
    X_test_processed = pipeline.transform(df_test)
    if hasattr(X_test_processed, 'toarray'):
        X_test_processed = X_test_processed.toarray()

    # Load selected indices if available
    selected_indices_path = os.path.join(model_dir, 'selected_indices.pkl')
    if os.path.exists(selected_indices_path):
        selected_indices = joblib.load(selected_indices_path)
        X_test_processed = X_test_processed[:, selected_indices]
    
    # Load feature names if possible
    feature_list_file = os.path.join(model_dir, config['output']['feature_list_file'])
    if os.path.exists(feature_list_file):
        with open(feature_list_file, 'r') as f:
            features = [line.strip() for line in f.readlines()]
    else:
        features = [f"Feature_{i}" for i in range(X_test_processed.shape[1])]
    
    X_test_df = pd.DataFrame(X_test_processed, columns=features)
    
    models = {}
    # Load individual models with fixed names using joblib
    for model_name in ['rf_model.pkl', 'xgb_model.pkl', 'lr_model.pkl']:
        model_path = os.path.join(model_dir, model_name)
        if os.path.exists(model_path):
            name = model_name.split('.')[0]
            models[name] = joblib.load(model_path)
    # Load best model - find versioned file
    best_model_files = [f for f in os.listdir(model_dir) if f.startswith('best_model') and f.endswith('.pkl')]
    if best_model_files:
        best_path = os.path.join(model_dir, best_model_files[0])
        models['best_model'] = joblib.load(best_path)
                
    return X_test_df, y_test, attack_cat_test, models, features, pipeline

def calculate_metrics(y_true, y_pred, y_prob):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    metrics = {
        'Accuracy': accuracy_score(y_true, y_pred),
        'Precision': precision_score(y_true, y_pred, zero_division=0),
        'Recall': recall_score(y_true, y_pred, zero_division=0),
        'F1-Score': f1_score(y_true, y_pred, zero_division=0),
        'ROC-AUC': roc_auc_score(y_true, y_prob),
        'PR-AUC': average_precision_score(y_true, y_prob),
        'FPR': fpr,
        'FNR': fnr,
    }
    return metrics

def compare_models(models, X_test, y_test, out_dir):
    logging.info("Comparing models...")
    comparison_results = []
    roc_data = {}
    pr_data = {}
    
    for name, model in models.items():
        if name == 'best_model':
            continue # Already evaluated under its specific name
        
        start_time = time.time()
        y_prob = model.predict_proba(X_test)[:, 1]
        inference_time = time.time() - start_time
        
        y_pred = (y_prob >= 0.5).astype(int)
        metrics = calculate_metrics(y_test, y_pred, y_prob)
        metrics['Model'] = name
        metrics['Inference Time (s)'] = inference_time
        
        comparison_results.append(metrics)
        
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_data[name] = (fpr, tpr, metrics['ROC-AUC'])
        
        precision, recall, _ = precision_recall_curve(y_test, y_prob)
        pr_data[name] = (precision, recall, metrics['PR-AUC'])
        
    df_comparison = pd.DataFrame(comparison_results).set_index('Model')
    
    # Plot ROC
    plt.figure(figsize=(8, 6))
    for name, (fpr, tpr, auc) in roc_data.items():
        plt.plot(fpr, tpr, label=f'{name} (AUC = {auc:.3f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curves')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'roc_curves.png'))
    plt.close()
    
    # Plot PR
    plt.figure(figsize=(8, 6))
    for name, (precision, recall, auc) in pr_data.items():
        plt.plot(recall, precision, label=f'{name} (PR-AUC = {auc:.3f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curves')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'pr_curves.png'))
    plt.close()
    
    return df_comparison

def threshold_analysis(model, X_test, y_test, out_dir):
    logging.info("Performing threshold analysis...")
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
    y_prob = model.predict_proba(X_test)[:, 1]
    
    results = []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        results.append({
            'Threshold': t,
            'Precision': precision_score(y_test, y_pred, zero_division=0),
            'Recall': recall_score(y_test, y_pred, zero_division=0),
            'F1-Score': f1_score(y_test, y_pred, zero_division=0),
            'FPR': fpr,
            'FNR': fnr
        })
        
    df_thresh = pd.DataFrame(results)
    
    plt.figure(figsize=(8, 6))
    plt.plot(df_thresh['Threshold'], df_thresh['Precision'], marker='o', label='Precision')
    plt.plot(df_thresh['Threshold'], df_thresh['Recall'], marker='s', label='Recall')
    plt.plot(df_thresh['Threshold'], df_thresh['F1-Score'], marker='^', label='F1-Score')
    plt.xlabel('Threshold')
    plt.ylabel('Score')
    plt.title('Performance vs Threshold')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'threshold_analysis.png'))
    plt.close()
    
    return df_thresh

def shap_analysis(model, X_test, y_test, out_dir):
    logging.info("Performing SHAP analysis...")
    shap_dir = os.path.join(out_dir, 'dependence_plots')
    ensure_dir(shap_dir)
    force_dir = os.path.join(out_dir, 'force_plots_for_examples')
    ensure_dir(force_dir)
    
    # Subsample for speed
    np.random.seed(42)
    sample_indices = np.random.choice(X_test.index, min(500, len(X_test)), replace=False)
    X_sample = X_test.loc[sample_indices]
    y_sample = y_test.loc[sample_indices]
    
    explainer = shap.TreeExplainer(model) if hasattr(model, 'feature_importances_') else shap.Explainer(model, X_sample)
    
    try:
        shap_values = explainer(X_sample)
        if len(shap_values.shape) > 2:
            shap_values = shap_values[:, :, 1] # Extract positive class if multiclass output
            
        plt.figure(figsize=(10, 8))
        shap.summary_plot(shap_values, X_sample, show=False)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, 'summary_plot.png'))
        plt.close()
        
        # Get feature importance
        vals = np.abs(shap_values.values).mean(0)
        feature_importance = pd.DataFrame(list(zip(X_sample.columns, vals)), columns=['col_name', 'feature_importance_vals'])
        feature_importance.sort_values(by=['feature_importance_vals'], ascending=False, inplace=True)
        top_features = feature_importance['col_name'].head(10).tolist()
        
        for i, feat in enumerate(top_features[:3]):
            plt.figure(figsize=(8, 6))
            shap.dependence_plot(feat, shap_values.values, X_sample, show=False)
            plt.tight_layout()
            plt.savefig(os.path.join(shap_dir, f'dependence_{i}_{feat}.png'))
            plt.close()
            
        # Local explanations
        y_prob = model.predict_proba(X_sample)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        
        tp_idx = X_sample[(y_sample == 1) & (y_pred == 1)].index.tolist()[:2]
        fp_idx = X_sample[(y_sample == 0) & (y_pred == 1)].index.tolist()[:2]
        fn_idx = X_sample[(y_sample == 1) & (y_pred == 0)].index.tolist()[:1]
        
        examples = {'True Positive': tp_idx, 'False Positive': fp_idx, 'False Negative': fn_idx}
        explanations = []
        
        for type_name, indices in examples.items():
            for idx in indices:
                pos = X_sample.index.get_loc(idx)
                plt.figure(figsize=(12, 6))
                shap.plots.waterfall(shap_values[pos], show=False)
                plt.tight_layout()
                plt.savefig(os.path.join(force_dir, f'{type_name.replace(" ", "_")}_{idx}.png'))
                plt.close()
                explanations.append(f"{type_name} (Index {idx}): Prediction driven by top features shown in waterfall plot.")
                
        return top_features, explanations
        
    except Exception as e:
        logging.error(f"SHAP error: {e}")
        return [], [f"Error calculating SHAP: {e}"]

def error_analysis(model, X_test, y_test, attack_cat, out_dir):
    logging.info("Performing error analysis...")
    y_pred = model.predict(X_test)
    
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'confusion_matrix.png'))
    plt.close()
    
    fp_mask = (y_test == 0) & (y_pred == 1)
    fn_mask = (y_test == 1) & (y_pred == 0)
    
    fp_analysis = "False Positives characteristics:\n"
    if fp_mask.sum() > 0:
        fp_analysis += f"Total FP: {fp_mask.sum()}\n"
    else:
        fp_analysis += "None found.\n"
        
    fn_analysis = "False Negatives characteristics:\n"
    if fn_mask.sum() > 0:
        fn_analysis += f"Total FN: {fn_mask.sum()}\n"
        if attack_cat is not None:
            fn_cats = attack_cat[fn_mask].value_counts()
            fn_analysis += "Missed attack categories:\n" + fn_cats.to_string() + "\n"
    else:
        fn_analysis += "None found.\n"
        
    return fp_analysis, fn_analysis

def generate_html_report(out_dir, df_comp, df_thresh, top_features, shap_expl, fp_analysis, fn_analysis, prod_metrics):
    html = f"""
    <html>
    <head>
        <title>Model Evaluation Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2 {{ color: #333; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            img {{ max-width: 100%; height: auto; border: 1px solid #ddd; padding: 5px; }}
            .section {{ margin-bottom: 40px; }}
        </style>
    </head>
    <body>
        <h1>Model Evaluation and Interpretability Report</h1>
        
        <div class="section">
            <h2>1. Model Comparison</h2>
            {df_comp.to_html()}
            <br>
            <img src="{image_to_base64(os.path.join(out_dir, 'roc_curves.png'))}" alt="ROC Curves" width="600">
            <img src="{image_to_base64(os.path.join(out_dir, 'pr_curves.png'))}" alt="PR Curves" width="600">
        </div>
        
        <div class="section">
            <h2>2. Threshold Analysis</h2>
            {df_thresh.to_html(index=False)}
            <br>
            <img src="{image_to_base64(os.path.join(out_dir, 'threshold_analysis.png'))}" alt="Threshold Analysis" width="600">
            <p><strong>Recommendation:</strong> Choose a threshold that prioritizes recall (lower false negatives) for security contexts, typically 0.4 or 0.3 depending on acceptable FPR.</p>
        </div>
        
        <div class="section">
            <h2>3. SHAP Interpretability</h2>
            <p><strong>Top 10 Features:</strong> {', '.join(top_features)}</p>
            <img src="{image_to_base64(os.path.join(out_dir, 'summary_plot.png'))}" alt="SHAP Summary Plot" width="800">
            <h3>Local Explanations</h3>
            <ul>
                {''.join(f'<li>{e}</li>' for e in shap_expl)}
            </ul>
        </div>
        
        <div class="section">
            <h2>4. Error Analysis</h2>
            <img src="{image_to_base64(os.path.join(out_dir, 'confusion_matrix.png'))}" alt="Confusion Matrix" width="500">
            <pre>{fp_analysis}</pre>
            <pre>{fn_analysis}</pre>
            <p><strong>Recommendations:</strong> Adjust threshold, investigate misclassified attack categories for missing features, or consider ensemble methods.</p>
        </div>
        
        <div class="section">
            <h2>5. Production Readiness Check</h2>
            <ul>
                <li>Average Inference Time (per sample): {prod_metrics['inference_time_ms']:.4f} ms</li>
                <li>Model File Size: {prod_metrics['model_size_mb']:.2f} MB</li>
                <li>Robustness Consistency Score (F1 on subsample): {prod_metrics['robustness_f1']:.4f}</li>
            </ul>
        </div>
    </body>
    </html>
    """
    
    with open(os.path.join(out_dir, 'evaluation_report.html'), 'w') as f:
        f.write(html)
        
    logging.info("HTML report generated successfully.")

def main():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        return
        
    config = load_config(config_path)
    out_dir = "shap_analysis"
    ensure_dir(out_dir)
    
    logging.info("Loading models and data...")
    X_test, y_test, attack_cat_test, models, features, _ = load_models_and_data(config)
    
    if not models:
        logging.error("No models found!")
        return
        
    if 'best_model' in models:
        best_model = models['best_model']
    else:
        best_model = list(models.values())[0]
        
    df_comp = compare_models(models, X_test, y_test, out_dir)
    print("Model Comparison:")
    print(df_comp)
    
    df_thresh = threshold_analysis(best_model, X_test, y_test, out_dir)
    
    top_features, shap_expl = shap_analysis(best_model, X_test, y_test, out_dir)
    
    fp_analysis, fn_analysis = error_analysis(best_model, X_test, y_test, attack_cat_test, out_dir)
    
    # Production metrics
    logging.info("Checking production readiness...")
    start = time.time()
    _ = best_model.predict(X_test.head(1000))
    inf_time = (time.time() - start) / 1000 * 1000 # in ms
    
    best_model_path = os.path.join(config['output']['model_dir'], config['output']['best_model_file'])
    model_size = os.path.getsize(best_model_path) / (1024 * 1024) if os.path.exists(best_model_path) else 0
    
    sub_X = X_test.sample(frac=0.5, random_state=42)
    sub_y = y_test.loc[sub_X.index]
    rob_f1 = f1_score(sub_y, best_model.predict(sub_X))
    
    prod_metrics = {
        'inference_time_ms': inf_time,
        'model_size_mb': model_size,
        'robustness_f1': rob_f1
    }
    
    generate_html_report(out_dir, df_comp, df_thresh, top_features, shap_expl, fp_analysis, fn_analysis, prod_metrics)
    logging.info(f"Evaluation complete. Results saved in {out_dir}/")

if __name__ == '__main__':
    main()
