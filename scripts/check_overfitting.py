"""
DeepShield - Overfitting Analysis Script
Compares Training Accuracy vs Test Accuracy for all 5 models.

A large gap (train >> test) = OVERFITTING
A small gap (<2%) = HEALTHY

Usage: python check_overfitting.py
"""

import sys
import os
import io

# Fix encoding for Windows PowerShell
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

MODELS_DIR = PROJECT_ROOT / "models"
ML_DATA_PATH = PROJECT_ROOT / "data/processed/balanced_features.csv"
DL_DATA_PATH = PROJECT_ROOT / "data/processed/balanced_urls.csv"

def evaluate_model(model, X_train, X_test, y_train, y_test, name, model_type):
    """Evaluate a model on both train and test sets"""
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)

    train_acc = accuracy_score(y_train, y_train_pred)
    test_acc = accuracy_score(y_test, y_test_pred)
    gap = train_acc - test_acc

    result = {
        'Model': name,
        'Type': model_type,
        'Train Accuracy': train_acc,
        'Test Accuracy': test_acc,
        'Gap': gap,
        'Train Precision': precision_score(y_train, y_train_pred),
        'Test Precision': precision_score(y_test, y_test_pred),
        'Train Recall': recall_score(y_train, y_train_pred),
        'Test Recall': recall_score(y_test, y_test_pred),
        'Train F1': f1_score(y_train, y_train_pred),
        'Test F1': f1_score(y_test, y_test_pred),
    }

    print(f"    Train Accuracy: {train_acc:.4f}")
    print(f"    Test Accuracy:  {test_acc:.4f}")
    print(f"    Gap:            {gap:.4f} ({gap*100:.2f}%)")
    return result


def check_ml_overfitting():
    """Check overfitting for XGBoost and Random Forest by retraining with same params"""
    print("=" * 70)
    print("  OVERFITTING ANALYSIS: ML MODELS (XGBoost & Random Forest)")
    print("=" * 70)

    # 1. Load data (same split as training)
    print("\n[1] Loading ML dataset...")
    df = pd.read_csv(ML_DATA_PATH)
    X = df.drop(['url', 'label'], axis=1, errors='ignore').fillna(0)
    y = df['label']
    feature_names = X.columns.tolist()
    print(f"    Samples: {len(df)} | Features: {len(feature_names)}")

    # Same split as training (random_state=42, test_size=0.2, stratify=y)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Train: {len(X_train)} | Test: {len(X_test)}")

    # Scale (same as training)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = []
    import xgboost as xgb
    from sklearn.ensemble import RandomForestClassifier

    # 2. XGBoost - retrain with same hyperparameters to avoid version issues
    print("\n[2] Training & Evaluating XGBoost (same hyperparams)...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        reg_alpha=0.1,
        reg_lambda=1.0,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='logloss',
        random_state=42
    )
    xgb_model.fit(X_train_scaled, y_train)
    results.append(evaluate_model(xgb_model, X_train_scaled, X_test_scaled, y_train, y_test, 'XGBoost', 'ML'))

    # 3. Random Forest - retrain with same hyperparameters
    print("\n[3] Training & Evaluating Random Forest (same hyperparams)...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    results.append(evaluate_model(rf_model, X_train_scaled, X_test_scaled, y_train, y_test, 'Random Forest', 'ML'))

    return results


def check_dl_overfitting():
    """Check overfitting for CharCNN, BiLSTM, and Transformer"""
    print("\n" + "=" * 70)
    print("  OVERFITTING ANALYSIS: DL MODELS (CharCNN, BiLSTM, Transformer)")
    print("=" * 70)

    # 1. Load data
    print("\n[1] Loading DL dataset...")
    
    try:
        import tensorflow as tf
        import logging
        logging.getLogger('tensorflow').setLevel(logging.ERROR)
    except ImportError:
        print("    [ERROR] TensorFlow not installed. Skipping DL models.")
        return []

    from url_preprocessing import URLTokenizer, DLDataGenerator

    df = pd.read_csv(DL_DATA_PATH)
    phishing_urls = df[df['label'] == 1]['url'].astype(str).tolist()
    legit_urls = df[df['label'] == 0]['url'].astype(str).tolist()
    print(f"    Phishing: {len(phishing_urls)} | Legitimate: {len(legit_urls)}")

    MAX_URL_LENGTH = 200
    BATCH_SIZE = 64

    tokenizer = URLTokenizer(max_url_length=MAX_URL_LENGTH)
    data_gen = DLDataGenerator(tokenizer, batch_size=BATCH_SIZE)

    X_train, X_val, y_train, y_val = data_gen.prepare_dl_dataset(
        phishing_urls, legit_urls, test_size=0.2
    )
    print(f"    Train: {len(X_train)} | Test: {len(X_val)}")

    results = []

    # Evaluate each DL model
    dl_models = ['charcnn', 'bilstm', 'transformer']

    for i, name in enumerate(dl_models):
        print(f"\n[{i+2}] Evaluating {name.upper()}...")
        model_path = MODELS_DIR / name / "best_model.h5"

        if not model_path.exists():
            print(f"    [SKIP] Model file not found: {model_path}")
            continue

        try:
            # Load model (need custom objects for weighted loss)
            model = tf.keras.models.load_model(
                str(model_path),
                compile=False  # Skip loading custom loss
            )
            # Recompile with standard metrics
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )

            # Predict on train set (use a subset if too large to save memory)
            train_subset_size = min(len(X_train), 50000)
            indices = np.random.RandomState(42).choice(len(X_train), train_subset_size, replace=False)
            X_train_subset = X_train[indices]
            y_train_subset = y_train[indices]

            # Training set predictions
            y_train_prob = model.predict(X_train_subset, batch_size=256, verbose=0)
            y_train_pred = (y_train_prob.flatten() > 0.5).astype(int)
            train_acc = accuracy_score(y_train_subset, y_train_pred)

            # Test set predictions
            y_test_prob = model.predict(X_val, batch_size=256, verbose=0)
            y_test_pred = (y_test_prob.flatten() > 0.5).astype(int)
            test_acc = accuracy_score(y_val, y_test_pred)

            gap = train_acc - test_acc

            results.append({
                'Model': name.upper(),
                'Type': 'DL',
                'Train Accuracy': train_acc,
                'Test Accuracy': test_acc,
                'Gap': gap,
                'Train Precision': precision_score(y_train_subset, y_train_pred, zero_division=0),
                'Test Precision': precision_score(y_val, y_test_pred, zero_division=0),
                'Train Recall': recall_score(y_train_subset, y_train_pred, zero_division=0),
                'Test Recall': recall_score(y_val, y_test_pred, zero_division=0),
                'Train F1': f1_score(y_train_subset, y_train_pred, zero_division=0),
                'Test F1': f1_score(y_val, y_test_pred, zero_division=0),
            })

            print(f"    Train Accuracy: {train_acc:.4f}")
            print(f"    Test Accuracy:  {test_acc:.4f}")
            print(f"    Gap:            {gap:.4f} ({gap*100:.2f}%)")

            # Free memory
            del model
            tf.keras.backend.clear_session()

        except Exception as e:
            print(f"    [ERROR] Failed to evaluate {name}: {e}")

    return results


def print_summary(all_results):
    """Print a final summary table with verdicts"""
    print("\n" + "=" * 70)
    print("  FINAL OVERFITTING REPORT")
    print("=" * 70)

    print(f"\n{'Model':<16} {'Type':<6} {'Train Acc':<12} {'Test Acc':<12} {'Gap':<10} {'Verdict'}")
    print("-" * 70)

    for r in all_results:
        gap_pct = r['Gap'] * 100
        if gap_pct < 0.5:
            verdict = "[OK] NO Overfitting"
        elif gap_pct < 2.0:
            verdict = "[!!] Mild (Acceptable)"
        elif gap_pct < 5.0:
            verdict = "[**] Moderate Overfitting"
        else:
            verdict = "[XX] SEVERE Overfitting"

        print(f"{r['Model']:<16} {r['Type']:<6} {r['Train Accuracy']:.4f}       {r['Test Accuracy']:.4f}       {gap_pct:>+.2f}%     {verdict}")

    # Detailed metrics
    print(f"\n{'='*70}")
    print("  DETAILED METRICS (Precision / Recall / F1)")
    print(f"{'='*70}")
    print(f"\n{'Model':<16} {'Train P/R/F1':<30} {'Test P/R/F1':<30}")
    print("-" * 70)

    for r in all_results:
        train_str = f"P={r['Train Precision']:.4f}  R={r['Train Recall']:.4f}  F1={r['Train F1']:.4f}"
        test_str = f"P={r['Test Precision']:.4f}  R={r['Test Recall']:.4f}  F1={r['Test F1']:.4f}"
        print(f"{r['Model']:<16} {train_str:<30} {test_str:<30}")

    print(f"\n{'='*70}")
    print("  INTERPRETATION GUIDE")
    print(f"{'='*70}")
    print("  Gap < 0.5%   -> [OK] No overfitting (model generalizes well)")
    print("  Gap 0.5-2%   -> [!!] Mild overfitting (acceptable for production)")
    print("  Gap 2-5%     -> [**] Moderate overfitting (consider more regularization)")
    print("  Gap > 5%     -> [XX] Severe overfitting (model memorized training data)")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    print("\n" + "==" * 35)
    print("  DeepShield - OVERFITTING ANALYSIS")
    print("==" * 35)

    all_results = []

    # ML Models
    ml_results = check_ml_overfitting()
    all_results.extend(ml_results)

    # DL Models
    dl_results = check_dl_overfitting()
    all_results.extend(dl_results)

    # Summary
    if all_results:
        print_summary(all_results)
    else:
        print("\n[ERROR] No models could be evaluated.")
