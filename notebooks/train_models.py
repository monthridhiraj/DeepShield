"""
DeepShield - Phishing Detection Model Training Script
Trains XGBoost and Random Forest models using extracted features.

Usage: python train_models.py
"""

import pandas as pd
import numpy as np
import os
import joblib
import warnings
from pathlib import Path
warnings.filterwarnings('ignore')

# ML Libraries
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score
)
import xgboost as xgb

# Configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = PROJECT_ROOT / "balanced_features_v2.csv"
MODELS_DIR = PROJECT_ROOT / "models"

def train_ml_models():
    print("=" * 60)
    print("DEEPSHIELD ML TRAINING PIPELINE (v2 Features)")
    print("=" * 60)

    # 1. Load Data
    print(f"\n[1/5] Loading Data from {DATA_PATH}...")
    if not DATA_PATH.exists():
        print(f"[ERROR] Data not found. Run 'recompute_features.py' first.")
        return

    try:
        df = pd.read_csv(DATA_PATH)
        print(f"  - Loaded {len(df)} samples")
        print(f"  - Phishing: {len(df[df['label']==1])}")
        print(f"  - Legitimate: {len(df[df['label']==0])}")
    except Exception as e:
        print(f"[ERROR] Failed to load data: {e}")
        return

    # 2. Prepare Data
    print("\n[2/5] Preparing Training Data...")
    
    # Drop non-feature columns
    X = df.drop(['url', 'label'], axis=1, errors='ignore')
    y = df['label']
    
    # Handle missing values
    X = X.fillna(0)
    
    feature_names = X.columns.tolist()
    print(f"  - Features: {len(feature_names)}")
    print(f"  - Names: {feature_names}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 3. Train XGBoost
    print("\n[3/5] Training XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        eval_metric='logloss',
        random_state=42
    )
    xgb_model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred_xgb = xgb_model.predict(X_test_scaled)
    acc_xgb = accuracy_score(y_test, y_pred_xgb)
    prec_xgb = precision_score(y_test, y_pred_xgb)
    rec_xgb = recall_score(y_test, y_pred_xgb)
    f1_xgb = f1_score(y_test, y_pred_xgb)
    print(f"  - Accuracy:  {acc_xgb:.4f}")
    print(f"  - Precision: {prec_xgb:.4f}")
    print(f"  - Recall:    {rec_xgb:.4f}")
    print(f"  - F1 Score:  {f1_xgb:.4f}")

    # 4. Train Random Forest
    print("\n[4/5] Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred_rf = rf_model.predict(X_test_scaled)
    acc_rf = accuracy_score(y_test, y_pred_rf)
    prec_rf = precision_score(y_test, y_pred_rf)
    rec_rf = recall_score(y_test, y_pred_rf)
    f1_rf = f1_score(y_test, y_pred_rf)
    print(f"  - Accuracy:  {acc_rf:.4f}")
    print(f"  - Precision: {prec_rf:.4f}")
    print(f"  - Recall:    {rec_rf:.4f}")
    print(f"  - F1 Score:  {f1_rf:.4f}")

    # 5. Save Models
    print("\n[5/5] Saving Artifacts to models/...")
    MODELS_DIR.mkdir(exist_ok=True)
    
    # Save Models
    xgb_model.save_model(MODELS_DIR / 'xgboost_model.json')
    joblib.dump(rf_model, MODELS_DIR / 'random_forest_model.joblib')
    
    # Save Scaler & Feature Names (Critical for API)
    joblib.dump(scaler, MODELS_DIR / 'feature_scaler.joblib')
    joblib.dump(feature_names, MODELS_DIR / 'feature_names.joblib')
    
    print("  - All files saved successfully.")
    print("=" * 60)

if __name__ == "__main__":
    train_ml_models()
