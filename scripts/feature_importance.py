"""Analyze feature importance and false positives"""
import sys, os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import warnings; warnings.filterwarnings('ignore')
sys.path.append(r'p:\DeepShield_v0.2\src')

import numpy as np, pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
from feature_extraction import FeatureExtractor, FEATURE_NAMES

P = Path(r'p:/DeepShield_v0.2')
df = pd.read_csv(P / 'data/processed/balanced_features.csv')
X = df.drop(['url', 'label'], axis=1, errors='ignore').fillna(0)
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
Xtr = scaler.fit_transform(X_train)

m = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.05,
    reg_alpha=0.1, reg_lambda=1.0, subsample=0.8, colsample_bytree=0.8,
    eval_metric='logloss', random_state=42)
m.fit(Xtr, y_train)

importances = m.feature_importances_
feat_names = X.columns.tolist()
pairs = sorted(zip(feat_names, importances), key=lambda x: x[1], reverse=True)

fe = FeatureExtractor()
test_urls = [
    'https://www.flipkart.com/search?q=laptop',
    'https://accounts.google.com/signin/v2/identifier',
    'https://login.microsoftonline.com/common/oauth2',
    'https://razorpay.com/payment-link/abc123',
    'https://myaccount.google.com/security',
    'https://en.wikipedia.org/wiki/Machine_learning',
    'https://www.amazon.in/dp/B09V3KXJPB',
    'https://mail.yahoo.com/d/folders/1',
]

out = P / 'docs/feature_analysis.txt'
with open(out, 'w', encoding='utf-8') as f:
    f.write('XGBOOST FEATURE IMPORTANCE RANKING\n')
    f.write('=' * 60 + '\n')
    for i, (name, imp) in enumerate(pairs):
        bar = '#' * int(imp * 200)
        f.write(f'{i+1:2d}. {name:30s} {imp:.4f}  {bar}\n')

    f.write('\n\nFALSE POSITIVE ANALYSIS - LEGIT URLs\n')
    f.write('=' * 60 + '\n')
    for url in test_urls:
        feats = fe.extract_features(url)
        feat_dict = dict(zip(FEATURE_NAMES, feats))
        features_df = pd.DataFrame([feat_dict])
        features_df = features_df[X.columns]
        scaled = scaler.transform(features_df)
        pred = m.predict(scaled)[0]
        prob = m.predict_proba(scaled)[0]

        verdict = 'PHISHING' if pred == 1 else 'SAFE'
        f.write(f'\nURL: {url}\n')
        f.write(f'  PREDICTION: {verdict} (phishing_prob={prob[1]:.4f})\n')
        f.write(f'  Triggering features:\n')
        f.write(f'    has_suspicious_keywords  = {feat_dict["has_suspicious_keywords"]}\n')
        f.write(f'    has_double_slash_redirect = {feat_dict["has_double_slash_redirect"]}\n')
        f.write(f'    brand_in_subdomain       = {feat_dict["brand_in_subdomain"]}\n')
        f.write(f'    is_trusted_domain        = {feat_dict["is_trusted_domain"]}\n')
        f.write(f'    has_prefix_suffix        = {feat_dict["has_prefix_suffix"]}\n')
        f.write(f'    url_entropy              = {feat_dict["url_entropy"]}\n')
        f.write(f'    path_depth               = {feat_dict["path_depth"]}\n')
        f.write(f'    num_subdomains           = {feat_dict["num_subdomains"]}\n')

print(f'Results saved to {out}')
