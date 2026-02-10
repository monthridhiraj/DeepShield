"""
DeepShield - Dataset Preparation Script
1. Loads PhishTank (Phishing) and Majestic Million (Legitimate)
2. Balances them (50k each)
3. Saves 'balanced_urls.csv' (Raw URLs)
4. Extracts features (Optional/Commented for speed)

Usage: python prepare_dataset.py
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

from feature_extraction import FeatureExtractor

# Configuration
DATA_DIR = PROJECT_ROOT
PHISHTANK_PATH = DATA_DIR / "PhishTank.csv"
MAJESTIC_PATH = DATA_DIR / "majestic_million.csv"
RAW_OUTPUT_PATH = DATA_DIR / "balanced_urls.csv"
FEATURES_OUTPUT_PATH = DATA_DIR / "balanced_features.csv"

# Request: 50k per class
SAMPLES_PER_CLASS = 50000 

def load_and_balance_data():
    """Load, balance, and save raw dataset"""
    print(f"\n[1/3] Loading Datasets...")
    
    # 1. Load PhishTank
    print("  - Loading PhishTank...")
    if not PHISHTANK_PATH.exists():
        print(f"Error: {PHISHTANK_PATH} not found.")
        return None
        
    df_phish = pd.read_csv(PHISHTANK_PATH)
    # Find URL column
    url_col = next((c for c in df_phish.columns if 'url' in c.lower()), None)
    if not url_col:
        print("Error: No URL column in PhishTank")
        return None
        
    phishing_urls = df_phish[url_col].dropna().tolist()
    # Basic validation
    phishing_urls = [u for u in phishing_urls if isinstance(u, str) and u.startswith('http')]
    print(f"    Found {len(phishing_urls)} valid phishing URLs")

    # 2. Load Majestic
    print("  - Loading Majestic Million...")
    if not MAJESTIC_PATH.exists():
        print(f"Error: {MAJESTIC_PATH} not found.")
        return None
        
    df_legit = pd.read_csv(MAJESTIC_PATH)
    # Find Domain column
    domain_col = next((c for c in df_legit.columns if 'domain' in c.lower()), None)
    if not domain_col:
        print("Error: No Domain column in Majestic")
        return None
        
    # Add protocol
    legit_domains = df_legit[domain_col].dropna().tolist()
    legit_urls = [f'https://{d}' for d in legit_domains]
    print(f"    Found {len(legit_urls)} valid noble domains")
    
    # 3. Balance
    n_samples = min(len(phishing_urls), len(legit_urls), SAMPLES_PER_CLASS)
    print(f"\n[2/3] Balancing Data: {n_samples} samples per class...")
    
    phishing_subset = np.random.choice(phishing_urls, n_samples, replace=False)
    legit_subset = np.random.choice(legit_urls, n_samples, replace=False)
    
    # Create DataFrame
    df_phish_final = pd.DataFrame({'url': phishing_subset, 'label': 1})
    df_legit_final = pd.DataFrame({'url': legit_subset, 'label': 0})
    
    df_balanced = pd.concat([df_phish_final, df_legit_final], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save Raw
    print(f"  - Saving balanced dataset to {RAW_OUTPUT_PATH}...")
    df_balanced.to_csv(RAW_OUTPUT_PATH, index=False)
    print("  - Done.")
    
    return df_balanced

def extract_features_parallel(df):
    """Run feature extraction (This will be slow for 100k)"""
    # For now, we will perform a sequential extraction on a small subset 
    # just to demonstrate, or we can use concurrent.futures if the user wants full run.
    # Given the user just asked to 'Combine them', we stop here or ask for confirmation.
    pass

if __name__ == "__main__":
    df = load_and_balance_data()
    if df is not None:
        print(f"\n[3/3] Dataset Ready: {len(df)} rows.")
        print(f"You can now use '{RAW_OUTPUT_PATH}' for DL training.")
        print("To generate features for ML training, run the feature extractor.")
