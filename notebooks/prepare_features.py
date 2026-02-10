"""
DeepShield - Feature Extraction Script

Reads 'balanced_urls.csv' (created by prepare_dataset.py)
Extracts 30 features for each URL.
Saves 'balanced_features.csv' for ML training.

Usage: python notebooks/prepare_features.py
"""

import os
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
import concurrent.futures
import csv
import socket
import logging

# Set global timeout for all socket operations (DNS, Whois, etc.) to 2 seconds
socket.setdefaulttimeout(2)

# Suppress logging
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

from feature_extraction import FeatureExtractor

# Configuration
DATA_DIR = PROJECT_ROOT
INPUT_FILE = DATA_DIR / "balanced_urls.csv"
OUTPUT_FILE = DATA_DIR / "balanced_features.csv"
MAX_WORKERS = 10  # Adjust based on CPU/Network limits

def process_url(args):
    """Helper for parallel processing"""
    url, label, extractor, feature_names = args
    try:
        features = extractor.extract_features(url)
        row = {'url': url, 'label': label}
        row.update(dict(zip(feature_names, features)))
        return row
    except Exception as e:
        return None

def main():
    print("="*60)
    print("FEATURE EXTRACTION PIPELINE")
    print("="*60)

    # 1. Load Data
    if not INPUT_FILE.exists():
        print(f"[ERROR] {INPUT_FILE} not found. Run 'prepare_dataset.py' first.")
        return

    print(f"[1/3] Loading {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    print(f"  - Found {len(df)} URLs")

    # 2. Extract Features
    print(f"\n[2/3] Extracting features (Parallel: {MAX_WORKERS} workers)...")
    print("  ! This process involves network requests (Whois, SSL, etc.)")
    print("  ! It may take significant time. Progress is saved automatically.")

    extractor = FeatureExtractor()
    
    # Feature names match those in feature_extraction.py
    feature_names = [
        'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol',
        'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'ssl_final_state',
        'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url',
        'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url',
        'redirect', 'on_mouseover', 'right_click', 'popup_window', 'iframe',
        'age_of_domain', 'dns_record', 'web_traffic', 'page_rank', 'google_index',
        'links_pointing_to_page', 'statistical_report'
    ]

    # Prepare arguments for parallel execution
    tasks = []
    for _, row in df.iterrows():
        tasks.append((row['url'], row['label'], extractor, feature_names))

    # Process with progress bar
    # Write header first
    header_written = False
    
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_url, task): task for task in tasks}
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(tasks), unit="url"):
                result = future.result()
                if result:
                    if not header_written:
                        writer = csv.DictWriter(f, fieldnames=result.keys())
                        writer.writeheader()
                        header_written = True
                    
                    writer.writerow(result)
                    f.flush()  # Ensure it's written to disk

    print(f"\n[3/3] Feature extraction complete.")
    print(f"  - Features saved to {OUTPUT_FILE}")
    print("  - Completed!")

if __name__ == "__main__":
    main()
