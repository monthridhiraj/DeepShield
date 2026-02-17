"""
Rebuild balanced_urls.csv using a HYBRID approach to fix path bias.

Source 1 (Legitimate): PhiUSIIL Dataset
   - Has realistic paths (mean depth ~1.0)
   - Eliminates "All legit are bare domains" bias

Source 2 (Phishing): Old Dataset (PhishTank/Old balanced_urls)
   - Has realistic paths (mean depth ~1.0)
   - Eliminates "All phishing are bare domains" bias (which PhiUSIIL had)

Result: Both classes have ~1.0 mean path depth. Model must learn content.
"""
import pandas as pd
import numpy as np
from pathlib import Path

PROJECT_ROOT = Path(r'p:/DeepShield_v0.2')
PHIUSIIL_PATH = PROJECT_ROOT / 'data/raw/PhiUSIIL_Phishing_URL_Dataset.csv'
OLD_DATA_PATH = PROJECT_ROOT / 'data/raw/balanced_urls_old.csv'
OUTPUT_PATH = PROJECT_ROOT / 'data/processed/balanced_urls.csv'

SAMPLES_PER_CLASS = 100000

def main():
    print("=" * 60)
    print("REBUILDING HYBRID DATASET (PhiUSIIL Legit + Old Phishing)")
    print("=" * 60)

    # 1. Load Legitimate from PhiUSIIL
    print(f"\n[1/3] Loading Legitimate URLs from PhiUSIIL...")
    try:
        df_phi = pd.read_csv(PHIUSIIL_PATH, usecols=['URL', 'label'])
        legit = df_phi[df_phi['label'] == 0].rename(columns={'URL': 'url'})
        legit = legit.dropna().drop_duplicates(subset=['url'])
        print(f"  Found {len(legit)} legitimate URLs (PhiUSIIL)")
    except Exception as e:
        print(f"  [ERROR] Failed to load PhiUSIIL: {e}")
        return

    # 2. Load Phishing from Old Dataset
    print(f"\n[2/3] Loading Phishing URLs from Old Dataset...")
    try:
        df_old = pd.read_csv(OLD_DATA_PATH)
        phish = df_old[df_old['label'] == 1]
        phish = phish.dropna().drop_duplicates(subset=['url'])
        print(f"  Found {len(phish)} phishing URLs (Old Dataset)")
    except Exception as e:
        print(f"  [ERROR] Failed to load Old Dataset: {e}")
        return

    # 3. Balance and Merge
    n_samples = min(len(legit), len(phish), SAMPLES_PER_CLASS)
    print(f"\n[3/3] Balancing: {n_samples} per class...")

    legit_sample = legit.sample(n=n_samples, random_state=42)
    phish_sample = phish.sample(n=n_samples, random_state=42)

    balanced = pd.concat([legit_sample[['url', 'label']], phish_sample[['url', 'label']]])
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    # 4. Save
    print(f"  Saving to {OUTPUT_PATH.name}...")
    temp_path = PROJECT_ROOT / 'balanced_urls_hybrid.csv'
    balanced.to_csv(temp_path, index=False)

    try:
        if OUTPUT_PATH.exists():
            OUTPUT_PATH.unlink()
        temp_path.rename(OUTPUT_PATH)
        print("  [OK] Saved successfully.")
    except PermissionError:
        print(f"  [WARN] Could not overwrite {OUTPUT_PATH.name} (locked).")
        print(f"  Saved as {temp_path.name}")

    # Stats validation
    from urllib.parse import urlparse
    def path_depth(u):
        try: return urlparse(str(u)).path.count('/')
        except: return 0

    l_depth = balanced[balanced.label==0]['url'].apply(path_depth).mean()
    p_depth = balanced[balanced.label==1]['url'].apply(path_depth).mean()
    
    print("\nDATASET STATS:")
    print(f"  Total: {len(balanced)}")
    print(f"  Legit Mean Path Depth: {l_depth:.2f}")
    print(f"  Phish Mean Path Depth: {p_depth:.2f}")
    
    if abs(l_depth - p_depth) < 0.2:
        print("\n[SUCCESS] Path depths are balanced! Bias fixed.")
    else:
        print("\n[WARNING] Path depths are still different.")

if __name__ == "__main__":
    main()
