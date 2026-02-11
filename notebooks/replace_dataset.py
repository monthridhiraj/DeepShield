
import pandas as pd
import os

# Paths
PHI_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"
CURRENT_PATH = "balanced_urls.csv"
BACKUP_PATH = "balanced_urls_old.csv"

# Manual Safe Domains (to be added as 0)
MANUAL_SAFE = [
    "https://www.bcci.tv/",
    "https://www.india.gov.in/",
    "https://twitch.tv/",
    "https://t.co/",
    "https://www.vce.ac.in/"
]

def replace_dataset():
    print("🚀 Starting Dataset Replacement...")
    
    # 1. Backup existing
    if os.path.exists(CURRENT_PATH):
        print(f"📦 Backing up {CURRENT_PATH} to {BACKUP_PATH}...")
        os.rename(CURRENT_PATH, BACKUP_PATH)
    
    # 2. Load PhiUSIIL
    print(f"Pb Loading {PHI_PATH}...")
    try:
        df = pd.read_csv(PHI_PATH)
        print(f"   - Loaded {len(df)} rows.")
    except Exception as e:
        print(f"❌ Error loading PhiUSIIL: {e}")
        return

    # 3. Flip Labels
    # PhiUSIIL: 1=Safe, 0=Phishing
    # DeepShield: 0=Safe, 1=Phishing
    print("🔄 Flipping Labels (1->0 for Safe, 0->1 for Phishing)...")
    
    # Logic: New Label = 1 - Old Label
    # If Old=1 (Safe) -> New=0 (Safe)
    # If Old=0 (Phishing) -> New=1 (Phishing)
    df['new_label'] = 1 - df['label']
    
    # Select only needed columns
    df_clean = df[['URL', 'new_label']].copy()
    df_clean.columns = ['url', 'label']
    
    # 4. Add Manual Safe Domains
    print("Bg Adding Manual Safe Domains...")
    manual_data = [{'url': url, 'label': 0} for url in MANUAL_SAFE]
    df_manual = pd.DataFrame(manual_data)
    
    # 5. Combine
    df_final = pd.concat([df_clean, df_manual], ignore_index=True)
    
    # 6. Save
    print(f"Cb Saving new dataset to {CURRENT_PATH}...")
    df_final.to_csv(CURRENT_PATH, index=False)
    print(f"✅ Done! New dataset has {len(df_final)} samples.")
    print("   - Label 0: Safe")
    print("   - Label 1: Phishing")

if __name__ == "__main__":
    replace_dataset()
