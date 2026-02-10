"""
DeepShield Data Preparation Pipeline

This module handles:
1. Multi-dataset loading (UCI, PhishTank, Majestic, OpenPhish)
2. Temporal splitting for zero-day testing
3. Cross-dataset generalization setup
4. Preprocessing for ML and DL branches
"""

import pandas as pd
import numpy as np
from datetime import datetime
from typing import Tuple, Dict, List
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')


DEFAULT_BASE_DIR = Path(__file__).resolve().parent.parent


class DatasetConfig:
    """Configuration for dataset paths and splits"""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else DEFAULT_BASE_DIR
        
        # Dataset paths
        self.uci_path = self.base_dir / "UCI Phishing Dataset.csv"
        self.phishtank_path = self.base_dir / "PhishTank.csv"
        self.majestic_path = self.base_dir / "majestic_million.csv"
        self.openphish_path = self.base_dir / "OpenPhish.txt"
        
        # Split ratios
        self.uci_train_ratio = 0.80
        self.uci_val_ratio = 0.10
        self.uci_test_ratio = 0.10
        
        self.phishtank_train_ratio = 0.70
        self.phishtank_val_ratio = 0.15
        self.phishtank_test_ratio = 0.15
        
        # Sampling
        self.majestic_sample_size = 50000  # Balance with phishing samples
        
        # Output paths
        self.output_dir = self.base_dir / "data" / "processed"
        self.output_dir.mkdir(parents=True, exist_ok=True)


class MultiDatasetLoader:
    """Load and preprocess multiple datasets with proper role assignment"""
    
    def __init__(self, config: DatasetConfig):
        self.config = config
        
    def load_uci_dataset(self) -> pd.DataFrame:
        """
        Load UCI Phishing Dataset (handcrafted features)
        
        Role: ML Branch training (XGBoost, Random Forest)
        """
        print("Loading UCI Phishing Dataset...")
        df = pd.read_csv(self.config.uci_path)
        
        # Clean column names (remove trailing spaces)
        df.columns = df.columns.str.strip()
        # Fix known header glitches from the UCI CSV
        df = df.rename(columns={
            'having_IPhaving_IP_Address': 'having_IP_Address',
            'URLURL_Length': 'URL_Length',
        })
        
        # Target column is the last one: 'Result' (1=legit, -1=phishing)
        # Convert to binary: 1=phishing, 0=legit (security-oriented)
        df['label'] = (df.iloc[:, -1] == -1).astype(int)
        
        # Drop original result and index columns (keep all 30 features)
        excluded = {'index', 'Result', 'label'}
        feature_cols = [col for col in df.columns if col not in excluded]
        
        print(f"  - Loaded {len(df):,} samples")
        print(f"  - Features: {len(feature_cols)}")
        print(f"  - Class distribution: {df['label'].value_counts().to_dict()}")
        
        return df[feature_cols + ['label']]
    
    def load_phishtank_dataset(self) -> pd.DataFrame:
        """
        Load PhishTank URLs (raw phishing URLs)
        
        Role: DL Branch training (Character-level models)
        """
        print("Loading PhishTank Dataset...")
        df = pd.read_csv(self.config.phishtank_path)
        
        # Extract URL and submission time for temporal split
        df_clean = pd.DataFrame({
            'url': df['url'],
            'label': 1,  # All phishing
            'submission_time': pd.to_datetime(df['submission_time'], errors='coerce')
        })
        
        # Remove rows with missing URLs or timestamps
        df_clean = df_clean.dropna(subset=['url', 'submission_time'])
        
        print(f"  - Loaded {len(df_clean):,} phishing URLs")
        print(f"  - Date range: {df_clean['submission_time'].min()} to {df_clean['submission_time'].max()}")
        
        return df_clean
    
    def load_majestic_dataset(self, sample_size: int = None) -> pd.DataFrame:
        """
        Load Majestic Million (legitimate domains)
        
        Role: Negative samples for DL Branch
        """
        print("Loading Majestic Million Dataset...")
        
        if sample_size is None:
            sample_size = self.config.majestic_sample_size
        
        # Read only necessary columns
        df = pd.read_csv(self.config.majestic_path, usecols=['Domain'])
        
        # Sample random legitimate domains
        df_sample = df.sample(n=min(sample_size, len(df)), random_state=42)
        
        # Add http:// prefix to create URLs
        df_clean = pd.DataFrame({
            'url': 'http://' + df_sample['Domain'],
            'label': 0  # Legitimate
        })
        
        print(f"  - Sampled {len(df_clean):,} legitimate domains")
        
        return df_clean
    
    def load_openphish_dataset(self) -> pd.DataFrame:
        """
        Load OpenPhish (recent phishing URLs)
        
        Role: Zero-day testing (completely held-out)
        """
        print("Loading OpenPhish Dataset...")
        
        with open(self.config.openphish_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        df = pd.DataFrame({
            'url': urls,
            'label': 1  # All phishing
        })
        
        print(f"  - Loaded {len(df):,} zero-day phishing URLs")
        
        return df


class TemporalSplitter:
    """Create temporal splits for zero-day testing"""
    
    @staticmethod
    def temporal_split_phishtank(
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split PhishTank by time (old → train, recent → test)
        
        Args:
            df: PhishTank dataframe with 'submission_time' column
            train_ratio: Ratio for training (oldest samples)
            val_ratio: Ratio for validation
            
        Returns:
            train_df, val_df, test_df
        """
        # Sort by time
        df_sorted = df.sort_values('submission_time').reset_index(drop=True)
        
        n = len(df_sorted)
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))
        
        train_df = df_sorted.iloc[:train_end].copy()
        val_df = df_sorted.iloc[train_end:val_end].copy()
        test_df = df_sorted.iloc[val_end:].copy()
        
        print(f"\nTemporal Split (PhishTank):")
        print(f"  - Train: {len(train_df):,} samples (dates: {train_df['submission_time'].min()} to {train_df['submission_time'].max()})")
        print(f"  - Val:   {len(val_df):,} samples (dates: {val_df['submission_time'].min()} to {val_df['submission_time'].max()})")
        print(f"  - Test:  {len(test_df):,} samples (dates: {test_df['submission_time'].min()} to {test_df['submission_time'].max()})")
        
        return train_df, val_df, test_df
    
    @staticmethod
    def random_split_uci(
        df: pd.DataFrame,
        train_ratio: float = 0.80,
        val_ratio: float = 0.10,
        random_state: int = 42
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Random split for UCI (no temporal info)
        
        Stratified to maintain class balance
        """
        from sklearn.model_selection import train_test_split
        
        # First split: train vs (val + test)
        train_df, temp_df = train_test_split(
            df,
            test_size=(1 - train_ratio),
            stratify=df['label'],
            random_state=random_state
        )
        
        # Second split: val vs test
        val_ratio_adjusted = val_ratio / (val_ratio + (1 - train_ratio - val_ratio))
        val_df, test_df = train_test_split(
            temp_df,
            test_size=(1 - val_ratio_adjusted),
            stratify=temp_df['label'],
            random_state=random_state
        )
        
        print(f"\nRandom Split (UCI):")
        print(f"  - Train: {len(train_df):,} samples (phishing: {train_df['label'].sum()})")
        print(f"  - Val:   {len(val_df):,} samples (phishing: {val_df['label'].sum()})")
        print(f"  - Test:  {len(test_df):,} samples (phishing: {test_df['label'].sum()})")
        
        return train_df, val_df, test_df


class DataPreparationPipeline:
    """Main pipeline for preparing all datasets"""
    
    def __init__(self, config: DatasetConfig = None):
        self.config = config or DatasetConfig()
        self.loader = MultiDatasetLoader(self.config)
        self.splitter = TemporalSplitter()
        
    def prepare_all_datasets(self) -> Dict[str, pd.DataFrame]:
        """
        Prepare all datasets with proper splits
        
        Returns:
            Dictionary with keys:
                - 'uci_train', 'uci_val', 'uci_test': ML branch (features)
                - 'phishtank_train', 'phishtank_val', 'phishtank_test': DL branch (phishing URLs)
                - 'majestic_train': DL branch (legitimate URLs)
                - 'openphish_test': Zero-day testing
        """
        datasets = {}
        
        print("="*60)
        print("DEEPSHIELD DATA PREPARATION PIPELINE")
        print("="*60)
        
        # 1. Load UCI Dataset (ML Branch)
        print("\n[1/4] UCI DATASET (ML Branch - Handcrafted Features)")
        uci_full = self.loader.load_uci_dataset()
        uci_train, uci_val, uci_test = self.splitter.random_split_uci(
            uci_full,
            self.config.uci_train_ratio,
            self.config.uci_val_ratio
        )
        datasets['uci_train'] = uci_train
        datasets['uci_val'] = uci_val
        datasets['uci_test'] = uci_test
        
        # 2. Load PhishTank (DL Branch - Phishing URLs)
        print("\n[2/4] PHISHTANK DATASET (DL Branch - Phishing URLs)")
        phishtank_full = self.loader.load_phishtank_dataset()
        pt_train, pt_val, pt_test = self.splitter.temporal_split_phishtank(
            phishtank_full,
            self.config.phishtank_train_ratio,
            self.config.phishtank_val_ratio
        )
        datasets['phishtank_train'] = pt_train
        datasets['phishtank_val'] = pt_val
        datasets['phishtank_test'] = pt_test
        
        # 3. Load Majestic Million (DL Branch - Legitimate URLs)
        print("\n[3/4] MAJESTIC MILLION DATASET (DL Branch - Legitimate URLs)")
        majestic = self.loader.load_majestic_dataset()
        datasets['majestic_train'] = majestic
        
        # 4. Load OpenPhish (Zero-Day Testing)
        print("\n[4/4] OPENPHISH DATASET (Zero-Day Testing)")
        openphish = self.loader.load_openphish_dataset()
        datasets['openphish_test'] = openphish
        
        # Summary
        print("\n" + "="*60)
        print("DATASET SUMMARY")
        print("="*60)
        print(f"ML Branch (UCI Features):")
        print(f"  - Train: {len(datasets['uci_train']):,} samples")
        print(f"  - Val:   {len(datasets['uci_val']):,} samples")
        print(f"  - Test:  {len(datasets['uci_test']):,} samples")
        print(f"\nDL Branch (URL Sequences):")
        print(f"  - PhishTank Train:  {len(datasets['phishtank_train']):,} (phishing)")
        print(f"  - PhishTank Val:    {len(datasets['phishtank_val']):,} (phishing)")
        print(f"  - PhishTank Test:   {len(datasets['phishtank_test']):,} (phishing)")
        print(f"  - Majestic Train:   {len(datasets['majestic_train']):,} (legitimate)")
        print(f"\nZero-Day Testing:")
        print(f"  - OpenPhish:        {len(datasets['openphish_test']):,} (phishing)")
        print("="*60)
        
        return datasets
    
    def save_datasets(self, datasets: Dict[str, pd.DataFrame]):
        """Save processed datasets to disk"""
        print(f"\nSaving datasets to {self.config.output_dir}...")
        
        for name, df in datasets.items():
            output_path = self.config.output_dir / f"{name}.csv"
            df.to_csv(output_path, index=False)
            print(f"  - Saved {name}: {output_path}")
        
        print("\n✓ All datasets saved successfully!")


if __name__ == "__main__":
    # Run data preparation pipeline
    pipeline = DataPreparationPipeline()
    datasets = pipeline.prepare_all_datasets()
    pipeline.save_datasets(datasets)
