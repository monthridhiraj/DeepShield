"""
DeepShield - Deep Learning Model Training Script
Trains CharCNN, BiLSTM, and Transformer models on real datasets.

Usage: python train_dl_models.py
"""

import os
import sys
import pandas as pd
import numpy as np
import tensorflow as tf
from pathlib import Path
from sklearn.utils import shuffle

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

from dl_models_new import CharCNN, BiLSTM, URLTransformer
from url_preprocessing import URLTokenizer, DLDataGenerator

# Configuration
# Configuration
MODELS_DIR = PROJECT_ROOT / "models"
DATA_PATH = PROJECT_ROOT / "balanced_urls.csv"

# Training Config
MAX_URL_LENGTH = 200
VOCAB_SIZE = 128  # ASCII
BATCH_SIZE = 64
EPOCHS = 5
SAMPLES_PER_CLASS = 15000  # Adjust based on memory/speed needs

def load_data():
    """Load pre-balanced dataset"""
    print(f"\n[1/5] Loading Data from {DATA_PATH}...")
    
    if not DATA_PATH.exists():
        print(f"[ERROR] Data not found. Run 'prepare_dataset.py' first.")
        return [], []
        
    try:
        df = pd.read_csv(DATA_PATH)
        print(f"  - Loaded {len(df)} samples")
        
        # Split by label
        phishing_urls = df[df['label'] == 1]['url'].astype(str).tolist()
        legit_urls = df[df['label'] == 0]['url'].astype(str).tolist()
        
        print(f"  - Phishing: {len(phishing_urls)}")
        print(f"  - Legitimate: {len(legit_urls)}")
        
        return phishing_urls, legit_urls
        
    except Exception as e:
        print(f"[ERROR] Failed to load data: {e}")
        return [], []

def train_models():
    # 1. Prepare Data
    phishing_urls, legit_urls = load_data()
    if not phishing_urls or not legit_urls:
        print("Error: Empty datasets")
        return

    tokenizer = URLTokenizer(max_url_length=MAX_URL_LENGTH)
    data_gen = DLDataGenerator(tokenizer, batch_size=BATCH_SIZE)
    
    X_train, X_val, y_train, y_val = data_gen.prepare_dl_dataset(
        phishing_urls, legit_urls, test_size=0.2
    )
    
    # 2. Train Models
    models_to_train = [
        {
            'name': 'charcnn',
            'class': CharCNN,
            'kwargs': {
                'vocab_size': tokenizer.vocab_size,
                'max_length': MAX_URL_LENGTH,
                'filters': [128, 256],    # Reduced for speed
                'kernel_sizes': [3, 5]
            }
        },
        {
            'name': 'bilstm',
            'class': BiLSTM,
            'kwargs': {
                'vocab_size': tokenizer.vocab_size,
                'max_length': MAX_URL_LENGTH,
                'lstm_units': [64]        # Reduced for speed
            }
        },
        {
            'name': 'transformer',
            'class': URLTransformer,
            'kwargs': {
                'vocab_size': tokenizer.vocab_size,
                'max_length': MAX_URL_LENGTH,
                'num_heads': 4,
                'num_transformer_blocks': 1 # Reduced for speed
            }
        }
    ]
    
    for config in models_to_train:
        name = config['name']
        print(f"\n{'='*40}")
        print(f"TRAINING: {name.upper()}")
        print(f"{'='*40}")
        
        # Instantiate
        model_wrapper = config['class'](**config['kwargs'])
        model_wrapper.compile_model(learning_rate=0.001)
        
        # Callbacks
        model_dir = MODELS_DIR / name
        model_dir.mkdir(parents=True, exist_ok=True)
        save_path = model_dir / "best_model.h5"
        
        callbacks = [
            tf.keras.callbacks.ModelCheckpoint(
                filepath=str(save_path),
                save_best_only=True,
                monitor='val_accuracy',
                mode='max',
                verbose=1
            ),
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=3,
                restore_best_weights=True
            )
        ]
        
        # Train
        try:
            history = model_wrapper.model.fit(
                X_train, y_train,
                validation_data=(X_val, y_val),
                epochs=EPOCHS,
                batch_size=BATCH_SIZE,
                callbacks=callbacks,
                verbose=1
            )
            print(f"\n[OK] Trained {name}. Best validation accuracy: {max(history.history['val_accuracy']):.4f}")
            print(f"Saved to: {save_path}")
            
        except Exception as e:
            print(f"\n[ERROR] Failed to train {name}: {e}")

if __name__ == "__main__":
    
    # Ensure standard directory structure
    MODELS_DIR.mkdir(exist_ok=True)
    
    print("="*60)
    print("DEEPSHIELD DL TRAINING PIPELINE")
    print("="*60)
    
    # Verify TF
    print(f"TensorFlow Version: {tf.__version__}")
    if tf.config.list_physical_devices('GPU'):
        print("GPU Available: Yes")
    else:
        print("GPU Available: No (Training might be slow)")
        
    train_models()
