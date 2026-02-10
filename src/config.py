"""
DeepShield Configuration Module
Contains all project settings, paths, and hyperparameters
"""

import os
from pathlib import Path

# Project root directory
ROOT_DIR = Path(__file__).parent.parent
DATA_DIR = ROOT_DIR / "data"
MODELS_DIR = ROOT_DIR / "models"
OUTPUTS_DIR = ROOT_DIR / "outputs"

# Data paths
RAW_DATA_PATH = DATA_DIR / "raw" / "phishing_dataset.csv"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
FEATURES_DATA_DIR = DATA_DIR / "features"

# Model directories
ML_MODELS_DIR = MODELS_DIR / "ml"
DL_MODELS_DIR = MODELS_DIR / "dl"
ENSEMBLE_MODELS_DIR = MODELS_DIR / "ensemble"

# Output directories
FIGURES_DIR = OUTPUTS_DIR / "figures"
REPORTS_DIR = OUTPUTS_DIR / "reports"
LOGS_DIR = OUTPUTS_DIR / "logs"

# Dataset parameters
TRAIN_TEST_SPLIT_RATIO = 0.8
RANDOM_STATE = 42
STRATIFY = True

# Feature engineering parameters
# Set TOP_K_FEATURES to None to keep all features for IG/GR.
TOP_K_FEATURES = None
# Set PCA_VARIANCE_THRESHOLD to 1.0 to preserve all variance (no reduction).
PCA_VARIANCE_THRESHOLD = 1.0
# Leave PCA_N_COMPONENTS as None to use variance threshold (or full components when threshold=1.0).
PCA_N_COMPONENTS = None
# Default to full feature set. Use 'all' to run original + IG + GR + PCA.
FEATURE_SET = 'all'  # options: 'original', 'ig', 'gr', 'pca', 'all'

# Deep Learning hyperparameters
DL_EPOCHS = 300  # Mirror IEEE paper iterations
DL_BATCH_SIZE = 32 # Reduced from 64 for better generalization
DL_HIDDEN_UNITS = 200  # Mirror IEEE paper hidden units
DL_DROPOUT_RATE = 0.4 # Increased from 0.3 to prevent overfitting
DL_INITIAL_LR = 0.0005 # Slower learning rate for stability
DL_LR_REDUCE_FACTOR = 0.5
DL_LR_PATIENCE = 3
DL_EARLY_STOP_PATIENCE = 8

# CNN-LSTM hyperparameters
CNN_LSTM_FILTERS = [64, 128]
CNN_LSTM_KERNEL_SIZE = 5
CNN_LSTM_POOL_SIZE = 2
CNN_LSTM_DROPOUT = 0.2
CNN_LSTM_USE_BATCHNORM = True
CNN_LSTM_BIDIRECTIONAL = True

# Machine Learning hyperparameters
ML_CV_FOLDS = 10 # Increased from 5 for more robust validation
ML_N_JOBS = 1 # Use single process for stability on Windows
SVM_KERNEL = 'rbf'
SVM_C_RANGE = [0.1, 1, 10, 100]
SVM_GAMMA_RANGE = ['scale', 'auto', 0.001, 0.01]
DT_MAX_DEPTH_RANGE = [5, 10, 15, 20, None]
KNN_K_RANGE = [3, 5, 7, 9, 11]

# Ensemble hyperparameters
RF_N_ESTIMATORS = 300 # Increased from 200
RF_MAX_DEPTH = None
XGBOOST_N_ESTIMATORS = 300 # Increased from 200
XGBOOST_MAX_DEPTH = 6
XGBOOST_LEARNING_RATE = 0.05 # Lower learning rate
ADABOOST_N_ESTIMATORS = 150
ADABOOST_LEARNING_RATE = 0.5 # Lower learning rate

# Model names
ML_MODELS = ['SVM', 'DecisionTree', 'KNN']
DL_MODELS = ['LSTM', 'RNN', 'GRU', 'CNN_LSTM']
ENSEMBLE_MODELS = ['AdaBoost', 'RandomForest', 'XGBoost']
ALL_MODELS = ML_MODELS + DL_MODELS + ENSEMBLE_MODELS

# Class labels
CLASS_LABELS = {-1: 'Phishing', 1: 'Legitimate'}
CLASS_NAMES = ['Phishing', 'Legitimate']

# Feature names
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 
    'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port', 
    'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 
    'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover', 
    'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord', 
    'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 
    'Statistical_report'
]

# Visualization settings
FIGURE_SIZE = (12, 8)
DPI = 300
PLOT_STYLE = 'seaborn-v0_8-darkgrid'

# API settings
API_HOST = '0.0.0.0'
API_PORT = 8000

# Dashboard settings
DASHBOARD_PORT = 8501
DASHBOARD_THEME = 'dark'

def ensure_directories():
    """Create all necessary directories if they don't exist"""
    directories = [
        DATA_DIR / "raw",
        DATA_DIR / "processed",
        DATA_DIR / "features",
        MODELS_DIR / "ml",
        MODELS_DIR / "dl",
        MODELS_DIR / "ensemble",
        OUTPUTS_DIR / "figures",
        OUTPUTS_DIR / "reports",
        OUTPUTS_DIR / "logs"
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

def set_run_directories(run_name: str):
    """
    Update output/model directories for a specific run to avoid overwriting.
    """
    global OUTPUTS_DIR, FIGURES_DIR, REPORTS_DIR, LOGS_DIR
    global MODELS_DIR, ML_MODELS_DIR, DL_MODELS_DIR, ENSEMBLE_MODELS_DIR

    suffix_dir = ROOT_DIR / "outputs" / "feature_sets" / run_name
    OUTPUTS_DIR = suffix_dir
    FIGURES_DIR = OUTPUTS_DIR / "figures"
    REPORTS_DIR = OUTPUTS_DIR / "reports"
    LOGS_DIR = OUTPUTS_DIR / "logs"

    MODELS_DIR = ROOT_DIR / "models" / "feature_sets" / run_name
    ML_MODELS_DIR = MODELS_DIR / "ml"
    DL_MODELS_DIR = MODELS_DIR / "dl"
    ENSEMBLE_MODELS_DIR = MODELS_DIR / "ensemble"

if __name__ == "__main__":
    ensure_directories()
    print("OK All directories created successfully")
