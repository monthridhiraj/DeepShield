# 🛡️ DeepShield - AI-Powered Phishing Detection

DeepShield is a cutting-edge browser extension that detects and blocks phishing websites in real-time using advanced Machine Learning (ML) and Deep Learning (DL) models. It provides proactive protection by analyzing URLs instantly and blocking malicious sites before they can steal your data.

## ✨ Key Features

-   **Real-Time Analysis**: Scans every URL you visit instantly.
-   **Hybrid AI Engine**: Combines **5 powerful models** for maximum accuracy (~99.6%):
    -   **ML**: XGBoost, Random Forest.
    -   **DL**: CharCNN, BiLSTM, Transformer (BERT-based).
-   **Smart Blocking**: Automatically redirects you to a warning page if a site is phishing.
-   **Trusted Domain Whitelist**: Instantly verifies major sites (Google, Amazon, Banking) locally to preserve privacy and speed.
-   **Detailed Insights**: Dashboard shows confidence scores from all 5 models.
-   **Privacy Focused**: Analysis runs on a local API server; your browsing history is never sent to the cloud.

---

## 🚀 Installation Guide

### Prerequisites
-   Python 3.8 or higher
-   Google Chrome (or any Chromium-based browser like Brave, Edge)

### 1. Backend Setup (The Brain)
The detection engine runs locally on your machine.

1.  **Clone/Download** this repository.
2.  Open a terminal in the project folder:
    ```bash
    cd DeepShield_v0.2
    ```
3.  **Create a virtual environment** (optional but recommended):
    ```bash
    python -m venv venv
    venv\Scripts\activate
    ```
4.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### 2. Extension Setup (The Shield)
1.  Open Chrome and go to `chrome://extensions`.
2.  Enable **Developer mode** (toggle in the top right).
3.  Click **Load unpacked**.
4.  Select the `extension` folder inside `DeepShield_v0.2`.
5.  Pin the DeepShield icon 🛡️ to your browser toolbar.

---

## 🎮 How to Run

### Step 1: Start the API Server
You must have the backend running for the extension to work.

**Option A (Easy):**
Double-click the **`start_api.bat`** file in the project folder.

**Option B (Manual):**
Run this command in your terminal:
```bash
python src/api_new.py
```
*You should see "Uvicorn running on http://0.0.0.0:8000"*

### Step 2: Browse Safely
-   Visit any website. The extension icon will change color:
    -   🟢 **Green**: Safe / Trusted
    -   🔴 **Red**: Phishing Detected
-   **Click the icon** to see detailed model predictions and feature analysis.
-   If you try to visit a phishing site, **DeepShield will block the page** and show a red warning screen.

---

## 🧠 Model Architecture

DeepShield uses an ensemble voting system. A URL is flagged as phishing only if the majority of models agree.

| Model | Type | Accuracy | Role |
|-------|------|----------|------|
| **XGBoost** | ML | 99.62% | Fast, feature-based detection |
| **Random Forest** | ML | 99.63% | Robust ensemble decision trees |
| **CharCNN** | DL | ~98% | Character-level pattern recognition |
| **BiLSTM** | DL | ~98% | Sequence learning for URL structure |
| **Transformer** | DL | ~98% | Contextual understanding of URLs |

**Feature Extraction**:
We extract **30 numerical features** from every URL, including:
-   URL entropy & length
-   Suspicious keywords/TLDs
-   IP address usage
-   Brand impersonation attempts

---

## 📂 Project Structure

```text
DeepShield_v0.2/
├── extension/             # Browser Extension Source
│   ├── manifest.json      # Extension config (MV3)
│   ├── background.js      # Core logic (interception, blocking)
│   ├── popup/             # UI for the popup window
│   └── block.html         # The "Blocked" warning page
├── src/                   # Backend Source Code
│   ├── api_new.py         # FastAPI server entry point
│   ├── feature_extraction.py # Feature engineering logic
│   ├── model_loader.py    # Loads ML/DL models
│   └── dl_models_new.py   # Deep Learning model definitions
├── models/                # Trained Model Artifacts
│   ├── xgboost_model.json
│   ├── random_forest_model.joblib
│   └── ... (DL models)
├── notebooks/             # Training Scripts
│   ├── recompute_features.py # Generates dataset from URLs
│   └── train_models.py    # Trains ML models
└── start_api.bat          # 1-click startup script
```

---

## 🛠️ Troubleshooting

**1. "Models not loaded" error?**
-   Ensure you have run `python src/api_new.py` or `start_api.bat`.
-   The startup logs should say `[OK] Loaded 5 ML/DL models`.

**2. Extension shows "Offline"?**
-   Check if the terminal window for the API server is still open.
-   Refresh the extension by clicking the "Retry" icon in the popup.

**3. Google Maps or valid sites getting blocked?**
-   We implemented a **Trusted Domain Check** to prevent this.
-   If it happens, click "Advanced Options" -> "Whitelist & Proceed" on the block page.

---

## 👨‍💻 Training Your Own Models (Advanced)

If you want to retrain the system with new data:

1.  Add your URLs to `balanced_urls.csv`.
2.  Run feature extraction (takes ~10 seconds):
    ```bash
    python notebooks/recompute_features.py
    ```
3.  Train the models:
    ```bash
    python notebooks/train_models.py
    ```
4.  Restart the API to load the new models.

---

**Developed for AI-Driven Cyber Security**
