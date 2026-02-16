"""
DeepShield API v2.0
Updated FastAPI backend for newly trained models
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import joblib

# Add src to path
sys.path.append(str(Path(__file__).parent))

from model_loader import ModelLoader
from feature_extraction import FeatureExtractor, FEATURE_NAMES, TRUSTED_DOMAINS
import feedback_db
from urllib.parse import urlparse

# Initialize FastAPI
app = FastAPI(
    title="DeepShield API",
    version="2.0.0",
    description="Phishing Detection System with ML and DL Models"
)

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
UI_DIR = Path(__file__).parent / "ui"

# Simple static UI (no Vite required)
if UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
model_loader: Optional[ModelLoader] = None
feature_extractor = FeatureExtractor()
feature_scaler = None
expected_features = None

# Data processing paths
SCALER_PATH = MODELS_DIR / "feature_scaler.joblib"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.joblib"


# Request/Response models
class PredictRequest(BaseModel):
    url: str = Field(..., description="URL to analyze for phishing")

class FeedbackRequest(BaseModel):
    url: str = Field(..., description="URL to report")
    verdict: str = Field(..., description="'safe' or 'phishing'")


class ModelPrediction(BaseModel):
    prediction: int
    probability: float
    label: str


class PredictResponse(BaseModel):
    url: str
    verdict: str
    confidence: float
    final_prediction: int
    ml_models: Dict[str, ModelPrediction]
    dl_models: Dict[str, ModelPrediction]
    recommendation: str


class HealthResponse(BaseModel):
    status: str
    models_loaded: Dict[str, List[str]]
    total_models: int


class ModelInfo(BaseModel):
    name: str
    type: str
    status: str


# Startup event
@app.on_event("startup")
async def startup_event():
    """Load models on startup"""
    global model_loader, feature_scaler, expected_features
    
    print("\n" + "="*70)
    print("STARTING DEEP SHIELD API v2.0")
    print("="*70)
    
    # Initialize Feedback DB
    feedback_db.init_db()
    
    # Load persistent whitelist
    try:
        whitelisted = feedback_db.get_whitelisted_domains()
        for domain in whitelisted:
            TRUSTED_DOMAINS.add(domain)
        print(f"[INFO] Loaded {len(whitelisted)} whitelisted domains from database")
    except Exception as e:
        print(f"[WARN] Failed to load whitelist: {e}")
        
    print("[*] DEEPSHIELD API STARTING UP")
    print("="*70)
    
    # Load feature scaler
    if SCALER_PATH.exists():
        try:
            feature_scaler = joblib.load(SCALER_PATH)
            print(f"[OK] Loaded feature scaler from {SCALER_PATH}")
        except Exception as e:
            print(f"[ERROR] Failed to load scaler: {e}")
    else:
        print(f"[WARN] Scaler not found at {SCALER_PATH}")
    
    # Load feature names
    if FEATURE_NAMES_PATH.exists():
        try:
            expected_features = joblib.load(FEATURE_NAMES_PATH)
            print(f"[OK] Loaded expected features ({len(expected_features)} features)")
        except Exception as e:
            print(f"[ERROR] Failed to load feature names: {e}")
    else:
        print(f"[WARN] Feature names not found at {FEATURE_NAMES_PATH}")
    
    model_loader = ModelLoader()
    model_loader.load_all_available_models()
    
    print("\n[OK] API Ready!")
    print("="*70)


# API Endpoints
@app.get("/", tags=["General"])
async def root(request: Request):
    """Root endpoint"""
    if UI_DIR.exists():
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            index_path = UI_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))

    return {
        "message": "DeepShield API v2.0",
        "docs": "/docs",
        "health": "/health",
        "ui": "/ui"
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """Check API health and loaded models"""
    if model_loader is None:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    info = model_loader.get_model_info()
    
    return HealthResponse(
        status="healthy",
        models_loaded={
            "ml": info['ml_models'],
            "dl": info['dl_models']
        },
        total_models=info['total_models']
    )


@app.get("/models", response_model=List[ModelInfo], tags=["Models"])
async def list_models():
    """List all available models"""
    if model_loader is None:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    info = model_loader.get_model_info()
    models = []
    
    for ml_model in info['ml_models']:
        models.append(ModelInfo(name=ml_model, type="ML", status="loaded"))
    
    for dl_model in info['dl_models']:
        models.append(ModelInfo(name=dl_model, type="DL", status="loaded"))
    
    return models


@app.post("/feedback", tags=["Feedback"])
async def submit_feedback(request: FeedbackRequest):
    """Submit user feedback for RL-Lite"""
    try:
        # 1. Add to Database
        success = feedback_db.add_feedback(request.url, request.verdict)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save feedback")
            
        # 2. Instant Whitelist (Runtime Patch)
        if request.verdict == 'safe':
            # Extract domain to whitelist
            try:
                parsed = urlparse(request.url)
                domain = parsed.netloc.lower().replace('www.', '')
                TRUSTED_DOMAINS.add(domain)
                print(f"[RL-Lite] Added {domain} to runtime whitelist")
            except:
                pass
        
        return {"status": "success", "message": "Feedback received. Model will be retrained."}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict", response_model=PredictResponse, tags=["Prediction"])
async def predict_url(request: PredictRequest):
    """Predict if a URL is phishing or legitimate"""
    if model_loader is None:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    try:
        # === SERVER-SIDE TRUSTED DOMAIN CHECK ===
        try:
            parsed = urlparse(request.url)
            domain = parsed.netloc.lower().replace('www.', '')
            # Extract base domain (e.g., maps.google.com -> google.com)
            parts = domain.split('.')
            base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        except Exception:
            base_domain = ''

        # Check if domain or base_domain is in trusted list
        # FIX: Handle multi-part TLDs (e.g. vce.ac.in) by checking the full domain too
        if domain in TRUSTED_DOMAINS or base_domain in TRUSTED_DOMAINS:
            # Trusted domain - return safe verdict with high confidence
            return PredictResponse(
                url=request.url,
                verdict='Legitimate',
                confidence=0.99,
                final_prediction=0,
                ml_models={},
                dl_models={},
                recommendation='Trusted domain - verified safe'
            )

        # === EXTRACT FEATURES FOR ML MODELS ===
        raw_features = feature_extractor.extract_features(request.url)
        
        # Scale features using the correct feature names
        if feature_scaler is not None and expected_features is not None:
            try:
                features_df = pd.DataFrame([raw_features], columns=expected_features)
                features = feature_scaler.transform(features_df)
            except Exception as e:
                print(f"[WARN] Feature scaling failed: {e}")
                features = np.array(raw_features, dtype=float).reshape(1, -1)
        else:
            features = np.array(raw_features, dtype=float).reshape(1, -1)
        
        # === ENSEMBLE PREDICTION (ALL MODELS) ===
        results = model_loader.predict_ensemble(features, request.url)
        
        # Format ML model responses
        ml_models_response = {}
        for model_name, result in results['ml_predictions'].items():
            label = "Phishing" if result['prediction'] == 1 else "Legitimate"
            ml_models_response[model_name] = ModelPrediction(
                prediction=result['prediction'],
                probability=result['probability'],
                label=label
            )
        
        # Format DL model responses
        dl_models_response = {}
        for model_name, result in results['dl_predictions'].items():
            label = "Phishing" if result['prediction'] == 1 else "Legitimate"
            dl_models_response[model_name] = ModelPrediction(
                prediction=result['prediction'],
                probability=result['probability'],
                label=label
            )
        
        # Generate recommendation
        confidence = results['confidence']
        if confidence > 0.9:
            recommendation = "High confidence - Action recommended"
        elif confidence > 0.7:
            recommendation = "Moderate confidence - Exercise caution"
        elif confidence > 0.5:
            recommendation = "Low-moderate confidence - Review suggested"
        else:
            recommendation = "Low confidence - Manual review recommended"
        
        return PredictResponse(
            url=request.url,
            verdict=results['verdict'],
            confidence=confidence,
            final_prediction=results['final_prediction'],
            ml_models=ml_models_response,
            dl_models=dl_models_response,
            recommendation=recommendation
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"Prediction error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.get("/stats", tags=["Analytics"])
async def get_statistics():
    """Get model statistics"""
    if model_loader is None:
        raise HTTPException(status_code=503, detail="Models not loaded")
    
    return {
        "message": "Model statistics",
        "models": model_loader.get_model_info(),
        "rl_dataset_stats": feedback_db.get_feedback_stats()
    }


if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*70)
    print("[*] STARTING DEEPSHIELD API SERVER")
    print("="*70)
    print("\nStarting server on http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    print("\nPress CTRL+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
