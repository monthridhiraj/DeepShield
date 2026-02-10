"""
DeepShield Model Loader
Loads trained models from the training pipeline
"""

from pathlib import Path
from typing import Dict, Optional, Tuple
import joblib
import numpy as np

# TensorFlow imports (optional - only needed for DL models)
try:
    import tensorflow as tf
    # In TF 2.15+, keras may need separate import
    try:
        import keras
    except ImportError:
        import tensorflow.keras as keras
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    tf = None
    keras = None

# Import custom layers for DL models (optional)
import sys
sys.path.append(str(Path(__file__).parent))

try:
    from dl_models_new import TransformerBlock
    from url_preprocessing import URLTokenizer
    DL_AVAILABLE = True
except ImportError:
    DL_AVAILABLE = False
    TransformerBlock = None
    URLTokenizer = None


DEFAULT_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


class ModelLoader:
    """Centralized model loading for DeepShield"""
    
    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.ml_models = {}
        self.dl_models = {}
        
        # Only initialize tokenizer if DL is available
        if DL_AVAILABLE and URLTokenizer:
            self.tokenizer = URLTokenizer(max_url_length=200)
        else:
            self.tokenizer = None
        
        # Define custom objects for TensorFlow model loading
        if TF_AVAILABLE:
            self.custom_objects = {
                'weighted_binary_crossentropy': self._weighted_binary_crossentropy,
                'TransformerBlock': TransformerBlock
            }
        else:
            self.custom_objects = {}
    
    @staticmethod
    def _weighted_binary_crossentropy(y_true, y_pred):
        """Custom loss function for DL models"""
        if not TF_AVAILABLE:
            return None
        class_weight_ratio = 10.0
        y_true = tf.cast(y_true, tf.float32)
        y_pred = tf.cast(y_pred, tf.float32)
        weights = y_true * tf.constant(class_weight_ratio, dtype=tf.float32) + (1.0 - y_true) * 1.0
        bce = keras.backend.binary_crossentropy(y_true, y_pred)
        return keras.backend.mean(bce * weights)
    
    def load_ml_model(self, model_name: str) -> bool:
        """Load a machine learning model"""
        model_map = {
            'xgboost': 'xgboost',
            'randomforest': 'randomforest',
            'rf': 'randomforest'
        }
        
        model_dir = model_map.get(model_name.lower(), model_name.lower())
        
        # Try multiple possible paths (new training notebook format first, then legacy)
        possible_paths = []
        
        if model_name.lower() == 'xgboost':
            possible_paths = [
                self.models_dir / 'xgboost_model.json',
                self.models_dir / model_dir / 'model.pkl',
                self.models_dir / model_dir / 'xgboost.pkl',
            ]
        elif model_name.lower() in ['randomforest', 'rf']:
            possible_paths = [
                self.models_dir / 'random_forest_model.joblib',
                self.models_dir / model_dir / 'model.pkl',
                self.models_dir / model_dir / 'random_forest.pkl',
            ]
        else:
            possible_paths = [
                self.models_dir / model_dir / 'model.pkl',
            ]
        
        for model_path in possible_paths:
            if model_path.exists():
                try:
                    if model_path.suffix == '.json':
                        # XGBoost JSON format
                        import xgboost as xgb
                        model = xgb.XGBClassifier()
                        model.load_model(str(model_path))
                        self.ml_models[model_name] = model
                    else:
                        # Joblib/pickle format
                        self.ml_models[model_name] = joblib.load(model_path)
                    
                    print(f"[OK] Loaded ML model: {model_name} from {model_path}")
                    return True
                except Exception as e:
                    print(f"[ERROR] Failed to load {model_name} from {model_path}: {e}")
                    continue
        
        print(f"[WARN] ML model not found. Tried paths: {possible_paths}")
        return False
    
    def load_dl_model(self, model_name: str) -> bool:
        """Load a deep learning model"""
        if not TF_AVAILABLE:
            print(f"[WARN] TensorFlow not available, skipping DL model: {model_name}")
            return False
            
        model_map = {
            'charcnn': 'charcnn',
            'bilstm': 'bilstm',
            'transformer': 'transformer',
            'cnn': 'charcnn',
            'lstm': 'bilstm'
        }
        
        model_dir = model_map.get(model_name.lower(), model_name.lower())
        model_path = self.models_dir / model_dir / 'best_model.h5'
        
        if not model_path.exists():
            print(f"[WARN] DL model not found: {model_path}")
            return False
        
        try:
            self.dl_models[model_name] = keras.models.load_model(
                model_path,
                custom_objects=self.custom_objects
            )
            print(f"[OK] Loaded DL model: {model_name}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load {model_name}: {e}")
            return False
    
    def load_all_available_models(self):
        """Load all available trained models"""
        print("\n" + "="*60)
        print("LOADING DEEPSHIELD MODELS")
        print("="*60)
        
        # Try to load ML models
        print("\n[1/2] Loading ML Models...")
        for model_name in ['xgboost', 'randomforest']:
            self.load_ml_model(model_name)
        
        # Try to load DL models
        print("\n[2/2] Loading DL Models...")
        for model_name in ['charcnn', 'bilstm', 'transformer']:
            self.load_dl_model(model_name)
        
        print("\n" + "="*60)
        print(f"[OK] Loaded {len(self.ml_models)} ML models, {len(self.dl_models)} DL models")
        print("="*60)
    
    def predict_ml(self, model_name: str, features: np.ndarray) -> Tuple[int, np.ndarray]:
        """Make prediction with ML model"""
        if model_name not in self.ml_models:
            raise ValueError(f"Model '{model_name}' not loaded")
        
        model = self.ml_models[model_name]
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        
        return int(prediction), probability
    
    def predict_dl(self, model_name: str, url: str) -> Tuple[int, float]:
        """Make prediction with DL model"""
        if model_name not in self.dl_models:
            raise ValueError(f"Model '{model_name}' not loaded")
        
        # Encode URL
        encoded_url = self.tokenizer.encode_batch([url])
        
        # Predict
        model = self.dl_models[model_name]
        probability = model.predict(encoded_url, verbose=0)[0][0]
        prediction = 1 if probability > 0.5 else 0
        
        return int(prediction), float(probability)

    
    def predict_ensemble(self, features: np.ndarray, url: str) -> Dict:
        """
        Make ensemble prediction using all available models
        
        Returns:
            Dictionary with predictions, probabilities, and final verdict
        """
        results = {
            'ml_predictions': {},
            'dl_predictions': {},
            'final_prediction': None,
            'confidence': 0.0,
            'verdict': ''
        }
        
        # ML predictions
        for model_name, model in self.ml_models.items():
            try:
                pred, proba = self.predict_ml(model_name, features)
                results['ml_predictions'][model_name] = {
                    'prediction': pred,
                    'probability': proba[1] if len(proba) > 1 else proba[0]
                }
            except Exception as e:
                print(f"Warning: {model_name} prediction failed: {e}")
        
        # DL predictions
        for model_name, model in self.dl_models.items():
            try:
                pred, proba = self.predict_dl(model_name, url)
                results['dl_predictions'][model_name] = {
                    'prediction': pred,
                    'probability': proba
                }
            except Exception as e:
                print(f"Warning: {model_name} prediction failed: {e}")
        
        # Ensemble decision (majority vote + average confidence)
        all_predictions = []
        all_probabilities = []
        
        for ml_result in results['ml_predictions'].values():
            all_predictions.append(ml_result['prediction'])
            all_probabilities.append(ml_result['probability'])
        
        for dl_result in results['dl_predictions'].values():
            all_predictions.append(dl_result['prediction'])
            all_probabilities.append(dl_result['probability'])
        
        if all_predictions:
            # Majority vote for final prediction
            final_pred = int(np.round(np.mean(all_predictions)))
            mean_probability = float(np.mean(all_probabilities))
            
            # Confidence calculation
            if final_pred == 1:
                results['confidence'] = mean_probability
            else:
                results['confidence'] = 1.0 - mean_probability
            
            results['final_prediction'] = final_pred
            results['verdict'] = 'Phishing' if final_pred == 1 else 'Legitimate'
        else:
            results['verdict'] = 'Error: No models available'
        
        return results
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models"""
        return {
            'ml_models': list(self.ml_models.keys()),
            'dl_models': list(self.dl_models.keys()),
            'total_models': len(self.ml_models) + len(self.dl_models)
        }


if __name__ == "__main__":
    # Test the model loader
    loader = ModelLoader()
    loader.load_all_available_models()
    
    print("\n" + "="*60)
    print("MODEL INFO")
    print("="*60)
    print(loader.get_model_info())
