"""
Machine Learning Models Module
Implements SVM, Decision Tree, and KNN classifiers
"""

import numpy as np
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
import joblib
from pathlib import Path

import config
from utils import logger, timer, print_section_header

class MLModels:
    """Machine Learning models for phishing detection"""
    
    def __init__(self):
        self.models = {}
        self.best_params = {}
        
    @timer
    def train_svm(self, X_train, y_train):
        """
        Train Support Vector Machine with grid search
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained SVM model
        """
        logger.info("Training SVM...")
        
        # Define parameter grid
        param_grid = {
            'C': config.SVM_C_RANGE,
            'gamma': config.SVM_GAMMA_RANGE,
            'kernel': [config.SVM_KERNEL]
        }
        
        # Grid search with cross-validation
        svm = SVC(probability=True, random_state=config.RANDOM_STATE)
        grid_search = GridSearchCV(
            svm, param_grid, cv=config.ML_CV_FOLDS,
            scoring='accuracy', n_jobs=config.ML_N_JOBS, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        best_model = grid_search.best_estimator_
        self.best_params['SVM'] = grid_search.best_params_
        
        logger.info(f"Best SVM parameters: {grid_search.best_params_}")
        logger.info(f"Best cross-validation score: {grid_search.best_score_:.4f}")
        
        # Cross-validation on best model
        cv_scores = cross_val_score(best_model, X_train, y_train, 
                                    cv=config.ML_CV_FOLDS, scoring='accuracy')
        logger.info(f"Cross-validation scores: {cv_scores}")
        logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        self.models['SVM'] = best_model
        return best_model
    
    @timer
    def train_decision_tree(self, X_train, y_train):
        """
        Train Decision Tree with grid search
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained Decision Tree model
        """
        logger.info("Training Decision Tree...")
        
        # Define parameter grid
        param_grid = {
            'max_depth': config.DT_MAX_DEPTH_RANGE,
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'criterion': ['gini', 'entropy']
        }
        
        # Grid search with cross-validation
        dt = DecisionTreeClassifier(random_state=config.RANDOM_STATE)
        grid_search = GridSearchCV(
            dt, param_grid, cv=config.ML_CV_FOLDS,
            scoring='accuracy', n_jobs=config.ML_N_JOBS, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        best_model = grid_search.best_estimator_
        self.best_params['DecisionTree'] = grid_search.best_params_
        
        logger.info(f"Best Decision Tree parameters: {grid_search.best_params_}")
        logger.info(f"Best cross-validation score: {grid_search.best_score_:.4f}")
        
        # Cross-validation on best model
        cv_scores = cross_val_score(best_model, X_train, y_train, 
                                    cv=config.ML_CV_FOLDS, scoring='accuracy')
        logger.info(f"Cross-validation scores: {cv_scores}")
        logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        self.models['DecisionTree'] = best_model
        return best_model
    
    @timer
    def train_knn(self, X_train, y_train):
        """
        Train K-Nearest Neighbors with grid search
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained KNN model
        """
        logger.info("Training KNN...")
        
        # Define parameter grid
        param_grid = {
            'n_neighbors': config.KNN_K_RANGE,
            'weights': ['uniform', 'distance'],
            'metric': ['euclidean', 'manhattan']
        }
        
        # Grid search with cross-validation
        knn = KNeighborsClassifier()
        grid_search = GridSearchCV(
            knn, param_grid, cv=config.ML_CV_FOLDS,
            scoring='accuracy', n_jobs=config.ML_N_JOBS, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        best_model = grid_search.best_estimator_
        self.best_params['KNN'] = grid_search.best_params_
        
        logger.info(f"Best KNN parameters: {grid_search.best_params_}")
        logger.info(f"Best cross-validation score: {grid_search.best_score_:.4f}")
        
        # Cross-validation on best model
        cv_scores = cross_val_score(best_model, X_train, y_train, 
                                    cv=config.ML_CV_FOLDS, scoring='accuracy')
        logger.info(f"Cross-validation scores: {cv_scores}")
        logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        self.models['KNN'] = best_model
        return best_model
    
    @timer
    def save_models(self, model_dir=None):
        """
        Save trained models to disk
        
        Args:
            model_dir: Directory to save models (default: config.ML_MODELS_DIR)
        """
        if model_dir is None:
            model_dir = config.ML_MODELS_DIR
        
        model_dir.mkdir(parents=True, exist_ok=True)
        
        for model_name, model in self.models.items():
            model_path = model_dir / f"{model_name}.pkl"
            joblib.dump(model, model_path)
            logger.info(f"Saved {model_name} to {model_path}")
        
        # Save best parameters
        params_path = model_dir / "best_params.pkl"
        joblib.dump(self.best_params, params_path)
        logger.info(f"Saved best parameters to {params_path}")
    
    @timer
    def load_models(self, model_dir=None):
        """
        Load trained models from disk
        
        Args:
            model_dir: Directory to load models from
        """
        if model_dir is None:
            model_dir = config.ML_MODELS_DIR
        
        for model_name in config.ML_MODELS:
            model_path = model_dir / f"{model_name}.pkl"
            if model_path.exists():
                self.models[model_name] = joblib.load(model_path)
                logger.info(f"Loaded {model_name} from {model_path}")
        
        # Load best parameters
        params_path = model_dir / "best_params.pkl"
        if params_path.exists():
            self.best_params = joblib.load(params_path)
    
    @timer
    def train_all_models(self, X_train, y_train):
        """
        Train all ML models
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print_section_header("MACHINE LEARNING MODELS TRAINING")
        
        self.train_svm(X_train, y_train)
        self.train_decision_tree(X_train, y_train)
        self.train_knn(X_train, y_train)
        
        self.save_models()
        logger.info("OK All ML models trained and saved successfully")
    
    def predict(self, model_name, X):
        """
        Make predictions with a specific model
        
        Args:
            model_name: Name of the model
            X: Features to predict
            
        Returns:
            Predictions
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        return self.models[model_name].predict(X)
    
    def predict_proba(self, model_name, X):
        """
        Get prediction probabilities
        
        Args:
            model_name: Name of the model
            X: Features to predict
            
        Returns:
            Prediction probabilities
        """
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        model = self.models[model_name]
        
        if hasattr(model, 'predict_proba'):
            return model.predict_proba(X)
        else:
            # For models without predict_proba, return binary predictions
            predictions = model.predict(X)
            proba = np.zeros((len(predictions), 2))
            for i, pred in enumerate(predictions):
                if pred == 1:
                    proba[i] = [0, 1]
                else:
                    proba[i] = [1, 0]
            return proba

def main():
    """Main function to train ML models"""
    from data_preprocessing import DataPreprocessor
    
    config.ensure_directories()
    
    # Load processed data
    preprocessor = DataPreprocessor()
    X_train, X_test, y_train, y_test = preprocessor.load_processed_data()
    
    # Train ML models
    ml_models = MLModels()
    ml_models.train_all_models(X_train, y_train)
    
    print(f"\n{'='*80}")
    print(f"MACHINE LEARNING TRAINING COMPLETED".center(80))
    print(f"{'='*80}")
    print(f"Models trained: {len(ml_models.models)}")
    print(f"Models: {list(ml_models.models.keys())}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
