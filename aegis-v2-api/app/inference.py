"""
Model inference service.
Loads the ensemble model and provides prediction functionality.
"""

import time
import numpy as np
import joblib
from typing import List, Dict
from datetime import datetime

from app.config import Config


class ModelInference:
    """
    Handles model loading and inference.
    
    Loads the complete ensemble at initialization.
    Provides fast prediction method.
    """
    
    def __init__(self):
        """Initialize by loading the ensemble."""
        self._load_ensemble()
    
    def _load_ensemble(self):
        """Load the trained ensemble model."""
        if not Config.ENSEMBLE_FILE.exists():
            raise FileNotFoundError(
                f"Ensemble model not found: {Config.ENSEMBLE_FILE}\n"
                "Please run Day 1 training scripts first."
            )
        
        print(f"Loading ensemble from: {Config.ENSEMBLE_FILE}")
        
        ensemble = joblib.load(Config.ENSEMBLE_FILE)
        
        # Extract components
        self.rf_model      = ensemble['random_forest']
        self.xgb_model     = ensemble['xgboost']
        self.lgb_model     = ensemble['lightgbm']
        self.meta_model    = ensemble['meta_learner']
        self.scaler        = ensemble['scaler']
        self.label_encoder = ensemble['label_encoder']
        self.version       = ensemble['version']
        self.trained_at    = ensemble['trained_at']
        
        print(f"Model version: {self.version}")
        print(f"Trained at: {self.trained_at}")
        print(f"Classes: {len(self.label_encoder.classes_)}")
    
    def predict(self, features: List[float]) -> Dict:
        """
        Make a prediction from feature vector.
        
        Args:
            features: List of 78 features
        
        Returns:
            Dictionary with prediction results
        """
        start_time = time.time()
        
        # Convert to numpy array
        X = np.array(features).reshape(1, -1)
        
        # Validate feature count
        if X.shape[1] != Config.EXPECTED_FEATURES:
            raise ValueError(
                f"Expected {Config.EXPECTED_FEATURES} features, "
                f"got {X.shape[1]}"
            )
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from each base model
        rf_probs  = self.rf_model.predict_proba(X_scaled)
        xgb_probs = self.xgb_model.predict_proba(X_scaled)
        lgb_probs = self.lgb_model.predict_proba(X_scaled)
        
        # Combine with meta-learner
        meta_features = np.hstack([rf_probs, xgb_probs, lgb_probs])
        final_probs = self.meta_model.predict_proba(meta_features)[0]
        prediction_idx = np.argmax(final_probs)
        
        # Decode prediction
        prediction = self.label_encoder.inverse_transform([prediction_idx])[0]
        confidence = float(final_probs[prediction_idx])
        
        # Build probability list
        probabilities = [
            {
                "attack_type": self.label_encoder.classes_[i],
                "probability": float(final_probs[i])
            }
            for i in range(len(self.label_encoder.classes_))
        ]
        
        # Sort by probability descending
        probabilities.sort(key=lambda x: x["probability"], reverse=True)
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000  # ms
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "is_attack": prediction != "BENIGN",
            "probabilities": probabilities,
            "timestamp": datetime.now().isoformat(),
            "processing_time_ms": round(processing_time, 2)
        }