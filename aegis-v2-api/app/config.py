"""
Configuration for Aegis AI v2 API.
"""

from pathlib import Path
import os

class Config:
    """Application configuration."""
    
    # Use environment variable if set (for Docker/production)
    # Otherwise fall back to local development path
    if os.getenv("MODELS_DIR"):
        MODELS_DIR = Path(os.getenv("MODELS_DIR"))
    else:
        PROJECT_ROOT = Path.home() / "cic_ids_project"
        MODELS_DIR = PROJECT_ROOT / "new_models"
    
    ENSEMBLE_FILE = MODELS_DIR / "aegis_v2_ensemble.pkl"
    
    API_TITLE       = "Aegis AI v2"
    API_VERSION     = "2.0.0"
    API_DESCRIPTION = "Production-ready network intrusion detection API"
    
    MIN_CONFIDENCE_THRESHOLD = 0.5
    EXPECTED_FEATURES = 78