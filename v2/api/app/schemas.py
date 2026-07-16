"""
Pydantic schemas for request/response validation.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime


class PredictionRequest(BaseModel):
    """Request schema for prediction endpoint."""
    
    features: List[float] = Field(
        ...,
        description="78 network flow features",
        min_length=78,
        max_length=78
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "features": [0.5, 1.2, 0.0] + [0.1] * 75
            }
        }


class ClassProbability(BaseModel):
    """Probability for a specific attack class."""
    
    attack_type: str
    probability: float = Field(..., ge=0.0, le=1.0)


class PredictionResponse(BaseModel):
    """Response schema for prediction endpoint."""
    
    prediction: str = Field(..., description="Predicted attack type")
    confidence: float = Field(..., ge=0.0, le=1.0)
    is_attack: bool
    probabilities: List[ClassProbability]
    timestamp: str
    processing_time_ms: float
    
    class Config:
        json_schema_extra = {
            "example": {
                "prediction": "DDoS",
                "confidence": 0.9987,
                "is_attack": True,
                "probabilities": [
                    {"attack_type": "BENIGN", "probability": 0.001},
                    {"attack_type": "DDoS", "probability": 0.998}
                ],
                "timestamp": "2026-07-08T18:00:00",
                "processing_time_ms": 45.2
            }
        }


class HealthResponse(BaseModel):
    """Response schema for health check."""
    
    status: str
    version: str
    model_loaded: bool
    timestamp: str