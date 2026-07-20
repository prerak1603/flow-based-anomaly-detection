"""
================================================================================
AEGIS AI v2 - Production API
================================================================================

FastAPI-based production API for network intrusion detection.

Author: Prerak Nain
Version: 2.0.0
================================================================================
"""

import numpy as np
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime

from app.config import Config
from app.inference import ModelInference
from app.schemas import PredictionRequest, PredictionResponse, HealthResponse
from app.parsers.universal import UniversalParser

# ==============================================================================
# APPLICATION SETUP
# ==============================================================================

app = FastAPI(
    title="Aegis AI v2",
    description="Production-ready network intrusion detection API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# GLOBAL SERVICES (loaded once at startup)
# ==============================================================================

model_service = None
parser_service = UniversalParser()


@app.on_event("startup")
async def startup_event():
    """Load model on startup - one time cost."""
    global model_service
    print("=" * 60)
    print("Loading Aegis AI v2 Ensemble Model...")
    print("=" * 60)
    model_service = ModelInference()
    print("Model loaded successfully!")
    print("=" * 60)


# ==============================================================================
# ROOT ENDPOINT
# ==============================================================================

@app.get("/")
async def root():
    """API information endpoint."""
    return {
        "service": "Aegis AI v2",
        "version": "2.0.0",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "analyze": "/analyze"
        }
    }


# ==============================================================================
# HEALTH CHECK
# ==============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    global model_service

    return HealthResponse(
        status="healthy" if model_service else "unhealthy",
        version="2.0.0",
        model_loaded=model_service is not None,
        timestamp=datetime.now().isoformat()
    )


# ==============================================================================
# PREDICTION ENDPOINT
# ==============================================================================

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """Make a prediction from a feature vector."""
    global model_service

    if model_service is None:
        raise HTTPException(
            status_code=503,
            detail="Model service not initialized"
        )

    try:
        result = model_service.predict(request.features)
        return PredictionResponse(**result)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )


# ==============================================================================
# ANALYZE UPLOADED FILE
# ==============================================================================

@app.post("/analyze")
async def analyze_log(file: UploadFile = File(...)):
    """
    Analyze an uploaded network log file.

    Automatically detects format (CICFlowMeter CSV, Zeek conn.log),
    parses it, and runs each flow through the ensemble model.
    Returns an aggregated summary of detected attacks.
    """
    global model_service, parser_service

    try:
        content = await file.read()

        df, detected_format = parser_service.parse(content, file.filename)

        if detected_format != "CICFlowMeter CSV":
            return {
                "filename": file.filename,
                "detected_format": detected_format,
                "rows_parsed": len(df),
                "status": "parsed_only",
                "note": f"{detected_format} detected, but prediction "
                        f"pipeline currently only supports CICFlowMeter "
                        f"format."
            }

        feature_df = df.select_dtypes(include=['number'])

        if feature_df.shape[1] != Config.EXPECTED_FEATURES:
            raise HTTPException(
                status_code=422,
                detail=f"Expected {Config.EXPECTED_FEATURES} numeric "
                       f"features, found {feature_df.shape[1]}."
            )

        # Clean infinity/NaN values before prediction
        for col in feature_df.columns:
            if np.isinf(feature_df[col]).any():
                finite_vals = feature_df[col][np.isfinite(feature_df[col])]
                finite_max = finite_vals.max() if len(finite_vals) > 0 else 0
                feature_df[col] = feature_df[col].replace([np.inf], finite_max)
                feature_df[col] = feature_df[col].replace([-np.inf], -finite_max)

        feature_df = feature_df.fillna(0)

        predictions = []
        for _, row in feature_df.iterrows():
            result = model_service.predict(row.tolist())
            predictions.append(result)

        total_flows = len(predictions)
        attack_counts = {}
        attack_flows = []

        for i, pred in enumerate(predictions):
            label = pred["prediction"]
            attack_counts[label] = attack_counts.get(label, 0) + 1

            if pred["is_attack"]:
                attack_flows.append({
                    "row": i,
                    "attack_type": label,
                    "confidence": pred["confidence"]
                })

        total_attacks = sum(
            count for label, count in attack_counts.items()
            if label != "BENIGN"
        )

        return {
            "filename": file.filename,
            "detected_format": detected_format,
            "total_flows_analyzed": total_flows,
            "total_attacks_detected": total_attacks,
            "attack_breakdown": attack_counts,
            "high_confidence_attacks": sorted(
                attack_flows, key=lambda x: x["confidence"], reverse=True
            )[:20],
            "status": "analysis_complete"
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


# ==============================================================================
# ERROR HANDLING
# ==============================================================================

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Catch-all exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )