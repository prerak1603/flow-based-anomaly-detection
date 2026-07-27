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
from app.context.attribution import get_attack_context
from app.context.agent import analyze_threat

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

# Cap on how many flows get full AI-agent analysis per upload.
# Keeps LLM cost and response latency predictable regardless of
# how many attacks are found in a single file.
MAX_AGENT_ANALYSES_PER_REQUEST = 8


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

    print("Pre-warming RAG knowledge base index...")
    try:
        from app.context.rag import get_rag
        get_rag()
        print("RAG index ready!")
    except Exception as e:
        print(f"WARNING: RAG pre-warm failed ({e}) — will build on first request.")
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
    parses it, runs each flow through the ensemble model, and generates
    full AI-agent threat analysis (attribution + RAG + LLM narrative +
    rule-based recommendation) for the top highest-confidence attacks.
    """
    global model_service, parser_service

    try:
        content = await file.read()

        if len(content) > Config.MAX_FILE_SIZE_BYTES:
            max_mb = Config.MAX_FILE_SIZE_BYTES / (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"File too large ({len(content) / (1024*1024):.1f} MB). "
                       f"Maximum allowed is {max_mb:.0f} MB. "
                       f"For larger datasets, please split the file or contact us directly."
            )

        df, detected_format = parser_service.parse(content, file.filename)

        if len(df) > Config.MAX_ROWS:
            raise HTTPException(
                status_code=413,
                detail=f"Too many rows ({len(df):,}). Maximum allowed per upload is "
                       f"{Config.MAX_ROWS:,}. Please split the file into smaller batches."
            )

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

        # ================================================================
        # AI AGENT ANALYSIS — capped to top N highest-confidence attacks
        # ================================================================
        attack_flows_sorted = sorted(
            attack_flows, key=lambda x: x["confidence"], reverse=True
        )
        flows_for_agent = attack_flows_sorted[:MAX_AGENT_ANALYSES_PER_REQUEST]

        ai_analyses = []
        for flow in flows_for_agent:
            row_index = flow["row"]
            pred = predictions[row_index]

            try:
                attribution = get_attack_context(df, row_index)
            except Exception as e:
                attribution = {
                    "mode": "degraded",
                    "available": False,
                    "reason": f"Attribution failed: {str(e)}",
                }

            try:
                agent_report = analyze_threat(
                    prediction=pred["prediction"],
                    confidence=pred["confidence"],
                    is_attack=pred["is_attack"],
                    attribution=attribution,
                    row_index=row_index,
                )
            except Exception as e:
                agent_report = {
                    "error": f"Agent analysis failed: {str(e)}",
                    "classification": {
                        "attack_type": pred["prediction"],
                        "confidence": pred["confidence"],
                    },
                }

            ai_analyses.append({
                "row": row_index,
                "report": agent_report,
            })

        return {
            "filename": file.filename,
            "detected_format": detected_format,
            "total_flows_analyzed": total_flows,
            "total_attacks_detected": total_attacks,
            "attack_breakdown": attack_counts,
            "high_confidence_attacks": attack_flows_sorted[:20],
            "ai_analysis": {
                "flows_analyzed": len(ai_analyses),
                "flows_available": len(attack_flows_sorted),
                "note": (
                    f"Full AI agent analysis (attribution + RAG + narrative "
                    f"+ recommendation) generated for the top "
                    f"{len(ai_analyses)} highest-confidence detections."
                    if len(attack_flows_sorted) > MAX_AGENT_ANALYSES_PER_REQUEST
                    else "Full AI agent analysis generated for all detected attacks."
                ),
                "reports": ai_analyses,
            },
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