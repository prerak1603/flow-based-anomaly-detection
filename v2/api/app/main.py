"""
================================================================================
AEGIS AI v2 - Production API  (multi-tenant, hardened)
================================================================================

FastAPI-based production API for network intrusion detection.

Author: Prerak Nain
Version: 2.1.1 — adds rate limiting, locked-down CORS, structured logging,
                  and safe error responses on top of the v2.1.0 auth/tenancy
                  layer and the v2.0.0 detection pipeline.
================================================================================
"""

import logging
import time
import numpy as np
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from sqlalchemy.orm import Session

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import Config
from app.inference import ModelInference
from app.schemas import PredictionRequest, PredictionResponse, HealthResponse
from app.parsers.universal import UniversalParser
from app.context.attribution import get_attack_context
from app.context.agent import analyze_threat

from app.db import get_db, init_db, Customer, Upload, Detection
from app.auth import get_current_customer

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("aegis")

# ==============================================================================
# APPLICATION SETUP
# ==============================================================================

app = FastAPI(
    title="Aegis AI v2",
    description="Production-ready network intrusion detection API",
    version="2.1.1",
    docs_url="/docs",
    redoc_url="/redoc",
)

# --- Rate limiting ------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --- CORS: locked to known frontends only, no wildcard ------------------------
ALLOWED_ORIGINS = [
    "https://flow-based-anomaly-detection-hqnj5ccn9xcz4ojug47sen.streamlit.app",
    "https://prerak1603.github.io",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- Lightweight request logging (timing + status, no bodies/secrets) --------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    logger.info(
        f"{request.method} {request.url.path} -> {response.status_code} "
        f"({duration_ms:.0f}ms)"
    )
    return response


# ==============================================================================
# GLOBAL SERVICES (loaded once at startup)
# ==============================================================================

model_service = None
parser_service = UniversalParser()

MAX_AGENT_ANALYSES_PER_REQUEST = 8


@app.on_event("startup")
async def startup_event():
    """Load model + init DB tables on startup - one time cost."""
    global model_service

    logger.info("=" * 60)
    logger.info("Initializing database (creating tables if needed)...")
    init_db()
    logger.info("Database ready!")

    logger.info("Loading Aegis AI v2 Ensemble Model...")
    model_service = ModelInference()
    logger.info("Model loaded successfully!")

    logger.info("Pre-warming RAG knowledge base index...")
    try:
        from app.context.rag import get_rag
        get_rag()
        logger.info("RAG index ready!")
    except Exception as e:
        logger.warning(f"RAG pre-warm failed ({e}) — will build on first request.")
    logger.info("=" * 60)


# ==============================================================================
# ROOT ENDPOINT (public, no auth, no rate limit — just service info)
# ==============================================================================

@app.get("/")
async def root():
    return {
        "service": "Aegis AI v2",
        "version": "2.1.1",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "health": "/health",
            "predict": "/predict (auth required)",
            "analyze": "/analyze (auth required)",
            "history": "/history (auth required)",
        },
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint — public, used by uptime monitors. No auth,
    no customer data, no rate limit — needs to always respond fast."""
    global model_service

    return HealthResponse(
        status="healthy" if model_service else "unhealthy",
        version="2.1.1",
        model_loaded=model_service is not None,
        timestamp=datetime.now().isoformat(),
    )


# ==============================================================================
# PREDICTION ENDPOINT (auth required, rate limited)
# ==============================================================================

@app.post("/predict", response_model=PredictionResponse)
@limiter.limit("30/minute")
async def predict(
    request: Request,
    request_body: PredictionRequest,
    customer: Customer = Depends(get_current_customer),
):
    """Make a prediction from a feature vector. Requires a valid API key."""
    global model_service

    if model_service is None:
        raise HTTPException(status_code=503, detail="Model service not initialized")

    try:
        result = model_service.predict(request_body.features)
        return PredictionResponse(**result)
    except Exception as e:
        logger.error(f"Prediction failed for customer {customer.id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Prediction failed")


# ==============================================================================
# ANALYZE UPLOADED FILE (auth required, rate limited, results persisted per-tenant)
# ==============================================================================

@app.post("/analyze")
@limiter.limit("5/minute")
async def analyze_log(
    request: Request,
    file: UploadFile = File(...),
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
):
    """
    Analyze an uploaded network log file, scoped entirely to the
    authenticated customer. Every upload and every detection produced
    is written to the DB tagged with customer.id — this is the one
    and only place in the request that data gets attached to a tenant,
    and every downstream read (see /history) filters by that same id.
    """
    global model_service, parser_service

    try:
        content = await file.read()

        if len(content) > Config.MAX_FILE_SIZE_BYTES:
            max_mb = Config.MAX_FILE_SIZE_BYTES / (1024 * 1024)
            raise HTTPException(
                status_code=413,
                detail=f"File too large ({len(content) / (1024*1024):.1f} MB). "
                       f"Maximum allowed is {max_mb:.0f} MB.",
            )

        df, detected_format = parser_service.parse(content, file.filename)

        if len(df) > Config.MAX_ROWS:
            raise HTTPException(
                status_code=413,
                detail=f"Too many rows ({len(df):,}). Maximum allowed per upload is "
                       f"{Config.MAX_ROWS:,}.",
            )

        if detected_format != "CICFlowMeter CSV":
            upload_row = Upload(
                customer_id=customer.id,
                filename=file.filename,
                detected_format=detected_format,
                total_flows=len(df),
                total_attacks=0,
                status="parsed_only",
            )
            db.add(upload_row)
            db.commit()

            return {
                "filename": file.filename,
                "detected_format": detected_format,
                "rows_parsed": len(df),
                "status": "parsed_only",
                "note": f"{detected_format} detected, but prediction "
                        f"pipeline currently only supports CICFlowMeter format.",
            }

        feature_df = df.select_dtypes(include=["number"])

        if feature_df.shape[1] != Config.EXPECTED_FEATURES:
            raise HTTPException(
                status_code=422,
                detail=f"Expected {Config.EXPECTED_FEATURES} numeric "
                       f"features, found {feature_df.shape[1]}.",
            )

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
                    "confidence": pred["confidence"],
                })

        total_attacks = sum(
            count for label, count in attack_counts.items() if label != "BENIGN"
        )

        upload_row = Upload(
            customer_id=customer.id,
            filename=file.filename,
            detected_format=detected_format,
            total_flows=total_flows,
            total_attacks=total_attacks,
            status="analysis_complete",
        )
        db.add(upload_row)
        db.commit()
        db.refresh(upload_row)

        attack_flows_sorted = sorted(attack_flows, key=lambda x: x["confidence"], reverse=True)
        flows_for_agent = attack_flows_sorted[:MAX_AGENT_ANALYSES_PER_REQUEST]

        ai_analyses = []
        for flow in flows_for_agent:
            row_index = flow["row"]
            pred = predictions[row_index]

            try:
                attribution = get_attack_context(df, row_index)
            except Exception as e:
                logger.warning(f"Attribution failed for row {row_index}: {e}")
                attribution = {
                    "mode": "degraded",
                    "available": False,
                    "reason": "Attribution failed",
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
                logger.error(f"Agent analysis failed for row {row_index}: {e}", exc_info=True)
                agent_report = {
                    "error": "Agent analysis failed",
                    "classification": {
                        "attack_type": pred["prediction"],
                        "confidence": pred["confidence"],
                    },
                }

            ai_analyses.append({"row": row_index, "report": agent_report})

            severity = None
            narrative = None
            recommendation = None
            if isinstance(agent_report, dict):
                sev = agent_report.get("severity")
                severity = sev.get("level") if isinstance(sev, dict) else sev
                narrative = agent_report.get("narrative")
                rec = agent_report.get("recommendation")
                recommendation = rec.get("recommended_action") if isinstance(rec, dict) else rec

            detection_row = Detection(
                customer_id=customer.id,
                upload_id=upload_row.id,
                row_index=row_index,
                attack_type=pred["prediction"],
                confidence=pred["confidence"],
                severity=severity,
                narrative=narrative,
                recommendation=recommendation,
                raw_report=agent_report if isinstance(agent_report, dict) else {"raw": str(agent_report)},
            )
            db.add(detection_row)

        db.commit()

        return {
            "upload_id": upload_row.id,
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
                    f"Full AI agent analysis generated for the top "
                    f"{len(ai_analyses)} highest-confidence detections."
                    if len(attack_flows_sorted) > MAX_AGENT_ANALYSES_PER_REQUEST
                    else "Full AI agent analysis generated for all detected attacks."
                ),
                "reports": ai_analyses,
            },
            "status": "analysis_complete",
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed for customer {customer.id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Analysis failed")


# ==============================================================================
# HISTORY — the entire point of persistence: a customer can only ever
# see their OWN uploads/detections. This is the tenancy guarantee made
# concrete as an actual query.
# ==============================================================================

@app.get("/history/uploads")
@limiter.limit("60/minute")
async def list_uploads(
    request: Request,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
    limit: int = 50,
):
    uploads = (
        db.query(Upload)
        .filter(Upload.customer_id == customer.id)   # <-- the tenancy filter
        .order_by(Upload.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": u.id,
            "filename": u.filename,
            "detected_format": u.detected_format,
            "total_flows": u.total_flows,
            "total_attacks": u.total_attacks,
            "status": u.status,
            "created_at": u.created_at.isoformat(),
        }
        for u in uploads
    ]


@app.get("/history/detections")
@limiter.limit("60/minute")
async def list_detections(
    request: Request,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
    upload_id: str = None,
    limit: int = 100,
):
    query = db.query(Detection).filter(Detection.customer_id == customer.id)  # <-- tenancy filter
    if upload_id:
        query = query.filter(Detection.upload_id == upload_id)

    detections = query.order_by(Detection.created_at.desc()).limit(limit).all()
    return [
        {
            "id": d.id,
            "upload_id": d.upload_id,
            "attack_type": d.attack_type,
            "confidence": d.confidence,
            "severity": d.severity,
            "narrative": d.narrative,
            "recommendation": d.recommendation,
            "created_at": d.created_at.isoformat(),
        }
        for d in detections
    ]


# ==============================================================================
# ERROR HANDLING — logs full internals server-side, returns a safe generic
# message to the client so stack traces / file paths never leak externally.
# ==============================================================================

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.now().isoformat(),
        },
    )