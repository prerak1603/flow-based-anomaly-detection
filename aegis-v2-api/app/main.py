"""
================================================================================
AEGIS AI v2 - Production API
================================================================================

FastAPI-based production API for network intrusion detection.

Author: Prerak Nain
Version: 2.0.0
================================================================================
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime

from app.config import Config
from app.inference import ModelInference
from app.schemas import PredictionRequest, PredictionResponse, HealthResponse

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
# GLOBAL MODEL INFERENCE (loaded once at startup)
# ==============================================================================

model_service = None


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
# ANALYZE UPLOADED FILE (placeholder for now)
# ==============================================================================

from app.parsers.universal import UniversalParser

parser_service = UniversalParser()


@app.post("/analyze")
async def analyze_log(file: UploadFile = File(...)):
    """
    Analyze an uploaded network log file.
    
    Automatically detects format (CICFlowMeter CSV, Zeek conn.log)
    and parses it for further analysis.
    """
    try:
        content = await file.read()
        
        df, detected_format = parser_service.parse(content, file.filename)
        
        return {
            "filename": file.filename,
            "detected_format": detected_format,
            "rows_parsed": len(df),
            "columns_found": len(df.columns),
            "sample_columns": list(df.columns[:10]),
            "status": "parsed_successfully",
            "note": "Feature extraction + prediction coming in Hour 4-5"
        }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse file: {str(e)}"
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