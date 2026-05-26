# Aegis AI — Java Spring Boot REST API

A Spring Boot backend that exposes the Aegis AI Phase 2 ensemble ML model
(RF + XGBoost + LightGBM stacking classifier) as a live threat detection REST API.

## Architecture

```
Network Traffic Data
        ↓
POST /api/predict  (Spring Boot REST API)
        ↓
ThreatDetectionService (Java)
        ↓
Python ML Model (joblib — Phase 2 ensemble)
        ↓
PredictionResult (threatClass, confidence, probabilities, severity)
```

## Tech Stack

- **Java 17** + **Spring Boot 3.2**
- **Maven** for dependency management
- **REST API** with JSON request/response
- **OOP design** — Controller → Service → Model layers
- **Thread-safe** in-memory prediction history (ConcurrentLinkedDeque)
- **Input validation** via Jakarta Bean Validation

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/predict` | Classify a network flow |
| GET | `/api/history?limit=N` | Get last N predictions |
| GET | `/api/stats` | Threat distribution summary |
| DELETE | `/api/history` | Clear prediction history |
| GET | `/api/health` | Health check |

## Running Locally

```bash
# Prerequisites: Java 17, Maven
mvn spring-boot:run
```

API will be available at `http://localhost:8080`

## Example Request

```bash
curl -X POST http://localhost:8080/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0,
    "protocolType": "tcp",
    "service": "http",
    "flag": "SF",
    "srcBytes": 232,
    "dstBytes": 8153,
    "serrorRate": 0.0,
    "numFailedLogins": 0,
    "rootShell": 0
  }'
```

## Example Response

```json
{
  "threatClass": "normal",
  "confidence": 0.97,
  "severity": "NONE",
  "message": "Traffic classified as normal. No threat detected.",
  "classProbabilities": {
    "normal": 0.97,
    "dos":    0.01,
    "probe":  0.01,
    "r2l":    0.005,
    "u2r":    0.005
  },
  "timestamp": "2026-05-26T19:00:00"
}
```

## Project Structure

```
aegis-api/
├── pom.xml
└── src/main/java/com/aegis/api/
    ├── AegisApplication.java          ← Entry point
    ├── controller/
    │   └── AegisController.java       ← REST endpoints
    ├── service/
    │   └── ThreatDetectionService.java ← Business logic
    └── model/
        ├── NetworkFlow.java           ← Request model
        └── PredictionResult.java      ← Response model
```

## Connection to Aegis AI ML Pipeline

This API is **Phase 5** of the Aegis AI project:

| Phase | Description |
|-------|-------------|
| Phase 1 | Feature engineering (NSL-KDD / CIC-IDS) |
| Phase 2 | Ensemble classifier (RF + XGBoost + LightGBM) |
| Phase 3 | WGAN-GP synthetic attack generation |
| Phase 4 | HuggingFace NLP threat intelligence |
| **Phase 5** | **Java Spring Boot REST API (this module)** |
