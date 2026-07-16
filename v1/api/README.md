# Aegis AI — Spring Boot REST API 🔌

Phase 5 of the Aegis AI security platform. A Java Spring Boot backend that serves real-time network intrusion predictions by integrating with the trained Python ensemble model.

![Java](https://img.shields.io/badge/Java-17-orange) ![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green) ![Maven](https://img.shields.io/badge/Build-Maven-red)

---

## 🎯 What It Does

Takes raw network flow features as JSON input → calls the trained Python ML model via `ProcessBuilder` → returns a threat prediction with severity classification in real time.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/predict` | Submit network flow, get threat prediction + severity |
| `GET` | `/api/history` | Retrieve last 100 predictions |
| `GET` | `/api/stats` | Aggregated prediction stats by severity class |
| `DELETE` | `/api/history` | Clear prediction history |
| `GET` | `/api/health` | Service health check |

---

## 🏗️ Architecture

```
Controller (REST layer)
    ↓
Service (Business logic + ProcessBuilder → Python subprocess)
    ↓
Model (Request/Response DTOs + Severity Enum)
    ↓
In-Memory Store (ConcurrentLinkedDeque, capped at 100 entries)
```

---

## ▶️ Running the API

```bash
# From the aegis-api directory
mvn spring-boot:run
# API available at http://localhost:8080
```

**Prerequisites:**
- Java 17+
- Maven 3.8+
- Python 3.10+ with trained model (`joblib` file) in expected path

---

## 📨 Sample Request & Response

**Request:**
```json
POST /api/predict
Content-Type: application/json

{
  "duration": 0,
  "protocol_type": "tcp",
  "service": "http",
  "src_bytes": 232,
  "dst_bytes": 8153
}
```

**Response:**
```json
{
  "prediction": "normal",
  "severity": "NONE",
  "confidence": 0.97,
  "timestamp": "2026-06-03T18:00:00Z"
}
```

---

## ⚙️ Key Implementation Details

- **Thread safety:** `ConcurrentLinkedDeque` for prediction history, capped at 100 entries
- **Java ↔ Python bridge:** `ProcessBuilder` calls trained `joblib` ensemble with graceful fallback to rule-based heuristics if model unavailable
- **Validation:** Jakarta Bean Validation on all incoming requests
- **Error handling:** Structured try-catch throughout service layer
- **Severity levels:** `NONE / MEDIUM / HIGH / CRITICAL` based on prediction class + confidence

---

## 📂 Structure

```
aegis-api/
├── src/main/java/com/aegisai/
│   ├── controller/     # AegisController.java — REST endpoints
│   ├── service/        # PredictionService.java — ML bridge logic
│   └── model/          # PredictionRequest.java, PredictionResponse.java
├── pom.xml
└── README.md
```

---

## 👤 Author

**Prerak Nain** — B.Tech CS, Bennett University (2023–2027)  
[LinkedIn](https://linkedin.com/in/preraknain) · [GitHub](https://github.com/prerak1603)