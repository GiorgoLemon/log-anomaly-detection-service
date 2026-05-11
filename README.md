# Log Anomaly Detection Microservice

A production-grade Python microservice for **real-time cybersecurity log monitoring** using **Unsupervised Machine Learning** (Isolation Forest). Designed to run as a sidecar intelligence service for a Java Spring Boot backend.

---

## Architecture Overview

```
Spring Boot Backend
        │
        │  POST /api/v1/detect (JSON)
        ▼
┌─────────────────────────────────────────────────┐
│           FastAPI Microservice                  │
│                                                 │
│  Raw Log ──► Preprocessing ──► Feature Eng.    │
│                                    │            │
│                              MinMaxScaler       │
│                                    │            │
│                          Isolation Forest       │
│                                    │            │
│                    score < 0.0 or has_threat_kw │
│                              │           │      │
│                           ANOMALY     NORMAL    │
└─────────────────────────────────────────────────┘
```

---

## Quickstart

### With Docker Compose (recommended)

```bash
git clone <repo>
cd log-anomaly-service
docker-compose up --build
```

The service starts on **http://localhost:8000**.  
The model is pre-trained on the safe baseline automatically at startup.

### Local Development

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## API Reference

### `GET /health`
Liveness + readiness probe.
```json
{
  "status": "ok",
  "model_trained": true,
  "training_samples": 39,
  "version": "1.0.0"
}
```

---

### `POST /api/v1/detect`
Analyse a single log entry.

**Request**
```json
{
  "log_message": "GET /../../../etc/passwd HTTP/1.1",
  "source_ip": "203.0.113.42",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response**
```json
{
  "log_message": "GET /../../../etc/passwd HTTP/1.1",
  "cleaned_message": "get /../../../etc/passwd http/1.1",
  "status": "ANOMALY",
  "anomaly_score": -0.1596,
  "heuristic_override": true,
  "features": {
    "length": 33,
    "symbol_density": 0.242,
    "has_threat_kw": 1
  },
  "source_ip": "203.0.113.42",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### `POST /api/v1/detect/batch`
Analyse up to 500 log entries in one call.

**Request**
```json
{
  "logs": [
    { "log_message": "user login successful" },
    { "log_message": "SELECT * FROM users WHERE 1=1--" }
  ]
}
```

**Response**
```json
{
  "total": 2,
  "anomalies": 1,
  "normal": 1,
  "results": [...]
}
```

---

### `POST /api/v1/train`
Retrain the model on company-specific historical logs (hot-swap, no restart needed).

**Request**
```json
{
  "logs": [
    "user login successful",
    "GET /api/dashboard 200",
    "db connection pool ok"
  ],
  "contamination": 0.05
}
```
- `contamination`: Expected fraction of anomalies in your data (0.01–0.50).  
  Lower → more permissive (fewer false positives).

---

## Spring Boot Integration

```java
// LogAnomalyClient.java
@Service
public class LogAnomalyClient {

    @Value("${anomaly.service.url:http://anomaly-detector:8000}")
    private String serviceUrl;

    private final RestTemplate restTemplate;

    public DetectionResult analyseLog(String logMessage, String sourceIp) {
        var request = new LogEntryRequest(logMessage, sourceIp, Instant.now().toString());
        return restTemplate.postForObject(
            serviceUrl + "/api/v1/detect",
            request,
            DetectionResult.class
        );
    }
}
```

In `application.properties`:
```properties
anomaly.service.url=http://anomaly-detector:8000
```

---

## ML Pipeline Details

### 1. Preprocessing
| Step | Implementation |
|------|---------------|
| URL decode | `urllib.parse.unquote_plus` – converts `%3C` → `<`, `+` → space |
| Normalise | lowercase + strip whitespace |

### 2. Feature Engineering
| Feature | Type | Description |
|---------|------|-------------|
| `length` | int | Total character count |
| `symbol_density` | float [0,1] | Ratio of `' " * = - ; / < > . % \` to length |
| `has_threat_kw` | int {0,1} | Presence of SQL/XSS/path-traversal keywords |

### 3. Scaling
`MinMaxScaler` normalises all features to [0, 1] so `length` (e.g. 200) doesn't dominate `has_threat_kw` (0 or 1).

### 4. Model
`IsolationForest(n_estimators=200, contamination=0.05)` — no labels required.

### 5. Classification Logic
```
anomaly_score = model.decision_function(scaled_features)

if has_threat_kw == 1:          # heuristic override
    status = ANOMALY
elif anomaly_score < 0.0:       # ML threshold
    status = ANOMALY
else:
    status = NORMAL
```


**Algorithm Choice: Isolation Forest was selected because it is an unsupervised algorithm that detects anomalies by isolating them in feature space. This is ideal for log monitoring where "normal" is common and "attacks" are rare outliers.

---

## Running Tests

```bash
pytest tests/ -v
```

Expected output: **28 tests passing**.

---

## Reducing False Positives

The built-in baseline covers generic normal patterns. To tune for your environment:

1. Collect 2–4 weeks of clean operational logs.
2. `POST /api/v1/train` with those logs and a low `contamination` (e.g. `0.03`).
3. Monitor `anomaly_score` values for legitimate traffic and adjust the threshold in `app/ml/model.py` → `_SCORE_THRESHOLD` if needed.

---

## Project Structure

```
log-anomaly-service/
├── app/
│   ├── main.py              # FastAPI app + lifespan (startup training)
│   ├── schemas.py           # Pydantic request/response models
│   ├── preprocessing.py     # URL decode, normalise, feature extraction
│   ├── routers/
│   │   ├── health.py        # GET /health
│   │   ├── detection.py     # POST /api/v1/detect[/batch]
│   │   └── training.py      # POST /api/v1/train
│   └── ml/
│       └── model.py         # IsolationForest + MinMaxScaler engine
├── tests/
│   └── test_service.py      # 28 unit + integration tests
├── Dockerfile               # Multi-stage build (builder → runtime)
├── docker-compose.yml
├── requirements.txt
└── pyproject.toml
```
