"""
AI Log Anomaly Detection Microservice
FastAPI entry point
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from app.routers import detection, health, training
from app.ml.model import AnomalyDetector

detector = AnomalyDetector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Train on safe baseline at startup to prevent cold-start failures."""
    detector.train_on_baseline()
    app.state.detector = detector
    yield

app = FastAPI(
    title="Log Anomaly Detection Service",
    description="Unsupervised ML microservice for real-time cybersecurity log monitoring.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Σύνδεση των Routers 
app.include_router(health.router, tags=["Health"])
app.include_router(detection.router, prefix="/api/v1", tags=["Detection"])
app.include_router(training.router, prefix="/api/v1", tags=["Training"])

# --- ΠΡΟΣΘΗΚΗ ΓΙΑ ΤΟ DASHBOARD ---

# Υπολογισμός της διαδρομής του φακέλου static (μέσα στο app/)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Σερβίρισμα στατικών αρχείων
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Αρχική σελίδα που επιστρέφει το index.html
@app.get("/")
async def read_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))