"""
Detection endpoints.

POST /api/v1/detect        – single log entry
POST /api/v1/detect/batch  – up to 500 log entries
"""

from fastapi import APIRouter, Request, HTTPException

from app.schemas import (
    LogEntry,
    BatchLogRequest,
    DetectionResult,
    BatchDetectionResponse,
)

router = APIRouter()


def _run_detection(detector, entry: LogEntry) -> DetectionResult:
    try:
        result = detector.predict(entry.log_message)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return DetectionResult(
        log_message=entry.log_message,
        source_ip=entry.source_ip,
        timestamp=entry.timestamp,
        **result,
    )


@router.post("/detect", response_model=DetectionResult)
async def detect_single(entry: LogEntry, request: Request) -> DetectionResult:
    """
    Analyse a single log entry and return a classification result.

    - **status**: `NORMAL` or `ANOMALY`
    - **anomaly_score**: raw Isolation Forest decision_function output
    - **heuristic_override**: `true` when a critical keyword forced ANOMALY
    """
    detector = request.app.state.detector
    return _run_detection(detector, entry)


@router.post("/detect/batch", response_model=BatchDetectionResponse)
async def detect_batch(
    payload: BatchLogRequest, request: Request
) -> BatchDetectionResponse:
    """
    Analyse up to 500 log entries in a single call.

    Returns per-entry results plus aggregate counts.
    """
    detector = request.app.state.detector
    results = [_run_detection(detector, entry) for entry in payload.logs]

    anomaly_count = sum(1 for r in results if r.status == "ANOMALY")
    return BatchDetectionResponse(
        total=len(results),
        anomalies=anomaly_count,
        normal=len(results) - anomaly_count,
        results=results,
    )
