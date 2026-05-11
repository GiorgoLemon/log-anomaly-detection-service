"""
Training endpoint.

POST /api/v1/train  – retrain the model on custom historical logs
"""

from fastapi import APIRouter, Request, HTTPException
from app.schemas import TrainRequest, TrainResponse

router = APIRouter()


@router.post("/train", response_model=TrainResponse)
async def retrain_model(payload: TrainRequest, request: Request) -> TrainResponse:
    """
    Retrain the Isolation Forest on company-specific historical logs.

    Pass at least 10 representative **normal** log lines. The model will
    be hot-swapped in memory; no restart is required.

    - **contamination**: expected fraction of anomalies (0.01–0.50).
      Lower values make the model more permissive.
    """
    detector = request.app.state.detector
    try:
        n = detector.retrain(payload.logs, contamination=payload.contamination)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Training failed: {exc}") from exc

    return TrainResponse(
        status="ok",
        samples_trained=n,
        message=(
            f"Model retrained on {n} samples "
            f"(contamination={payload.contamination}). "
            "Changes are effective immediately."
        ),
    )
