"""Health check endpoint."""

from fastapi import APIRouter, Request
from app.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """Liveness + readiness probe for Docker / Kubernetes."""
    detector = request.app.state.detector
    return HealthResponse(
        status="ok",
        model_trained=detector.is_trained,
        training_samples=detector.training_samples,
        version="1.0.0",
    )
