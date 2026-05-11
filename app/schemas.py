"""
Pydantic schemas for request and response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional


class LogEntry(BaseModel):
    log_message: str = Field(
        ...,
        min_length=1,
        description="The raw log string to be analysed.",
        examples=["GET /index.html HTTP/1.1 200"],
    )
    source_ip: Optional[str] = Field(
        None,
        description="Optional originating IP address for richer context.",
        examples=["192.168.1.10"],
    )
    timestamp: Optional[str] = Field(
        None,
        description="ISO-8601 timestamp of the log event.",
        examples=["2024-01-15T10:30:00Z"],
    )


class BatchLogRequest(BaseModel):
    logs: list[LogEntry] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Up to 500 log entries for batch analysis.",
    )


class DetectionResult(BaseModel):
    log_message: str
    cleaned_message: str
    status: str = Field(..., description="'NORMAL' or 'ANOMALY'")
    anomaly_score: float = Field(
        ...,
        description=(
            "Isolation Forest decision_function score. "
            "Negative = anomalous, positive = normal."
        ),
    )
    heuristic_override: bool = Field(
        ...,
        description="True when a critical threat keyword forced ANOMALY status.",
    )
    features: dict = Field(
        ...,
        description="Extracted numerical features used for classification.",
    )
    source_ip: Optional[str] = None
    timestamp: Optional[str] = None


class BatchDetectionResponse(BaseModel):
    total: int
    anomalies: int
    normal: int
    results: list[DetectionResult]


class TrainRequest(BaseModel):
    logs: list[str] = Field(
        ...,
        min_length=10,
        description="Custom historical log lines used to retrain the model.",
    )
    contamination: float = Field(
        0.1,
        ge=0.01,
        le=0.5,
        description="Expected proportion of anomalies in training data.",
    )


class TrainResponse(BaseModel):
    status: str
    samples_trained: int
    message: str


class HealthResponse(BaseModel):
    status: str
    model_trained: bool
    training_samples: int
    version: str
