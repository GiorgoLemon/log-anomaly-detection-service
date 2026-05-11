"""
ML engine: Isolation Forest + MinMaxScaler.

Design decisions
----------------
* MinMaxScaler normalises all features into [0, 1] so that the "length"
  integer does not overpower the binary has_threat_kw flag or the
  fractional symbol_density ratio.
* contamination=0.05 reflects a clean baseline (very few anomalies).
* decision_function threshold of 0.0: scores below → ANOMALY.
* Heuristic override: has_threat_kw == 1 always forces ANOMALY.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from app.preprocessing import preprocess

# ---------------------------------------------------------------------------
# Safe baseline dataset (cold-start prevention)
# ---------------------------------------------------------------------------
_BASELINE_LOGS = [
    "user login successful",
    "user logout",
    "db ok",
    "system heartbeat",
    "GET /index.html HTTP/1.1 200",
    "GET /api/health HTTP/1.1 200",
    "POST /api/login HTTP/1.1 200",
    "PUT /api/user/42 HTTP/1.1 204",
    "DELETE /api/session/abc123 HTTP/1.1 200",
    "ping ok",
    "connection established",
    "connection closed",
    "cache hit",
    "cache miss",
    "file read ok",
    "file write ok",
    "scheduled job completed",
    "backup successful",
    "certificate renewed",
    "ssl handshake ok",
    "dns lookup ok",
    "load balancer health check ok",
    "GET /static/style.css HTTP/1.1 304",
    "GET /favicon.ico HTTP/1.1 200",
    "user password changed",
    "2fa token validated",
    "session token refreshed",
    "rate limit check passed",
    "audit log flushed",
    "service started",
    "service stopped gracefully",
    "configuration reloaded",
    "metrics exported",
    "thread pool: 4/8 active",
    "queue depth: 0",
    "memory usage: 42%",
    "cpu usage: 18%",
    "disk io: normal",
    "network throughput: normal",
]

# Anomaly score threshold (decision_function output)
_SCORE_THRESHOLD = 0.0

# Feature column order – must match model training
_FEATURE_COLS = ["length", "symbol_density", "has_threat_kw"]


class AnomalyDetector:
    """Wraps IsolationForest + MinMaxScaler for log anomaly detection."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self._model: IsolationForest | None = None
        self._scaler: MinMaxScaler | None = None
        self._training_samples: int = 0

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train_on_baseline(self) -> None:
        """Pre-train on the built-in safe baseline (cold-start prevention)."""
        self._fit(_BASELINE_LOGS, contamination=self.contamination)

    def retrain(self, log_lines: list[str], contamination: float = 0.1) -> int:
        """
        Retrain the model on company-specific historical logs.

        Parameters
        ----------
        log_lines    : list of raw log strings
        contamination: expected fraction of anomalies in the corpus

        Returns
        -------
        Number of samples used for training.
        """
        self._fit(log_lines, contamination=contamination)
        return self._training_samples

    def _fit(self, log_lines: list[str], contamination: float) -> None:
        feature_matrix = self._extract_matrix(log_lines)

        self._scaler = MinMaxScaler()
        scaled = self._scaler.fit_transform(feature_matrix)

        self._model = IsolationForest(
            contamination=contamination,
            random_state=self.random_state,
            n_estimators=200,
            max_samples="auto",
        )
        self._model.fit(scaled)
        self._training_samples = len(log_lines)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, raw_log: str) -> dict:
        """
        Classify a single raw log string.

        Returns a dict with:
            cleaned_message, status, anomaly_score,
            heuristic_override, features
        """
        if self._model is None or self._scaler is None:
            raise RuntimeError("Model is not trained. Call train_on_baseline() first.")

        cleaned, features = preprocess(raw_log)
        feature_vec = np.array([[features[c] for c in _FEATURE_COLS]])
        scaled_vec = self._scaler.transform(feature_vec)

        score: float = float(self._model.decision_function(scaled_vec)[0])

        # Heuristic override: critical keyword → always ANOMALY
        heuristic_override = bool(features["has_threat_kw"] == 1)

        if heuristic_override or score < _SCORE_THRESHOLD:
            status = "ANOMALY"
        else:
            status = "NORMAL"

        return {
            "cleaned_message": cleaned,
            "status": status,
            "anomaly_score": round(score, 6),
            "heuristic_override": heuristic_override,
            "features": features,
        }

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _extract_matrix(self, log_lines: list[str]) -> np.ndarray:
        rows = []
        for line in log_lines:
            _, features = preprocess(line)
            rows.append([features[c] for c in _FEATURE_COLS])
        return np.array(rows)

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    @property
    def training_samples(self) -> int:
        return self._training_samples
