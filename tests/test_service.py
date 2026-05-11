"""
Tests for the Log Anomaly Detection microservice.

Run with:  pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.preprocessing import decode_and_clean, compute_features, preprocess
from app.ml.model import AnomalyDetector

client = TestClient(app)


# ---------------------------------------------------------------------------
# Preprocessing tests
# ---------------------------------------------------------------------------


class TestPreprocessing:
    def test_url_decode_percent_encoding(self):
        assert decode_and_clean("%3Cscript%3E") == "<script>"

    def test_url_decode_plus_to_space(self):
        assert decode_and_clean("hello+world") == "hello world"

    def test_lowercase_and_strip(self):
        assert decode_and_clean("  USER LOGIN  ") == "user login"

    def test_combined_decode_and_clean(self):
        result = decode_and_clean("SELECT+%2A+FROM+users")
        assert result == "select * from users"

    def test_symbol_density_zero_for_clean_log(self):
        features = compute_features("user login successful")
        assert features["symbol_density"] == 0.0

    def test_symbol_density_nonzero_for_sql(self):
        features = compute_features("select * from users where id=1")
        assert features["symbol_density"] > 0

    def test_threat_kw_flag_set_for_select(self):
        _, features = preprocess("SELECT * FROM users")
        assert features["has_threat_kw"] == 1

    def test_threat_kw_flag_set_for_script_tag(self):
        _, features = preprocess("<script>alert(1)</script>")
        assert features["has_threat_kw"] == 1

    def test_threat_kw_flag_clear_for_normal_log(self):
        _, features = preprocess("user logout successful")
        assert features["has_threat_kw"] == 0

    def test_length_feature(self):
        _, features = preprocess("hello")
        assert features["length"] == 5

    def test_empty_string_symbol_density(self):
        features = compute_features("")
        assert features["symbol_density"] == 0.0


# ---------------------------------------------------------------------------
# ML model tests
# ---------------------------------------------------------------------------


class TestAnomalyDetector:
    @pytest.fixture
    def trained_detector(self):
        det = AnomalyDetector()
        det.train_on_baseline()
        return det

    def test_model_trains_without_error(self, trained_detector):
        assert trained_detector.is_trained

    def test_baseline_sample_count(self, trained_detector):
        assert trained_detector.training_samples >= 30

    def test_normal_log_classified_correctly(self, trained_detector):
        result = trained_detector.predict("user login successful")
        assert result["status"] == "NORMAL"

    def test_sql_injection_detected(self, trained_detector):
        result = trained_detector.predict("SELECT * FROM users WHERE 1=1")
        assert result["status"] == "ANOMALY"

    def test_xss_detected(self, trained_detector):
        result = trained_detector.predict("<script>alert('xss')</script>")
        assert result["status"] == "ANOMALY"

    def test_path_traversal_detected(self, trained_detector):
        result = trained_detector.predict("GET /../../../etc/passwd HTTP/1.1")
        assert result["status"] == "ANOMALY"

    def test_heuristic_override_for_sql_keyword(self, trained_detector):
        result = trained_detector.predict("SELECT name FROM accounts")
        assert result["heuristic_override"] is True
        assert result["status"] == "ANOMALY"

    def test_no_heuristic_override_for_normal(self, trained_detector):
        result = trained_detector.predict("GET /api/health 200")
        assert result["heuristic_override"] is False

    def test_anomaly_score_present(self, trained_detector):
        result = trained_detector.predict("login ok")
        assert "anomaly_score" in result
        assert isinstance(result["anomaly_score"], float)

    def test_retrain_updates_sample_count(self, trained_detector):
        custom_logs = [f"custom normal log entry number {i}" for i in range(20)]
        n = trained_detector.retrain(custom_logs, contamination=0.05)
        assert n == 20

    def test_untrained_model_raises(self):
        det = AnomalyDetector()
        with pytest.raises(RuntimeError):
            det.predict("anything")


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_200(self):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_model_is_trained(self):
        data = client.get("/health").json()
        assert data["model_trained"] is True
        assert data["training_samples"] > 0


class TestDetectEndpoint:
    def test_single_normal_log(self):
        resp = client.post(
            "/api/v1/detect",
            json={"log_message": "user login successful"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "NORMAL"

    def test_single_sql_injection(self):
        resp = client.post(
            "/api/v1/detect",
            json={"log_message": "SELECT * FROM users WHERE 1=1--"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ANOMALY"
        assert body["heuristic_override"] is True

    def test_url_encoded_xss_payload(self):
        resp = client.post(
            "/api/v1/detect",
            json={"log_message": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ANOMALY"

    def test_optional_fields_accepted(self):
        resp = client.post(
            "/api/v1/detect",
            json={
                "log_message": "system heartbeat",
                "source_ip": "10.0.0.1",
                "timestamp": "2024-01-15T10:00:00Z",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source_ip"] == "10.0.0.1"

    def test_empty_log_message_rejected(self):
        resp = client.post("/api/v1/detect", json={"log_message": ""})
        assert resp.status_code == 422

    def test_response_includes_features(self):
        resp = client.post(
            "/api/v1/detect", json={"log_message": "cache hit"}
        )
        body = resp.json()
        assert "length" in body["features"]
        assert "symbol_density" in body["features"]
        assert "has_threat_kw" in body["features"]


class TestBatchDetectEndpoint:
    def test_batch_mixed_logs(self):
        resp = client.post(
            "/api/v1/detect/batch",
            json={
                "logs": [
                    {"log_message": "user login ok"},
                    {"log_message": "SELECT * FROM accounts"},
                    {"log_message": "system heartbeat"},
                    {"log_message": "<script>alert(1)</script>"},
                ]
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 4
        assert body["anomalies"] == 2
        assert body["normal"] == 2

    def test_batch_empty_list_rejected(self):
        resp = client.post("/api/v1/detect/batch", json={"logs": []})
        assert resp.status_code == 422


class TestTrainEndpoint:
    def test_retrain_succeeds(self):
        resp = client.post(
            "/api/v1/train",
            json={
                "logs": [f"normal operation log {i}" for i in range(15)],
                "contamination": 0.05,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["samples_trained"] == 15

    def test_retrain_too_few_samples_rejected(self):
        resp = client.post(
            "/api/v1/train",
            json={"logs": ["too few"], "contamination": 0.1},
        )
        assert resp.status_code == 422

    def test_contamination_out_of_range_rejected(self):
        resp = client.post(
            "/api/v1/train",
            json={
                "logs": [f"log {i}" for i in range(15)],
                "contamination": 0.99,
            },
        )
        assert resp.status_code == 422
