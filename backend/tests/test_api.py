"""Tests for API endpoints."""
import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert "timestamp" in data
        assert "dependencies" in data

    def test_health_check_shows_resolver_status(self, client):
        response = client.get("/api/v1/health")
        data = response.json()
        assert "mitre_id_resolver" in data["dependencies"]
        assert data["dependencies"]["mitre_id_resolver"] in ("available", "unavailable")


class TestDetectionRulesEndpoint:
    def test_get_detection_rules(self, client):
        response = client.get("/api/v1/detection-rules")
        assert response.status_code == 200
        rules = response.json()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_detection_rules_have_techniques(self, client):
        response = client.get("/api/v1/detection-rules")
        rules = response.json()
        # At least one rule should have techniques
        rules_with_techniques = [r for r in rules if len(r["techniques"]) > 0]
        assert len(rules_with_techniques) > 0

    def test_detection_rules_limit(self, client):
        response = client.get("/api/v1/detection-rules?limit=2")
        assert response.status_code == 200

    def test_detection_rules_invalid_limit(self, client):
        response = client.get("/api/v1/detection-rules?limit=0")
        assert response.status_code == 422

    def test_detection_rules_pagination(self, client):
        response = client.get("/api/v1/detection-rules?offset=1")
        assert response.status_code == 200
        all_response = client.get("/api/v1/detection-rules")
        all_rules = all_response.json()
        offset_rules = response.json()
        if len(all_rules) > 1:
            assert len(offset_rules) == len(all_rules) - 1


class TestIncidentsEndpoint:
    def test_get_incidents(self, client):
        response = client.get("/api/v1/incidents")
        assert response.status_code == 200
        incidents = response.json()
        assert isinstance(incidents, list)
        assert len(incidents) > 0

    def test_incidents_have_fields(self, client):
        response = client.get("/api/v1/incidents")
        incidents = response.json()
        inc = incidents[0]
        assert "id" in inc
        assert "title" in inc
        assert "severity" in inc

    def test_incidents_with_days_param(self, client):
        response = client.get("/api/v1/incidents?days=7")
        assert response.status_code == 200

    def test_incidents_pagination(self, client):
        response = client.get("/api/v1/incidents?offset=1")
        assert response.status_code == 200


class TestCoverageEndpoint:
    def test_get_coverage(self, client):
        response = client.get("/api/v1/coverage")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    def test_get_coverage_summary(self, client):
        response = client.get("/api/v1/coverage/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total_techniques" in data
        assert "avg_score" in data
        assert "coverage_by_severity" in data


class TestLayerEndpoints:
    def test_coverage_layer(self, client):
        response = client.get("/api/v1/layers/coverage")
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "Detection Coverage"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert "gradient" in layer

    def test_coverage_layer_custom_name(self, client):
        response = client.get("/api/v1/layers/coverage?name=My+Layer")
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "My Layer"

    def test_incident_layer(self, client):
        response = client.get("/api/v1/layers/incidents")
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "Incident Heatmap"
        assert "techniques" in layer

    def test_combined_layer(self, client):
        response = client.get("/api/v1/layers/combined")
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "Security Posture"
        assert "techniques" in layer

    def test_atlas_layer(self, client):
        response = client.get("/api/v1/layers/atlas")
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "AI/ML Threat Coverage"
        assert layer["domain"] == "mitre-atlas"

    def test_layer_has_versions(self, client):
        response = client.get("/api/v1/layers/coverage")
        layer = response.json()
        assert "versions" in layer
        assert layer["versions"]["attack"] == "16"
        assert layer["versions"]["layer"] == "4.5"

    def test_custom_layer_post(self, client):
        payload = {
            "name": "Custom Test Layer",
            "domain": "enterprise-attack",
            "techniques": [
                {"techniqueID": "T1059", "score": 50, "comment": "test"}
            ],
        }
        response = client.post("/api/v1/layers/custom", json=payload)
        assert response.status_code == 200
        layer = response.json()
        assert layer["name"] == "Custom Test Layer"
        assert len(layer["techniques"]) == 1


class TestCustomLayerValidation:
    def test_custom_layer_too_many_techniques(self, client):
        techniques = [{"techniqueID": f"T{1000+i}"} for i in range(5001)]
        payload = {"name": "Too Big", "techniques": techniques}
        response = client.post("/api/v1/layers/custom", json=payload)
        assert response.status_code == 422

    def test_custom_layer_max_techniques_ok(self, client):
        techniques = [{"techniqueID": f"T{1000+i}"} for i in range(100)]
        payload = {"name": "OK Layer", "techniques": techniques}
        response = client.post("/api/v1/layers/custom", json=payload)
        assert response.status_code == 200


class TestRateLimiting:
    def test_rate_limit_headers_present(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200


class TestRootRedirect:
    def test_root_redirects_to_docs(self, client):
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 307
        assert "/docs" in response.headers["location"]
