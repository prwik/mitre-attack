"""Shared test fixtures."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import _reliaquest_client, get_reliaquest_client
from app.services.reliaquest import MockReliaQuestClient
from app.models.detection import (
    DetectionRule,
    Incident,
    TechniqueMapping,
    DetectionCoverage,
)


@pytest.fixture(autouse=True)
def reset_client_singleton():
    """Reset the singleton client between tests."""
    import app.api.routes as routes_module
    routes_module._reliaquest_client = None
    yield
    routes_module._reliaquest_client = None


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def mock_rq_client():
    """Mock ReliaQuest client."""
    return MockReliaQuestClient()


@pytest.fixture
def sample_technique_mapping():
    """Sample TechniqueMapping with resolved MITRE ID."""
    return TechniqueMapping(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        source="reliaquest",
        mitre_id_resolved=True,
    )


@pytest.fixture
def sample_rule(sample_technique_mapping):
    """Sample DetectionRule."""
    return DetectionRule(
        id="rule-test-001",
        name="Test PowerShell Rule",
        slug="test-powershell-rule",
        description="Test rule",
        severity="high",
        source="reliaquest",
        techniques=[sample_technique_mapping],
    )


@pytest.fixture
def sample_incident(sample_technique_mapping):
    """Sample Incident."""
    return Incident(
        id="inc-test-001",
        title="Test Incident",
        source="reliaquest",
        severity="high",
        techniques=[sample_technique_mapping],
    )


@pytest.fixture
def sample_coverage():
    """Sample coverage data dict."""
    return {
        "T1059.001": DetectionCoverage(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="execution",
            detection_count=3,
            incident_count=2,
            sources=["reliaquest"],
        ),
        "T1003.001": DetectionCoverage(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="credential-access",
            detection_count=1,
            incident_count=0,
            sources=["reliaquest"],
        ),
    }
