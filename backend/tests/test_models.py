"""Tests for Pydantic models."""
from app.models.detection import (
    TechniqueMapping,
    DetectionRule,
    Incident,
    DetectionCoverage,
    DETECTION_SCORE_WEIGHT,
    MAX_DETECTION_SCORE,
    INCIDENT_SCORE_WEIGHT,
    MAX_INCIDENT_SCORE,
)
from app.models.layer import (
    NavigatorLayer,
    Technique,
    Metadata,
    Link,
    Gradient,
    Versions,
)


class TestTechniqueMapping:
    def test_defaults(self):
        m = TechniqueMapping(technique_id="T1059")
        assert m.technique_name is None
        assert m.confidence == 1.0
        assert m.source == "manual"
        assert m.mitre_id_resolved is False

    def test_reliaquest_fields(self):
        m = TechniqueMapping(
            technique_id="rq-123",
            reliaquest_technique_id="rq-123",
            reliaquest_tactic_id="rq-tactic-456",
            source="reliaquest",
        )
        assert m.reliaquest_technique_id == "rq-123"
        assert m.reliaquest_tactic_id == "rq-tactic-456"


class TestDetectionRule:
    def test_technique_ids_property(self):
        rule = DetectionRule(
            id="r1",
            name="Rule 1",
            source="test",
            techniques=[
                TechniqueMapping(technique_id="T1059"),
                TechniqueMapping(technique_id="T1003"),
            ],
        )
        assert rule.technique_ids == ["T1059", "T1003"]

    def test_empty_techniques(self):
        rule = DetectionRule(id="r1", name="Rule 1", source="test")
        assert rule.technique_ids == []


class TestIncident:
    def test_technique_ids_property(self):
        inc = Incident(
            id="i1",
            title="Inc 1",
            source="test",
            techniques=[TechniqueMapping(technique_id="T1059")],
        )
        assert inc.technique_ids == ["T1059"]

    def test_defaults(self):
        inc = Incident(id="i1", title="Inc 1", source="test")
        assert inc.state == "open"
        assert inc.severity == "medium"
        assert inc.internal_only is False


class TestDetectionCoverage:
    def test_coverage_score_no_data(self):
        cov = DetectionCoverage(technique_id="T1059")
        assert cov.coverage_score == 0

    def test_coverage_score_detections_only(self):
        cov = DetectionCoverage(technique_id="T1059", detection_count=3)
        # 3 * 20 = 60, capped at 60 for detections
        assert cov.coverage_score == 60

    def test_coverage_score_with_incidents(self):
        cov = DetectionCoverage(
            technique_id="T1059", detection_count=3, incident_count=2
        )
        # base: min(60, 60) = 60, bonus: min(20, 40) = 20 -> 80
        assert cov.coverage_score == 80

    def test_coverage_score_capped_at_100(self):
        cov = DetectionCoverage(
            technique_id="T1059", detection_count=10, incident_count=10
        )
        assert cov.coverage_score == 100

    def test_coverage_score_incidents_only(self):
        cov = DetectionCoverage(technique_id="T1059", incident_count=2)
        # base: 0, bonus: 20 -> 20
        assert cov.coverage_score == 20

    def test_coverage_score_uses_constants(self):
        """Verify coverage score uses the extracted constants."""
        assert DETECTION_SCORE_WEIGHT == 20
        assert MAX_DETECTION_SCORE == 60
        assert INCIDENT_SCORE_WEIGHT == 10
        assert MAX_INCIDENT_SCORE == 40
        cov = DetectionCoverage(technique_id="T1059", detection_count=1, incident_count=1)
        expected = min(1 * DETECTION_SCORE_WEIGHT, MAX_DETECTION_SCORE) + min(1 * INCIDENT_SCORE_WEIGHT, MAX_INCIDENT_SCORE)
        assert cov.coverage_score == expected


class TestNavigatorLayer:
    def test_defaults(self):
        layer = NavigatorLayer(name="Test")
        assert layer.domain == "enterprise-attack"
        assert layer.techniques == []
        assert layer.versions.attack == "16"

    def test_add_technique_new(self):
        layer = NavigatorLayer(name="Test")
        layer.add_technique("T1059", score=80, comment="test")
        assert len(layer.techniques) == 1
        assert layer.techniques[0].techniqueID == "T1059"
        assert layer.techniques[0].score == 80

    def test_add_technique_update_existing(self):
        layer = NavigatorLayer(name="Test")
        layer.add_technique("T1059", score=50, comment="first")
        layer.add_technique("T1059", score=80, comment="updated")
        assert len(layer.techniques) == 1
        assert layer.techniques[0].score == 80
        assert layer.techniques[0].comment == "updated"

    def test_add_technique_different_tactics(self):
        layer = NavigatorLayer(name="Test")
        layer.add_technique("T1059", tactic="execution", score=50)
        layer.add_technique("T1059", tactic="persistence", score=70)
        assert len(layer.techniques) == 2

    def test_to_json(self):
        layer = NavigatorLayer(name="Test", description="desc")
        layer.add_technique("T1059", score=80)
        result = layer.to_json()
        assert result["name"] == "Test"
        assert result["description"] == "desc"
        assert len(result["techniques"]) == 1
        assert result["techniques"][0]["techniqueID"] == "T1059"

    def test_add_technique_with_metadata(self):
        layer = NavigatorLayer(name="Test")
        meta = [Metadata(name="key", value="val")]
        layer.add_technique("T1059", metadata=meta)
        assert len(layer.techniques[0].metadata) == 1
        assert layer.techniques[0].metadata[0].name == "key"
