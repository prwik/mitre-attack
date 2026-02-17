"""Tests for LayerGenerator service."""
import pytest

from app.services.layer_generator import LayerGenerator
from app.models.detection import DetectionCoverage
from app.models.layer import NavigatorLayer, Technique


class TestGenerateCoverageLayer:
    def setup_method(self):
        self.gen = LayerGenerator()

    def test_basic_layer(self, sample_coverage):
        layer = self.gen.generate_coverage_layer(sample_coverage)
        assert layer.name == "Detection Coverage"
        assert layer.domain == "enterprise-attack"
        assert len(layer.techniques) == 2

    def test_custom_name_and_domain(self, sample_coverage):
        layer = self.gen.generate_coverage_layer(
            sample_coverage, name="Custom", domain="mobile-attack"
        )
        assert layer.name == "Custom"
        assert layer.domain == "mobile-attack"

    def test_gradient_set(self, sample_coverage):
        layer = self.gen.generate_coverage_layer(sample_coverage)
        assert layer.gradient.minValue == 0
        assert layer.gradient.maxValue == 100
        assert len(layer.gradient.colors) == 3

    def test_legend_items(self, sample_coverage):
        layer = self.gen.generate_coverage_layer(sample_coverage)
        assert len(layer.legendItems) == 3

    def test_filters_atlas_techniques(self):
        coverage = {
            "T1059": DetectionCoverage(technique_id="T1059", detection_count=1),
            "AML.T0044": DetectionCoverage(technique_id="AML.T0044", detection_count=1),
        }
        layer = self.gen.generate_coverage_layer(coverage, domain="enterprise-attack")
        tech_ids = [t.techniqueID for t in layer.techniques]
        assert "T1059" in tech_ids
        assert "AML.T0044" not in tech_ids

    def test_technique_metadata(self, sample_coverage):
        layer = self.gen.generate_coverage_layer(sample_coverage)
        tech = next(t for t in layer.techniques if t.techniqueID == "T1059.001")
        meta_names = [m.name for m in tech.metadata]
        assert "Detection Rules" in meta_names
        assert "Incidents" in meta_names
        assert "Sources" in meta_names


class TestGenerateIncidentLayer:
    def setup_method(self):
        self.gen = LayerGenerator()

    def test_only_includes_techniques_with_incidents(self):
        coverage = {
            "T1059": DetectionCoverage(
                technique_id="T1059", detection_count=1, incident_count=3
            ),
            "T1003": DetectionCoverage(
                technique_id="T1003", detection_count=1, incident_count=0
            ),
        }
        layer = self.gen.generate_incident_layer(coverage)
        tech_ids = [t.techniqueID for t in layer.techniques]
        assert "T1059" in tech_ids
        assert "T1003" not in tech_ids

    def test_score_is_incident_count(self):
        coverage = {
            "T1059": DetectionCoverage(
                technique_id="T1059", incident_count=5
            ),
        }
        layer = self.gen.generate_incident_layer(coverage)
        assert layer.techniques[0].score == 5

    def test_empty_coverage(self):
        layer = self.gen.generate_incident_layer({})
        assert len(layer.techniques) == 0


class TestGenerateCombinedLayer:
    def setup_method(self):
        self.gen = LayerGenerator()

    def test_includes_all_techniques(self, sample_coverage):
        layer = self.gen.generate_combined_layer(sample_coverage)
        assert len(layer.techniques) == 2

    def test_detection_only_gets_blue(self):
        coverage = {
            "T1003": DetectionCoverage(
                technique_id="T1003", detection_count=1, incident_count=0
            ),
        }
        layer = self.gen.generate_combined_layer(coverage)
        assert layer.techniques[0].color == "#66b3ff"

    def test_high_coverage_color(self):
        coverage = {
            "T1059": DetectionCoverage(
                technique_id="T1059", detection_count=5, incident_count=3
            ),
        }
        layer = self.gen.generate_combined_layer(coverage)
        assert layer.techniques[0].color == "#8ec843"  # green for high

    def test_comment_contains_stats(self, sample_coverage):
        layer = self.gen.generate_combined_layer(sample_coverage)
        tech = next(t for t in layer.techniques if t.techniqueID == "T1059.001")
        assert "Coverage:" in tech.comment
        assert "Detections:" in tech.comment
        assert "Incidents:" in tech.comment


class TestGenerateAtlasLayer:
    def setup_method(self):
        self.gen = LayerGenerator()

    def test_filters_to_atlas_only(self):
        coverage = {
            "T1059": DetectionCoverage(technique_id="T1059", detection_count=1),
            "AML.T0044": DetectionCoverage(
                technique_id="AML.T0044", detection_count=2
            ),
        }
        layer = self.gen.generate_atlas_layer(coverage)
        assert layer.domain == "mitre-atlas"
        assert len(layer.techniques) == 1
        assert layer.techniques[0].techniqueID == "AML.T0044"

    def test_empty_when_no_atlas(self):
        coverage = {
            "T1059": DetectionCoverage(technique_id="T1059", detection_count=1),
        }
        layer = self.gen.generate_atlas_layer(coverage)
        assert len(layer.techniques) == 0


class TestMergeLayers:
    def setup_method(self):
        self.gen = LayerGenerator()

    def test_merge_empty(self):
        layer = self.gen.merge_layers([])
        assert layer.name == "Merged Layer"
        assert len(layer.techniques) == 0

    def test_merge_max(self):
        l1 = NavigatorLayer(name="L1")
        l1.add_technique("T1059", score=30)
        l2 = NavigatorLayer(name="L2")
        l2.add_technique("T1059", score=70)
        merged = self.gen.merge_layers([l1, l2], aggregate="max")
        assert merged.techniques[0].score == 70

    def test_merge_min(self):
        l1 = NavigatorLayer(name="L1")
        l1.add_technique("T1059", score=30)
        l2 = NavigatorLayer(name="L2")
        l2.add_technique("T1059", score=70)
        merged = self.gen.merge_layers([l1, l2], aggregate="min")
        assert merged.techniques[0].score == 30

    def test_merge_avg(self):
        l1 = NavigatorLayer(name="L1")
        l1.add_technique("T1059", score=30)
        l2 = NavigatorLayer(name="L2")
        l2.add_technique("T1059", score=70)
        merged = self.gen.merge_layers([l1, l2], aggregate="avg")
        assert merged.techniques[0].score == 50

    def test_merge_sum(self):
        l1 = NavigatorLayer(name="L1")
        l1.add_technique("T1059", score=30)
        l2 = NavigatorLayer(name="L2")
        l2.add_technique("T1059", score=70)
        merged = self.gen.merge_layers([l1, l2], aggregate="sum")
        assert merged.techniques[0].score == 100

    def test_merge_different_techniques(self):
        l1 = NavigatorLayer(name="L1")
        l1.add_technique("T1059", score=30)
        l2 = NavigatorLayer(name="L2")
        l2.add_technique("T1003", score=70)
        merged = self.gen.merge_layers([l1, l2])
        assert len(merged.techniques) == 2
