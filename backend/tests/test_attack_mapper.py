"""Tests for AttackMapper service."""
import pytest
from unittest.mock import MagicMock

from app.services.attack_mapper import AttackMapper
from app.models.detection import (
    DetectionRule,
    Incident,
    TechniqueMapping,
    DetectionCoverage,
)


class TestNormalizeTactic:
    def setup_method(self):
        # Use a mock resolver to avoid downloading STIX data
        self.mapper = AttackMapper(mitre_resolver=MagicMock())

    def test_spaces_to_hyphens(self):
        assert self.mapper._normalize_tactic("Initial Access") == "initial-access"

    def test_underscores_to_hyphens(self):
        assert self.mapper._normalize_tactic("command_and_control") == "command-and-control"

    def test_already_normalized(self):
        assert self.mapper._normalize_tactic("execution") == "execution"

    def test_none(self):
        assert self.mapper._normalize_tactic(None) is None


class TestCalculateCoverage:
    def setup_method(self):
        mock_resolver = MagicMock()
        mock_resolver.is_valid_technique_id.return_value = True
        self.mapper = AttackMapper(mitre_resolver=mock_resolver)

    def _make_rule(self, tech_id, tech_name="Test", tactic="Execution"):
        return DetectionRule(
            id="r1",
            name="Rule",
            source="test",
            techniques=[
                TechniqueMapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    mitre_id_resolved=True,
                )
            ],
        )

    def _make_incident(self, tech_id, tech_name="Test", tactic="Execution"):
        return Incident(
            id="i1",
            title="Inc",
            source="test",
            techniques=[
                TechniqueMapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    mitre_id_resolved=True,
                )
            ],
        )

    def test_single_rule(self):
        rules = [self._make_rule("T1059")]
        coverage = self.mapper.calculate_coverage(rules, [], resolve_ids=False)
        assert "T1059" in coverage
        assert coverage["T1059"].detection_count == 1
        assert coverage["T1059"].incident_count == 0

    def test_single_incident(self):
        incidents = [self._make_incident("T1059")]
        coverage = self.mapper.calculate_coverage([], incidents, resolve_ids=False)
        assert "T1059" in coverage
        assert coverage["T1059"].detection_count == 0
        assert coverage["T1059"].incident_count == 1

    def test_combined_rule_and_incident(self):
        rules = [self._make_rule("T1059")]
        incidents = [self._make_incident("T1059")]
        coverage = self.mapper.calculate_coverage(rules, incidents, resolve_ids=False)
        assert coverage["T1059"].detection_count == 1
        assert coverage["T1059"].incident_count == 1

    def test_multiple_techniques(self):
        rules = [
            self._make_rule("T1059"),
            self._make_rule("T1003"),
        ]
        coverage = self.mapper.calculate_coverage(rules, [], resolve_ids=False)
        assert len(coverage) == 2
        assert "T1059" in coverage
        assert "T1003" in coverage

    def test_empty_inputs(self):
        coverage = self.mapper.calculate_coverage([], [], resolve_ids=False)
        assert len(coverage) == 0

    def test_skips_invalid_technique_ids(self):
        self.mapper.resolver.is_valid_technique_id.return_value = False
        rules = [self._make_rule("invalid-id")]
        coverage = self.mapper.calculate_coverage(rules, [], resolve_ids=False)
        assert len(coverage) == 0

    def test_total_score_set(self):
        rules = [self._make_rule("T1059")]
        coverage = self.mapper.calculate_coverage(rules, [], resolve_ids=False)
        cov = coverage["T1059"]
        assert cov.total_score == cov.coverage_score


class TestGetCoverageSummary:
    def setup_method(self):
        self.mapper = AttackMapper(mitre_resolver=MagicMock())

    def test_empty_coverage(self):
        summary = self.mapper.get_coverage_summary({})
        assert summary["total_techniques"] == 0
        assert summary["avg_score"] == 0

    def test_summary_stats(self, sample_coverage):
        summary = self.mapper.get_coverage_summary(sample_coverage)
        assert summary["total_techniques"] == 2
        assert summary["detection_rules"] == 4  # 3 + 1
        assert summary["incidents"] == 2  # 2 + 0
        assert summary["max_score"] >= summary["min_score"]

    def test_coverage_by_severity(self, sample_coverage):
        summary = self.mapper.get_coverage_summary(sample_coverage)
        severity = summary["coverage_by_severity"]
        total = severity["high"] + severity["medium"] + severity["low"]
        assert total == 2  # 2 techniques


class TestSeparateByFramework:
    def setup_method(self):
        self.mapper = AttackMapper(mitre_resolver=MagicMock())

    def test_separates_attack_and_atlas(self):
        coverage = {
            "T1059": DetectionCoverage(technique_id="T1059"),
            "AML.T0044": DetectionCoverage(technique_id="AML.T0044"),
        }
        attack, atlas = self.mapper.separate_by_framework(coverage)
        assert "T1059" in attack
        assert "AML.T0044" not in attack
        assert "AML.T0044" in atlas
        assert "T1059" not in atlas

    def test_empty_coverage(self):
        attack, atlas = self.mapper.separate_by_framework({})
        assert len(attack) == 0
        assert len(atlas) == 0


class TestStaticMethods:
    def test_is_atlas_technique(self):
        assert AttackMapper.is_atlas_technique("AML.T0044") is True
        assert AttackMapper.is_atlas_technique("T1059") is False

    def test_is_attack_technique(self):
        assert AttackMapper.is_attack_technique("T1059") is True
        assert AttackMapper.is_attack_technique("T1059.001") is True
        assert AttackMapper.is_attack_technique("AML.T0044") is False
        assert AttackMapper.is_attack_technique("TA0002") is False
