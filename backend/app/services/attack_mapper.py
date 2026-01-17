"""
ATT&CK technique mapping service.

Maps detection rules and incidents to ATT&CK/ATLAS techniques
and calculates coverage metrics.
"""
import logging
from typing import Optional
from collections import defaultdict

from ..models.detection import DetectionRule, Incident, TechniqueMapping, DetectionCoverage

logger = logging.getLogger(__name__)


# Common ATT&CK technique ID patterns for validation
ATTACK_TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
ATLAS_TECHNIQUE_PATTERN = r"^AML\.T\d{4}(\.\d{3})?$"


class AttackMapper:
    """
    Service for mapping security data to ATT&CK/ATLAS techniques.

    Provides:
    - Technique extraction from detection rules and incidents
    - Coverage calculation and aggregation
    - Technique validation
    """

    # ATT&CK Enterprise tactic order (for consistent display)
    ATTACK_TACTICS = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]

    # ATLAS tactic order
    ATLAS_TACTICS = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "ml-model-access",
        "execution",
        "persistence",
        "defense-evasion",
        "discovery",
        "collection",
        "ml-attack-staging",
        "exfiltration",
        "impact",
    ]

    def __init__(self):
        self._coverage_cache: dict[str, DetectionCoverage] = {}

    def calculate_coverage(
        self,
        rules: list[DetectionRule],
        incidents: list[Incident],
    ) -> dict[str, DetectionCoverage]:
        """
        Calculate detection coverage per technique.

        Returns a dict of technique_id -> DetectionCoverage
        """
        coverage: dict[str, DetectionCoverage] = defaultdict(
            lambda: DetectionCoverage(technique_id="")
        )

        # Process detection rules
        for rule in rules:
            for mapping in rule.techniques:
                tech_id = mapping.technique_id
                if tech_id not in coverage:
                    coverage[tech_id] = DetectionCoverage(
                        technique_id=tech_id,
                        technique_name=mapping.technique_name,
                        tactic=mapping.tactic,
                    )
                cov = coverage[tech_id]
                cov.detection_count += 1
                if mapping.technique_name and not cov.technique_name:
                    cov.technique_name = mapping.technique_name
                if mapping.tactic and not cov.tactic:
                    cov.tactic = mapping.tactic
                if rule.source not in cov.sources:
                    cov.sources.append(rule.source)

        # Process incidents
        for incident in incidents:
            for mapping in incident.techniques:
                tech_id = mapping.technique_id
                if tech_id not in coverage:
                    coverage[tech_id] = DetectionCoverage(
                        technique_id=tech_id,
                        technique_name=mapping.technique_name,
                        tactic=mapping.tactic,
                    )
                cov = coverage[tech_id]
                cov.incident_count += 1
                if mapping.technique_name and not cov.technique_name:
                    cov.technique_name = mapping.technique_name
                if mapping.tactic and not cov.tactic:
                    cov.tactic = mapping.tactic
                if incident.source not in cov.sources:
                    cov.sources.append(incident.source)

        # Calculate total scores
        for cov in coverage.values():
            cov.total_score = cov.coverage_score

        self._coverage_cache = dict(coverage)
        return dict(coverage)

    def get_techniques_by_tactic(
        self,
        coverage: dict[str, DetectionCoverage],
        tactics: Optional[list[str]] = None,
    ) -> dict[str, list[DetectionCoverage]]:
        """
        Group coverage data by tactic.

        Args:
            coverage: Coverage data from calculate_coverage()
            tactics: Tactic filter (defaults to all ATTACK_TACTICS)

        Returns:
            Dict of tactic -> list of coverage data
        """
        if tactics is None:
            tactics = self.ATTACK_TACTICS

        by_tactic: dict[str, list[DetectionCoverage]] = {t: [] for t in tactics}
        by_tactic["unknown"] = []

        for cov in coverage.values():
            tactic = cov.tactic or "unknown"
            # Normalize tactic name
            tactic = tactic.lower().replace(" ", "-").replace("_", "-")
            if tactic in by_tactic:
                by_tactic[tactic].append(cov)
            else:
                by_tactic["unknown"].append(cov)

        return by_tactic

    def get_coverage_summary(
        self,
        coverage: dict[str, DetectionCoverage],
    ) -> dict:
        """
        Generate coverage summary statistics.
        """
        total_techniques = len(coverage)
        if total_techniques == 0:
            return {
                "total_techniques": 0,
                "avg_score": 0,
                "max_score": 0,
                "min_score": 0,
                "detection_rules": 0,
                "incidents": 0,
                "coverage_by_severity": {},
            }

        scores = [c.coverage_score for c in coverage.values()]
        total_detections = sum(c.detection_count for c in coverage.values())
        total_incidents = sum(c.incident_count for c in coverage.values())

        # Group by coverage level
        high_coverage = sum(1 for s in scores if s >= 70)
        medium_coverage = sum(1 for s in scores if 30 <= s < 70)
        low_coverage = sum(1 for s in scores if s < 30)

        return {
            "total_techniques": total_techniques,
            "avg_score": sum(scores) / total_techniques,
            "max_score": max(scores),
            "min_score": min(scores),
            "detection_rules": total_detections,
            "incidents": total_incidents,
            "coverage_by_severity": {
                "high": high_coverage,
                "medium": medium_coverage,
                "low": low_coverage,
            },
        }

    def extract_technique_ids(
        self,
        rules: list[DetectionRule],
        incidents: list[Incident],
    ) -> set[str]:
        """Extract unique technique IDs from rules and incidents."""
        technique_ids = set()
        for rule in rules:
            technique_ids.update(rule.technique_ids)
        for incident in incidents:
            technique_ids.update(incident.technique_ids)
        return technique_ids

    @staticmethod
    def is_atlas_technique(technique_id: str) -> bool:
        """Check if a technique ID is from ATLAS (AI/ML focused)."""
        return technique_id.startswith("AML.")

    @staticmethod
    def is_attack_technique(technique_id: str) -> bool:
        """Check if a technique ID is from ATT&CK."""
        return technique_id.startswith("T") and not technique_id.startswith("TA")

    def separate_by_framework(
        self,
        coverage: dict[str, DetectionCoverage],
    ) -> tuple[dict[str, DetectionCoverage], dict[str, DetectionCoverage]]:
        """
        Separate coverage data into ATT&CK and ATLAS techniques.

        Returns:
            Tuple of (attack_coverage, atlas_coverage)
        """
        attack_coverage = {}
        atlas_coverage = {}

        for tech_id, cov in coverage.items():
            if self.is_atlas_technique(tech_id):
                atlas_coverage[tech_id] = cov
            else:
                attack_coverage[tech_id] = cov

        return attack_coverage, atlas_coverage
