"""
ATT&CK technique mapping service.

Maps detection rules and incidents to ATT&CK/ATLAS techniques
and calculates coverage metrics.
"""
import logging
from typing import Optional
from collections import defaultdict

from ..models.detection import DetectionRule, Incident, TechniqueMapping, DetectionCoverage
from .mitre_id_resolver import MitreIdResolver, get_mitre_id_resolver

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

    def __init__(self, mitre_resolver: Optional[MitreIdResolver] = None):
        self._coverage_cache: dict[str, DetectionCoverage] = {}
        self._resolver = mitre_resolver

    @property
    def resolver(self) -> MitreIdResolver:
        """Get the MITRE ID resolver, initializing lazily if needed."""
        if self._resolver is None:
            self._resolver = get_mitre_id_resolver()
        return self._resolver

    def resolve_technique_mapping(self, mapping: TechniqueMapping) -> TechniqueMapping:
        """
        Resolve a TechniqueMapping to use actual MITRE IDs.

        ReliaQuest returns their own internal IDs for techniques. This method
        uses the technique name to look up the actual MITRE ID (e.g., T1059.001).

        Args:
            mapping: TechniqueMapping with potentially non-MITRE IDs

        Returns:
            Updated TechniqueMapping with resolved MITRE technique_id
        """
        # If already resolved or already a valid MITRE ID, skip
        if mapping.mitre_id_resolved:
            return mapping

        if self.resolver.is_valid_technique_id(mapping.technique_id):
            # Already a valid MITRE ID
            mapping.mitre_id_resolved = True
            return mapping

        # Try to resolve by technique name
        if mapping.technique_name:
            mitre_id = self.resolver.resolve_technique_id(mapping.technique_name)
            if mitre_id:
                logger.debug(
                    f"Resolved '{mapping.technique_name}' -> {mitre_id} "
                    f"(was: {mapping.technique_id})"
                )
                mapping.technique_id = mitre_id
                mapping.mitre_id_resolved = True
                return mapping

        # Could not resolve - log warning and keep original ID
        logger.warning(
            f"Could not resolve technique to MITRE ID: "
            f"name='{mapping.technique_name}', id='{mapping.technique_id}'"
        )
        return mapping

    def resolve_all_techniques(
        self,
        rules: list[DetectionRule],
        incidents: list[Incident],
    ) -> tuple[list[DetectionRule], list[Incident]]:
        """
        Resolve all technique mappings in rules and incidents to MITRE IDs.

        This should be called before calculate_coverage to ensure all
        technique_ids are actual MITRE IDs.
        """
        # Resolve rules
        for rule in rules:
            for i, mapping in enumerate(rule.techniques):
                rule.techniques[i] = self.resolve_technique_mapping(mapping)

        # Resolve incidents
        for incident in incidents:
            for i, mapping in enumerate(incident.techniques):
                incident.techniques[i] = self.resolve_technique_mapping(mapping)

        return rules, incidents

    def calculate_coverage(
        self,
        rules: list[DetectionRule],
        incidents: list[Incident],
        resolve_ids: bool = True,
    ) -> dict[str, DetectionCoverage]:
        """
        Calculate detection coverage per technique.

        Args:
            rules: Detection rules from security tools
            incidents: Security incidents
            resolve_ids: If True, resolve ReliaQuest IDs to MITRE IDs first

        Returns:
            Dict of technique_id -> DetectionCoverage
        """
        # Resolve technique IDs first if requested
        if resolve_ids:
            rules, incidents = self.resolve_all_techniques(rules, incidents)

        coverage: dict[str, DetectionCoverage] = defaultdict(
            lambda: DetectionCoverage(technique_id="")
        )

        # Process detection rules
        for rule in rules:
            for mapping in rule.techniques:
                tech_id = mapping.technique_id
                # Skip unresolved/invalid technique IDs
                if not tech_id or not self.resolver.is_valid_technique_id(tech_id):
                    logger.debug(f"Skipping invalid technique ID: {tech_id}")
                    continue

                if tech_id not in coverage:
                    # Normalize tactic name for ATT&CK Navigator
                    tactic = self._normalize_tactic(mapping.tactic)
                    coverage[tech_id] = DetectionCoverage(
                        technique_id=tech_id,
                        technique_name=mapping.technique_name,
                        tactic=tactic,
                    )
                cov = coverage[tech_id]
                cov.detection_count += 1
                if mapping.technique_name and not cov.technique_name:
                    cov.technique_name = mapping.technique_name
                if mapping.tactic and not cov.tactic:
                    cov.tactic = self._normalize_tactic(mapping.tactic)
                if rule.source not in cov.sources:
                    cov.sources.append(rule.source)

        # Process incidents
        for incident in incidents:
            for mapping in incident.techniques:
                tech_id = mapping.technique_id
                # Skip unresolved/invalid technique IDs
                if not tech_id or not self.resolver.is_valid_technique_id(tech_id):
                    logger.debug(f"Skipping invalid technique ID: {tech_id}")
                    continue

                if tech_id not in coverage:
                    tactic = self._normalize_tactic(mapping.tactic)
                    coverage[tech_id] = DetectionCoverage(
                        technique_id=tech_id,
                        technique_name=mapping.technique_name,
                        tactic=tactic,
                    )
                cov = coverage[tech_id]
                cov.incident_count += 1
                if mapping.technique_name and not cov.technique_name:
                    cov.technique_name = mapping.technique_name
                if mapping.tactic and not cov.tactic:
                    cov.tactic = self._normalize_tactic(mapping.tactic)
                if incident.source not in cov.sources:
                    cov.sources.append(incident.source)

        # Calculate total scores
        for cov in coverage.values():
            cov.total_score = cov.coverage_score

        self._coverage_cache = dict(coverage)
        return dict(coverage)

    def _normalize_tactic(self, tactic: Optional[str]) -> Optional[str]:
        """
        Normalize tactic name to ATT&CK Navigator format.

        E.g., "Initial Access" -> "initial-access"
        """
        if not tactic:
            return None
        return tactic.lower().replace(" ", "-").replace("_", "-")

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
