"""
ATT&CK Navigator layer generator service.

Generates Navigator-compatible JSON layers from detection coverage data.
"""
import logging
from typing import Optional

from ..models.layer import (
    NavigatorLayer,
    Technique,
    Gradient,
    LegendItem,
    Metadata,
    Link,
)
from ..models.detection import DetectionCoverage

logger = logging.getLogger(__name__)


# Color schemes for different visualization types
COLOR_SCHEMES = {
    "coverage": {
        "high": "#8ec843",      # Green - good coverage
        "medium": "#ffe766",    # Yellow - partial coverage
        "low": "#ff6666",       # Red - low coverage
        "none": "#ffffff",      # White - no coverage
    },
    "incidents": {
        "critical": "#ff0000",  # Red
        "high": "#ff6600",      # Orange
        "medium": "#ffcc00",    # Yellow
        "low": "#00cc00",       # Green
    },
    "heatmap": {
        "gradient": ["#ffffff", "#fff7bc", "#fee391", "#fec44f", "#fe9929", "#ec7014", "#cc4c02", "#8c2d04"],
    },
}


class LayerGenerator:
    """
    Generates ATT&CK Navigator layers from security data.

    Supports multiple layer types:
    - Detection coverage layers
    - Incident frequency heatmaps
    - Combined security posture views
    """

    def __init__(self):
        self.color_schemes = COLOR_SCHEMES

    def generate_coverage_layer(
        self,
        coverage: dict[str, DetectionCoverage],
        name: str = "Detection Coverage",
        description: str = "Detection rule coverage mapped to ATT&CK",
        domain: str = "enterprise-attack",
    ) -> NavigatorLayer:
        """
        Generate a layer showing detection coverage.

        Colors techniques based on coverage score:
        - Green (70-100): High coverage
        - Yellow (30-69): Medium coverage
        - Red (0-29): Low coverage
        """
        layer = NavigatorLayer(
            name=name,
            description=description,
            domain=domain,
        )

        # Set up gradient for score-based coloring
        layer.gradient = Gradient(
            colors=["#ff6666", "#ffe766", "#8ec843"],
            minValue=0,
            maxValue=100,
        )

        # Add legend
        layer.legendItems = [
            LegendItem(label="High Coverage (70-100)", color="#8ec843"),
            LegendItem(label="Medium Coverage (30-69)", color="#ffe766"),
            LegendItem(label="Low Coverage (0-29)", color="#ff6666"),
        ]

        # Add techniques (filter to ATT&CK only for enterprise-attack domain)
        for tech_id, cov in coverage.items():
            # Skip ATLAS techniques for enterprise-attack domain
            if domain == "enterprise-attack" and tech_id.startswith("AML."):
                continue
            # Skip ATT&CK techniques for ATLAS domain
            if domain == "mitre-atlas" and not tech_id.startswith("AML."):
                continue

            metadata = [
                Metadata(name="Detection Rules", value=str(cov.detection_count)),
                Metadata(name="Incidents", value=str(cov.incident_count)),
                Metadata(name="Sources", value=", ".join(cov.sources)),
            ]

            comment = f"Detection rules: {cov.detection_count}, Incidents: {cov.incident_count}"
            if cov.technique_name:
                comment = f"{cov.technique_name}\n{comment}"

            layer.add_technique(
                technique_id=tech_id,
                score=cov.coverage_score,
                comment=comment,
                tactic=cov.tactic,
                metadata=metadata,
            )

        return layer

    def generate_incident_layer(
        self,
        coverage: dict[str, DetectionCoverage],
        name: str = "Incident Heatmap",
        description: str = "Incident frequency mapped to ATT&CK",
        domain: str = "enterprise-attack",
    ) -> NavigatorLayer:
        """
        Generate a heatmap layer showing incident frequency.

        Higher incident counts result in more intense colors.
        """
        layer = NavigatorLayer(
            name=name,
            description=description,
            domain=domain,
        )

        # Calculate max incidents for normalization
        max_incidents = max(
            (cov.incident_count for cov in coverage.values()),
            default=1
        )
        if max_incidents == 0:
            max_incidents = 1

        # Set up gradient
        layer.gradient = Gradient(
            colors=["#ffffff", "#ffcc00", "#ff6600", "#ff0000"],
            minValue=0,
            maxValue=max_incidents,
        )

        # Add legend
        layer.legendItems = [
            LegendItem(label="No Incidents", color="#ffffff"),
            LegendItem(label="Low Frequency", color="#ffcc00"),
            LegendItem(label="Medium Frequency", color="#ff6600"),
            LegendItem(label="High Frequency", color="#ff0000"),
        ]

        # Add techniques with incidents (filter by domain)
        for tech_id, cov in coverage.items():
            # Skip ATLAS techniques for enterprise-attack domain
            if domain == "enterprise-attack" and tech_id.startswith("AML."):
                continue
            # Skip ATT&CK techniques for ATLAS domain
            if domain == "mitre-atlas" and not tech_id.startswith("AML."):
                continue

            if cov.incident_count > 0:
                metadata = [
                    Metadata(name="Incident Count", value=str(cov.incident_count)),
                ]

                layer.add_technique(
                    technique_id=tech_id,
                    score=cov.incident_count,
                    comment=f"Incidents: {cov.incident_count}",
                    tactic=cov.tactic,
                    metadata=metadata,
                )

        return layer

    def generate_combined_layer(
        self,
        coverage: dict[str, DetectionCoverage],
        name: str = "Security Posture",
        description: str = "Combined detection coverage and incident data",
        domain: str = "enterprise-attack",
    ) -> NavigatorLayer:
        """
        Generate a combined layer showing both coverage and incidents.

        Uses color for coverage level and score for incident count.
        """
        layer = NavigatorLayer(
            name=name,
            description=description,
            domain=domain,
        )

        # Add legend
        layer.legendItems = [
            LegendItem(label="High Coverage + Incidents", color="#8ec843"),
            LegendItem(label="Medium Coverage + Incidents", color="#ffe766"),
            LegendItem(label="Low Coverage + Incidents", color="#ff6666"),
            LegendItem(label="Detection Only (No Incidents)", color="#66b3ff"),
        ]

        colors = self.color_schemes["coverage"]

        for tech_id, cov in coverage.items():
            # Skip ATLAS techniques for enterprise-attack domain
            if domain == "enterprise-attack" and tech_id.startswith("AML."):
                continue
            # Skip ATT&CK techniques for ATLAS domain
            if domain == "mitre-atlas" and not tech_id.startswith("AML."):
                continue
            # Determine color based on coverage
            score = cov.coverage_score
            if score >= 70:
                color = colors["high"]
            elif score >= 30:
                color = colors["medium"]
            else:
                color = colors["low"]

            # Use different color if no incidents
            if cov.incident_count == 0 and cov.detection_count > 0:
                color = "#66b3ff"  # Blue for detection-only

            metadata = [
                Metadata(name="Coverage Score", value=str(score)),
                Metadata(name="Detection Rules", value=str(cov.detection_count)),
                Metadata(name="Incidents", value=str(cov.incident_count)),
                Metadata(name="Sources", value=", ".join(cov.sources)),
            ]

            comment_parts = []
            if cov.technique_name:
                comment_parts.append(cov.technique_name)
            comment_parts.append(f"Coverage: {score}%")
            comment_parts.append(f"Detections: {cov.detection_count}")
            comment_parts.append(f"Incidents: {cov.incident_count}")

            layer.add_technique(
                technique_id=tech_id,
                score=score,
                color=color,
                comment="\n".join(comment_parts),
                tactic=cov.tactic,
                metadata=metadata,
            )

        return layer

    def generate_atlas_layer(
        self,
        coverage: dict[str, DetectionCoverage],
        name: str = "AI/ML Threat Coverage",
        description: str = "ATLAS technique coverage for AI/ML systems",
    ) -> NavigatorLayer:
        """
        Generate an ATLAS layer for AI/ML technique coverage.

        Uses the ATLAS domain and technique IDs (AML.T####).
        """
        # Filter to only ATLAS techniques
        atlas_coverage = {
            k: v for k, v in coverage.items()
            if k.startswith("AML.")
        }

        layer = NavigatorLayer(
            name=name,
            description=description,
            domain="mitre-atlas",  # ATLAS domain
        )

        layer.gradient = Gradient(
            colors=["#ff6666", "#ffe766", "#8ec843"],
            minValue=0,
            maxValue=100,
        )

        layer.legendItems = [
            LegendItem(label="High Coverage", color="#8ec843"),
            LegendItem(label="Medium Coverage", color="#ffe766"),
            LegendItem(label="Low Coverage", color="#ff6666"),
        ]

        for tech_id, cov in atlas_coverage.items():
            layer.add_technique(
                technique_id=tech_id,
                score=cov.coverage_score,
                comment=f"AI/ML Detections: {cov.detection_count}",
                tactic=cov.tactic,
            )

        return layer

    def merge_layers(
        self,
        layers: list[NavigatorLayer],
        name: str = "Merged Layer",
        description: str = "Combined view from multiple sources",
        aggregate: str = "max",
    ) -> NavigatorLayer:
        """
        Merge multiple layers into one.

        Args:
            layers: List of layers to merge
            name: Name for merged layer
            description: Description for merged layer
            aggregate: How to combine scores ("max", "min", "avg", "sum")
        """
        if not layers:
            return NavigatorLayer(name=name, description=description)

        merged = NavigatorLayer(
            name=name,
            description=description,
            domain=layers[0].domain,
        )

        # Collect all techniques
        technique_data: dict[str, list[Technique]] = {}
        for layer in layers:
            for tech in layer.techniques:
                key = f"{tech.techniqueID}:{tech.tactic or 'all'}"
                if key not in technique_data:
                    technique_data[key] = []
                technique_data[key].append(tech)

        # Aggregate techniques
        for key, techs in technique_data.items():
            tech_id, tactic = key.split(":", 1)
            tactic = tactic if tactic != "all" else None

            scores = [t.score for t in techs if t.score is not None]
            if scores:
                if aggregate == "max":
                    score = max(scores)
                elif aggregate == "min":
                    score = min(scores)
                elif aggregate == "avg":
                    score = sum(scores) // len(scores)
                else:  # sum
                    score = sum(scores)
            else:
                score = None

            # Merge comments
            comments = [t.comment for t in techs if t.comment]
            merged_comment = "\n---\n".join(comments) if comments else ""

            # Merge metadata
            merged_metadata = []
            for tech in techs:
                merged_metadata.extend(tech.metadata)

            merged.add_technique(
                technique_id=tech_id,
                score=score,
                comment=merged_comment,
                tactic=tactic,
                metadata=merged_metadata,
            )

        return merged
