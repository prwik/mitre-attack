"""
ATT&CK Navigator Layer format models (v4.5 spec).
See: https://github.com/mitre-attack/attack-navigator/blob/master/layers/
"""
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class Metadata(BaseModel):
    """Custom metadata key-value pair."""
    name: str
    value: str
    divider: bool = False


class Link(BaseModel):
    """Hyperlink reference."""
    label: str
    url: str
    divider: bool = False


class Versions(BaseModel):
    """Version information for the layer."""
    attack: str = "16"
    navigator: str = "5.1.0"
    layer: str = "4.5"


class Filter(BaseModel):
    """Platform filter for the matrix."""
    platforms: list[str] = Field(default_factory=lambda: [
        "Linux", "macOS", "Windows", "Network", "PRE",
        "Containers", "Office Suite", "SaaS", "IaaS",
        "Google Workspace", "Azure AD", "Microsoft 365"
    ])


class Layout(BaseModel):
    """Matrix layout configuration."""
    layout: str = "side"
    showID: bool = True
    showName: bool = True
    showAggregateScores: bool = False
    countUnscored: bool = False
    aggregateFunction: str = "average"
    expandedSubtechniques: str = "none"


class Gradient(BaseModel):
    """Color gradient for technique scores."""
    colors: list[str] = Field(default_factory=lambda: ["#ff6666ff", "#ffe766ff", "#8ec843ff"])
    minValue: int = 0
    maxValue: int = 100


class LegendItem(BaseModel):
    """Legend entry for the layer."""
    label: str
    color: str


class Technique(BaseModel):
    """Individual technique annotation."""
    techniqueID: str
    tactic: Optional[str] = None
    comment: str = ""
    enabled: bool = True
    score: Optional[int] = None
    color: str = ""
    metadata: list[Metadata] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    showSubtechniques: bool = False


class NavigatorLayer(BaseModel):
    """
    ATT&CK Navigator Layer (v4.5 format).

    This is the JSON format used by the MITRE ATT&CK Navigator
    for importing/exporting matrix annotations.
    """
    versions: Versions = Field(default_factory=Versions)
    name: str
    description: str = ""
    domain: str = "enterprise-attack"
    customDataURL: Optional[str] = None
    filters: Filter = Field(default_factory=Filter)
    sorting: int = 0
    layout: Layout = Field(default_factory=Layout)
    hideDisabled: bool = False
    techniques: list[Technique] = Field(default_factory=list)

    @field_validator("techniques")
    @classmethod
    def validate_techniques_count(cls, v):
        if len(v) > 5000:
            raise ValueError(f"Too many techniques: {len(v)} (max 5000)")
        return v

    gradient: Gradient = Field(default_factory=Gradient)
    legendItems: list[LegendItem] = Field(default_factory=list)
    showTacticRowBackground: bool = False
    tacticRowBackground: str = "#dddddd"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = True
    selectVisibleTechniques: bool = False
    metadata: list[Metadata] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)

    def add_technique(
        self,
        technique_id: str,
        score: Optional[int] = None,
        color: str = "",
        comment: str = "",
        tactic: Optional[str] = None,
        metadata: Optional[list[Metadata]] = None,
        links: Optional[list[Link]] = None,
    ) -> None:
        """Add or update a technique annotation."""
        existing = next(
            (t for t in self.techniques
             if t.techniqueID == technique_id and t.tactic == tactic),
            None
        )
        if existing:
            if score is not None:
                existing.score = score
            if color:
                existing.color = color
            if comment:
                existing.comment = comment
            if metadata:
                existing.metadata.extend(metadata)
            if links:
                existing.links.extend(links)
        else:
            self.techniques.append(Technique(
                techniqueID=technique_id,
                tactic=tactic,
                score=score,
                color=color,
                comment=comment,
                metadata=metadata or [],
                links=links or [],
            ))

    def to_json(self) -> dict:
        """Export layer as JSON dict."""
        return self.model_dump(exclude_none=True)
