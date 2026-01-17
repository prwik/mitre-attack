"""
Detection rule and incident models for security data sources.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class TechniqueMapping(BaseModel):
    """Mapping of a detection/incident to ATT&CK technique."""
    technique_id: str = Field(..., description="ATT&CK technique ID (e.g., T1059)")
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = Field(default="manual", description="Source of the mapping")


class DetectionRule(BaseModel):
    """Detection rule from security tools (e.g., ReliaQuest, Splunk, etc.)."""
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    enabled: bool = True
    source: str = Field(..., description="Source system (e.g., reliaquest, splunk)")
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    raw_data: Optional[dict] = None

    @property
    def technique_ids(self) -> list[str]:
        """Get list of technique IDs this rule maps to."""
        return [t.technique_id for t in self.techniques]


class Incident(BaseModel):
    """Security incident from SIEM/XDR platforms."""
    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    status: str = "open"
    source: str = Field(..., description="Source system")
    techniques: list[TechniqueMapping] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    assignee: Optional[str] = None
    raw_data: Optional[dict] = None

    @property
    def technique_ids(self) -> list[str]:
        """Get list of technique IDs this incident maps to."""
        return [t.technique_id for t in self.techniques]


class DetectionCoverage(BaseModel):
    """Aggregated detection coverage statistics."""
    technique_id: str
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    detection_count: int = 0
    incident_count: int = 0
    total_score: float = 0.0
    sources: list[str] = Field(default_factory=list)

    @property
    def coverage_score(self) -> int:
        """Calculate coverage score (0-100)."""
        base_score = min(self.detection_count * 20, 60)
        incident_bonus = min(self.incident_count * 10, 40)
        return min(base_score + incident_bonus, 100)
