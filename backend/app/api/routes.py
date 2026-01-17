"""
API routes for the ATT&CK Navigator backend.
"""
import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import JSONResponse

from ..models.layer import NavigatorLayer
from ..models.detection import DetectionRule, Incident, DetectionCoverage
from ..services.reliaquest import ReliaQuestClient, MockReliaQuestClient
from ..services.attack_mapper import AttackMapper
from ..services.layer_generator import LayerGenerator
from ..utils.config import get_settings, Settings

logger = logging.getLogger(__name__)
router = APIRouter()


def get_reliaquest_client(settings: Settings = Depends(get_settings)) -> ReliaQuestClient:
    """Dependency to get ReliaQuest client."""
    if settings.use_mock_data:
        return MockReliaQuestClient()
    return ReliaQuestClient(api_key=settings.reliaquest_api_key)


def get_attack_mapper() -> AttackMapper:
    """Dependency to get ATT&CK mapper."""
    return AttackMapper()


def get_layer_generator() -> LayerGenerator:
    """Dependency to get layer generator."""
    return LayerGenerator()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@router.get("/detection-rules", response_model=list[DetectionRule])
async def get_detection_rules(
    limit: int = Query(100, ge=1, le=1000),
    enabled_only: bool = Query(True),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
):
    """
    Fetch detection rules from ReliaQuest.

    Returns detection rules with their ATT&CK technique mappings.
    """
    try:
        rules = await client.get_detection_rules(limit=limit, enabled_only=enabled_only)
        return rules
    except Exception as e:
        logger.error(f"Failed to fetch detection rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/incidents", response_model=list[Incident])
async def get_incidents(
    limit: int = Query(100, ge=1, le=1000),
    status: Optional[str] = Query(None),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
):
    """
    Fetch incidents from ReliaQuest.

    Returns incidents with their ATT&CK technique mappings.
    """
    try:
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, status=status, since=since)
        return incidents
    except Exception as e:
        logger.error(f"Failed to fetch incidents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/coverage", response_model=dict[str, DetectionCoverage])
async def get_coverage(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
):
    """
    Calculate detection coverage from rules and incidents.

    Returns coverage data per ATT&CK technique.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        return coverage
    except Exception as e:
        logger.error(f"Failed to calculate coverage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/coverage/summary")
async def get_coverage_summary(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
):
    """
    Get a summary of detection coverage.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        summary = mapper.get_coverage_summary(coverage)
        return summary
    except Exception as e:
        logger.error(f"Failed to get coverage summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/layers/coverage")
async def get_coverage_layer(
    name: str = Query("Detection Coverage"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
):
    """
    Generate an ATT&CK Navigator layer showing detection coverage.

    Returns a JSON layer file compatible with the ATT&CK Navigator.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        layer = generator.generate_coverage_layer(
            coverage,
            name=name,
            domain=domain,
        )

        return JSONResponse(
            content=layer.to_json(),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{name.replace(" ", "_")}.json"'
            }
        )
    except Exception as e:
        logger.error(f"Failed to generate coverage layer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/layers/incidents")
async def get_incident_layer(
    name: str = Query("Incident Heatmap"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
):
    """
    Generate an ATT&CK Navigator layer showing incident frequency.

    Returns a heatmap-style layer where color intensity indicates incident count.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        layer = generator.generate_incident_layer(
            coverage,
            name=name,
            domain=domain,
        )

        return JSONResponse(
            content=layer.to_json(),
            media_type="application/json",
        )
    except Exception as e:
        logger.error(f"Failed to generate incident layer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/layers/combined")
async def get_combined_layer(
    name: str = Query("Security Posture"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
):
    """
    Generate a combined ATT&CK Navigator layer.

    Shows both detection coverage and incident data in a single view.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        layer = generator.generate_combined_layer(
            coverage,
            name=name,
            domain=domain,
        )

        return JSONResponse(
            content=layer.to_json(),
            media_type="application/json",
        )
    except Exception as e:
        logger.error(f"Failed to generate combined layer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/layers/atlas")
async def get_atlas_layer(
    name: str = Query("AI/ML Threat Coverage"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
):
    """
    Generate an ATLAS Navigator layer for AI/ML techniques.

    Filters to only ATLAS (AML.T####) techniques.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since)

        coverage = mapper.calculate_coverage(rules, incidents)
        layer = generator.generate_atlas_layer(coverage, name=name)

        return JSONResponse(
            content=layer.to_json(),
            media_type="application/json",
        )
    except Exception as e:
        logger.error(f"Failed to generate ATLAS layer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/layers/custom")
async def create_custom_layer(
    layer: NavigatorLayer,
):
    """
    Create a custom layer with user-provided data.

    Accepts a NavigatorLayer object and returns the formatted JSON.
    """
    return JSONResponse(
        content=layer.to_json(),
        media_type="application/json",
    )
