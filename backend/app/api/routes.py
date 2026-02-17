"""
API routes for the ATT&CK Navigator backend.
"""
import logging
from typing import Optional
from datetime import datetime, timedelta, timezone

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


def _safe_error_detail(e: Exception, settings: Settings | None = None) -> str:
    """Return error detail safe for API responses. Only expose internals in debug mode."""
    if settings and settings.debug:
        return str(e)
    return "An internal error occurred. Check server logs for details."

# Shared client instance so TTLCache persists across requests
_reliaquest_client: ReliaQuestClient | None = None


def get_reliaquest_client(settings: Settings = Depends(get_settings)) -> ReliaQuestClient:
    """Dependency to get ReliaQuest client (singleton per process)."""
    global _reliaquest_client
    if _reliaquest_client is None:
        if settings.use_mock_data:
            _reliaquest_client = MockReliaQuestClient()
        else:
            _reliaquest_client = ReliaQuestClient(
                api_key=settings.reliaquest_api_key,
                cache_ttl=settings.cache_ttl,
            )
    return _reliaquest_client


def get_attack_mapper() -> AttackMapper:
    """Dependency to get ATT&CK mapper."""
    return AttackMapper()


def get_layer_generator() -> LayerGenerator:
    """Dependency to get layer generator."""
    return LayerGenerator()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/detection-rules", response_model=list[DetectionRule])
async def get_detection_rules(
    limit: int = Query(100, ge=1, le=1000),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    settings: Settings = Depends(get_settings),
):
    """
    Fetch detection rules from ReliaQuest.

    Returns detection rules with their ATT&CK technique mappings.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        return rules
    except Exception as e:
        logger.error(f"Failed to fetch detection rules: {e}")
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/incidents", response_model=list[Incident])
async def get_incidents(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    settings: Settings = Depends(get_settings),
):
    """
    Fetch incidents from ReliaQuest.

    Returns incidents with their ATT&CK technique mappings.
    Techniques are populated from linked detection rules.
    """
    try:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        # Fetch rules first to build cache for technique lookup
        rules = await client.get_detection_rules(limit=1000)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)
        return incidents
    except Exception as e:
        logger.error(f"Failed to fetch incidents: {e}")
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/coverage", response_model=dict[str, DetectionCoverage])
async def get_coverage(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    settings: Settings = Depends(get_settings),
):
    """
    Calculate detection coverage from rules and incidents.

    Returns coverage data per ATT&CK technique.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

        coverage = mapper.calculate_coverage(rules, incidents)
        return coverage
    except Exception as e:
        logger.error(f"Failed to calculate coverage: {e}")
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/coverage/summary")
async def get_coverage_summary(
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    settings: Settings = Depends(get_settings),
):
    """
    Get a summary of detection coverage.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

        coverage = mapper.calculate_coverage(rules, incidents)
        summary = mapper.get_coverage_summary(coverage)
        return summary
    except Exception as e:
        logger.error(f"Failed to get coverage summary: {e}")
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/layers/coverage")
async def get_coverage_layer(
    name: str = Query("Detection Coverage"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
    settings: Settings = Depends(get_settings),
):
    """
    Generate an ATT&CK Navigator layer showing detection coverage.

    Returns a JSON layer file compatible with the ATT&CK Navigator.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

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
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/layers/incidents")
async def get_incident_layer(
    name: str = Query("Incident Heatmap"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
    settings: Settings = Depends(get_settings),
):
    """
    Generate an ATT&CK Navigator layer showing incident frequency.

    Returns a heatmap-style layer where color intensity indicates incident count.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

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
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/layers/combined")
async def get_combined_layer(
    name: str = Query("Security Posture"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
    settings: Settings = Depends(get_settings),
):
    """
    Generate a combined ATT&CK Navigator layer.

    Shows both detection coverage and incident data in a single view.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

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
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


@router.get("/layers/atlas")
async def get_atlas_layer(
    name: str = Query("AI/ML Threat Coverage"),
    limit: int = Query(100, ge=1, le=1000),
    days: int = Query(30, ge=1, le=365),
    client: ReliaQuestClient = Depends(get_reliaquest_client),
    mapper: AttackMapper = Depends(get_attack_mapper),
    generator: LayerGenerator = Depends(get_layer_generator),
    settings: Settings = Depends(get_settings),
):
    """
    Generate an ATLAS Navigator layer for AI/ML techniques.

    Filters to only ATLAS (AML.T####) techniques.
    """
    try:
        rules = await client.get_detection_rules(limit=limit)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}
        since = datetime.now(timezone.utc) - timedelta(days=days)
        incidents = await client.get_incidents(limit=limit, since=since, rules_cache=rules_cache)

        coverage = mapper.calculate_coverage(rules, incidents)
        layer = generator.generate_atlas_layer(coverage, name=name)

        return JSONResponse(
            content=layer.to_json(),
            media_type="application/json",
        )
    except Exception as e:
        logger.error(f"Failed to generate ATLAS layer: {e}")
        raise HTTPException(status_code=500, detail=_safe_error_detail(e, settings))


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
