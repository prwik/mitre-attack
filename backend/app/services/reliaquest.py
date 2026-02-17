"""
ReliaQuest GreyMatter API client.

API Documentation: https://apidocs.myreliaquest.com/
The API uses GraphQL over HTTPS with API key authentication.
"""
import logging
from typing import Optional
from datetime import datetime, timedelta

import httpx
from cachetools import TTLCache

from ..models.detection import DetectionRule, Incident, TechniqueMapping

logger = logging.getLogger(__name__)


class ReliaQuestClient:
    """
    Client for ReliaQuest GreyMatter GraphQL API.

    Queries detection rules and incidents, mapping them to ATT&CK techniques.
    """

    BASE_URL = "https://api.myreliaquest.com/graphql"

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        cache_ttl: int = 300,
    ):
        self.api_key = api_key
        self.base_url = base_url or self.BASE_URL
        self.timeout = timeout
        self._cache = TTLCache(maxsize=100, ttl=cache_ttl)

    def _get_headers(self) -> dict:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _execute_query(self, query: str, variables: Optional[dict] = None) -> dict:
        """Execute a GraphQL query."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.base_url,
                headers=self._get_headers(),
                json={"query": query, "variables": variables or {}},
            )
            response.raise_for_status()
            result = response.json()

            if "errors" in result:
                logger.error(f"GraphQL errors: {result['errors']}")
                raise ValueError(f"GraphQL query failed: {result['errors']}")

            return result.get("data", {})

    async def get_detection_rules(
        self,
        limit: int = 100,
    ) -> list[DetectionRule]:
        """
        Fetch detection rules from GreyMatter.

        Note: mitreTacticTechniques contains ReliaQuest-specific IDs, not MITRE IDs.
        The technique/tactic names are used to lookup actual MITRE IDs via MitreIdResolver.
        """
        query = """
        query GetDetectionRules($limit: Int) {
            detectionRules(first: $limit) {
                edges {
                    node {
                        id
                        name
                        slug
                        description
                        severity
                        updatedAt
                        logSourceTypes
                        mitreTacticTechniques {
                            id
                            name
                            techniques {
                                id
                                name
                            }
                        }
                    }
                }
            }
        }
        """
        cache_key = f"rules:{limit}"
        if cache_key in self._cache:
            logger.debug("Returning cached detection rules")
            return self._cache[cache_key]

        try:
            data = await self._execute_query(
                query,
                {"limit": limit}
            )

            rules = []
            for edge in data.get("detectionRules", {}).get("edges", []):
                node = edge.get("node", {})
                techniques = self._parse_mitre_tactic_techniques(
                    node.get("mitreTacticTechniques", [])
                )
                rules.append(DetectionRule(
                    id=node.get("id", ""),
                    name=node.get("name", ""),
                    slug=node.get("slug", ""),
                    description=node.get("description", ""),
                    severity=node.get("severity", "medium"),
                    log_source_types=node.get("logSourceTypes", []),
                    source="reliaquest",
                    techniques=techniques,
                    updated_at=node.get("updatedAt"),
                    raw_data=node,
                ))
            self._cache[cache_key] = rules
            return rules
        except Exception as e:
            logger.error(f"Failed to fetch detection rules: {e}")
            raise

    def _parse_mitre_tactic_techniques(
        self, mitre_tactic_techniques: list[dict]
    ) -> list[TechniqueMapping]:
        """
        Parse the mitreTacticTechniques structure from ReliaQuest.

        Structure:
            mitreTacticTechniques: [
                {
                    id: "reliaquest-tactic-id",
                    name: "Execution",
                    techniques: [
                        { id: "reliaquest-technique-id", name: "PowerShell" }
                    ]
                }
            ]

        Note: The IDs are ReliaQuest-specific. We store the names and use
        MitreIdResolver to translate to actual MITRE IDs (T1059, TA0002, etc.)
        """
        techniques = []
        for tactic in mitre_tactic_techniques:
            tactic_name = tactic.get("name", "")
            reliaquest_tactic_id = tactic.get("id", "")

            for technique in tactic.get("techniques", []):
                technique_name = technique.get("name", "")
                reliaquest_technique_id = technique.get("id", "")

                techniques.append(TechniqueMapping(
                    technique_id=reliaquest_technique_id,  # Will be resolved later
                    technique_name=technique_name,
                    tactic=tactic_name,
                    source="reliaquest",
                    # Store ReliaQuest IDs for reference
                    reliaquest_tactic_id=reliaquest_tactic_id,
                    reliaquest_technique_id=reliaquest_technique_id,
                ))
        return techniques

    async def get_incidents(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        rules_cache: Optional[dict[str, DetectionRule]] = None,
    ) -> list[Incident]:
        """
        Fetch incidents from GreyMatter.

        Args:
            limit: Maximum number of incidents to fetch
            since: Only fetch incidents created after this time
            rules_cache: Optional dict of slug -> DetectionRule for technique lookup

        Note: Incidents don't have mitreTacticTechniques directly. They link to
        detection rules via rule.id -> detectionRule.slug. Pass rules_cache to
        automatically populate techniques from linked rules.
        """
        if since is None:
            since = datetime.utcnow() - timedelta(days=30)

        cache_key = f"incidents:{limit}:{since.date().isoformat()}"
        if cache_key in self._cache:
            logger.debug("Returning cached incidents")
            return self._cache[cache_key]

        query = """
        query GetIncidents($earliest: DateTime) {
            incidents(
                incidentFilter: { created: { earliest: $earliest } },
                incidentOrder: { orderBy: CREATED_AT, direction: ASC }
            ) {
                edges {
                    cursor
                    node {
                        id
                        ticketNumber
                        title
                        description
                        summary
                        severity
                        state
                        type
                        category
                        createdAt
                        updatedAt
                        closedAt
                        closeCode
                        closeNote
                        escalatedAt
                        originator
                        logSourceType
                        internalOnly
                        acknowledgement
                        rule {
                            id
                            name
                            version
                        }
                    }
                }
                pageInfo {
                    startCursor
                    endCursor
                    hasPreviousPage
                    hasNextPage
                }
            }
        }
        """
        try:
            data = await self._execute_query(
                query,
                {"earliest": since.isoformat() if since else None}
            )

            incidents = []
            for edge in data.get("incidents", {}).get("edges", []):
                node = edge.get("node", {})

                # Get techniques from linked rule if rules_cache provided
                techniques = []
                rule_info = node.get("rule")
                if rule_info and rules_cache:
                    rule_id = rule_info.get("id", "")
                    # rule.id matches detectionRule.slug
                    linked_rule = rules_cache.get(rule_id)
                    if linked_rule:
                        techniques = linked_rule.techniques.copy()

                incidents.append(Incident(
                    id=node.get("id", ""),
                    ticket_number=node.get("ticketNumber", ""),
                    title=node.get("title", ""),
                    description=node.get("description", ""),
                    summary=node.get("summary", ""),
                    severity=node.get("severity", "medium"),
                    state=node.get("state", "open"),
                    incident_type=node.get("type", ""),
                    category=node.get("category", ""),
                    source="reliaquest",
                    techniques=techniques,
                    created_at=node.get("createdAt"),
                    updated_at=node.get("updatedAt"),
                    closed_at=node.get("closedAt"),
                    close_code=node.get("closeCode"),
                    close_note=node.get("closeNote"),
                    escalated_at=node.get("escalatedAt"),
                    originator=node.get("originator"),
                    log_source_type=node.get("logSourceType"),
                    internal_only=node.get("internalOnly", False),
                    acknowledgement=node.get("acknowledgement"),
                    rule_id=rule_info.get("id") if rule_info else None,
                    rule_name=rule_info.get("name") if rule_info else None,
                    rule_version=rule_info.get("version") if rule_info else None,
                    raw_data=node,
                ))
            self._cache[cache_key] = incidents
            return incidents
        except Exception as e:
            logger.error(f"Failed to fetch incidents: {e}")
            raise

    async def get_incidents_with_techniques(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
    ) -> list[Incident]:
        """
        Fetch incidents and automatically populate MITRE techniques from linked rules.

        This is a convenience method that:
        1. Fetches all detection rules
        2. Builds a slug -> rule cache
        3. Fetches incidents with technique lookup
        """
        # First fetch rules to build cache
        rules = await self.get_detection_rules(limit=1000)
        rules_cache = {rule.slug: rule for rule in rules if rule.slug}

        # Then fetch incidents with the cache
        return await self.get_incidents(
            limit=limit,
            since=since,
            rules_cache=rules_cache,
        )

    async def introspect_schema(self) -> dict:
        """
        Introspect the GraphQL schema to discover available queries.

        Useful for understanding the actual API structure.
        """
        query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                types {
                    name
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
        """
        return await self._execute_query(query)


class MockReliaQuestClient(ReliaQuestClient):
    """
    Mock client for testing without API access.

    Returns sample data that mimics actual ReliaQuest responses, including
    the mitreTacticTechniques structure with ReliaQuest-specific IDs.
    """

    def __init__(self):
        super().__init__(api_key="mock-key")

    def _build_mock_mitre_tactic_techniques(
        self, tactic_data: list[dict]
    ) -> list[TechniqueMapping]:
        """
        Build TechniqueMappings from mock mitreTacticTechniques data.

        This simulates the actual ReliaQuest response structure where IDs
        are ReliaQuest-specific, not MITRE IDs. The technique names are
        used to resolve actual MITRE IDs.
        """
        return self._parse_mitre_tactic_techniques(tactic_data)

    async def get_detection_rules(
        self,
        limit: int = 100,
    ) -> list[DetectionRule]:
        """
        Return sample detection rules with ReliaQuest-style structure.

        Note: The IDs (e.g., "rq-tactic-001") are ReliaQuest internal IDs,
        NOT MITRE IDs. The MitreIdResolver will translate technique names
        to actual MITRE IDs (T1059, etc.).
        """
        return [
            DetectionRule(
                id="rule-001",
                name="PowerShell Empire Detection",
                slug="powershell-empire-detection",
                description="Detects PowerShell Empire C2 activity",
                severity="high",
                log_source_types=["windows", "endpoint"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-exec-001",
                        "name": "Execution",
                        "techniques": [
                            {"id": "rq-tech-ps-001", "name": "PowerShell"}
                        ]
                    },
                    {
                        "id": "rq-tactic-c2-001",
                        "name": "Command and Control",
                        "techniques": [
                            {"id": "rq-tech-web-001", "name": "Web Protocols"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-002",
                name="Credential Dumping via LSASS",
                slug="credential-dumping-lsass",
                description="Detects attempts to dump credentials from LSASS",
                severity="critical",
                log_source_types=["windows", "endpoint"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-cred-001",
                        "name": "Credential Access",
                        "techniques": [
                            {"id": "rq-tech-lsass-001", "name": "LSASS Memory"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-003",
                name="Lateral Movement via WMI",
                slug="lateral-movement-wmi",
                description="Detects WMI-based lateral movement",
                severity="high",
                log_source_types=["windows", "network"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-exec-002",
                        "name": "Execution",
                        "techniques": [
                            {"id": "rq-tech-wmi-001", "name": "Windows Management Instrumentation"}
                        ]
                    },
                    {
                        "id": "rq-tactic-lat-001",
                        "name": "Lateral Movement",
                        "techniques": [
                            {"id": "rq-tech-winrm-001", "name": "Windows Remote Management"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-004",
                name="Scheduled Task Persistence",
                slug="scheduled-task-persistence",
                description="Detects scheduled task creation for persistence",
                severity="medium",
                log_source_types=["windows"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-pers-001",
                        "name": "Persistence",
                        "techniques": [
                            {"id": "rq-tech-schtask-001", "name": "Scheduled Task"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-005",
                name="Data Exfiltration via DNS",
                slug="data-exfiltration-dns",
                description="Detects DNS tunneling for data exfiltration",
                severity="high",
                log_source_types=["network", "dns"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-exfil-001",
                        "name": "Exfiltration",
                        "techniques": [
                            {"id": "rq-tech-exfil-dns-001", "name": "Exfiltration Over Alternative Protocol"}
                        ]
                    },
                    {
                        "id": "rq-tactic-c2-002",
                        "name": "Command and Control",
                        "techniques": [
                            {"id": "rq-tech-dns-001", "name": "DNS"}
                        ]
                    }
                ]),
            ),
            # ATLAS (AI/ML) detection rules
            DetectionRule(
                id="rule-006",
                name="ML Model Extraction Attempt",
                slug="ml-model-extraction-attempt",
                description="Detects repeated API queries that may indicate model extraction",
                severity="high",
                log_source_types=["application", "api"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-mlaccess-001",
                        "name": "ML Model Access",
                        "techniques": [
                            {"id": "rq-tech-mlextract-001", "name": "Full ML Model Access"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-007",
                name="Adversarial Input Detection",
                slug="adversarial-input-detection",
                description="Detects potential adversarial examples targeting ML models",
                severity="medium",
                log_source_types=["application", "api"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-mlstage-001",
                        "name": "ML Attack Staging",
                        "techniques": [
                            {"id": "rq-tech-advdata-001", "name": "Craft Adversarial Data"}
                        ]
                    }
                ]),
            ),
            DetectionRule(
                id="rule-008",
                name="Training Data Poisoning",
                slug="training-data-poisoning",
                description="Detects suspicious modifications to ML training datasets",
                severity="critical",
                log_source_types=["application", "database"],
                source="reliaquest",
                techniques=self._build_mock_mitre_tactic_techniques([
                    {
                        "id": "rq-tactic-pers-002",
                        "name": "Persistence",
                        "techniques": [
                            {"id": "rq-tech-poison-001", "name": "Poison Training Data"}
                        ]
                    }
                ]),
            ),
        ]

    async def get_incidents(
        self,
        limit: int = 100,
        since: Optional[datetime] = None,
        rules_cache: Optional[dict[str, DetectionRule]] = None,
    ) -> list[Incident]:
        """
        Return sample incidents with ReliaQuest-style structure.

        Incidents link to detection rules via rule_id -> detectionRule.slug.
        Pass rules_cache to automatically populate techniques from linked rules.
        """
        # Build rules cache if not provided (for mock, get our own rules)
        if rules_cache is None:
            rules = await self.get_detection_rules()
            rules_cache = {rule.slug: rule for rule in rules if rule.slug}

        # Helper to get techniques from linked rule
        def get_rule_techniques(rule_slug: str) -> list[TechniqueMapping]:
            rule = rules_cache.get(rule_slug)
            return rule.techniques.copy() if rule else []

        return [
            Incident(
                id="inc-001",
                ticket_number="INC-2024-001",
                title="Suspected Ransomware Activity",
                description="Multiple file encryption events detected",
                summary="Ransomware indicators detected on endpoint WKSTN-042",
                severity="critical",
                state="open",
                incident_type="malware",
                category="ransomware",
                source="reliaquest",
                log_source_type="endpoint",
                # Links to a rule that detects data encryption
                rule_id="powershell-empire-detection",
                rule_name="PowerShell Empire Detection",
                rule_version="1.0",
                techniques=get_rule_techniques("powershell-empire-detection"),
            ),
            Incident(
                id="inc-002",
                ticket_number="INC-2024-002",
                title="Phishing Campaign Detected",
                description="User clicked malicious link in phishing email",
                summary="User jsmith@company.com clicked link in suspicious email",
                severity="high",
                state="acknowledged",
                incident_type="phishing",
                category="social-engineering",
                source="reliaquest",
                log_source_type="email",
                acknowledgement="Investigating user activity",
                rule_id="credential-dumping-lsass",
                rule_name="Credential Dumping via LSASS",
                rule_version="2.1",
                techniques=get_rule_techniques("credential-dumping-lsass"),
            ),
            Incident(
                id="inc-003",
                ticket_number="INC-2024-003",
                title="Brute Force Authentication Attempt",
                description="Multiple failed login attempts from single IP",
                summary="500+ failed login attempts from 192.168.1.100",
                severity="medium",
                state="closed",
                incident_type="unauthorized-access",
                category="credential-attack",
                source="reliaquest",
                log_source_type="authentication",
                close_code="false-positive",
                close_note="Legitimate user forgot password",
                rule_id="scheduled-task-persistence",
                rule_name="Scheduled Task Persistence",
                rule_version="1.5",
                techniques=get_rule_techniques("scheduled-task-persistence"),
            ),
        ]
