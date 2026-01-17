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
    ):
        self.api_key = api_key
        self.base_url = base_url or self.BASE_URL
        self.timeout = timeout
        self._cache = TTLCache(maxsize=100, ttl=300)

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
        enabled_only: bool = True,
    ) -> list[DetectionRule]:
        """
        Fetch detection rules from GreyMatter.

        Note: Actual field names depend on the ReliaQuest GraphQL schema.
        Use introspection to discover available fields.
        """
        query = """
        query GetDetectionRules($limit: Int, $enabledOnly: Boolean) {
            detectionRules(first: $limit, filter: { enabled: $enabledOnly }) {
                edges {
                    node {
                        id
                        name
                        description
                        severity
                        enabled
                        mitreTechniques {
                            techniqueId
                            techniqueName
                            tactic
                        }
                        createdAt
                        updatedAt
                    }
                }
            }
        }
        """
        try:
            data = await self._execute_query(
                query,
                {"limit": limit, "enabledOnly": enabled_only}
            )

            rules = []
            for edge in data.get("detectionRules", {}).get("edges", []):
                node = edge.get("node", {})
                techniques = [
                    TechniqueMapping(
                        technique_id=t.get("techniqueId", ""),
                        technique_name=t.get("techniqueName"),
                        tactic=t.get("tactic"),
                        source="reliaquest",
                    )
                    for t in node.get("mitreTechniques", [])
                ]
                rules.append(DetectionRule(
                    id=node.get("id", ""),
                    name=node.get("name", ""),
                    description=node.get("description", ""),
                    severity=node.get("severity", "medium"),
                    enabled=node.get("enabled", True),
                    source="reliaquest",
                    techniques=techniques,
                    created_at=node.get("createdAt"),
                    updated_at=node.get("updatedAt"),
                    raw_data=node,
                ))
            return rules
        except Exception as e:
            logger.error(f"Failed to fetch detection rules: {e}")
            raise

    async def get_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[Incident]:
        """
        Fetch incidents from GreyMatter.

        Args:
            limit: Maximum number of incidents to fetch
            status: Filter by status (open, closed, acknowledged)
            since: Only fetch incidents created after this time
        """
        if since is None:
            since = datetime.utcnow() - timedelta(days=30)

        query = """
        query GetIncidents($limit: Int, $status: String, $since: DateTime) {
            incidents(
                first: $limit,
                filter: { status: $status, createdAfter: $since }
            ) {
                edges {
                    node {
                        id
                        title
                        description
                        severity
                        status
                        mitreTechniques {
                            techniqueId
                            techniqueName
                            tactic
                        }
                        createdAt
                        updatedAt
                        closedAt
                        assignee {
                            name
                        }
                    }
                }
            }
        }
        """
        try:
            data = await self._execute_query(
                query,
                {
                    "limit": limit,
                    "status": status,
                    "since": since.isoformat() if since else None,
                }
            )

            incidents = []
            for edge in data.get("incidents", {}).get("edges", []):
                node = edge.get("node", {})
                techniques = [
                    TechniqueMapping(
                        technique_id=t.get("techniqueId", ""),
                        technique_name=t.get("techniqueName"),
                        tactic=t.get("tactic"),
                        source="reliaquest",
                    )
                    for t in node.get("mitreTechniques", [])
                ]
                incidents.append(Incident(
                    id=node.get("id", ""),
                    title=node.get("title", ""),
                    description=node.get("description", ""),
                    severity=node.get("severity", "medium"),
                    status=node.get("status", "open"),
                    source="reliaquest",
                    techniques=techniques,
                    created_at=node.get("createdAt"),
                    updated_at=node.get("updatedAt"),
                    closed_at=node.get("closedAt"),
                    assignee=node.get("assignee", {}).get("name") if node.get("assignee") else None,
                    raw_data=node,
                ))
            return incidents
        except Exception as e:
            logger.error(f"Failed to fetch incidents: {e}")
            raise

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

    Returns sample data that mimics ReliaQuest responses.
    """

    def __init__(self):
        super().__init__(api_key="mock-key")

    async def get_detection_rules(
        self,
        limit: int = 100,
        enabled_only: bool = True,
    ) -> list[DetectionRule]:
        """Return sample detection rules."""
        return [
            DetectionRule(
                id="rule-001",
                name="PowerShell Empire Detection",
                description="Detects PowerShell Empire C2 activity",
                severity="high",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1059.001",
                        technique_name="PowerShell",
                        tactic="execution",
                        source="reliaquest",
                    ),
                    TechniqueMapping(
                        technique_id="T1071.001",
                        technique_name="Web Protocols",
                        tactic="command-and-control",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-002",
                name="Credential Dumping via LSASS",
                description="Detects attempts to dump credentials from LSASS",
                severity="critical",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1003.001",
                        technique_name="LSASS Memory",
                        tactic="credential-access",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-003",
                name="Lateral Movement via WMI",
                description="Detects WMI-based lateral movement",
                severity="high",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1047",
                        technique_name="Windows Management Instrumentation",
                        tactic="execution",
                        source="reliaquest",
                    ),
                    TechniqueMapping(
                        technique_id="T1021.006",
                        technique_name="Windows Remote Management",
                        tactic="lateral-movement",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-004",
                name="Scheduled Task Persistence",
                description="Detects scheduled task creation for persistence",
                severity="medium",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1053.005",
                        technique_name="Scheduled Task",
                        tactic="persistence",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-005",
                name="Data Exfiltration via DNS",
                description="Detects DNS tunneling for data exfiltration",
                severity="high",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1048.003",
                        technique_name="Exfiltration Over Unencrypted Non-C2 Protocol",
                        tactic="exfiltration",
                        source="reliaquest",
                    ),
                    TechniqueMapping(
                        technique_id="T1071.004",
                        technique_name="DNS",
                        tactic="command-and-control",
                        source="reliaquest",
                    ),
                ],
            ),
            # ATLAS (AI/ML) detection rules
            DetectionRule(
                id="rule-006",
                name="ML Model Extraction Attempt",
                description="Detects repeated API queries that may indicate model extraction",
                severity="high",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="AML.T0044",
                        technique_name="Full ML Model Access",
                        tactic="ml-model-access",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-007",
                name="Adversarial Input Detection",
                description="Detects potential adversarial examples targeting ML models",
                severity="medium",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="AML.T0043",
                        technique_name="Craft Adversarial Data",
                        tactic="ml-attack-staging",
                        source="reliaquest",
                    ),
                ],
            ),
            DetectionRule(
                id="rule-008",
                name="Training Data Poisoning",
                description="Detects suspicious modifications to ML training datasets",
                severity="critical",
                enabled=True,
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="AML.T0020",
                        technique_name="Poison Training Data",
                        tactic="persistence",
                        source="reliaquest",
                    ),
                ],
            ),
        ]

    async def get_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[Incident]:
        """Return sample incidents."""
        return [
            Incident(
                id="inc-001",
                title="Suspected Ransomware Activity",
                description="Multiple file encryption events detected",
                severity="critical",
                status="open",
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1486",
                        technique_name="Data Encrypted for Impact",
                        tactic="impact",
                        source="reliaquest",
                    ),
                    TechniqueMapping(
                        technique_id="T1490",
                        technique_name="Inhibit System Recovery",
                        tactic="impact",
                        source="reliaquest",
                    ),
                ],
            ),
            Incident(
                id="inc-002",
                title="Phishing Campaign Detected",
                description="User clicked malicious link in phishing email",
                severity="high",
                status="acknowledged",
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1566.001",
                        technique_name="Spearphishing Attachment",
                        tactic="initial-access",
                        source="reliaquest",
                    ),
                    TechniqueMapping(
                        technique_id="T1204.001",
                        technique_name="Malicious Link",
                        tactic="execution",
                        source="reliaquest",
                    ),
                ],
            ),
            Incident(
                id="inc-003",
                title="Brute Force Authentication Attempt",
                description="Multiple failed login attempts from single IP",
                severity="medium",
                status="closed",
                source="reliaquest",
                techniques=[
                    TechniqueMapping(
                        technique_id="T1110.001",
                        technique_name="Password Guessing",
                        tactic="credential-access",
                        source="reliaquest",
                    ),
                ],
            ),
        ]
