"""
MITRE ID Resolver service.

Translates technique/tactic names to actual MITRE ATT&CK IDs using the
mitreattack-python library. This is necessary because ReliaQuest returns
their own internal IDs rather than standard MITRE IDs.
"""
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import httpx
from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)


class MitreIdResolver:
    """
    Resolves technique and tactic names to MITRE ATT&CK IDs.

    Uses mitreattack-python to load official ATT&CK data and provides
    lookup methods to find technique IDs (T1059, T1059.001) and tactic
    IDs (TA0001) from their names.
    """

    # Standard ATT&CK STIX data URLs
    ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    # ATLAS data needs to be loaded separately if needed

    # Cache directory for downloaded STIX data - prefer /app/cache (Docker volume) if available
    _DOCKER_CACHE = Path("/app/cache")
    CACHE_DIR = _DOCKER_CACHE if _DOCKER_CACHE.is_dir() else Path(tempfile.gettempdir()) / "mitre_attack_cache"

    def __init__(self, stix_filepath: Optional[str] = None):
        """
        Initialize the resolver.

        Args:
            stix_filepath: Path to local STIX JSON file. If None, downloads from MITRE.
        """
        self._attack_data: Optional[MitreAttackData] = None
        self._stix_filepath = stix_filepath

        # Lookup caches (name -> MITRE ID)
        self._technique_name_to_id: dict[str, str] = {}
        self._tactic_name_to_id: dict[str, str] = {}

        # Reverse lookups (MITRE ID -> name)
        self._technique_id_to_name: dict[str, str] = {}
        self._tactic_id_to_name: dict[str, str] = {}

        # ATLAS techniques (manually maintained since not in main ATT&CK STIX)
        self._atlas_techniques: dict[str, str] = {}

    def _download_stix_data(self, url: str) -> str:
        """
        Download STIX data from URL and cache locally.

        Returns path to cached file.
        """
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = self.CACHE_DIR / "enterprise-attack.json"

        # Use cached file if it exists and is less than 24 hours old
        if cache_file.exists():
            age_hours = (time.time() - os.path.getmtime(str(cache_file))) / 3600
            if age_hours < 24:
                logger.info(f"Using cached STIX data from {cache_file}")
                return str(cache_file)

        logger.info(f"Downloading STIX data from {url}...")
        try:
            response = httpx.get(url, timeout=60.0, follow_redirects=True)
            response.raise_for_status()
            cache_file.write_bytes(response.content)
            logger.info(f"STIX data cached to {cache_file}")
            return str(cache_file)
        except Exception as e:
            # If download fails but cache exists, use stale cache
            if cache_file.exists():
                logger.warning(f"Failed to download STIX data: {e}. Using stale cache.")
                return str(cache_file)
            raise

    def initialize(self) -> None:
        """
        Load ATT&CK data and build lookup tables.

        Call this once at startup. Can be called again to refresh data.
        """
        logger.info("Initializing MITRE ID resolver...")

        try:
            if self._stix_filepath:
                stix_path = self._stix_filepath
            else:
                # Download from MITRE GitHub and cache locally
                stix_path = self._download_stix_data(self.ENTERPRISE_ATTACK_URL)

            self._attack_data = MitreAttackData(stix_filepath=stix_path)

            self._build_technique_lookup()
            self._build_tactic_lookup()
            self._load_atlas_techniques()

            logger.info(
                f"MITRE ID resolver initialized: {len(self._technique_name_to_id)} techniques, "
                f"{len(self._tactic_name_to_id)} tactics"
            )
        except Exception as e:
            logger.error(f"Failed to initialize MITRE ID resolver: {e}")
            raise

    def _build_technique_lookup(self) -> None:
        """Build technique name to ID lookup table."""
        if not self._attack_data:
            return

        techniques = self._attack_data.get_techniques()

        for technique in techniques:
            # Get technique name
            name = technique.get("name", "")
            if not name:
                continue

            # Get external ID (T1059, T1059.001, etc.)
            external_refs = technique.get("external_references", [])
            mitre_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break

            if mitre_id:
                # Store with normalized name (lowercase, stripped)
                normalized_name = self._normalize_name(name)
                self._technique_name_to_id[normalized_name] = mitre_id
                self._technique_id_to_name[mitre_id] = name

                # Also store without sub-technique suffix for partial matching
                # e.g., "PowerShell" should match T1059.001
                logger.debug(f"Loaded technique: {name} -> {mitre_id}")

    def _build_tactic_lookup(self) -> None:
        """Build tactic name to ID lookup table."""
        if not self._attack_data:
            return

        tactics = self._attack_data.get_tactics()

        for tactic in tactics:
            name = tactic.get("name", "")
            if not name:
                continue

            # Get external ID (TA0001, etc.)
            external_refs = tactic.get("external_references", [])
            mitre_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break

            if mitre_id:
                normalized_name = self._normalize_name(name)
                self._tactic_name_to_id[normalized_name] = mitre_id
                self._tactic_id_to_name[mitre_id] = name

                # Also store the x_mitre_shortname if available
                shortname = tactic.get("x_mitre_shortname", "")
                if shortname:
                    self._tactic_name_to_id[self._normalize_name(shortname)] = mitre_id

                logger.debug(f"Loaded tactic: {name} -> {mitre_id}")

    def _load_atlas_techniques(self) -> None:
        """
        Load MITRE ATLAS (AI/ML) technique mappings.

        ATLAS is a separate framework for AI/ML threats. Since it may not be
        in the main STIX data, we maintain a mapping here.
        """
        # Common ATLAS techniques - this can be expanded or loaded from a file
        self._atlas_techniques = {
            "full ml model access": "AML.T0044",
            "craft adversarial data": "AML.T0043",
            "poison training data": "AML.T0020",
            "ml model inference api access": "AML.T0040",
            "discover ml model ontology": "AML.T0001",
            "discover ml model family": "AML.T0002",
            "ml supply chain compromise": "AML.T0010",
            "backdoor ml model": "AML.T0018",
            "evade ml model": "AML.T0015",
            "extract ml model": "AML.T0024",
            "functional extraction": "AML.T0024.000",
            "invert ml model": "AML.T0025",
            "exfiltration via ml inference api": "AML.T0035",
            "publish poisoned datasets": "AML.T0019",
            "insert backdoor trigger": "AML.T0019.001",
        }

        # Add to technique lookup
        for name, mitre_id in self._atlas_techniques.items():
            self._technique_name_to_id[name] = mitre_id
            self._technique_id_to_name[mitre_id] = name.title()

        logger.debug(f"Loaded {len(self._atlas_techniques)} ATLAS techniques")

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a technique/tactic name for lookup."""
        # Lowercase, strip whitespace, remove special chars
        normalized = name.lower().strip()
        # Replace common separators with spaces
        normalized = re.sub(r"[-_/]", " ", normalized)
        # Remove multiple spaces
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    def resolve_technique_id(self, name: str) -> Optional[str]:
        """
        Resolve a technique name to its MITRE ID.

        Args:
            name: Technique name (e.g., "PowerShell", "Command and Scripting Interpreter")

        Returns:
            MITRE technique ID (e.g., "T1059.001") or None if not found
        """
        if not name:
            return None

        normalized = self._normalize_name(name)

        # Direct lookup
        if normalized in self._technique_name_to_id:
            return self._technique_name_to_id[normalized]

        # Check ATLAS techniques
        if normalized in self._atlas_techniques:
            return self._atlas_techniques[normalized]

        # Fuzzy matching - try partial matches
        for stored_name, mitre_id in self._technique_name_to_id.items():
            if normalized in stored_name or stored_name in normalized:
                logger.debug(f"Fuzzy matched '{name}' to '{stored_name}' -> {mitre_id}")
                return mitre_id

        logger.warning(f"Could not resolve technique name: {name}")
        return None

    def resolve_tactic_id(self, name: str) -> Optional[str]:
        """
        Resolve a tactic name to its MITRE ID.

        Args:
            name: Tactic name (e.g., "Execution", "Initial Access")

        Returns:
            MITRE tactic ID (e.g., "TA0002") or None if not found
        """
        if not name:
            return None

        normalized = self._normalize_name(name)

        # Direct lookup
        if normalized in self._tactic_name_to_id:
            return self._tactic_name_to_id[normalized]

        # Try common variations
        variations = [
            normalized.replace(" ", "-"),  # "initial access" -> "initial-access"
            normalized.replace("-", " "),  # "initial-access" -> "initial access"
        ]
        for variation in variations:
            if variation in self._tactic_name_to_id:
                return self._tactic_name_to_id[variation]

        logger.warning(f"Could not resolve tactic name: {name}")
        return None

    def resolve_tactic_name_to_shortname(self, name: str) -> str:
        """
        Convert a tactic name to its shortname format used in ATT&CK Navigator.

        Args:
            name: Tactic name (e.g., "Initial Access", "Command and Control")

        Returns:
            Shortname format (e.g., "initial-access", "command-and-control")
        """
        # Standard mapping
        return name.lower().replace(" ", "-").replace("_", "-")

    def get_technique_name(self, technique_id: str) -> Optional[str]:
        """Get technique name from MITRE ID."""
        return self._technique_id_to_name.get(technique_id)

    def get_tactic_name(self, tactic_id: str) -> Optional[str]:
        """Get tactic name from MITRE ID."""
        return self._tactic_id_to_name.get(tactic_id)

    def is_valid_technique_id(self, technique_id: str) -> bool:
        """Check if a string is a valid MITRE technique ID format."""
        # ATT&CK: T1234 or T1234.001
        if re.match(r"^T\d{4}(\.\d{3})?$", technique_id):
            return True
        # ATLAS: AML.T0044 or AML.T0044.001
        if re.match(r"^AML\.T\d{4}(\.\d{3})?$", technique_id):
            return True
        return False

    def is_valid_tactic_id(self, tactic_id: str) -> bool:
        """Check if a string is a valid MITRE tactic ID format."""
        return bool(re.match(r"^TA\d{4}$", tactic_id))


# Singleton instance for easy access
_resolver_instance: Optional[MitreIdResolver] = None
_resolver_lock = threading.Lock()


def get_mitre_id_resolver() -> MitreIdResolver:
    """Get the singleton MitreIdResolver instance."""
    global _resolver_instance
    if _resolver_instance is None:
        with _resolver_lock:
            if _resolver_instance is None:
                resolver = MitreIdResolver()
                resolver.initialize()
                _resolver_instance = resolver
    return _resolver_instance
