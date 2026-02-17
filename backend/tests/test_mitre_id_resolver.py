"""Tests for MitreIdResolver service."""
import pytest

from app.services.mitre_id_resolver import MitreIdResolver


class TestIsValidTechniqueId:
    def setup_method(self):
        self.resolver = MitreIdResolver.__new__(MitreIdResolver)

    def test_valid_attack_technique(self):
        assert self.resolver.is_valid_technique_id("T1059") is True

    def test_valid_attack_subtechnique(self):
        assert self.resolver.is_valid_technique_id("T1059.001") is True

    def test_valid_atlas_technique(self):
        assert self.resolver.is_valid_technique_id("AML.T0044") is True

    def test_valid_atlas_subtechnique(self):
        assert self.resolver.is_valid_technique_id("AML.T0044.001") is True

    def test_invalid_tactic_id(self):
        assert self.resolver.is_valid_technique_id("TA0002") is False

    def test_invalid_reliaquest_id(self):
        assert self.resolver.is_valid_technique_id("rq-tech-ps-001") is False

    def test_invalid_empty(self):
        assert self.resolver.is_valid_technique_id("") is False

    def test_invalid_random_string(self):
        assert self.resolver.is_valid_technique_id("foobar") is False


class TestIsValidTacticId:
    def setup_method(self):
        self.resolver = MitreIdResolver.__new__(MitreIdResolver)

    def test_valid_tactic(self):
        assert self.resolver.is_valid_tactic_id("TA0002") is True

    def test_invalid_technique(self):
        assert self.resolver.is_valid_tactic_id("T1059") is False

    def test_invalid_empty(self):
        assert self.resolver.is_valid_tactic_id("") is False


class TestNormalizeName:
    def test_lowercase(self):
        assert MitreIdResolver._normalize_name("PowerShell") == "powershell"

    def test_strips_whitespace(self):
        assert MitreIdResolver._normalize_name("  PowerShell  ") == "powershell"

    def test_replaces_hyphens(self):
        assert MitreIdResolver._normalize_name("Command-Line") == "command line"

    def test_replaces_underscores(self):
        assert MitreIdResolver._normalize_name("some_name") == "some name"

    def test_collapses_multiple_spaces(self):
        assert MitreIdResolver._normalize_name("a   b") == "a b"


class TestResolveTechniqueId:
    def setup_method(self):
        self.resolver = MitreIdResolver.__new__(MitreIdResolver)
        self.resolver._technique_name_to_id = {
            "powershell": "T1059.001",
            "lsass memory": "T1003.001",
        }
        self.resolver._atlas_techniques = {
            "full ml model access": "AML.T0044",
        }

    def test_direct_match(self):
        assert self.resolver.resolve_technique_id("PowerShell") == "T1059.001"

    def test_atlas_match(self):
        assert self.resolver.resolve_technique_id("Full ML Model Access") == "AML.T0044"

    def test_partial_match(self):
        # "powershell" is in "powershell" (substring match)
        result = self.resolver.resolve_technique_id("PowerShell")
        assert result == "T1059.001"

    def test_no_match(self):
        assert self.resolver.resolve_technique_id("NonExistentTechnique") is None

    def test_empty_string(self):
        assert self.resolver.resolve_technique_id("") is None

    def test_none(self):
        assert self.resolver.resolve_technique_id(None) is None


class TestResolveTacticId:
    def setup_method(self):
        self.resolver = MitreIdResolver.__new__(MitreIdResolver)
        self.resolver._tactic_name_to_id = {
            "execution": "TA0002",
            "initial access": "TA0001",
            "initial-access": "TA0001",
        }

    def test_direct_match(self):
        assert self.resolver.resolve_tactic_id("Execution") == "TA0002"

    def test_with_spaces(self):
        assert self.resolver.resolve_tactic_id("Initial Access") == "TA0001"

    def test_hyphenated_variation(self):
        assert self.resolver.resolve_tactic_id("initial-access") == "TA0001"

    def test_no_match(self):
        assert self.resolver.resolve_tactic_id("fake-tactic") is None

    def test_none(self):
        assert self.resolver.resolve_tactic_id(None) is None


class TestTacticNameToShortname:
    def setup_method(self):
        self.resolver = MitreIdResolver.__new__(MitreIdResolver)

    def test_spaces_to_hyphens(self):
        assert self.resolver.resolve_tactic_name_to_shortname("Initial Access") == "initial-access"

    def test_already_shortname(self):
        assert self.resolver.resolve_tactic_name_to_shortname("execution") == "execution"

    def test_command_and_control(self):
        assert self.resolver.resolve_tactic_name_to_shortname("Command and Control") == "command-and-control"
