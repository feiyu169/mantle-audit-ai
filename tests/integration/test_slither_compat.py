"""Tests for Slither compatibility and enum consistency."""

import json
import os
import subprocess

import pytest

from mantle_audit.detector import (
    Confidence,
    DetectionResult,
    Severity,
    Vulnerability,
)
from mantle_audit.llm_agent import _parse_llm_vulns

SLOW = os.environ.get("SLOW_TESTS", "0") == "1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not SLOW, reason="Set SLOW_TESTS=1"),
]


# ─────────────────────────────────────────────────────────────
# TestSolcAbiOutputFormat
# ─────────────────────────────────────────────────────────────


class TestSolcAbiOutputFormat:
    """Verify solc combined-json output can be parsed correctly."""

    def test_compiled_abi_is_parseable(self, tmp_path):
        """Compile a minimal contract and verify the ABI is valid JSON."""
        sol = tmp_path / "Minimal.sol"
        sol.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.19;\n"
            "contract Minimal {}\n"
        )
        subprocess.run(
            ["solc", "--combined-json", "abi,bin", "-o", str(tmp_path), str(sol)],
            capture_output=True,
            text=True,
            check=True,
        )
        # solc --combined-json writes to stdout
        result = subprocess.run(
            ["solc", "--combined-json", "abi,bin", str(sol)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        # The key includes the path; grab the first contract
        contract_key = next(k for k in data["contracts"] if "Minimal" in k)
        abi_raw = data["contracts"][contract_key]["abi"]
        # ABI is already a list from solc's JSON output
        abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
        assert isinstance(abi, list)

    def test_compiled_bytecode_is_non_empty(self, tmp_path):
        """Verify solc produces non-empty bytecode for a minimal contract."""
        sol = tmp_path / "Minimal.sol"
        sol.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.19;\n"
            "contract Minimal {}\n"
        )
        result = subprocess.run(
            ["solc", "--combined-json", "abi,bin", str(sol)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        contract_key = next(k for k in data["contracts"] if "Minimal" in k)
        bytecode = data["contracts"][contract_key]["bin"]
        assert bytecode, "Bytecode should be non-empty"
        assert len(bytecode) > 0

    def test_abi_is_valid_json_list(self, tmp_path):
        """Verify the ABI parses as a list of items (functions/events)."""
        sol = tmp_path / "Minimal.sol"
        sol.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.19;\n"
            "contract Minimal {\n"
            "    function foo() public pure returns (uint256) { return 1; }\n"
            "}\n"
        )
        result = subprocess.run(
            ["solc", "--combined-json", "abi,bin", str(sol)],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        contract_key = next(k for k in data["contracts"] if "Minimal" in k)
        abi_raw = data["contracts"][contract_key]["abi"]
        abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
        assert isinstance(abi, list)
        assert len(abi) >= 1  # at least the constructor + foo()


# ─────────────────────────────────────────────────────────────
# TestSeverityEnumValues
# ─────────────────────────────────────────────────────────────


class TestSeverityEnumValues:
    """Verify Severity enum value properties and construction."""

    def test_all_members_are_title_case(self):
        """Every Severity member value should be Title Case."""
        for member in Severity:
            value = member.value
            assert value == value.title(), (
                f"{member.name}={value!r} is not Title Case"
            )

    def test_severity_high_works(self):
        """Severity('High') should return Severity.HIGH."""
        assert Severity("High") == Severity.HIGH

    def test_severity_uppercase_raises_value_error(self):
        """Severity('HIGH') should raise ValueError (real bug regression)."""
        with pytest.raises(ValueError):
            Severity("HIGH")

    def test_severity_round_trip(self):
        """Severity(member.value) == member for every member."""
        for member in Severity:
            assert Severity(member.value) == member


# ─────────────────────────────────────────────────────────────
# TestSeverityCaseInsensitiveMapping
# ─────────────────────────────────────────────────────────────


class TestSeverityCaseInsensitiveMapping:
    """Verify an uppercase-keyed mapping built from Severity works."""

    @pytest.fixture
    def mapping(self):
        return {s.value.upper(): s for s in Severity}

    def test_high_maps_correctly(self, mapping):
        """'HIGH' should map to Severity.HIGH."""
        assert mapping["HIGH"] == Severity.HIGH

    def test_critical_via_upper(self, mapping):
        """'Critical' via .upper() should map to Severity.CRITICAL."""
        assert mapping["Critical".upper()] == Severity.CRITICAL

    def test_all_five_severities_present(self, mapping):
        """All 5 severity values should be in the mapping."""
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
        assert set(mapping.keys()) == expected


# ─────────────────────────────────────────────────────────────
# TestDetectionResultSummaryConsistency
# ─────────────────────────────────────────────────────────────


class TestDetectionResultSummaryConsistency:
    """Verify DetectionResult.summary matches vulnerabilities."""

    def test_summary_total_matches_count(self):
        """Summary dict total should equal len(vulnerabilities)."""
        vulns = [
            Vulnerability(
                vuln_id="V-1",
                check="test",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="high vuln",
            ),
            Vulnerability(
                vuln_id="V-2",
                check="test",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description="low vuln",
            ),
            Vulnerability(
                vuln_id="V-3",
                check="test",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description="another high vuln",
            ),
        ]
        result = DetectionResult(vulnerabilities=vulns)
        total = sum(result.summary.values())
        assert total == len(vulns)

    def test_summary_keys_are_title_case(self):
        """Summary dict keys should match Severity values (Title Case)."""
        vulns = [
            Vulnerability(
                vuln_id="V-1",
                check="test",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="",
            ),
            Vulnerability(
                vuln_id="V-2",
                check="test",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description="",
            ),
        ]
        result = DetectionResult(vulnerabilities=vulns)
        for key in result.summary:
            assert key == key.title(), f"Summary key {key!r} is not Title Case"

    def test_empty_result_has_empty_summary(self):
        """An empty DetectionResult should have an empty summary."""
        result = DetectionResult()
        assert result.summary == {}


# ─────────────────────────────────────────────────────────────
# TestLlmResponseParsingEdgeCases
# ─────────────────────────────────────────────────────────────


class TestLlmResponseParsingEdgeCases:
    """Verify _parse_llm_vulns handles various code_location formats."""

    def test_code_location_file_colon_line(self):
        """'file.sol:42' should parse line_start=42 and file_path='file.sol'."""
        raw = json.dumps([
            {
                "vuln_id": "V-1",
                "check": "test",
                "severity": "High",
                "confidence": "High",
                "description": "test",
                "code_location": "file.sol:42",
            }
        ])
        vulns = _parse_llm_vulns(raw)
        assert len(vulns) == 1
        assert vulns[0].line_start == 42
        assert vulns[0].file_path == "file.sol"

    def test_code_location_line_comma_col(self):
        """'17,29' should parse line_start=17."""
        raw = json.dumps([
            {
                "vuln_id": "V-1",
                "check": "test",
                "severity": "High",
                "confidence": "High",
                "description": "test",
                "code_location": "17,29",
            }
        ])
        vulns = _parse_llm_vulns(raw)
        assert len(vulns) == 1
        assert vulns[0].line_start == 17

    def test_code_location_just_number(self):
        """'42' should parse line_start=42."""
        raw = json.dumps([
            {
                "vuln_id": "V-1",
                "check": "test",
                "severity": "High",
                "confidence": "High",
                "description": "test",
                "code_location": "42",
            }
        ])
        vulns = _parse_llm_vulns(raw)
        assert len(vulns) == 1
        assert vulns[0].line_start == 42

    def test_code_location_empty_string(self):
        """'' should parse line_start=0."""
        raw = json.dumps([
            {
                "vuln_id": "V-1",
                "check": "test",
                "severity": "High",
                "confidence": "High",
                "description": "test",
                "code_location": "",
            }
        ])
        vulns = _parse_llm_vulns(raw)
        assert len(vulns) == 1
        assert vulns[0].line_start == 0

    def test_code_location_missing_field(self):
        """Missing code_location field should default line_start=0 and file_path=''."""
        raw = json.dumps([
            {
                "vuln_id": "V-1",
                "check": "test",
                "severity": "High",
                "confidence": "High",
                "description": "test",
                # no code_location
            }
        ])
        vulns = _parse_llm_vulns(raw)
        assert len(vulns) == 1
        assert vulns[0].line_start == 0
        assert vulns[0].file_path == ""
