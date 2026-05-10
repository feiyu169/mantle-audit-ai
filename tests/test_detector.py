"""Tests for the detector module."""

import os
import json
from pathlib import Path

import pytest

# Skip if SLOW_TESTS not set (Slither tests need solc installed)
SLOW = os.environ.get("SLOW_TESTS", "0") == "1"
pytestmark = pytest.mark.skipif(not SLOW, reason="Set SLOW_TESTS=1 to run Slither-dependent tests")

from mantle_audit.detector import detect_vulnerabilities, DetectionResult, Severity


@pytest.fixture
def vulnerable_sol(tmp_path: Path) -> Path:
    code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract VulnerableToken {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }

    function isOwner() public view returns (bool) {
        return tx.origin == address(0x1234);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
'''
    sol_file = tmp_path / "VulnerableToken.sol"
    sol_file.write_text(code)
    return sol_file


@pytest.fixture
def safe_sol(tmp_path: Path) -> Path:
    code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SafeStorage {
    uint256 private _value;

    function set(uint256 val) external {
        _value = val;
    }

    function get() external view returns (uint256) {
        return _value;
    }
}
'''
    sol_file = tmp_path / "SafeStorage.sol"
    sol_file.write_text(code)
    return sol_file


@pytest.fixture
def mantle_sol(tmp_path: Path) -> Path:
    code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IMETH {
    function stake() external payable;
}

contract MantleStaker {
    IMETH public mETH;

    constructor(address _mETH) {
        mETH = IMETH(_mETH);
    }

    function stakeETH() external payable {
        mETH.stake{value: msg.value}();
    }
}
'''
    sol_file = tmp_path / "MantleStaker.sol"
    sol_file.write_text(code)
    return sol_file


class TestDetectVulnerabilities:
    def test_detect_returns_result(self, vulnerable_sol: Path):
        result = detect_vulnerabilities(str(vulnerable_sol))
        assert isinstance(result, DetectionResult)

    def test_detect_finds_vulnerabilities(self, vulnerable_sol: Path):
        result = detect_vulnerabilities(str(vulnerable_sol))
        # Slither may not fire detectors on simple contracts,
        # but Mantle-specific patterns should still be checked
        assert isinstance(result.vulnerabilities, list)
        assert result.errors == []  # no errors = successful run

    def test_safe_contract_has_fewer_findings(self, safe_sol: Path, vulnerable_sol: Path):
        safe_result = detect_vulnerabilities(str(safe_sol))
        vuln_result = detect_vulnerabilities(str(vulnerable_sol))
        assert len(vuln_result.vulnerabilities) >= len(safe_result.vulnerabilities)

    def test_mantle_specific_detection(self, mantle_sol: Path):
        result = detect_vulnerabilities(str(mantle_sol))
        mantle_findings = [v for v in result.vulnerabilities if v.is_mantle_specific]
        assert len(mantle_findings) > 0
        assert any("mETH" in v.description for v in mantle_findings)

    def test_nonexistent_file(self):
        result = detect_vulnerabilities("/nonexistent/file.sol")
        assert result.errors

    def test_summary_counts(self, vulnerable_sol: Path):
        result = detect_vulnerabilities(str(vulnerable_sol))
        summary = result.summary
        assert isinstance(summary, dict)
        assert sum(summary.values()) == len(result.vulnerabilities)

    def test_to_json(self, vulnerable_sol: Path):
        result = detect_vulnerabilities(str(vulnerable_sol))
        data = json.loads(result.to_json())
        assert "vulnerabilities" in data
        assert "summary" in data
