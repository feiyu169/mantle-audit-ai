"""Shared fixtures for Mantle-Audit-AI tests."""

from pathlib import Path

import pytest

from mantle_audit.detector import Confidence, DetectionResult, Severity, Vulnerability


@pytest.fixture
def sample_sol(tmp_path: Path) -> Path:
    """A simple Solidity contract for basic testing."""
    code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleToken {
    string public name = "SimpleToken";
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor(uint256 _supply) {
        totalSupply = _supply;
        balances[msg.sender] = _supply;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }

    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
}
"""
    sol_file = tmp_path / "SimpleToken.sol"
    sol_file.write_text(code)
    return sol_file


@pytest.fixture
def sample_detection() -> DetectionResult:
    """Create a sample detection result for testing."""
    det = DetectionResult()
    det.vulnerabilities = [
        Vulnerability(
            vuln_id="SL-reentrancy-1",
            check="reentrancy-eth",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Reentrancy vulnerability in withdraw()",
            file_path="contracts/Token.sol",
            line_start=42,
            line_end=58,
            attack_path="1. Call withdraw()\n2. Re-enter in receive()",
            recommendation="Use Checks-Effects-Interactions pattern",
        ),
        Vulnerability(
            vuln_id="MANTLE-001",
            check="Mantle-mETH",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="Contract interacts with mETH without slashing protection",
            file_path="contracts/Token.sol",
            line_start=15,
            line_end=15,
            is_mantle_specific=True,
        ),
    ]
    return det


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test outputs."""
    return tmp_path
