"""Tests for the parser module."""

import os
import pytest
from pathlib import Path

# Skip if SLOW_TESTS not set (Slither tests need solc installed)
SLOW = os.environ.get("SLOW_TESTS", "0") == "1"
pytestmark = pytest.mark.skipif(not SLOW, reason="Set SLOW_TESTS=1 to run Slither-dependent tests")

from mantle_audit.parser import parse_contract, ParseResult


@pytest.fixture
def simple_sol(tmp_path: Path) -> Path:
    code = '''
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
'''
    sol_file = tmp_path / "SimpleToken.sol"
    sol_file.write_text(code)
    return sol_file


class TestParseContract:
    def test_parse_basic_contract(self, simple_sol: Path):
        result = parse_contract(str(simple_sol))
        assert isinstance(result, ParseResult)
        assert result.total_contracts == 1
        assert result.contracts[0].name == "SimpleToken"

    def test_parse_extracts_functions(self, simple_sol: Path):
        result = parse_contract(str(simple_sol))
        contract = result.contracts[0]
        func_names = [f.name for f in contract.functions]
        assert "transfer" in func_names
        assert "balanceOf" in func_names

    def test_parse_extracts_state_variables(self, simple_sol: Path):
        result = parse_contract(str(simple_sol))
        contract = result.contracts[0]
        assert "name" in contract.state_variables
        assert "totalSupply" in contract.state_variables

    def test_parse_extracts_events(self, simple_sol: Path):
        result = parse_contract(str(simple_sol))
        contract = result.contracts[0]
        assert "Transfer" in contract.events

    def test_parse_nonexistent_file(self):
        result = parse_contract("/nonexistent/file.sol")
        assert result.errors

    def test_parse_solidity_version(self, simple_sol: Path):
        result = parse_contract(str(simple_sol))
        assert "0.8.19" in result.solidity_version

    def test_parse_to_json(self, simple_sol: Path):
        import json
        result = parse_contract(str(simple_sol))
        data = json.loads(result.to_json())
        assert "contracts" in data
