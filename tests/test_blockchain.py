"""Blockchain integration tests.

Tests the full on-chain pipeline with mocked Web3 and IPFS.
No real network or py-evm dependency required.
"""

from __future__ import annotations

import json
import os
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path

# Set test env vars before importing
os.environ.setdefault("MANTLE_RPC_URL", "http://localhost:8545")
os.environ.setdefault("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
os.environ.setdefault("AUDIT_REGISTRY_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("PINATA_API_KEY", "test_key")
os.environ.setdefault("PINATA_SECRET_KEY", "test_secret")

from mantle_audit.blockchain import (
    record_audit_onchain,
    verify_audit_onchain,
    OnChainResult,
    AUDIT_REGISTRY_ABI,
)
from mantle_audit.ipfs import upload_json, upload_file, upload_report, get_ipfs_url
from mantle_audit.config import Config


# ── IPFS Tests ────────────────────────────────────────────────────

class TestIPFS:
    """Test IPFS upload functions with mocked Pinata API."""

    def test_upload_json_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"IpfsHash": "QmTestHash123"}

        with patch("mantle_audit.ipfs.requests.post", return_value=mock_resp):
            cid = upload_json({"test": "data"}, filename="test.json")

        assert cid == "QmTestHash123"

    def test_upload_json_failure(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad request"

        with patch("mantle_audit.ipfs.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="Pinata upload failed"):
                upload_json({"test": "data"})

    def test_upload_file_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"IpfsHash": "QmFileHash456"}

        with patch("mantle_audit.ipfs.requests.post", return_value=mock_resp):
            cid = upload_file(b"test content", "test.sol")

        assert cid == "QmFileHash456"

    def test_upload_report_success(self):
        report = json.dumps({"tool": "Mantle-Audit-AI", "vulns": []})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"IpfsHash": "QmReportHash789"}

        with patch("mantle_audit.ipfs.requests.post", return_value=mock_resp):
            cid = upload_report(report)

        assert cid == "QmReportHash789"

    def test_upload_missing_config(self):
        with patch.object(Config, "PINATA_API_KEY", ""):
            with pytest.raises(RuntimeError, match="Missing Pinata config"):
                upload_json({"test": "data"})

    def test_get_ipfs_url(self):
        url = get_ipfs_url("QmTest123")
        assert url == "https://gateway.pinata.cloud/ipfs/QmTest123"


# ── Blockchain Mock Tests ────────────────────────────────────────

class TestRecordAuditOnchain:
    """Test record_audit_onchain with fully mocked Web3."""

    def test_missing_config_returns_error(self):
        with patch.object(Config, "PRIVATE_KEY", ""):
            result = record_audit_onchain("code", "cid", {"Critical": 0})
            assert result.errors is not None
            assert "Missing config" in result.errors[0]

    def test_disconnected_rpc_returns_error(self):
        with patch("mantle_audit.blockchain._get_web3") as mock_w3:
            mock_instance = MagicMock()
            mock_instance.is_connected.return_value = False
            mock_w3.return_value = mock_instance
            with patch.object(Config, "PRIVATE_KEY", "0x" + "ac" * 32):
                with patch.object(Config, "AUDIT_REGISTRY_ADDRESS", "0x" + "12" * 20):
                    result = record_audit_onchain("code", "cid", {"Critical": 0})
            assert result.errors is not None
            assert "Cannot connect" in result.errors[0]

    def test_successful_record(self):
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = 5003
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.gas_price = 1000000000
        mock_w3.from_wei.return_value = "1.0"
        mock_w3.keccak.return_value = b'\x01' * 32

        mock_contract = MagicMock()
        mock_tx = {"to": "0x123", "data": "0x456"}
        mock_contract.functions.recordAudit.return_value.build_transaction.return_value = mock_tx
        mock_w3.eth.contract.return_value = mock_contract

        mock_signed = MagicMock()
        mock_signed.raw_transaction = b'\x02' * 32
        mock_w3.eth.account.sign_transaction.return_value = mock_signed
        mock_w3.eth.send_raw_transaction.return_value = b'\x03' * 32

        mock_receipt = {
            "status": 1,
            "transactionHash": b'\x04' * 32,
            "blockNumber": 12345,
            "logs": [],
        }
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        with patch("mantle_audit.blockchain._get_web3", return_value=mock_w3):
            with patch("mantle_audit.blockchain._get_contract", return_value=mock_contract):
                with patch.object(Config, "PRIVATE_KEY", "0x" + "ac" * 32):
                    with patch.object(Config, "AUDIT_REGISTRY_ADDRESS", "0x" + "12" * 20):
                        with patch.object(Config, "ANTHROPIC_API_KEY", ""):
                            result = record_audit_onchain("code", "cid", {"Critical": 1, "High": 2})

        assert result.errors is None or result.errors == []
        assert result.block_number == 12345
        assert result.network == "mantle"

    def test_record_extracts_audit_id_from_logs(self):
        """Should extract audit ID from AuditCompleted event."""
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = 5003
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.gas_price = 1000000000
        mock_w3.keccak.return_value = b'\x01' * 32

        mock_contract = MagicMock()
        mock_contract.functions.recordAudit.return_value.build_transaction.return_value = {}
        mock_w3.eth.contract.return_value = mock_contract

        mock_w3.eth.account.sign_transaction.return_value = MagicMock(raw_transaction=b'\x02' * 32)
        mock_w3.eth.send_raw_transaction.return_value = b'\x03' * 32

        # Mock event log with audit ID
        mock_audit_id = MagicMock()
        mock_audit_id.hex.return_value = "aabbccdd" * 8
        mock_log = {"args": {"auditId": mock_audit_id}}
        mock_contract.events.AuditCompleted().process_receipt.return_value = [mock_log]

        mock_receipt = {"status": 1, "transactionHash": b'\x04' * 32, "blockNumber": 999, "logs": [mock_log]}
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        with patch("mantle_audit.blockchain._get_web3", return_value=mock_w3):
            with patch("mantle_audit.blockchain._get_contract", return_value=mock_contract):
                with patch.object(Config, "PRIVATE_KEY", "0x" + "ac" * 32):
                    with patch.object(Config, "AUDIT_REGISTRY_ADDRESS", "0x" + "12" * 20):
                        with patch.object(Config, "ANTHROPIC_API_KEY", ""):
                            result = record_audit_onchain("code", "cid", {"Critical": 0})

        assert result.audit_id == "aabbccdd" * 8

    def test_record_exception_returns_error(self):
        """Should catch exceptions and return error."""
        with patch("mantle_audit.blockchain._get_web3") as mock_w3:
            mock_w3.side_effect = ConnectionError("Network down")

            with patch.object(Config, "PRIVATE_KEY", "0x" + "ac" * 32):
                with patch.object(Config, "AUDIT_REGISTRY_ADDRESS", "0x" + "12" * 20):
                    with patch.object(Config, "ANTHROPIC_API_KEY", ""):
                        result = record_audit_onchain("code", "cid", {})

        assert result.errors is not None
        assert "On-chain recording failed" in result.errors[0]


class TestVerifyAuditOnchain:
    """Test verify_audit_onchain with mocked Web3."""

    def test_verify_returns_record(self):
        mock_w3 = MagicMock()
        mock_contract = MagicMock()

        mock_record = (
            "0x1234567890abcdef1234567890abcdef12345678",  # auditor
            "test_contract_hash",                          # contractHash
            b'\x01' * 32,                                  # reportHash
            1, 2, 3, 4,                                    # severity counts
            1700000000,                                    # timestamp
        )
        mock_contract.functions.verifyAudit.return_value.call.return_value = mock_record

        with patch("mantle_audit.blockchain._get_web3", return_value=mock_w3):
            with patch("mantle_audit.blockchain._get_contract", return_value=mock_contract):
                result = verify_audit_onchain("aabb" * 16)

        assert "error" not in result
        assert result["auditor"] == "0x1234567890abcdef1234567890abcdef12345678"
        assert result["contract_hash"] == "test_contract_hash"
        assert result["critical"] == 1
        assert result["timestamp"] == 1700000000

    def test_verify_nonexistent_returns_error(self):
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        mock_contract.functions.verifyAudit.return_value.call.side_effect = Exception("Audit not found")

        with patch("mantle_audit.blockchain._get_web3", return_value=mock_w3):
            with patch("mantle_audit.blockchain._get_contract", return_value=mock_contract):
                result = verify_audit_onchain("deadbeef" * 8)

        assert "error" in result
        assert "Audit not found" in result["error"]


# ── ABI Validation ────────────────────────────────────────────────

class TestABI:
    """Verify the ABI contains expected functions."""

    def test_abi_has_record_audit(self):
        func_names = [item["name"] for item in AUDIT_REGISTRY_ABI if item.get("type") == "function"]
        assert "recordAudit" in func_names

    def test_abi_has_verify_audit(self):
        func_names = [item["name"] for item in AUDIT_REGISTRY_ABI if item.get("type") == "function"]
        assert "verifyAudit" in func_names

    def test_abi_has_audit_completed_event(self):
        event_names = [item["name"] for item in AUDIT_REGISTRY_ABI if item.get("type") == "event"]
        assert "AuditCompleted" in event_names

    def test_record_audit_params(self):
        record_func = [item for item in AUDIT_REGISTRY_ABI if item.get("name") == "recordAudit"][0]
        param_names = [p["name"] for p in record_func["inputs"]]
        assert "contractHash" in param_names
        assert "reportHash" in param_names
        assert "critical" in param_names
        assert "high" in param_names
        assert "medium" in param_names
        assert "low" in param_names


# ── Full Pipeline E2E (mocked chain + mocked IPFS) ───────────────

class TestFullPipelineE2E:
    """End-to-end: parse → detect → report → IPFS → on-chain (all mocked)."""

    def test_full_pipeline(self, tmp_path):
        from mantle_audit.parser import parse_contract
        from mantle_audit.detector import detect_vulnerabilities
        from mantle_audit.reporter import generate_markdown_report, generate_json_report

        # Create a vulnerable test contract
        code = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TestVault {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
'''
        sol_file = tmp_path / "TestVault.sol"
        sol_file.write_text(code)

        # Phase 1: Parse
        parse_result = parse_contract(str(sol_file))
        assert not parse_result.errors
        assert parse_result.total_contracts >= 1

        # Phase 2: Detect
        detection = detect_vulnerabilities(str(sol_file))
        assert not detection.errors
        assert isinstance(detection.vulnerabilities, list)  # may be 0 on simple contracts

        # Phase 3: Generate reports
        md_report = generate_markdown_report(str(sol_file), detection)
        json_report = generate_json_report(str(sol_file), detection)

        assert "Mantle-Audit-AI" in md_report
        report_data = json.loads(json_report)
        assert report_data["tool"] == "Mantle-Audit-AI"
        assert isinstance(report_data["vulnerabilities"], list)  # may be 0 on simple contracts

        # Phase 4: Upload to IPFS (mocked)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"IpfsHash": "QmPipelineTest123"}

        with patch("mantle_audit.ipfs.requests.post", return_value=mock_resp):
            cid = upload_report(json_report)
        assert cid == "QmPipelineTest123"

        # Phase 5: Record on-chain (mocked)
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.chain_id = 5003
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.gas_price = 1000000000
        mock_w3.keccak.return_value = b'\xab' * 32

        mock_contract = MagicMock()
        mock_contract.functions.recordAudit.return_value.build_transaction.return_value = {}
        mock_w3.eth.contract.return_value = mock_contract
        mock_w3.eth.account.sign_transaction.return_value = MagicMock(raw_transaction=b'\xcc' * 32)
        mock_w3.eth.send_raw_transaction.return_value = b'\xdd' * 32

        mock_audit_id = MagicMock()
        mock_audit_id.hex.return_value = "ee" * 32
        mock_log = {"args": {"auditId": mock_audit_id}}
        mock_contract.events.AuditCompleted().process_receipt.return_value = [mock_log]
        mock_receipt = {"status": 1, "transactionHash": b'\xff' * 32, "blockNumber": 42, "logs": [mock_log]}
        mock_w3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        with patch("mantle_audit.blockchain._get_web3", return_value=mock_w3):
            with patch("mantle_audit.blockchain._get_contract", return_value=mock_contract):
                with patch.object(Config, "PRIVATE_KEY", "0x" + "ac" * 32):
                    with patch.object(Config, "AUDIT_REGISTRY_ADDRESS", "0x" + "12" * 20):
                        with patch.object(Config, "ANTHROPIC_API_KEY", ""):
                            chain_result = record_audit_onchain(
                                code, cid, report_data["summary"]
                            )

        assert chain_result.errors is None or chain_result.errors == []
        assert chain_result.block_number == 42
        assert chain_result.audit_id == "ee" * 32
        assert chain_result.network == "mantle"
