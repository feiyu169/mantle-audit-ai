"""Blockchain integration — AuditRegistry + ERC-8004."""

from __future__ import annotations

import json
from dataclasses import dataclass

from eth_account import Account
from web3 import Web3

from .config import Config

# Minimal ABI for AuditRegistry.recordAudit()
AUDIT_REGISTRY_ABI = json.loads("""[
    {
        "inputs": [
            {"name": "contractHash", "type": "string"},
            {"name": "reportHash", "type": "bytes32"},
            {"name": "critical", "type": "uint8"},
            {"name": "high", "type": "uint8"},
            {"name": "medium", "type": "uint8"},
            {"name": "low", "type": "uint8"}
        ],
        "name": "recordAudit",
        "outputs": [{"name": "auditId", "type": "bytes32"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "auditId", "type": "bytes32"}],
        "name": "verifyAudit",
        "outputs": [
            {
                "components": [
                    {"name": "auditor", "type": "address"},
                    {"name": "contractHash", "type": "string"},
                    {"name": "reportHash", "type": "bytes32"},
                    {"name": "criticalCount", "type": "uint8"},
                    {"name": "highCount", "type": "uint8"},
                    {"name": "mediumCount", "type": "uint8"},
                    {"name": "lowCount", "type": "uint8"},
                    {"name": "timestamp", "type": "uint256"}
                ],
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": false,
        "inputs": [
            {"indexed": true, "name": "auditId", "type": "bytes32"},
            {"indexed": true, "name": "auditor", "type": "address"},
            {"indexed": false, "name": "contractHash", "type": "string"},
            {"indexed": false, "name": "reportHash", "type": "bytes32"}
        ],
        "name": "AuditCompleted",
        "type": "event"
    }
]""")


@dataclass
class OnChainResult:
    ipfs_cid: str = ""
    tx_hash: str = ""
    audit_id: str = ""
    block_number: int = 0
    contract_address: str = ""
    network: str = "mantle"
    errors: list[str] | None = None

    def to_dict(self) -> dict:
        return {
            "ipfs_cid": self.ipfs_cid,
            "tx_hash": self.tx_hash,
            "audit_id": self.audit_id,
            "block_number": self.block_number,
            "contract_address": self.contract_address,
            "network": self.network,
            "errors": self.errors or [],
        }


def _get_web3() -> Web3:
    """Get Web3 instance connected to Mantle."""
    return Web3(Web3.HTTPProvider(Config.MANTLE_RPC_URL))


def _get_contract(w3: Web3):
    """Get AuditRegistry contract instance."""
    if not Config.AUDIT_REGISTRY_ADDRESS:
        raise RuntimeError("AUDIT_REGISTRY_ADDRESS not configured")
    return w3.eth.contract(
        address=Web3.to_checksum_address(Config.AUDIT_REGISTRY_ADDRESS),
        abi=AUDIT_REGISTRY_ABI,
    )


def record_audit_onchain(
    contract_code: str,
    ipfs_cid: str,
    summary: dict[str, int],
) -> OnChainResult:
    """Record an audit result on the Mantle blockchain.

    Args:
        contract_code: Original Solidity source (for hashing).
        ipfs_cid: IPFS CID of the audit report.
        summary: Vulnerability counts by severity.

    Returns:
        OnChainResult with tx hash and audit ID.
    """
    result = OnChainResult(ipfs_cid=ipfs_cid, network="mantle")

    missing = Config.validate(require_llm=False, require_chain=True)
    if missing:
        result.errors = [f"Missing config: {', '.join(missing)}"]
        return result

    try:
        w3 = _get_web3()
        if not w3.is_connected():
            result.errors = ["Cannot connect to Mantle RPC"]
            return result

        contract = _get_contract(w3)
        account = Account.from_key(Config.PRIVATE_KEY)

        # Compute contract hash
        contract_hash = Web3.keccak(text=contract_code).hex()

        # Convert CID to bytes32 (use first 32 bytes of hex-encoded CID)
        cid_bytes = Web3.keccak(text=ipfs_cid)  # 32 bytes hash of CID

        # Build transaction
        nonce = w3.eth.get_transaction_count(account.address)
        tx = contract.functions.recordAudit(
            contract_hash,
            cid_bytes,
            summary.get("Critical", 0),
            summary.get("High", 0),
            summary.get("Medium", 0),
            summary.get("Low", 0),
        ).build_transaction({
            "from": account.address,
            "nonce": nonce,
            "gas": 500000,
            "gasPrice": w3.eth.gas_price,
            "chainId": w3.eth.chain_id,  # auto-detect from RPC
        })

        # Sign and send
        signed = w3.eth.account.sign_transaction(tx, Config.PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        result.tx_hash = receipt["transactionHash"].hex()
        result.block_number = receipt["blockNumber"]
        result.contract_address = Config.AUDIT_REGISTRY_ADDRESS

        # Extract audit ID from event logs
        if receipt["logs"]:
            try:
                logs = contract.events.AuditCompleted().process_receipt(receipt)
                if logs:
                    result.audit_id = logs[0]["args"]["auditId"].hex()
            except Exception:
                pass

    except Exception as e:
        result.errors = [f"On-chain recording failed: {e}"]

    return result


def verify_audit_onchain(audit_id_hex: str) -> dict:
    """Verify an audit record on-chain.

    Args:
        audit_id_hex: The audit ID as hex string.

    Returns:
        Audit record dict or error.
    """
    try:
        w3 = _get_web3()
        contract = _get_contract(w3)
        audit_id = bytes.fromhex(audit_id_hex.replace("0x", ""))
        record = contract.functions.verifyAudit(audit_id).call()
        return {
            "auditor": record[0],
            "contract_hash": record[1],
            "report_hash": record[2].hex(),
            "critical": record[3],
            "high": record[4],
            "medium": record[5],
            "low": record[6],
            "timestamp": record[7],
        }
    except Exception as e:
        return {"error": str(e)}
