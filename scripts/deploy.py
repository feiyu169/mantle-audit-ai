"""Deploy AuditRegistry.sol to Mantle Sepolia testnet."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from web3 import Web3
from eth_account import Account

# Load project config
sys.path.insert(0, str(Path(__file__).parent / "src"))
from mantle_audit.config import Config


def get_solc_output(sol_path: Path) -> dict:
    """Compile Solidity file with solc and return output."""
    import subprocess
    import tempfile

    solc_path = Path.home() / ".local/bin/solc"
    if not solc_path.exists():
        # Try system solc
        solc_path = Path("solc")

    result = subprocess.run(
        [str(solc_path), "--combined-json", "abi,bin", str(sol_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        raise RuntimeError(f"solc compilation failed:\n{result.stderr}")

    return json.loads(result.stdout)


def deploy():
    """Deploy AuditRegistry to Mantle Sepolia."""
    print("=" * 60)
    print("  Deploying AuditRegistry to Mantle Sepolia")
    print("=" * 60)

    # Connect
    w3 = Web3(Web3.HTTPProvider(Config.MANTLE_RPC_URL))
    if not w3.is_connected():
        print("ERROR: Cannot connect to Mantle RPC")
        return

    print(f"✅ Connected to Mantle Sepolia (Chain ID: {w3.eth.chain_id})")

    # Account
    account = Account.from_key(Config.PRIVATE_KEY)
    balance = w3.eth.get_balance(account.address)
    balance_eth = w3.from_wei(balance, "ether")
    print(f"✅ Account: {account.address}")
    print(f"✅ Balance: {balance_eth} MNT")

    if balance == 0:
        print("\n❌ Zero balance. Please fund your wallet first.")
        print("   Faucet: https://faucet.sepolia.mantle.xyz")
        return

    # Compile
    sol_path = Path(__file__).parent / "contracts" / "AuditRegistry.sol"
    print(f"\n📦 Compiling {sol_path.name}...")
    compiled = get_solc_output(sol_path)

    # Find contract in output
    contract_key = None
    for key in compiled["contracts"]:
        if "AuditRegistry" in key:
            contract_key = key
            break

    if not contract_key:
        print("ERROR: AuditRegistry not found in compilation output")
        return

    contract_data = compiled["contracts"][contract_key]
    abi_raw = contract_data["abi"]
    abi = abi_raw if isinstance(abi_raw, list) else json.loads(abi_raw)
    bytecode = contract_data["bin"]

    print(f"✅ Compiled: {len(bytecode)} bytes bytecode, {len(abi)} ABI entries")

    # Deploy
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)

    nonce = w3.eth.get_transaction_count(account.address)
    print(f"\n🚀 Deploying... (nonce: {nonce})")

    tx = contract.constructor().build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 1000000,
        "gasPrice": w3.eth.gas_price,
        "chainId": 5003,
    })

    signed = w3.eth.account.sign_transaction(tx, Config.PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"📤 TX Hash: {tx_hash.hex()}")

    print("⏳ Waiting for confirmation...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt["status"] == 1:
        contract_address = receipt["contractAddress"]
        print(f"\n✅ Deployment successful!")
        print(f"   Contract Address: {contract_address}")
        print(f"   Block Number: {receipt['blockNumber']}")
        print(f"   Gas Used: {receipt['gasUsed']}")
        print(f"\n   Explorer: https://explorer.sepolia.mantle.xyz/address/{contract_address}")

        # Save deployment info
        deploy_info = {
            "network": "mantle-sepolia",
            "chainId": 5003,
            "contractAddress": contract_address,
            "deployer": account.address,
            "txHash": tx_hash.hex(),
            "blockNumber": receipt["blockNumber"],
            "gasUsed": receipt["gasUsed"],
        }

        deploy_path = Path(__file__).parent / "deployments" / "mantle-sepolia.json"
        deploy_path.parent.mkdir(parents=True, exist_ok=True)
        deploy_path.write_text(json.dumps(deploy_info, indent=2))
        print(f"\n   Deployment info saved to: {deploy_path}")

        return contract_address
    else:
        print(f"\n❌ Deployment failed! Status: {receipt['status']}")
        return None


if __name__ == "__main__":
    deploy()
