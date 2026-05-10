"""Configuration management."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(_env_path)


class Config:
    """Application configuration from environment variables."""

    # LLM
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_BASE_URL: str = os.getenv("ANTHROPIC_BASE_URL", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")

    # IPFS (Pinata)
    PINATA_API_KEY: str = os.getenv("PINATA_API_KEY", "")
    PINATA_SECRET_KEY: str = os.getenv("PINATA_SECRET_KEY", "")

    # Blockchain
    MANTLE_RPC_URL: str = os.getenv("MANTLE_RPC_URL", "https://rpc.mantle.xyz")
    ETH_RPC_URL: str = os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com")
    PRIVATE_KEY: str = os.getenv("PRIVATE_KEY", "")

    # Contract addresses
    AUDIT_REGISTRY_ADDRESS: str = os.getenv("AUDIT_REGISTRY_ADDRESS", "")

    # ERC-8004 official contracts (Ethereum Mainnet)
    ERC8004_IDENTITY_REGISTRY: str = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
    ERC8004_REPUTATION_REGISTRY: str = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"

    # CLI
    DEFAULT_OUTPUT_FORMAT: str = "markdown"
    CI_MODE: bool = False

    @classmethod
    def validate(cls, *, require_llm: bool = True, require_chain: bool = False) -> list[str]:
        """Return list of missing config items."""
        missing: list[str] = []
        if require_llm and not cls.ANTHROPIC_API_KEY:
            missing.append("ANTHROPIC_API_KEY")
        if require_chain:
            if not cls.PRIVATE_KEY:
                missing.append("PRIVATE_KEY")
            if not cls.AUDIT_REGISTRY_ADDRESS:
                missing.append("AUDIT_REGISTRY_ADDRESS")
        return missing
