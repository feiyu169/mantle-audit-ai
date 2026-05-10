# Mantle-Audit-AI

> AI-powered smart contract audit agent for the Mantle ecosystem.

[![Track 5 - AI DevTools](https://img.shields.io/badge/Track-5%20AI%20DevTools-blue)](https://dorahacks.io/hackathon/mantleturingtesthackathon2026)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-green.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is Mantle-Audit-AI?

Mantle-Audit-AI is a CLI tool that uses AI to audit Solidity smart contracts for security vulnerabilities, with deep integration into the Mantle L2 blockchain.

**Key features:**
- 🔍 **3-layer detection**: Slither static analysis + AI deep analysis + Mantle-specific rules
- ⛓️ **On-chain audit records**: Results stored permanently on Mantle blockchain
- 🆔 **ERC-8004 agent identity**: Registered AI agent with on-chain reputation
- 📊 **Human vs AI comparison**: Benchmarks AI analysis against static tools
- 📝 **Multi-format reports**: JSON, Markdown, HTML, SARIF

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Audit a contract
mantle-audit audit --file contracts/MyToken.sol

# Audit with on-chain recording
mantle-audit audit --file contracts/MyToken.sol --onchain

# CI/CD mode
mantle-audit audit --file contracts/MyToken.sol --ci --fail-on HIGH

# Skip LLM (faster, free)
mantle-audit audit --file contracts/MyToken.sol --skip-llm
```

## Architecture

```
User Input (.sol)
    ↓
Phase 1: Slither Static Analysis (100+ detectors)
    ↓
Phase 2: LLM Deep Analysis (Claude, business logic understanding)
    ↓
Phase 3: Report Generation (JSON/Markdown/HTML/SARIF)
    ↓
Phase 4: On-Chain Integration
  ├─ Pinata IPFS (report storage)
  ├─ Mantle AuditRegistry (audit record)
  └─ Ethereum ERC-8004 (agent identity)
    ↓
Output: Audit Report + On-Chain Proof
```

## Mantle-Specific Detection

| Rule | Risk |
|------|------|
| MANTLE-001 | mETH interaction without slashing protection |
| MANTLE-002 | RWA token (USDY) compliance violations |
| MANTLE-003 | Cross-domain messenger source validation |
| MANTLE-004 | block.gaslimit assumptions on L2 |
| MANTLE-005 | tx.gasprice L2 fee model differences |

## Configuration

Copy `.env.example` to `.env` and fill in:

```bash
# Required for LLM analysis
ANTHROPIC_API_KEY=sk-ant-...

# Required for on-chain recording
PRIVATE_KEY=0x...
AUDIT_REGISTRY_ADDRESS=0x...

# Required for IPFS upload
PINATA_API_KEY=...
PINATA_SECRET_KEY=...
```

## Project Structure

```
mantle-audit-ai/
├── src/mantle_audit/
│   ├── cli.py          # Command-line interface
│   ├── parser.py       # Solidity code parser (Slither API)
│   ├── detector.py     # Vulnerability detector (Slither + Mantle rules)
│   ├── llm_agent.py    # LLM deep analysis (Claude)
│   ├── reporter.py     # Report generator (JSON/Markdown/HTML)
│   ├── blockchain.py   # On-chain integration (Web3.py)
│   ├── ipfs.py         # Pinata IPFS upload
│   └── config.py       # Configuration
├── contracts/
│   └── AuditRegistry.sol  # On-chain audit storage
├── tests/
└── pyproject.toml
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Lint
ruff check src/ tests/
```

## The Turing Test Hackathon 2026

This project is built for **Track 5: AI DevTools** of the [Mantle Turing Test Hackathon 2026](https://dorahacks.io/hackathon/mantleturingtesthackathon2026).

**What makes it different:**
1. **On-chain audit records** — every audit result is permanently stored on Mantle
2. **ERC-8004 integration** — the audit agent has a verifiable on-chain identity
3. **Mantle ecosystem awareness** — understands mETH, RWA tokens, cross-domain messaging
4. **Human vs AI benchmarking** — directly addresses the "Turing Test" theme

## License

MIT
