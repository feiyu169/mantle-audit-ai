# 🛡️ Mantle-Audit-AI

> *AI-powered smart contract audit agent for the Mantle ecosystem — parse, detect, analyze, and publish audit results on-chain.*

[![Track 5: AI DevTools](https://img.shields.io/badge/Track-5%20AI%20DevTools-purple?style=flat-square&logo=dorahacks)](https://dorahacks.io/hackathon/mantleturingtesthackathon2026)
[![Turing Test Hackathon 2026](https://img.shields.io/badge/Turing%20Test-2026-blue?style=flat-square)](https://dorahacks.io/hackathon/mantleturingtesthackathon2026)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-brightgreen?style=flat-square&logo=python)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)
[![Slither](https://img.shields.io/badge/Slither-100%2B%20detectors-blueviolet?style=flat-square)](https://github.com/crytic/slither)
[![Claude](https://img.shields.io/badge/LLM-Claude%20Sonnet%204-orange?style=flat-square)](https://www.anthropic.com)
[![Mantle](https://img.shields.io/badge/Mantle-L2-00D4AA?style=flat-square&logo=ethereum)](https://www.mantle.xyz)
[![IPFS](https://img.shields.io/badge/IPFS-Pinata-65C2CB?style=flat-square&logo=ipfs)](https://www.pinata.cloud)
[![Web3.py](https://img.shields.io/badge/Web3.py-7.x-3776AB?style=flat-square)](https://web3py.readthedocs.io/)
[![CLI](https://img.shields.io/badge/CLI-Click-555?style=flat-square)](https://click.palletsprojects.com/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Ready-success?style=flat-square)](https://github.com/)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Mantle-Specific Detection Rules](#-mantle-specific-detection-rules)
- [Human vs AI Benchmark](#-human-vs-ai-benchmark)
- [Tech Stack](#️-tech-stack)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [CI/CD Integration](#-cicd-integration)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)
- [Hackathon Info](#-hackathon-info)

---

## 🔍 Overview

**Mantle-Audit-AI** is a CLI-first smart contract security audit tool purpose-built for the **Mantle L2 ecosystem**. It combines **Slither static analysis** (100+ detectors) with **15 Mantle-specific vulnerability patterns** and **LLM-powered deep analysis** (Claude Sonnet 4) to produce professional audit reports. Results can be uploaded to **IPFS** via Pinata and permanently recorded on the **Mantle blockchain** through the `AuditRegistry.sol` contract — creating an immutable, verifiable audit trail.

Built for **Track 5: AI DevTools** of the **The Turing Test Hackathon 2026**, this project directly addresses the "Turing Test" theme by benchmarking AI analysis against traditional static analysis tools — quantifying exactly how much value AI adds to the security audit pipeline.

---

## ✨ Key Features

- **🔬 3-Layer Detection Pipeline** — Slither static analysis (100+ detectors) → 15 Mantle-specific pattern rules → LLM deep analysis with false positive filtering
- **⛓️ On-Chain Audit Publishing** — Record audit results permanently on Mantle via `AuditRegistry.sol` with severity counts and IPFS-linked reports
- **📡 IPFS Report Storage** — Upload full audit reports to IPFS via Pinata, generating immutable content-addressed references
- **🤖 Human vs AI Benchmark** — Built-in `benchmark` command that compares Slither-only results against Slither + LLM, quantifying AI's contribution (new findings found, false positives flagged, confidence distribution)
- **🏛️ 15 Mantle-Specific Rules** — Custom detection patterns for mETH, USDY, L2 cross-domain messaging, Mantle-native DEX protocols (Merchant Moe, Agni Finance, MantleSwap), L1Block usage, Mantle precompiles, OP Stack-specific delegatecall/selfdestruct behavior, and more
- **📊 Multi-Format Reports** — Markdown, JSON, and HTML (dark-themed with severity bar charts)
- **⚡ CI/CD Native** — `--ci` mode with configurable `--fail-on` thresholds (CRITICAL/HIGH/MEDIUM/LOW), non-zero exit codes for pipeline integration
- **🖥️ CLI-First Design** — Rich terminal output with progress spinners, severity summary tables, and status indicators via the `rich` library
- **🧪 Test Suite** — Comprehensive pytest tests for Mantle patterns, Slither integration, parser, reporter, blockchain, and end-to-end pipeline

---

## 🏗️ Architecture

The audit pipeline flows through six distinct phases:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     MANTLE-AUDIT-AI PIPELINE                               │
└────────────────────────────────────────────────────────────────────────────┘

                               ┌─────────────┐
                               │  Solidity .sol │
                               └──────┬───────┘
                                      │
                                      ▼
                           ┌─────────────────────┐
                           │   PHASE 1: PARSE    │
                           │  (Slither API)      │
                           │  Contracts, funcs,  │
                           │  state vars, ABIs   │
                           └──────────┬──────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────┐
                    │      PHASE 2: DETECT             │
                    │  ┌──────────────────────────┐   │
                    │  │ 2a. Slither Static       │   │
                    │  │  100+ built-in detectors │   │
                    │  └──────────┬───────────────┘   │
                    │  ┌──────────────────────────┐   │
                    │  │ 2b. Mantle Rules Engine  │   │
                    │  │ 15 Mantle-specific       │   │
                    │  │ pattern matchers         │   │
                    │  └──────────┬───────────────┘   │
                    └──────────────┼──────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────┐
                    │     PHASE 3: LLM AGENT          │
                    │  ┌──────────────────────────┐   │
                    │  │ Claude Sonnet 4          │   │
                    │  │ • True/false positive    │   │
                    │  │ • Severity re-evaluation │   │
                    │  │ • Attack path analysis   │   │
                    │  │ • Fix recommendations    │   │
                    │  • Mantle ecosystem aware   │   │
                    │  └──────────────────────────┘   │
                    └──────────────┬──────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────┐
                    │     PHASE 4: REPORTER            │
                    │  ┌──────────────────────────┐   │
                    │  │ Markdown  │  JSON  │ HTML │   │
                    │  │ (severity tables, bar    │   │
                    │  │  charts, expandable      │   │
                    │  │  vulnerability details)   │   │
                    │  └──────────────────────────┘   │
                    └──────────────┬──────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────┐
                    │     PHASE 5: IPFS               │
                    │  Upload report JSON to Pinata   │
                    │  Returns immutable CID          │
                    └──────────────┬──────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────┐
                    │     PHASE 6: ON-CHAIN           │
                    │  AuditRegistry.sol (Mantle L2)  │
                    │  ┌─────────────────────────┐    │
                    │  │ recordAudit(            │    │
                    │  │   contractHash,         │    │
                    │  │   reportHash (IPFS),    │    │
                    │  │   critical, high,       │    │
                    │  │   medium, low           │    │
                    │  │ ) → auditId + event     │    │
                    │  └─────────────────────────┘    │
                    └──────────────┬──────────────────┘
                                   │
                                   ▼
                         ┌─────────────────┐
                         │  FINAL OUTPUT    │
                         │  • Audit Report  │
                         │  • IPFS CID      │
                         │  • TX Hash       │
                         │  • Audit ID      │
                         └─────────────────┘
```

---

## ⚙️ Mantle-Specific Detection Rules

What makes Mantle-Audit-AI unique: **15 custom detection rules** purpose-built for the Mantle L2 ecosystem. These rules identify vulnerabilities that generic Solidity auditors would miss — from mETH staking slashing risks to OP Stack-specific `delegatecall` semantics.

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| **MANTLE-001** | `mETH` | 🟡 Medium | Contract interacts with mETH (Mantle Staked ETH). Ensure slashing scenarios are handled — mETH staking carries LST-specific risks. |
| **MANTLE-002** | `USDY` | 🟠 High | Contract interacts with USDY (Ondo's USD Yield token). RWA tokens often have transfer restrictions and compliance checks — verify the contract respects these constraints. |
| **MANTLE-003** | `L2CrossDomainMessenger` | 🟡 Medium | Contract uses Mantle's cross-domain messenger. Verify that cross-chain message source is validated and replay protection is in place. |
| **MANTLE-004** | `block.gaslimit` | 🔵 Low | Reliance on block.gaslimit — Mantle L2 has different gas pricing than Ethereum L1. Gas-dependent logic may behave differently on L2. |
| **MANTLE-005** | `tx.gasprice` | 🔵 Low | Use of tx.gasprice — Mantle L2 uses a different fee model. Gas price assumptions from L1 may not hold on Mantle. |
| **MANTLE-006** | `delegatecall` | 🟠 High | Use of delegatecall on Mantle L2. OP Stack delegatecall semantics may differ from L1, especially when calling precompiles. |
| **MANTLE-007** | `selfdestruct` | 🟠 High | Use of selfdestruct — deprecated post-EIP-6780 and may behave differently on Mantle L2. Mantle may not fully support selfdestruct semantics. |
| **MANTLE-008** | `Merchant Moe` / `Agni` / `MantleSwap` | 🟡 Medium | Contract may interact with a Mantle-native DEX. Verify slippage protection, TWAP oracle usage, and liquidity checks. |
| **MANTLE-009** | `L1Block` | 🟡 Medium | Use of L1Block.number or L1Block.timestamp on Mantle L2. These return L1 values which may differ from L2 block context. |
| **MANTLE-010** | `ecrecover` | 🟡 Medium | Use of ecrecover for signature verification. Ensure replay protection across L1/L2 boundaries — signatures valid on L1 may also be valid on L2. |
| **MANTLE-011** | `create2` | 🔵 Low | Use of CREATE2 for deterministic deployment on Mantle L2. Deployments may collide with L1 addresses due to different chain IDs. |
| **MANTLE-012** | `0x0000...0100` (precompile) | 🟡 Medium | Reference to Mantle custom precompile address (0x...0100). Mantle has custom precompiles at different addresses than Ethereum L1. |
| **MANTLE-013** | `MNT` | 🔵 Low | Reference to MNT (Mantle's native token). Contracts assuming ETH as native token may need adaptation for MNT's tokenomics and gas mechanics. |
| **MANTLE-014** | `block.basefee` | 🔵 Low | Use of block.basefee — EIP-1559 fee mechanics differ on Mantle L2. The basefee may not behave identically to L1. |
| **MANTLE-015** | `Chainlink` (oracle) | 🟠 High | Use of a price oracle on Mantle L2. Oracle latency and L1/L2 price divergence can be exploited. Verify staleness checks and deviation thresholds. |

---

## 📊 Human vs AI Benchmark

The `benchmark` command directly addresses the **Turing Test** theme by running a controlled experiment:

1. **Phase 1 — Static Analysis Only**: Runs Slither (100+ detectors) + Mantle rules and records all findings.
2. **Phase 2 — Slither + LLM Analysis**: Sends the same code + all Phase 1 findings to Claude Sonnet 4, which re-evaluates each finding for true vs false positives, re-assesses severity, and discovers any new vulnerabilities Slither missed.
3. **Phase 3 — Comparison**: Generates a side-by-side comparison table:

```
📊 Human vs AI Benchmark
┌──────────────────────────────────────┬────────┐
│ Metric                               │  Value │
├──────────────────────────────────────┼────────┤
│ Slither-only findings                │     12 │
│ LLM true positives (confirmed + new) │     18 │
│ LLM false positives flagged          │      3 │
│ Findings only LLM found (new)        │      7 │
│ Slither findings missed by LLM       │      1 │
│ Overlap (both found)                 │     11 │
│ Improvement (Δ)                      │     +6 │
└──────────────────────────────────────┴────────┘

LLM Confidence Distribution
┌────────────┬───────┐
│ Confidence │ Count │
├────────────┼───────┤
│ High       │    10 │
│ Medium     │     7 │
│ Low        │     1 │
└────────────┴───────┘
```

This benchmark provides **quantifiable evidence** of AI's value in code auditing — a core requirement for the Turing Test theme.

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| **Language** | Python 3.11+ |
| **Static Analysis** | [Slither](https://github.com/crytic/slither) (100+ detectors) |
| **LLM** | [Claude Sonnet 4](https://www.anthropic.com) via Anthropic SDK |
| **Blockchain** | [Web3.py](https://web3py.readthedocs.io/) (Mantle L2, AuditRegistry.sol) |
| **IPFS** | [Pinata](https://www.pinata.cloud) API |
| **CLI Framework** | [Click](https://click.palletsprojects.com/) |
| **Terminal UI** | [Rich](https://github.com/Textualize/rich) |
| **Templating** | [Jinja2](https://jinja.palletsprojects.com/) |
| **Config** | [python-dotenv](https://github.com/theskumar/python-dotenv) |
| **Testing** | [pytest](https://pytest.org/) |
| **Linting** | [Ruff](https://docs.astral.sh/ruff/) |
| **Packaging** | [setuptools](https://setuptools.pypa.io/) + pyproject.toml |

---

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- solc-select (install a Solidity compiler for Slither: `solc-select install 0.8.19 && solc-select use 0.8.19`)
- An [Anthropic API key](https://console.anthropic.com/) (for LLM analysis; optional, tool works without it)
- [Pinata API keys](https://www.pinata.cloud/) (for IPFS upload; optional)
- A Mantle wallet private key (for on-chain recording; optional)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/feiyu169/mantle-audit-ai.git
cd mantle-audit-ai

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your API keys (see Configuration section)
```

### Verify Installation

```bash
mantle-audit --version
# 🔍 Mantle-Audit-AI v0.1.0

mantle-audit --help
# Usage: mantle-audit [OPTIONS] COMMAND [ARGS]...
#   AI-powered smart contract audit tool.
#
# Commands:
#   audit       Audit a Solidity smart contract
#   parse       Parse a Solidity file and show contract structure
#   benchmark   Compare AI analysis vs static analysis on a contract
```

---

## 🚀 Quick Start

### Parse a Contract

View the structure of a Solidity file — contracts, functions, state variables, modifiers, and inheritance:

```bash
mantle-audit parse contracts/MyToken.sol

# Output example:
# Solidity version: pragma solidity ^0.8.19
# Contracts: 2
#
# MyToken (contracts/MyToken.sol)
#   Inherits: ERC20, Ownable
#   State vars: name, symbol, decimals, totalSupply
#   Functions:
#     public nonpayable mint(address,uint256) → void [L42]
#     external view balanceOf(address) → uint256 [L55]
```

### Audit a Contract

Run the full pipeline: parse → detect (Slither + Mantle rules) → LLM analyze → report:

```bash
# Basic audit (requires ANTHROPIC_API_KEY for LLM analysis)
mantle-audit audit --file contracts/MyToken.sol

# Skip LLM analysis (faster, no API key needed)
mantle-audit audit --file contracts/MyToken.sol --skip-llm

# Save report as JSON
mantle-audit audit --file contracts/MyToken.sol --output report.json --format json

# Generate HTML report
mantle-audit audit --file contracts/MyToken.sol --output report.html --format html

# Full pipeline with on-chain + IPFS
mantle-audit audit --file contracts/MyToken.sol --onchain --output report.md

# Use a specific LLM model
mantle-audit audit --file contracts/MyToken.sol --model claude-sonnet-4-20250514
```

### Run Benchmark

Compare Slither-only vs Slither + LLM:

```bash
mantle-audit benchmark --file contracts/MyToken.sol

# Save benchmark results as JSON
mantle-audit benchmark --file contracts/MyToken.sol --output benchmark.json
```

### CI/CD Mode

Integrate audits into your CI pipeline — non-zero exit code if findings exceed threshold:

```bash
# Fail on any HIGH+ vulnerability
mantle-audit audit --file contracts/MyToken.sol --ci --fail-on HIGH

# Fail on any CRITICAL vulnerability
mantle-audit audit --file contracts/MyToken.sol --ci --fail-on CRITICAL

# In CI script (e.g., GitHub Actions)
- name: Audit contract
  run: |
    mantle-audit audit --file contracts/MyToken.sol --ci --fail-on HIGH
    # Exit code 1 if HIGH+ vulnerabilities found
```

---

## 🔧 Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

```bash
# ── LLM Configuration ───────────────────────────────────
# Required for AI deep analysis. Get one at https://console.anthropic.com/
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxx
# Optional: custom API base URL (for proxy or self-hosted)
ANTHROPIC_BASE_URL=
# LLM model (default: claude-sonnet-4-20250514)
LLM_MODEL=claude-sonnet-4-20250514

# ── IPFS Configuration (Pinata) ─────────────────────────
# Required for uploading reports to IPFS
# Get keys at https://app.pinata.cloud/developers/api-keys
PINATA_API_KEY=xxxxxxxxxxxx
PINATA_SECRET_KEY=xxxxxxxxxxxx

# ── Blockchain Configuration ────────────────────────────
# Mantle RPC endpoint (default: public Mantle RPC)
MANTLE_RPC_URL=https://rpc.mantle.xyz
# Optional: Ethereum RPC for ERC-8004 identity registry
ETH_RPC_URL=https://eth.llamarpc.com
# Wallet private key (for signing on-chain transactions)
PRIVATE_KEY=0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
# Deployed AuditRegistry contract address
AUDIT_REGISTRY_ADDRESS=0xYourDeployedContractAddress
```

### Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | For LLM | — | Anthropic API key for Claude |
| `ANTHROPIC_BASE_URL` | No | — | Custom Anthropic API base URL |
| `LLM_MODEL` | No | `claude-sonnet-4-20250514` | LLM model identifier |
| `PINATA_API_KEY` | For IPFS | — | Pinata API key |
| `PINATA_SECRET_KEY` | For IPFS | — | Pinata secret key |
| `MANTLE_RPC_URL` | No | `https://rpc.mantle.xyz` | Mantle L2 RPC endpoint |
| `ETH_RPC_URL` | No | `https://eth.llamarpc.com` | Ethereum L1 RPC endpoint |
| `PRIVATE_KEY` | For chain | — | Wallet private key for signing txs |
| `AUDIT_REGISTRY_ADDRESS` | For chain | — | Deployed `AuditRegistry.sol` address |

---

## 🤖 CI/CD Integration

Mantle-Audit-AI is designed to be CI/CD-native. The `--ci` flag enables pipeline-friendly behavior:

- **Exit codes**: 0 = pass, 1 = failed (findings above threshold)
- **Configurable thresholds**: `--fail-on HIGH` (default), `--fail-on MEDIUM`, etc.
- **False positive aware**: LLM-flagged false positives are excluded from CI failure checks
- **Silent mode**: Use `--format json --output report.json` for machine-readable output

### GitHub Actions Example

```yaml
name: Smart Contract Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install solc
        run: |
          pip install solc-select
          solc-select install 0.8.19
          solc-select use 0.8.19

      - name: Install mantle-audit-ai
        run: pip install -e ".[dev]"

      - name: Run Audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          mantle-audit audit --file contracts/MyToken.sol \
            --ci --fail-on HIGH \
            --format json --output audit-report.json
```

---

## 📁 Project Structure

```
mantle-audit-ai/
│
├── src/
│   └── mantle_audit/              # Main package
│       ├── __init__.py            # Package init
│       ├── cli.py                 # CLI interface (Click + Rich)
│       ├── config.py              # .env configuration loader
│       ├── parser.py              # Solidity code parser (Slither API)
│       ├── detector.py            # Vulnerability detector
│       │   ├── Slither engine     # 100+ built-in detectors
│       │   └── Mantle rules       # 15 Mantle-specific patterns
│       ├── llm_agent.py           # LLM deep analysis (Claude)
│       ├── reporter.py            # Report generators
│       │   ├── markdown
│       │   ├── json
│       │   └── html (dark theme)
│       ├── ipfs.py                # Pinata IPFS upload
│       └── blockchain.py          # On-chain integration (Web3.py)
│
├── contracts/
│   └── AuditRegistry.sol          # On-chain audit storage contract
│
├── scripts/
│   └── deploy.py                  # Contract deployment script
│
├── tests/
│   ├── test_mantle_patterns.py    # 15 Mantle rule unit tests
│   ├── test_detector.py           # Slither detector integration tests
│   ├── test_parser.py             # Parser tests
│   ├── test_reporter.py           # Report generator tests
│   ├── test_blockchain.py         # On-chain integration tests
│   └── test_e2e.py                # End-to-end pipeline tests
│
├── docs/                          # Documentation
├── templates/                     # Jinja2 templates (optional)
├── .env.example                   # Environment template
├── pyproject.toml                 # Project metadata & deps
├── README.md                      # This file
└── CONTRIBUTING.md                # Contribution guidelines
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🏆 Hackathon Info

**The Turing Test Hackathon 2026** — *Track 5: AI DevTools*

| Detail | Info |
|--------|------|
| **Hackathon** | [The Turing Test Hackathon 2026](https://dorahacks.io/hackathon/mantleturingtesthackathon2026) by DoraHacks & Mantle |
| **Track** | **Track 5: AI DevTools** |
| **Theme** | *Turing Test* — demonstrating AI's ability to match or exceed human-level code auditing |
| **Chain** | Mantle L2 (OP Stack) |
| **Submission** | April – May 2026 |

### Why This Project Fits Track 5

1. **🎯 AI DevTools Focus** — A developer tool that augments human auditors with AI, making smart contract security accessible and automated
2. **🧪 Turing Test Theme** — The `benchmark` command directly compares AI analysis against traditional tools, providing quantitative evidence of AI capability
3. **⛓️ Mantle Native** — 15 custom detection rules for Mantle-specific vulnerabilities, `AuditRegistry.sol` contract deployed on Mantle L2, full IPFS + on-chain publishing pipeline
4. **🔧 Developer-First** — CLI-native design with CI/CD integration, rich terminal output, and multi-format reporting

### Key Differentiators

| Feature | Mantle-Audit-AI | Traditional Auditors |
|---------|----------------|---------------------|
| **Speed** | Minutes (automated) | Days–weeks (manual) |
| **Cost** | Near-zero (LLM API fees) | $5,000–$50,000+ |
| **False Positives** | AI-filtered (LLM re-evaluation) | Human review |
| **On-Chain Proof** | IPFS + Mantle registry | PDF report |
| **Mantle Awareness** | 15 custom rules | Generic Solidity |
| **CI/CD** | Native (`--ci` flag) | None |
| **Benchmarking** | Built-in AI vs static comparison | None |

---

<div align="center">
  <br/>
  <p><strong>Built with ❤️ for The Turing Test Hackathon 2026 — Track 5: AI DevTools</strong></p>
  <p>
    <a href="https://dorahacks.io/hackathon/mantleturingtesthackathon2026">Hackathon Page</a> •
    <a href="https://www.mantle.xyz">Mantle Network</a> •
    <a href="https://github.com/crytic/slither">Slither</a> •
    <a href="https://www.anthropic.com">Claude</a>
  </p>
</div>
