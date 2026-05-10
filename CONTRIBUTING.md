# Contributing to Mantle-Audit-AI

Thank you for considering contributing to Mantle-Audit-AI! We welcome contributions of all kinds — bug fixes, feature additions, documentation improvements, and new Mantle-specific detection rules.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Adding Mantle-Specific Rules](#adding-mantle-specific-rules)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and harassment-free environment for everyone. Be constructive, be kind, and assume good faith.

---

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/mantle-audit-ai.git
   cd mantle-audit-ai
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

---

## Development Setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Install a Solidity compiler (required by Slither)
pip install solc-select
solc-select install 0.8.19
solc-select use 0.8.19

# Copy and configure .env
cp .env.example .env
# Edit .env with your API keys

# Run the test suite to verify
pytest -v
```

---

## Project Architecture

The codebase follows a clean pipeline architecture:

```
src/mantle_audit/
├── cli.py          # Entry point — Click commands (audit, parse, benchmark)
├── config.py       # Environment config loader (.env → dataclass)
├── parser.py       # Slither-based Solidity parser → ParseResult
├── detector.py     # Vulnerability detection (Slither + Mantle rules)
├── llm_agent.py    # Claude-powered deep analysis
├── reporter.py     # Report generation (Markdown, JSON, HTML)
├── ipfs.py         # Pinata IPFS upload integration
└── blockchain.py   # Web3.py — Mantle AuditRegistry interaction
```

**Data flow**: `parse()` → `detect_vulnerabilities()` → `analyze_with_llm()` → `generate_*_report()` → `upload_report()` → `record_audit_onchain()`

---

## Adding Mantle-Specific Rules

This is one of the most valuable contributions you can make! New rules help Mantle-Audit-AI stay relevant as the Mantle ecosystem evolves.

### Step 1: Add the Rule Definition

Edit `src/mantle_audit/detector.py`. Add your pattern to the `_MANTLE_PATTERNS` list:

```python
{
    "id": "MANTLE-016",              # Next available ID
    "pattern": "YourPatternHere",    # Case-insensitive substring match
    "severity": Severity.MEDIUM,     # Critical / High / Medium / Low / Info
    "description": (
        "Detailed description of the risk. "
        "Explain why this pattern is dangerous on Mantle L2 specifically."
    ),
},
```

**Guidelines for good rules**:
- **Unique ID**: Use the next available MANTLE-XXX number.
- **Mantle-specific**: The rule should be relevant to Mantle L2 specifically — not a generic Solidity vulnerability (those are covered by Slither).
- **Clear description**: Explain the risk, the Mantle-specific context, and what developers should check.
- **Appropriate severity**:
  - 🔴 **Critical**: Direct loss of funds, no prerequisites.
  - 🟠 **High**: Likely loss of funds under specific conditions.
  - 🟡 **Medium**: Potential for loss with user mistakes or edge cases.
  - 🔵 **Low**: Best practice violations, informational.
- **Pattern specificity**: Use distinctive substrings that won't trigger false positives on unrelated code.

### Step 2: Write Tests

Add tests in `tests/test_mantle_patterns.py`:

```python
def test_detects_your_pattern(self, tmp_path):
    code = "contract X { function f() { YourPatternHere.doSomething(); } }"
    sol = tmp_path / "test.sol"
    sol.write_text(code)
    findings = _check_mantle_patterns(str(sol))
    assert any(f.vuln_id == "MANTLE-016" for f in findings)
```

### Step 3: Update Documentation

- Update the Mantle rules table in `README.md`.
- Update the pattern count test in `test_mantle_patterns.py` if the total changes.

### Step 4: Run Tests

```bash
pytest tests/test_mantle_patterns.py -v
```

---

## Testing

We use `pytest` with the following test structure:

```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=src/mantle_audit --cov-report=term-missing

# Run specific test file
pytest tests/test_mantle_patterns.py -v

# Run a specific test
pytest tests/test_mantle_patterns.py::TestMantlePatterns::test_detects_meth_pattern -v
```

**Test categories**:

| File | What it tests |
|------|--------------|
| `test_mantle_patterns.py` | All 15 Mantle-specific detection rules |
| `test_detector.py` | Slither integration and DetectionResult |
| `test_parser.py` | Solidity parsing and ParseResult |
| `test_reporter.py` | Markdown, JSON, HTML report generation |
| `test_blockchain.py` | Web3.py and AuditRegistry interaction |
| `test_e2e.py` | Full pipeline end-to-end |

---

## Code Style

We use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check for lint issues
ruff check src/ tests/

# Auto-fix issues
ruff check --fix src/ tests/
```

**Guidelines**:
- Line length: **100 characters maximum**
- Target Python version: **3.11+**
- Type hints: **Required** for all function signatures
- Docstrings: Google-style docstrings for public functions
- Imports: Standard library → third-party → local (alphabetical within groups)

---

## Pull Request Process

1. **Ensure your branch is up to date** with the main branch:
   ```bash
   git checkout main
   git pull upstream main
   git checkout feature/your-feature-name
   git rebase main
   ```

2. **Run the full test suite** and ensure all tests pass:
   ```bash
   pytest -v
   ```

3. **Run linting** and fix any issues:
   ```bash
   ruff check src/ tests/
   ```

4. **Commit your changes** with a clear, descriptive message:
   ```bash
   git commit -m "feat: add MANTLE-016 rule for <pattern>"
   ```

   Use conventional commit prefixes:
   - `feat:` — New feature or rule
   - `fix:` — Bug fix
   - `docs:` — Documentation changes
   - `test:` — Test additions or changes
   - `refactor:` — Code refactoring
   - `chore:` — Build/config/infra changes

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** on the main repository with:
   - A clear title describing the change
   - A description of what was changed and why
   - Reference any related issues (e.g., "Closes #12")
   - Screenshots for UI/CLI changes (if applicable)
   - Test results

7. **Respond to review feedback** — maintainers may request changes before merging.

---

## Reporting Issues

Found a bug or have a feature request? [Open an issue](https://github.com/feiyu169/mantle-audit-ai/issues) with:

- **Bug reports**: Steps to reproduce, expected behavior, actual behavior, environment details (OS, Python version, Solidity compiler version)
- **Feature requests**: Clear description of the feature, use case, and any implementation ideas
- **New Mantle rules**: Pattern description, severity rationale, example vulnerable code snippet

---

## Adding Mantle Ecosystem Integrations

As the Mantle ecosystem grows, we need support for:
- New Mantle-native protocols (DEXs, lending platforms, yield aggregators)
- New Mantle L2 precompiles or system contracts
- Updates to cross-domain messaging patterns
- New RWA token standards

If you're building on Mantle, please contribute detection rules for your protocol!

---

## Release Process

1. Version bump in `pyproject.toml` (semantic versioning).
2. Update `CHANGELOG.md` with new features and fixes.
3. Tag the release: `git tag v0.x.x && git push --tags`.
4. Build and publish to PyPI: `python -m build && twine upload dist/*`.

---

## Questions?

If you have questions about contributing, please [open a discussion](https://github.com/feiyu169/mantle-audit-ai/discussions) or reach out to the maintainers.

Thank you for helping make Mantle-Audit-AI better! 🛡️
