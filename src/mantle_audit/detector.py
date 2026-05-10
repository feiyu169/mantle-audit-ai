"""Vulnerability detector — runs Slither detectors + Mantle-specific rules."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from slither import Slither
from slither.detectors.abstract_detector import DetectorClassification


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Vulnerability:
    vuln_id: str
    check: str
    severity: Severity
    confidence: Confidence
    description: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    attack_path: str = ""
    is_false_positive: bool = False
    is_mantle_specific: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class DetectionResult:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    slither_raw: list[dict] = field(default_factory=list)
    mantle_checks: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "slither_raw_count": len(self.slither_raw),
            "mantle_checks": [v.to_dict() for v in self.mantle_checks],
            "errors": self.errors,
            "summary": self.summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
        return counts


# Severity mapping from Slither's classification
_SEVERITY_MAP = {
    DetectorClassification.HIGH: Severity.HIGH,
    DetectorClassification.MEDIUM: Severity.MEDIUM,
    DetectorClassification.LOW: Severity.LOW,
    DetectorClassification.INFORMATIONAL: Severity.INFO,
}

_CONFIDENCE_MAP = {
    "High": Confidence.HIGH,
    "Medium": Confidence.MEDIUM,
    "Low": Confidence.LOW,
}

# ────────────────────────────────────────────────────────────────
# Mantle-specific detection patterns (string matching, not Slither)
# ────────────────────────────────────────────────────────────────

_MANTLE_PATTERNS: list[dict] = [
    {
        "id": "MANTLE-001",
        "pattern": "mETH",
        "severity": Severity.MEDIUM,
        "description": (
            "Contract interacts with mETH (Mantle Staked ETH). "
            "Ensure slashing scenarios are handled — mETH staking carries LST-specific risks."
        ),
    },
    {
        "id": "MANTLE-002",
        "pattern": "USDY",
        "severity": Severity.HIGH,
        "description": (
            "Contract interacts with USDY (Ondo's USD Yield token). "
            "RWA tokens often have transfer restrictions and compliance checks — "
            "verify that the contract respects these constraints."
        ),
    },
    {
        "id": "MANTLE-003",
        "pattern": "L2CrossDomainMessenger",
        "severity": Severity.MEDIUM,
        "description": (
            "Contract uses Mantle's cross-domain messenger. "
            "Verify that cross-chain message source is validated and replay protection is in place."
        ),
    },
    {
        "id": "MANTLE-004",
        "pattern": "block.gaslimit",
        "severity": Severity.LOW,
        "description": (
            "Reliance on block.gaslimit — Mantle L2 has different gas pricing than Ethereum L1. "
            "Gas-dependent logic may behave differently on L2."
        ),
    },
    {
        "id": "MANTLE-005",
        "pattern": "tx.gasprice",
        "severity": Severity.LOW,
        "description": (
            "Use of tx.gasprice — Mantle L2 uses a different fee model. "
            "Gas price assumptions from L1 may not hold on Mantle."
        ),
    },
    {
        "id": "MANTLE-006",
        "pattern": "delegatecall",
        "severity": Severity.HIGH,
        "description": (
            "Use of delegatecall on Mantle L2. OP Stack delegatecall semantics may differ from L1, "
            "especially when calling precompiles. Verify storage context and security assumptions."
        ),
    },
    {
        "id": "MANTLE-007",
        "pattern": "selfdestruct",
        "severity": Severity.HIGH,
        "description": (
            "Use of selfdestruct — deprecated post-EIP-6780 and may behave differently on Mantle L2. "
            "Mantle may not fully support selfdestruct semantics; avoid relying on it for state cleanup."
        ),
    },
    {
        "id": "MANTLE-008",
        "pattern": "Merchant Moe",
        "severity": Severity.MEDIUM,
        "description": (
            "Contract may interact with Merchant Moe, a Mantle-native DEX. "
            "Verify slippage protection, twap oracle usage, and liquidity checks are in place."
        ),
    },
    {
        "id": "MANTLE-008",
        "pattern": "Agni",
        "severity": Severity.MEDIUM,
        "description": (
            "Contract may interact with Agni Finance, a Mantle-native DEX. "
            "Verify slippage protection and liquidity validation."
        ),
    },
    {
        "id": "MANTLE-008",
        "pattern": "MantleSwap",
        "severity": Severity.MEDIUM,
        "description": (
            "Contract may interact with MantleSwap, a Mantle-native DEX. "
            "Verify slippage protection and liquidity checks."
        ),
    },
    {
        "id": "MANTLE-009",
        "pattern": "L1Block",
        "severity": Severity.MEDIUM,
        "description": (
            "Use of L1Block.number or L1Block.timestamp on Mantle L2. "
            "These return L1 values which may differ from L2 block context — "
            "verify that time-sensitive logic accounts for this discrepancy."
        ),
    },
    {
        "id": "MANTLE-010",
        "pattern": "ecrecover",
        "severity": Severity.MEDIUM,
        "description": (
            "Use of ecrecover for signature verification on Mantle L2. "
            "Ensure replay protection across L1/L2 boundaries — signatures valid on L1 "
            "may also be valid on L2 without proper domain separation."
        ),
    },
    {
        "id": "MANTLE-011",
        "pattern": "create2",
        "severity": Severity.LOW,
        "description": (
            "Use of CREATE2 for deterministic deployment on Mantle L2. "
            "Deployments may collide with L1 addresses due to different chain IDs. "
            "Verify address determinism assumptions."
        ),
    },
    {
        "id": "MANTLE-012",
        "pattern": "0x0000000000000000000000000000000000000100",
        "severity": Severity.MEDIUM,
        "description": (
            "Reference to Mantle custom precompile address (0x...0100). "
            "Mantle has custom precompiles at different addresses than Ethereum L1. "
            "Verify the correct precompile address is used."
        ),
    },
    {
        "id": "MANTLE-013",
        "pattern": "MNT",
        "severity": Severity.LOW,
        "description": (
            "Reference to MNT (Mantle's native token). Contracts assuming ETH as native "
            "token may need adaptation for MNT's tokenomics and gas mechanics."
        ),
    },
    {
        "id": "MANTLE-014",
        "pattern": "block.basefee",
        "severity": Severity.LOW,
        "description": (
            "Use of block.basefee — EIP-1559 fee mechanics differ on Mantle L2. "
            "The basefee may not behave identically to L1; gas-dependent logic may need adjustment."
        ),
    },
    {
        "id": "MANTLE-015",
        "pattern": "Chainlink",
        "severity": Severity.HIGH,
        "description": (
            "Use of a price oracle (Chainlink or similar) on Mantle L2. "
            "Oracle latency and L1/L2 price divergence can be exploited. "
            "Verify staleness checks, deviation thresholds, and that the feed is deployed on Mantle."
        ),
    },
]


def _run_slither(sol_path: str) -> tuple[list[Vulnerability], list[dict]]:
    """Run Slither built-in detectors and return structured results."""
    vulnerabilities: list[Vulnerability] = []
    raw_results: list[dict] = []

    try:
        slither = Slither(sol_path)
    except Exception as e:
        return [], [{"error": str(e)}]

    detector_classes = slither.detectors
    for detector_cls in detector_classes:
        try:
            detector = detector_cls(slither.contracts, slither.compilation_units)
            results = detector.detect()
            for i, result in enumerate(results):
                raw_dict = result.to_json() if hasattr(result, "to_json") else {}
                raw_results.append(raw_dict)

                classification = detector_cls.IMPACT
                severity = _SEVERITY_MAP.get(classification, Severity.INFO)
                conf_str = raw_dict.get("confidence", "Medium") if isinstance(raw_dict, dict) else "Medium"
                confidence = _CONFIDENCE_MAP.get(conf_str, Confidence.MEDIUM)

                # Extract location
                elements = raw_dict.get("elements", []) if isinstance(raw_dict, dict) else []
                file_path = ""
                line = 0
                snippet = ""
                if elements:
                    loc = elements[0].get("source_mapping", {})
                    file_path = loc.get("filename_relative", "")
                    lines = loc.get("lines", [])
                    line = lines[0] if lines else 0

                desc = raw_dict.get("description", str(result)) if isinstance(raw_dict, dict) else str(result)

                vulnerabilities.append(Vulnerability(
                    vuln_id=f"SL-{detector_cls.ARGUMENT}-{i+1}",
                    check=detector_cls.ARGUMENT,
                    severity=severity,
                    confidence=confidence,
                    description=desc[:500],
                    file_path=file_path,
                    line_start=line,
                    line_end=line,
                    code_snippet=snippet,
                ))
        except Exception:
            continue

    return vulnerabilities, raw_results


def _check_mantle_patterns(sol_path: str) -> list[Vulnerability]:
    """Scan source code for Mantle-specific patterns."""
    findings: list[Vulnerability] = []
    try:
        code = Path(sol_path).read_text()
    except Exception:
        return findings

    lines = code.split("\n")
    for pat in _MANTLE_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if pat["pattern"].lower() in line.lower():
                findings.append(Vulnerability(
                    vuln_id=pat["id"],
                    check=f"Mantle-{pat['id']}",
                    severity=pat["severity"],
                    confidence=Confidence.MEDIUM,
                    description=pat["description"],
                    file_path=sol_path,
                    line_start=i,
                    line_end=i,
                    code_snippet=line.strip()[:200],
                    is_mantle_specific=True,
                ))
                break  # one match per pattern is enough

    return findings


def detect_vulnerabilities(sol_path: str) -> DetectionResult:
    """Run all detectors on a Solidity file.

    Args:
        sol_path: Path to the .sol file.

    Returns:
        DetectionResult with Slither + Mantle-specific vulnerabilities.
    """
    result = DetectionResult()

    if not Path(sol_path).exists():
        result.errors.append(f"File not found: {sol_path}")
        return result

    # Phase 1: Slither built-in detectors
    vulns, raw = _run_slither(sol_path)
    result.vulnerabilities.extend(vulns)
    result.slither_raw = raw

    # Phase 2: Mantle-specific pattern checks
    mantle_vulns = _check_mantle_patterns(sol_path)
    result.vulnerabilities.extend(mantle_vulns)
    result.mantle_checks = mantle_vulns

    return result
