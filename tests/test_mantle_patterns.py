"""Tests for Mantle-specific pattern detection (no solc needed)."""

import json
from pathlib import Path

from mantle_audit.detector import _check_mantle_patterns, _MANTLE_PATTERNS


class TestMantlePatterns:
    def test_detects_meth_pattern(self, tmp_path):
        code = "contract X { function stakeMETH() public { mETH.stake(); } }"
        sol = tmp_path / "m.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("mETH" in f.description for f in findings)

    def test_detects_usdy_pattern(self, tmp_path):
        code = "contract X { IERC20 usdy = IERC20(0x...); }"
        sol = tmp_path / "u.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("USDY" in f.description for f in findings)

    def test_detects_bridge_pattern(self, tmp_path):
        code = "contract X { L2CrossDomainMessenger messenger; }"
        sol = tmp_path / "b.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("cross-domain" in f.description.lower() for f in findings)

    def test_no_mantle_patterns_in_safe_code(self, tmp_path):
        code = "contract Safe { uint256 x; function set(uint256 v) external { x = v; } }"
        sol = tmp_path / "s.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert len(findings) == 0

    def test_nonexistent_file_returns_empty(self):
        findings = _check_mantle_patterns("/nonexistent.sol")
        assert findings == []

    def test_mantle_pattern_count(self):
        """Verify we have the expected number of Mantle patterns."""
        assert len(_MANTLE_PATTERNS) == 5
