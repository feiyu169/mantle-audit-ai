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
        """Verify we have the expected number of unique Mantle pattern IDs."""
        unique_ids = {p["id"] for p in _MANTLE_PATTERNS}
        assert len(unique_ids) == 15, f"Expected 15 unique Mantle rule IDs, got {len(unique_ids)}"
        assert len(_MANTLE_PATTERNS) == 17, (
            f"Expected 17 pattern entries (15 rules, MANTLE-008 has 3 variants), "
            f"got {len(_MANTLE_PATTERNS)}"
        )

    def test_detects_delegatecall(self, tmp_path):
        code = "contract X { function f(address t) external { (bool ok,) = t.delegatecall(abi.encodeWithSignature('g()')); } }"
        sol = tmp_path / "dc.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("delegatecall" in f.description for f in findings)
        high_sev = [f for f in findings if f.vuln_id == "MANTLE-006"]
        assert len(high_sev) >= 1

    def test_detects_selfdestruct(self, tmp_path):
        code = "contract X { function kill() external { selfdestruct(payable(msg.sender)); } }"
        sol = tmp_path / "sd.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("selfdestruct" in f.description for f in findings)
        assert any(f.vuln_id == "MANTLE-007" for f in findings)

    def test_detects_oracle(self, tmp_path):
        code = "contract X { function getPrice() external view returns (uint256) { return ChainlinkOracle.latestAnswer(); } }"
        sol = tmp_path / "oracle.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any("oracle" in f.description.lower() for f in findings)
        assert any(f.vuln_id == "MANTLE-015" for f in findings)

    def test_detects_mantle_dex(self, tmp_path):
        code = "// Merchant Moe DEX integration\nimport {IMerchantMoeRouter} from 'path';\ncontract X { function swap() external { } }"
        sol = tmp_path / "dex.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-008" for f in findings)

    def test_detects_mantle_dex_agni(self, tmp_path):
        code = "contract X { function swap() external { AgniPool.swap(...); } }"
        sol = tmp_path / "dex2.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-008" for f in findings)

    def test_detects_mantle_dex_swap(self, tmp_path):
        code = "contract X { function swap() external { MantleSwapRouter.swap(...); } }"
        sol = tmp_path / "dex3.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-008" for f in findings)

    def test_detects_l1block(self, tmp_path):
        code = "contract X { function check() external view returns (uint256) { return L1Block.number; } }"
        sol = tmp_path / "l1b.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-009" for f in findings)

    def test_detects_ecrecover(self, tmp_path):
        code = "contract X { function verify(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns (address) { return ecrecover(h, v, r, s); } }"
        sol = tmp_path / "ec.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-010" for f in findings)

    def test_detects_create2(self, tmp_path):
        code = "contract X { function deploy(bytes32 salt, bytes memory code) external returns (address addr) { assembly { addr := create2(0, add(code, 0x20), mload(code), salt) } } }"
        sol = tmp_path / "c2.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-011" for f in findings)

    def test_detects_basefee(self, tmp_path):
        code = "contract X { function gas() external view returns (uint256) { return block.basefee; } }"
        sol = tmp_path / "bf.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-014" for f in findings)

    def test_detects_mnt_token(self, tmp_path):
        code = "contract X { IERC20 mnt = IERC20(address(0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000)); }"
        sol = tmp_path / "mnt.sol"
        sol.write_text(code)
        findings = _check_mantle_patterns(str(sol))
        assert any(f.vuln_id == "MANTLE-013" for f in findings)
