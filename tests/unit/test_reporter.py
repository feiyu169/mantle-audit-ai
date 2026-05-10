"""Tests for the reporter module."""

import json
from pathlib import Path

from mantle_audit.detector import DetectionResult
from mantle_audit.reporter import generate_json_report, generate_markdown_report, save_report


class TestMarkdownReport:
    def test_report_contains_header(self, sample_detection: DetectionResult):
        report = generate_markdown_report("test.sol", sample_detection)
        assert "Mantle-Audit-AI" in report
        assert "test.sol" in report

    def test_report_contains_vulnerabilities(self, sample_detection: DetectionResult):
        report = generate_markdown_report("test.sol", sample_detection)
        assert "reentrancy-eth" in report
        assert "MANTLE-001" in report

    def test_report_contains_mantle_marker(self, sample_detection: DetectionResult):
        report = generate_markdown_report("test.sol", sample_detection)
        assert "Mantle 生态特有风险" in report

    def test_report_contains_chain_info(self, sample_detection: DetectionResult):
        chain_info = {"ipfs_cid": "QmTest123", "tx_hash": "0xabc", "audit_id": "0xdef", "block_number": 12345}
        report = generate_markdown_report("test.sol", sample_detection, chain_info=chain_info)
        assert "QmTest123" in report
        assert "0xabc" in report

    def test_empty_report(self):
        det = DetectionResult()
        report = generate_markdown_report("test.sol", det)
        assert "未发现漏洞" in report


class TestJsonReport:
    def test_json_is_valid(self, sample_detection: DetectionResult):
        report_json = generate_json_report("test.sol", sample_detection)
        data = json.loads(report_json)
        assert data["tool"] == "Mantle-Audit-AI"
        assert len(data["vulnerabilities"]) == 2

    def test_json_contains_summary(self, sample_detection: DetectionResult):
        report_json = generate_json_report("test.sol", sample_detection)
        data = json.loads(report_json)
        assert "summary" in data
        assert data["summary"]["High"] == 1


class TestSaveReport:
    def test_save_creates_file(self, tmp_path: Path):
        path = save_report("test content", str(tmp_path / "report.md"))
        assert Path(path).exists()
        assert Path(path).read_text() == "test content"

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        path = save_report("test", str(tmp_path / "a" / "b" / "report.md"))
        assert Path(path).exists()
