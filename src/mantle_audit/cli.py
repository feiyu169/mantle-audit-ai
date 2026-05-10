"""CLI — command-line interface for Mantle-Audit-AI."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import Config
from .parser import parse_contract
from .detector import detect_vulnerabilities, Severity
from .llm_agent import analyze_with_llm
from .reporter import generate_markdown_report, generate_json_report, generate_html_report, save_report
from .ipfs import upload_report
from .blockchain import record_audit_onchain

console = Console()

_BANNER = """[bold cyan]🔍 Mantle-Audit-AI v0.1.0[/bold cyan]
[dim]AI-powered smart contract audit for Mantle ecosystem[/dim]"""


@click.group()
@click.version_option(version="0.1.0", prog_name="mantle-audit")
def main():
    """Mantle-Audit-AI: AI-powered smart contract audit tool."""
    pass


@main.command()
@click.option("--file", "-f", "sol_path", required=True, type=click.Path(exists=True), help="Solidity file to audit")
@click.option("--output", "-o", "output_path", default=None, help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["markdown", "json", "html"]), default="markdown", help="Output format")
@click.option("--onchain/--no-onchain", default=False, help="Publish results on-chain")
@click.option("--ci", is_flag=True, default=False, help="CI/CD mode (exit code 1 if High+ found)")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default="HIGH", help="CI failure threshold")
@click.option("--skip-llm", is_flag=True, default=False, help="Skip LLM analysis (faster)")
@click.option("--model", default=None, help="LLM model override")
def audit(sol_path: str, output_path: str | None, fmt: str, onchain: bool, ci: bool, fail_on: str, skip_llm: bool, model: str | None):
    """Audit a Solidity smart contract."""
    console.print(Panel(_BANNER, border_style="cyan"))

    if model:
        Config.LLM_MODEL = model

    # ── Phase 1: Parse ──
    with console.status("[bold green]Parsing Solidity code..."):
        parse_result = parse_contract(sol_path)

    if parse_result.errors:
        console.print(f"[red]Parse errors:[/red] {parse_result.errors}")
        sys.exit(1)

    console.print(f"  ✅ Identified {parse_result.total_contracts} contract(s), {parse_result.total_functions} function(s)")

    # ── Phase 2: Static Analysis ──
    with console.status("[bold green]Running static analysis (Slither)..."):
        detection = detect_vulnerabilities(sol_path)

    slither_count = len(detection.vulnerabilities) - len(detection.mantle_checks)
    mantle_count = len(detection.mantle_checks)
    console.print(f"  ✅ Slither: {slither_count} findings, Mantle-specific: {mantle_count} findings")

    if detection.errors:
        for err in detection.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")

    # ── Phase 3: LLM Analysis ──
    llm_vulns = None
    if not skip_llm:
        console.print("[bold green]Running AI deep analysis...[/bold green]")
        if not Config.ANTHROPIC_API_KEY:
            console.print("  [yellow]⚠ ANTHROPIC_API_KEY not set, skipping LLM analysis[/yellow]")
        else:
            try:
                source_code = Path(sol_path).read_text()
                with console.status(f"  🤖 Calling {Config.LLM_MODEL}..."):
                    llm_result = analyze_with_llm(detection, source_code, sol_path)

                if llm_result.errors:
                    for err in llm_result.errors:
                        console.print(f"  [yellow]⚠ {err}[/yellow]")
                else:
                    llm_vulns = llm_result.vulnerabilities
                    fp_count = sum(1 for v in llm_vulns if v.is_false_positive)
                    console.print(f"  ✅ AI analyzed {len(llm_vulns)} findings, flagged {fp_count} as false positives")
            except Exception as e:
                console.print(f"  [yellow]⚠ LLM analysis failed: {e}[/yellow]")

    # ── Phase 4: Report Generation ──
    vulns_for_report = llm_vulns if llm_vulns else detection.vulnerabilities

    if fmt == "json":
        report_content = generate_json_report(sol_path, detection, llm_vulns)
    elif fmt == "html":
        report_content = generate_html_report(sol_path, detection, llm_vulns)
    else:
        report_content = generate_markdown_report(sol_path, detection, llm_vulns)

    if output_path:
        saved = save_report(report_content, output_path)
        console.print(f"  📝 Report saved to {saved}")
    else:
        console.print(report_content)

    # ── Summary Table ──
    table = Table(title="Audit Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    summary = detection.summary
    emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Informational": "ℹ️"}
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        count = summary.get(sev, 0)
        table.add_row(f"{emoji_map.get(sev, '')} {sev}", str(count))
    console.print(table)

    # ── On-chain (optional) ──
    if onchain and Config.AUDIT_REGISTRY_ADDRESS:
        console.print("[bold green]Publishing to Mantle blockchain...[/bold green]")
        try:
            source_code = Path(sol_path).read_text()
            # Upload report to IPFS first
            with console.status("  📦 Uploading to IPFS (Pinata)..."):
                cid = upload_report(report_content if fmt == "json" else generate_json_report(sol_path, detection, llm_vulns))
            console.print(f"  ✅ IPFS CID: {cid}")

            # Record on-chain
            with console.status("  ⛓️ Recording on Mantle..."):
                chain_result = record_audit_onchain(source_code, cid, summary)

            if chain_result.errors:
                console.print(f"  [yellow]⚠ On-chain errors: {chain_result.errors}[/yellow]")
            else:
                console.print(f"  ✅ TX: {chain_result.tx_hash}")
                console.print(f"  ✅ Audit ID: {chain_result.audit_id}")
                console.print(f"  ✅ Block: {chain_result.block_number}")
        except Exception as e:
            console.print(f"  [yellow]⚠ On-chain publishing failed: {e}[/yellow]")

    # ── CI mode ──
    if ci:
        _fail_on_map = {s.value.upper(): s for s in Severity}
        fail_severity = _fail_on_map.get(fail_on.upper(), Severity.HIGH) if fail_on else Severity.HIGH
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        fail_idx = severity_order.index(fail_severity)

        has_failures = False
        for v in vulns_for_report:
            if v.is_false_positive:
                continue
            if severity_order.index(v.severity) <= fail_idx:
                has_failures = True
                break

        if has_failures:
            console.print(f"\n[red bold]CI FAILED: Found {fail_on}+ vulnerabilities[/red bold]")
            sys.exit(1)
        else:
            console.print(f"\n[green bold]CI PASSED[/green bold]")


@main.command()
@click.argument("sol_path", type=click.Path(exists=True))
def parse(sol_path: str):
    """Parse a Solidity file and show contract structure."""
    result = parse_contract(sol_path)
    if result.errors:
        console.print(f"[red]{result.errors}[/red]")
        return

    console.print(f"Solidity version: {result.solidity_version}")
    console.print(f"Contracts: {result.total_contracts}")
    for c in result.contracts:
        console.print(f"\n[bold]{c.name}[/bold] ({c.file_path})")
        console.print(f"  Inherits: {', '.join(c.inherits) or 'none'}")
        console.print(f"  State vars: {', '.join(c.state_variables) or 'none'}")
        console.print(f"  Functions:")
        for f in c.functions:
            console.print(f"    {f.visibility} {f.state_mutability} {f.name}({', '.join(f.parameters)}) → {', '.join(f.return_type) or 'void'} [L{f.line_start}]")


@main.command()
@click.option("--file", "-f", "sol_path", required=True, type=click.Path(exists=True), help="Solidity file to benchmark")
@click.option("--output", "-o", "output_path", default=None, help="Output benchmark report (JSON)")
def benchmark(sol_path: str, output_path: str | None):
    """Compare AI analysis vs static analysis on a contract."""
    console.print(Panel(_BANNER, border_style="cyan"))

    source_code = Path(sol_path).read_text()

    # ── Phase 1: Slither-only ──
    with console.status("[bold green]Phase 1: Running static analysis (Slither only)..."):
        detection = detect_vulnerabilities(sol_path)

    slither_vulns = list(detection.vulnerabilities)
    slither_count = len(slither_vulns)
    console.print(f"  ✅ Slither found {slither_count} findings")

    if detection.errors:
        for err in detection.errors:
            console.print(f"  [yellow]⚠ {err}[/yellow]")

    # ── Phase 2: Slither + LLM ──
    llm_vulns = None
    llm_result = None
    if not Config.ANTHROPIC_API_KEY:
        console.print("  [yellow]⚠ ANTHROPIC_API_KEY not set, skipping LLM analysis[/yellow]")
    else:
        console.print("[bold green]Phase 2: Running AI deep analysis (Slither + LLM)...[/bold green]")
        try:
            with console.status(f"  🤖 Calling {Config.LLM_MODEL}..."):
                llm_result = analyze_with_llm(detection, source_code, sol_path)
            if llm_result.errors:
                for err in llm_result.errors:
                    console.print(f"  [yellow]⚠ {err}[/yellow]")
            else:
                llm_vulns = llm_result.vulnerabilities
                console.print(f"  ✅ AI analyzed {len(llm_vulns)} findings")
        except Exception as e:
            console.print(f"  [yellow]⚠ LLM analysis failed: {e}[/yellow]")

    # ── Phase 3: Compare ──
    if llm_vulns is None:
        console.print("\n[yellow]⚠ No LLM results to compare. Only Slither results shown.[/yellow]")
        return

    # Build comparison
    slither_ids = {v.vuln_id for v in slither_vulns}
    llm_ids = {v.vuln_id for v in llm_vulns}

    # Findings Slither found (original slither vulns)
    # Findings only LLM found (new vulns the LLM discovered that weren't in Slither)
    llm_only = [v for v in llm_vulns if v.vuln_id not in slither_ids and not v.is_false_positive]
    # False positives flagged by LLM
    llm_false_positives = [v for v in llm_vulns if v.is_false_positive]
    # True positives from LLM evaluation
    llm_true_positives = [v for v in llm_vulns if not v.is_false_positive]
    # Slither findings that LLM confirmed or replaced
    slither_only = [v for v in slither_vulns if v.vuln_id not in llm_ids]
    # Overlap: findings in both
    overlap = [v for v in slither_vulns if v.vuln_id in llm_ids]

    improvement = len(llm_true_positives) - len(slither_vulns)

    # ── Comparison Table ──
    console.print("\n[bold cyan]📊 Human vs AI Benchmark[/bold cyan]")
    table = Table(title=f"Comparison: Slither vs Slither+LLM — {Path(sol_path).name}")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Slither-only findings", str(len(slither_vulns)))
    table.add_row("LLM true positives (confirmed + new)", str(len(llm_true_positives)))
    table.add_row("LLM false positives flagged", str(len(llm_false_positives)))
    table.add_row("Findings only LLM found (new)", str(len(llm_only)))
    table.add_row("Slither findings missed by LLM", str(len(slither_only)))
    table.add_row("Overlap (both found)", str(len(overlap)))
    table.add_row("Improvement (Δ)", f"{improvement:+d}", style="green" if improvement > 0 else "red" if improvement < 0 else "")
    console.print(table)

    # ── Confidence Distribution ──
    if llm_vulns:
        conf_table = Table(title="LLM Confidence Distribution")
        conf_table.add_column("Confidence", style="bold")
        conf_table.add_column("Count", justify="right")

        conf_counts: dict[str, int] = {}
        for v in llm_vulns:
            conf_counts[v.confidence.value] = conf_counts.get(v.confidence.value, 0) + 1
        for level in ["High", "Medium", "Low"]:
            conf_table.add_row(level, str(conf_counts.get(level, 0)))
        console.print(conf_table)

    # ── Save to JSON ──
    if output_path:
        benchmark_data = {
            "tool": "Mantle-Audit-AI",
            "version": "0.1.0",
            "benchmark": True,
            "file": sol_path,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": {
                "slither_only": len(slither_vulns),
                "llm_true_positives": len(llm_true_positives),
                "llm_false_positives": len(llm_false_positives),
                "llm_only_new_findings": len(llm_only),
                "slither_missed_by_llm": len(slither_only),
                "overlap": len(overlap),
                "improvement": improvement,
            },
            "confidence_distribution": conf_counts,
            "llm_only_findings": [v.to_dict() for v in llm_only],
            "llm_false_positive_findings": [v.to_dict() for v in llm_false_positives],
            "slither_only_findings": [v.to_dict() for v in slither_only],
            "slither_raw_count": len(detection.slither_raw),
        }
        saved = save_report(json.dumps(benchmark_data, indent=2, ensure_ascii=False), output_path)
        console.print(f"  📝 Benchmark report saved to {saved}")


if __name__ == "__main__":
    main()
