"""CLI — command-line interface for Mantle-Audit-AI."""

from __future__ import annotations

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
from .reporter import generate_markdown_report, generate_json_report, save_report
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
@click.option("--format", "fmt", type=click.Choice(["markdown", "json"]), default="markdown", help="Output format")
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
        fail_severity = Severity(fail_on) if fail_on else Severity.HIGH
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


if __name__ == "__main__":
    main()
