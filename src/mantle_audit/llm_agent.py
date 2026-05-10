"""LLM Agent — deep analysis of Slither results using Claude."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

import anthropic

from .config import Config
from .detector import DetectionResult, Vulnerability, Severity, Confidence

_SYSTEM_PROMPT = """\
You are a senior smart contract security auditor specializing in Solidity and the Mantle L2 ecosystem.

Your task: analyze Slither static analysis results together with the original Solidity code,
then produce a professional audit report.

For each vulnerability:
1. Determine if it's a TRUE POSITIVE or FALSE POSITIVE
2. Re-evaluate severity (Critical / High / Medium / Low / Informational)
3. Provide a clear attack path (for Critical/High)
4. Write a fix recommendation with compilable Solidity code (Before/After)

Special focus on Mantle ecosystem risks:
- mETH (Mantle Staked ETH) interactions and slashing risks
- RWA token compliance (USDY, etc.)
- Cross-domain messaging (L1 ↔ L2 bridge security)
- L2 gas pricing differences vs L1
- DeFi protocols native to Mantle (Merchant Moe, Agni Finance)

Output MUST be valid JSON matching the schema below.
"""


_USER_PROMPT_TEMPLATE = """\
# Slither Static Analysis Report

{slither_report}

# Original Solidity Code

```solidity
{solidity_code}
```

# Task

Analyze the above. For each vulnerability, output a JSON object with these fields:
- vuln_id: unique identifier
- check: detector name
- severity: Critical / High / Medium / Low / Informational
- confidence: High / Medium / Low
- description: human-readable explanation (50-100 words)
- attack_path: step-by-step attack scenario (for Critical/High, empty string otherwise)
- recommendation: fix with Before/After Solidity code
- code_location: "file:line"
- is_false_positive: true / false

Return a JSON array of vulnerability objects. No markdown wrapping.
"""


@dataclass
class LLMAnalysisResult:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_response: str = ""
    model_used: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "model_used": self.model_used,
            "errors": self.errors,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def _parse_llm_vulns(raw: str) -> list[Vulnerability]:
    """Parse LLM JSON response into Vulnerability objects."""
    # Strip markdown code fences if present
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]

    try:
        items = json.loads(text)
    except json.JSONDecodeError:
        # Try extracting the array
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1:
            try:
                items = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return []
        else:
            return []

    vulns: list[Vulnerability] = []
    for item in items:
        sev_str = item.get("severity", "Informational")
        try:
            severity = Severity(sev_str)
        except ValueError:
            severity = Severity.INFO

        conf_str = item.get("confidence", "Medium")
        try:
            confidence = Confidence(conf_str)
        except ValueError:
            confidence = Confidence.MEDIUM

        vulns.append(Vulnerability(
            vuln_id=item.get("vuln_id", "LLM-0"),
            check=item.get("check", "LLM-Analysis"),
            severity=severity,
            confidence=confidence,
            description=item.get("description", ""),
            file_path=item.get("code_location", "").split(":")[0] if ":" in item.get("code_location", "") else "",
            line_start=int(item.get("code_location", "0:0").split(":")[1]) if ":" in item.get("code_location", "") else 0,
            line_end=int(item.get("code_location", "0:0").split(":")[1]) if ":" in item.get("code_location", "") else 0,
            recommendation=item.get("recommendation", ""),
            attack_path=item.get("attack_path", ""),
            is_false_positive=item.get("is_false_positive", False),
        ))
    return vulns


def analyze_with_llm(
    detection_result: DetectionResult,
    solidity_code: str,
    sol_path: str = "",
) -> LLMAnalysisResult:
    """Run LLM deep analysis on Slither results.

    Args:
        detection_result: Output from detect_vulnerabilities().
        solidity_code: Raw Solidity source code.
        sol_path: File path for context.

    Returns:
        LLMAnalysisResult with re-evaluated vulnerabilities.
    """
    result = LLMAnalysisResult(model_used=Config.LLM_MODEL)

    missing = Config.validate(require_llm=True)
    if missing:
        result.errors.append(f"Missing config: {', '.join(missing)}")
        return result

    client = anthropic.Anthropic(api_key=Config.ANTHROPIC_API_KEY)

    # Build Slither report summary for the prompt
    slither_summary = []
    for v in detection_result.vulnerabilities:
        slither_summary.append({
            "check": v.check,
            "severity": v.severity.value,
            "description": v.description[:200],
            "location": f"{v.file_path}:{v.line_start}",
        })

    user_msg = _USER_PROMPT_TEMPLATE.format(
        slither_report=json.dumps(slither_summary, indent=2, ensure_ascii=False),
        solidity_code=solidity_code[:60000],  # Claude context limit safety
    )

    try:
        response = client.messages.create(
            model=Config.LLM_MODEL,
            max_tokens=8192,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw_text = response.content[0].text
        result.raw_response = raw_text
        result.vulnerabilities = _parse_llm_vulns(raw_text)
    except anthropic.APIError as e:
        result.errors.append(f"Anthropic API error: {e}")
    except Exception as e:
        result.errors.append(f"LLM analysis error: {e}")

    return result
