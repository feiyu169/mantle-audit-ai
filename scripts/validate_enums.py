"""Pre-commit hook: validate enum consistency.

Ensures all enum values match expected patterns.
Catches bugs like Severity("HIGH") vs Severity("High").
"""

import sys

sys.path.insert(0, "src")

from mantle_audit.detector import Severity, Confidence


def validate_enums() -> list[str]:
    """Validate enum values match expected patterns."""
    errors = []

    # Severity: verify enum member names and their string values
    expected_severity = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Informational",
    }
    for member_name, expected_value in expected_severity.items():
        try:
            member = Severity[member_name]
            if member.value != expected_value:
                errors.append(
                    f"Severity.{member_name}.value = '{member.value}', expected '{expected_value}'"
                )
        except KeyError:
            errors.append(f"Severity.{member_name} not found")

    # Confidence: verify enum member names and their string values
    expected_confidence = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
    for member_name, expected_value in expected_confidence.items():
        try:
            member = Confidence[member_name]
            if member.value != expected_value:
                errors.append(
                    f"Confidence.{member_name}.value = '{member.value}', expected '{expected_value}'"
                )
        except KeyError:
            errors.append(f"Confidence.{member_name} not found")

    # Validate that Severity(value) round-trips correctly
    for sev in Severity:
        try:
            reconstructed = Severity(sev.value)
            if reconstructed != sev:
                errors.append(
                    f"Severity round-trip failed: Severity('{sev.value}') != Severity.{sev.name}"
                )
        except ValueError:
            errors.append(f"Severity('{sev.value}') raises ValueError")

    return errors


if __name__ == "__main__":
    errors = validate_enums()
    if errors:
        print("❌ Enum validation failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    print("✅ Enum validation passed")
    sys.exit(0)
