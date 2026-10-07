import json
from pathlib import Path

from threat_intelligence import load_threat_intelligence, get_threat_context
from severity import load_severity_rules, get_severity
from remediation import load_remediation_data, get_remediation
from ai_analyzer import analyze_with_ai


def load_sample_findings():
    file_path = Path(__file__).parent / "data" / "sample_findings.json"

    with open(file_path, "r", encoding="utf-8") as file:
        findings = json.load(file)

    return findings


def display_findings(findings, threat_data, severity_rules, remediation_data):

    for finding in findings:

        threat_context = get_threat_context(
            finding["issue"],
            threat_data
        )

        severity_result = get_severity(
            finding["issue"],
            severity_rules
        )

        remediation_result = get_remediation(
            finding["issue"],
            remediation_data
        )

        ai_explanation = analyze_with_ai(
            finding,
            threat_context,
            severity_result,
            remediation_result
        )

        print(f"Finding: {finding['issue']}")
        print(f"Category: {finding['category']}")
        print(f"Evidence: {finding['evidence']}")

        print(f"Threat: {threat_context['threat']}")
        print(f"Impact: {threat_context['impact']}")
        print(f"Context: {threat_context['context']}")

        print(f"Severity: {severity_result['severity']}")
        print(f"Severity Reason: {severity_result['reason']}")

        print(f"Recommendation: {remediation_result['recommendation']}")
        print(f"Action: {remediation_result['action']}")

        print("\nAI Security Analysis:")
        print(ai_explanation)

        print("-" * 60)


if __name__ == "__main__":

    findings = load_sample_findings()
    threat_data = load_threat_intelligence()
    severity_rules = load_severity_rules()
    remediation_data = load_remediation_data()

    display_findings(
        findings,
        threat_data,
        severity_rules,
        remediation_data
    )