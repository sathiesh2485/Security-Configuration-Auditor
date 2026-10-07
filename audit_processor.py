from finding_handler import load_sample_findings
from threat_intelligence import load_threat_intelligence, get_threat_context
from severity import load_severity_rules, get_severity
from remediation import load_remediation_data, get_remediation
from ai_analyzer import analyze_with_ai


def process_findings():

    findings = load_sample_findings()
    threat_data = load_threat_intelligence()
    severity_rules = load_severity_rules()
    remediation_data = load_remediation_data()

    results = []

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

        result = {
            "id": finding["id"],
            "configuration": finding["configuration"],
            "issue": finding["issue"],
            "category": finding["category"],
            "evidence": finding["evidence"],
            "threat": threat_context["threat"],
            "impact": threat_context["impact"],
            "context": threat_context["context"],
            "severity": severity_result["severity"],
            "severity_reason": severity_result["reason"],
            "recommendation": remediation_result["recommendation"],
            "action": remediation_result["action"],
            "ai_explanation": ai_explanation
        }

        results.append(result)

    return results


if __name__ == "__main__":

    results = process_findings()

    for result in results:

        print("\n" + "=" * 70)

        print("Finding:", result["issue"])
        print("Category:", result["category"])
        print("Severity:", result["severity"])
        print("Threat:", result["threat"])
        print("Recommendation:", result["recommendation"])

        print("\nAI Analysis:")
        print(result["ai_explanation"])

    print("\n" + "=" * 70)
    print("Audit processing completed successfully.")