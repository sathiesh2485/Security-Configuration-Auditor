import requests


def analyze_with_ai(finding, threat_context, severity_result, remediation_result):

    prompt = f"""
You are a cybersecurity security configuration auditor.

Analyze the following security finding.

Finding:
{finding["issue"]}

Category:
{finding["category"]}

Evidence:
{finding["evidence"]}

Threat Intelligence:
Threat: {threat_context["threat"]}
Impact: {threat_context["impact"]}
Context: {threat_context["context"]}

Severity:
{severity_result["severity"]}

Severity Reason:
{severity_result["reason"]}

Recommended Remediation:
{remediation_result["recommendation"]}

Provide a concise professional explanation of:

1. What the security issue means
2. Why it is a security risk
3. What could happen if it is not fixed
4. How the recommended remediation helps

Do not invent technical details that are not supported by the information provided.
"""

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        if response.status_code != 200:
            print("Ollama API Error:")
            print(response.text)

            return "AI analysis could not be generated."

        result = response.json()

        return result.get(
            "response",
            "AI analysis was not returned."
        )

    except requests.exceptions.RequestException as error:

        print("Connection error with Ollama:")
        print(error)

        return "AI analysis could not be generated because Ollama was unavailable."


if __name__ == "__main__":

    test_finding = {
        "issue": "Insecure file permissions",
        "category": "Access Control",
        "evidence": "Permission value: 777"
    }

    test_threat = {
        "threat": "Unauthorized file access or modification",
        "impact": "Overly permissive permissions may allow unintended users or processes to access or modify files.",
        "context": "Permissions such as 777 allow broad read, write, and execute access."
    }

    test_severity = {
        "severity": "High",
        "reason": "Overly permissive file permissions may allow unauthorized users or processes to access or modify files."
    }

    test_remediation = {
        "recommendation": "Restrict file permissions to only the users and processes that require access.",
        "action": "Review files with overly permissive permissions and apply appropriate access permissions."
    }

    explanation = analyze_with_ai(
        test_finding,
        test_threat,
        test_severity,
        test_remediation
    )

    print("\nAI Security Analysis:")
    print(explanation)