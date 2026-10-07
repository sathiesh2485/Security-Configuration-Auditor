import json
from pathlib import Path


def load_remediation_data():
    file_path = Path(__file__).parent / "data" / "remediation.json"

    with open(file_path, "r", encoding="utf-8") as file:
        remediation_data = json.load(file)

    return remediation_data


def get_remediation(issue, remediation_data):
    if issue in remediation_data:
        return remediation_data[issue]

    return {
        "recommendation": "No specific remediation available.",
        "action": "Review the configuration manually."
    }


if __name__ == "__main__":
    remediation_data = load_remediation_data()

    issue = "Insecure file permissions"

    result = get_remediation(issue, remediation_data)

    print("Recommendation:", result["recommendation"])
    print("Action:", result["action"])