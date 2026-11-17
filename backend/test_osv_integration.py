from pathlib import Path
from app.scanners.dependency_scanner import scan_dependencies

project_root = Path(__file__).resolve().parents[1]

repository = (
    project_root
    / "test_repositories"
    / "vulnerable"
)

findings = scan_dependencies(repository)

print(f"\nTotal vulnerabilities detected: {len(findings)}")

for finding in findings:
    print("\n-----------------------------")
    print("ID:", finding["rule_id"])
    print("Package:", finding["package"])
    print("Version:", finding["version"])
    print("Severity:", finding["severity"])
    print("Description:", finding["description"])
    print("Recommendation:", finding["recommendation"])