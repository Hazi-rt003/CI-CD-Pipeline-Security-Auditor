from pathlib import Path

from app.scanners.workflow_scanner import scan_repository


def test_insecure_workflow():
    project_root = Path(__file__).resolve().parents[2]

    repository = (
        project_root
        / "test_repositories"
        / "vulnerable"
    )

    findings = scan_repository(repository)

    rule_ids = {finding["rule_id"] for finding in findings}

    assert "WF002" in rule_ids
    assert "WF003" in rule_ids
    assert "WF004" in rule_ids