
import json
from pathlib import Path
from unittest.mock import patch

import subprocess

from app.scanners.dependency_scanner import scan_dependencies


def test_dependency_vulnerability_detection(tmp_path):

    repository = tmp_path / "test-repository"
    repository.mkdir()

    sample_output = {
        "results": [
            {
                "source": {
                    "path": "requirements.txt",
                    "type": "lockfile"
                },
                "packages": [
                    {
                        "package": {
                            "name": "Django",
                            "version": "2.2",
                            "ecosystem": "PyPI"
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-TEST-1234",
                                "summary": "Test vulnerability",
                                "database_specific": {
                                    "severity": "HIGH"
                                },
                                "affected": [
                                    {
                                        "ranges": [
                                            {
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "2.2.1"}
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    mocked_result = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout=json.dumps(sample_output),
        stderr=""
    )

    with patch(
        "app.scanners.dependency_scanner.subprocess.run",
        return_value=mocked_result
    ):

        findings = scan_dependencies(repository)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == "OSV-GHSA-TEST-1234"
    assert finding["severity"] == "High"
    assert finding["package"] == "Django"
    assert finding["version"] == "2.2"
    assert finding["fixed_version"] == "2.2.1"


def test_no_vulnerabilities_found(tmp_path):

    repository = tmp_path / "secure-repository"
    repository.mkdir()

    mocked_result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps({"results": []}),
        stderr=""
    )

    with patch(
        "app.scanners.dependency_scanner.subprocess.run",
        return_value=mocked_result
    ):

        findings = scan_dependencies(repository)

    assert findings == []
