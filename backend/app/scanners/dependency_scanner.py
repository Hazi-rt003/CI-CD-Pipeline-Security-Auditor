
import json
import subprocess
from pathlib import Path


def determine_severity(vulnerability):
    """
    Use the severity label supplied by the vulnerability database
    when available. Do not invent a severity if it is unavailable.
    """

    database_specific = vulnerability.get("database_specific", {})

    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")

        if isinstance(severity, str):
            severity = severity.upper()

            if severity in {
                "CRITICAL", "HIGH", "MEDIUM", "LOW"
            }:
                return severity.title()

    return "Unknown"


def get_fixed_version(vulnerability):
    """Extract an available fixed version from OSV vulnerability data."""

    for affected in vulnerability.get("affected", []):
        if not isinstance(affected, dict):
            continue

        for version_range in affected.get("ranges", []):
            if not isinstance(version_range, dict):
                continue

            for event in version_range.get("events", []):
                if "fixed" in event:
                    return event["fixed"]

    return None


def convert_vulnerability_to_finding(
    vulnerability,
    package,
    source_path
):
    """Convert OSV vulnerability information into our finding format."""

    vulnerability_id = vulnerability.get("id", "UNKNOWN")

    package_name = package.get("name", "Unknown package")
    package_version = package.get("version", "Unknown version")
    ecosystem = package.get("ecosystem", "Unknown ecosystem")

    fixed_version = get_fixed_version(vulnerability)

    description = vulnerability.get(
        "summary",
        vulnerability.get(
            "details",
            "A known vulnerability affects this dependency."
        )
    )

    if fixed_version:
        recommendation = (
            f"Upgrade {package_name} from {package_version} "
            f"to at least version {fixed_version}, after verifying "
            "compatibility."
        )
    else:
        recommendation = (
            f"Review the advisory for {package_name} and determine "
            "whether a patched version or alternative package is available."
        )

    return {
        "rule_id": f"OSV-{vulnerability_id}",
        "title": f"Vulnerable dependency: {package_name}",
        "severity": determine_severity(vulnerability),
        "file": source_path,
        "description": description,
        "recommendation": recommendation,
        "package": package_name,
        "version": package_version,
        "ecosystem": ecosystem,
        "vulnerability_id": vulnerability_id,
        "fixed_version": fixed_version
    }


def scan_dependencies(repository_path):
    """Scan project dependencies using OSV-Scanner."""

    repository_path = Path(repository_path).resolve()

    if not repository_path.exists():
        raise FileNotFoundError(
            f"Repository not found: {repository_path}"
        )

    command = [
        "osv-scanner",
        "scan",
        "source",
        "--recursive",
        "--format",
        "json",
        str(repository_path)
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

    except FileNotFoundError:
        raise RuntimeError(
            "OSV-Scanner was not found. "
            "Check that it is installed and available in PATH."
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError("OSV-Scanner execution timed out.")

    # Exit code 0: no vulnerabilities found.
    # Exit code 1: vulnerabilities/findings found.
    # Exit code 128: no packages found.
    if result.returncode not in (0, 1, 128):
        raise RuntimeError(
            f"OSV-Scanner execution failed: {result.stderr}"
        )

    if not result.stdout.strip():
        return []

    try:
        scan_data = json.loads(result.stdout)

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Could not parse OSV-Scanner JSON output."
        ) from error

    findings = []

    for scan_result in scan_data.get("results", []):

        source = scan_result.get("source", {})
        source_path = source.get("path", "Unknown file")

        for package_result in scan_result.get("packages", []):

            package = package_result.get("package", {})

            for vulnerability in package_result.get(
                "vulnerabilities", []
            ):

                finding = convert_vulnerability_to_finding(
                    vulnerability,
                    package,
                    source_path
                )

                findings.append(finding)

    return findings
