
from pathlib import Path
import re
import yaml


def create_finding(rule_id, title, severity, file_path,
                   description, recommendation):

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "file": str(file_path),
        "description": description,
        "recommendation": recommendation
    }


def get_workflow_steps(workflow_data):
    """Collect all steps from jobs in a workflow."""

    steps = []

    jobs = workflow_data.get("jobs", {})

    if not isinstance(jobs, dict):
        return steps

    for job in jobs.values():
        if isinstance(job, dict):
            job_steps = job.get("steps", [])

            if isinstance(job_steps, list):
                steps.extend(job_steps)

    return steps


def scan_workflow_file(file_path):
    """Analyse a GitHub Actions workflow YAML file."""

    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            workflow = yaml.load(file, Loader=yaml.BaseLoader)

    except yaml.YAMLError:
        return findings

    except OSError:
        return findings

    if not isinstance(workflow, dict):
        return findings

    # Rule WF001: Missing explicit permissions
    permissions = workflow.get("permissions")

    if permissions is None:
        findings.append(create_finding(
            "WF001",
            "Missing explicit workflow permissions",
            "Medium",
            file_path,
            "The workflow does not explicitly define its GITHUB_TOKEN permissions.",
            "Define the minimum permissions required by the workflow."
        ))

    # Rule WF002: Excessive write permissions
    if isinstance(permissions, str):
        if permissions.lower() == "write-all":
            findings.append(create_finding(
                "WF002",
                "Excessive workflow permissions",
                "High",
                file_path,
                "The workflow grants write access to all available permissions.",
                "Replace write-all with explicitly defined least-privilege permissions."
            ))

    # Rule WF003: Dangerous pull_request_target combination
    triggers = workflow.get("on", {})

    if isinstance(triggers, str):
        triggers = [triggers]

    elif isinstance(triggers, dict):
        triggers = list(triggers.keys())

    if not isinstance(triggers, list):
        triggers = []

    has_pull_request_target = (
        "pull_request_target" in triggers
    )

    steps = get_workflow_steps(workflow)

    uses_checkout = any(
        isinstance(step, dict)
        and isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@")
        for step in steps
    )

    if has_pull_request_target and uses_checkout:
        findings.append(create_finding(
            "WF003",
            "Potentially unsafe pull_request_target configuration",
            "High",
            file_path,
            "The workflow uses pull_request_target together with actions/checkout. "
            "This combination can expose privileged workflow contexts if untrusted "
            "pull request code is checked out or executed.",
            "Review the workflow carefully. Avoid checking out or executing "
            "untrusted pull request code in a privileged context."
        ))

    # Rule WF004: Actions not pinned to full commit SHA
    sha_pattern = re.compile(r"@[0-9a-fA-F]{40}$")

    for step in steps:
        if not isinstance(step, dict):
            continue

        action = step.get("uses")

        if not isinstance(action, str):
            continue

        # Skip local actions and Docker references
        if action.startswith("./") or action.startswith("docker://"):
            continue

        if "@" in action and not sha_pattern.search(action):
            findings.append(create_finding(
                "WF004",
                "GitHub Action is not pinned to a full commit SHA",
                "Medium",
                file_path,
                f"The action '{action}' uses a tag or version instead of "
                "a full commit SHA.",
                "Pin the action to its verified full commit SHA."
            ))

        elif "@" not in action:
            findings.append(create_finding(
                "WF004",
                "GitHub Action reference has no version",
                "Medium",
                file_path,
                f"The action '{action}' does not specify a version or commit SHA.",
                "Specify a verified full commit SHA."
            ))

    return findings


def scan_repository(repository_path):
    """Scan all GitHub Actions workflow files in a repository."""

    repository_path = Path(repository_path)

    workflow_directory = (
        repository_path / ".github" / "workflows"
    )

    findings = []

    if not workflow_directory.exists():
        return findings

    workflow_files = list(workflow_directory.glob("*.yml"))
    workflow_files += list(workflow_directory.glob("*.yaml"))

    for workflow_file in workflow_files:
        findings.extend(scan_workflow_file(workflow_file))

    return findings
