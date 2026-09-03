"""Every workflow that reports on a pull request must have one requirable name.

#92 asks for a required status check on `master`. Branch protection can only
require a check *by name*, so "make CI required" is only meaningful if, for
each workflow, there is a single name that is red whenever anything in that
workflow failed.

The first version of this file checked that for `ci.yml` alone. `ci.yml` is one
of nine workflows that trigger on `pull_request` and produces five of the
statuses this repository reports, so requiring `CI Gate` and stopping there
would have left CodeQL, the QEMU boot test, the ARM64 kernel cross-build, the
Python suites and the SBOM validation outside the requirement -- while the test
that existed to prevent exactly that rot only ever read one file. See the
review on #121.

So the scan is over every workflow now, and the mapping from workflow to the
name a maintainer must require is pinned in REQUIRED_CHECKS below. Adding a
workflow, or a job to an existing one, fails these tests until the registry is
updated -- which is the point of the file.

Two workflows need no gate job because they define exactly one job that can run
on a pull request; that job's own name is stable and requirable. The tests
enforce that they stay single-job, so a second job cannot appear beside an
uncovered one.
"""

import json
import subprocess
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
GATE_SCRIPT = ROOT / ".github" / "scripts" / "ci-gate-check.sh"

# workflow file -> (job id that must be green, display name to require)
#
# This is the list a maintainer types into branch protection. It is pinned
# rather than derived, so that adding a workflow is a deliberate decision about
# whether it gates a merge.
REQUIRED_CHECKS = {
    "ci.yml": ("ci-gate", "CI Gate"),
    "build.yml": ("build-gate", "Build Gate"),
    "eos-simulation.yml": ("integration-summary", "Full-stack integration summary"),
    "codeql.yml": ("analyze", "Analyze (C/C++)"),
    "python-tests.yml": ("test", "Run Python tests"),
    "third-party.yml": ("policy", "Validate third_party/ and the SBOM"),
}

# Workflows that deliberately gate nothing, with the reason. A check that is
# skipped on a pull request cannot be required: branch protection waits for a
# status that never arrives, so the pull request hangs rather than going red.
NOT_REQUIRED = {
    "auto-assign.yml":
        "housekeeping; its only job is skipped on every fork pull request "
        "(if: head.repo.full_name == github.repository)",
    "claude-code-review.yml":
        "advisory; both jobs are gated on a label or a non-pull_request event",
    "book-build.yml":
        "documentation build; build-pdf is conditional on whether a book "
        "exists, so the workflow legitimately skips on most pull requests",
}

# (workflow, job) pairs excluded from their gate's `needs`, with the reason.
#
# Pinned rather than inferred. The previous version asked whether the job's
# `if:` contained the substring "refs/tags", which also matches the *inverted*
# condition -- a job that runs on every pull request would have been classified
# as tag-only and silently dropped from the requirement.
CANNOT_RUN_ON_PR = {
    ("ci.yml", "release"): "startsWith(github.ref, 'refs/tags/v')",
}


def _load(name):
    return yaml.safe_load((WORKFLOW_DIR / name).read_text(encoding="utf-8"))


def _triggers_on_pull_request(doc):
    # PyYAML parses a bare `on:` key as the boolean True.
    on = doc.get("on", doc.get(True)) or {}
    return isinstance(on, dict) and "pull_request" in on


def _pr_workflows():
    found = {}
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        doc = _load(path.name)
        if doc and _triggers_on_pull_request(doc):
            found[path.name] = doc
    return found


@pytest.fixture(scope="module")
def pr_workflows():
    workflows = _pr_workflows()
    assert workflows, "no workflows trigger on pull_request; the scan is broken"
    return workflows


# ---- the registry covers reality --------------------------------------------

def test_every_pull_request_workflow_is_classified(pr_workflows):
    """A new workflow must be a deliberate decision, not an accident."""
    classified = set(REQUIRED_CHECKS) | set(NOT_REQUIRED)
    unclassified = set(pr_workflows) - classified
    assert not unclassified, (
        f"these workflows report on pull requests but are in neither "
        f"REQUIRED_CHECKS nor NOT_REQUIRED: {sorted(unclassified)}. Decide "
        f"whether each gates a merge and record it here."
    )


def test_the_registry_has_no_stale_entries(pr_workflows):
    stale = (set(REQUIRED_CHECKS) | set(NOT_REQUIRED)) - set(pr_workflows)
    assert not stale, (
        f"these are registered but no longer trigger on pull_request: "
        f"{sorted(stale)}"
    )


def test_required_names_are_unique():
    """Branch protection matches on the name, so two checks cannot share one."""
    names = [name for _, name in REQUIRED_CHECKS.values()]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, (
        f"these required-check names are claimed by more than one workflow: "
        f"{duplicates}. A name behind several check runs cannot be required."
    )


# ---- each required check is real and covers its workflow ---------------------

def test_each_required_job_exists_with_the_pinned_name(pr_workflows):
    for workflow, (job_id, display) in REQUIRED_CHECKS.items():
        jobs = pr_workflows[workflow]["jobs"]
        assert job_id in jobs, f"{workflow}: no job {job_id!r}"
        actual = jobs[job_id].get("name", job_id)
        assert actual == display, (
            f"{workflow}: job {job_id!r} is displayed as {actual!r}, but "
            f"branch protection is told to require {display!r}. Renaming it "
            f"silently un-requires the check."
        )


def test_each_gate_covers_every_job_that_can_run_on_a_pull_request(pr_workflows):
    for workflow, (job_id, _) in REQUIRED_CHECKS.items():
        jobs = pr_workflows[workflow]["jobs"]
        expected = {
            name for name in jobs
            if name != job_id and (workflow, name) not in CANNOT_RUN_ON_PR
        }
        if not expected:
            # Single-job workflow: the job is its own gate, nothing to cover.
            continue
        declared = set(jobs[job_id].get("needs", []))
        missing = expected - declared
        assert not missing, (
            f"{workflow}: {sorted(missing)} run on pull requests but "
            f"{job_id!r} does not wait for them, so the required check does "
            f"not cover them."
        )


def test_single_job_workflows_stay_single_job(pr_workflows):
    """Their gate is the job itself, which only holds while there is one."""
    for workflow, (job_id, _) in REQUIRED_CHECKS.items():
        jobs = pr_workflows[workflow]["jobs"]
        if set(jobs) == {job_id}:
            continue
        assert jobs[job_id].get("needs"), (
            f"{workflow} has more than one job but {job_id!r} declares no "
            f"`needs`, so it gates only itself."
        )


def test_gates_run_even_when_an_earlier_job_fails(pr_workflows):
    for workflow, (job_id, _) in REQUIRED_CHECKS.items():
        job = pr_workflows[workflow]["jobs"][job_id]
        if not job.get("needs"):
            continue  # its own gate; nothing upstream to survive
        assert str(job.get("if", "")).strip() == "always()", (
            f"{workflow}: {job_id!r} needs `if: always()`. Without it the gate "
            f"is skipped when an earlier job fails, and a skipped required "
            f"check never reports -- the pull request waits for a status that "
            f"never arrives instead of showing a failure."
        )


def test_exclusions_are_justified(pr_workflows):
    """A job left out of a gate must really be unable to run on a PR."""
    for (workflow, job_id), expected_condition in CANNOT_RUN_ON_PR.items():
        job = pr_workflows[workflow]["jobs"][job_id]
        condition = str(job.get("if", ""))
        assert expected_condition in condition, (
            f"{workflow}: {job_id!r} is excluded from its gate on the grounds "
            f"that it cannot run on a pull request, but its condition is "
            f"{condition!r}, which does not contain {expected_condition!r}."
        )


# ---- the rule itself, executed rather than pattern-matched -------------------

def _run_gate(payload):
    return subprocess.run(
        ["bash", str(GATE_SCRIPT)], input=payload,
        capture_output=True, text=True,
    ).returncode


def test_gate_script_exists_and_is_executable():
    assert GATE_SCRIPT.is_file(), f"{GATE_SCRIPT} is missing"


@pytest.mark.parametrize("results,expected", [
    ({"a": {"result": "success"}}, 0),
    ({"a": {"result": "success"}, "b": {"result": "success"}}, 0),
    ({"a": {"result": "failure"}}, 1),
    ({"a": {"result": "skipped"}}, 1),
    ({"a": {"result": "cancelled"}}, 1),
    ({"a": {"result": "success"}, "b": {"result": "skipped"}}, 1),
])
def test_gate_script_accepts_only_all_success(results, expected):
    """The rule is run against real inputs, not grepped for in the YAML.

    The previous version searched the workflow's `run:` text for `!= "success"`
    and `exit 1`, which would pass for those tokens sitting in a comment and
    fail for a correct rewrite that said the same thing differently.
    """
    assert _run_gate(json.dumps(results)) == expected


@pytest.mark.parametrize("payload", ["", "null"])
def test_gate_script_refuses_an_empty_context(payload):
    """No results is not the same as no failures."""
    assert _run_gate(payload) == 1


def test_every_gate_invokes_the_shared_script(pr_workflows):
    """One rule in one place, so the tests above cover every gate."""
    for workflow, (job_id, _) in REQUIRED_CHECKS.items():
        job = pr_workflows[workflow]["jobs"][job_id]
        if not job.get("needs"):
            continue
        script = "\n".join(str(s.get("run", "")) for s in job.get("steps", []))
        assert "ci-gate-check.sh" in script, (
            f"{workflow}: {job_id!r} does not call "
            f".github/scripts/ci-gate-check.sh, so its behaviour is not "
            f"covered by the tests above."
        )
