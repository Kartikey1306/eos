"""The CI workflow must expose one job that summarises all the others.

#92 asks for a required status check on `master`. Branch protection can only
require a check by name, and the names this workflow produces are not usable
for that directly: `release` is skipped on every pull request, so requiring it would leave
every pull request waiting for a status that never arrives.

So `ci-gate` exists to be the one name to require. These tests keep it honest
-- specifically, they fail if someone adds a job to the workflow and does not
wire it into the gate, which would otherwise silently create a job that the
required check does not cover.
"""

import yaml
import pytest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"

# The name branch protection is pointed at. Changing it silently un-requires
# the check, so it is pinned here rather than merely read.
GATE_ID = "ci-gate"
GATE_NAME = "CI Gate"


@pytest.fixture(scope="module")
def workflow():
    assert WORKFLOW.is_file(), f"{WORKFLOW} does not exist"
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def jobs(workflow):
    return workflow["jobs"]


def _only_runs_on_tags(job):
    """Is this job gated to tag builds, and therefore skipped on every PR?"""
    condition = str(job.get("if", ""))
    return "refs/tags" in condition


def test_gate_job_exists(jobs):
    assert GATE_ID in jobs, (
        f"no {GATE_ID!r} job; branch protection has no single name to require"
    )


def test_gate_display_name_is_pinned(jobs):
    assert jobs[GATE_ID]["name"] == GATE_NAME, (
        "the gate's display name is what branch protection matches on; "
        "renaming it un-requires the check without failing anything"
    )


def test_gate_runs_even_when_an_earlier_job_fails(jobs):
    condition = str(jobs[GATE_ID].get("if", "")).strip()
    assert condition == "always()", (
        "the gate needs `if: always()`. Without it the gate is skipped when an "
        "earlier job fails, and a skipped required check never reports -- the "
        "pull request waits for a status that never arrives instead of showing "
        "a failure"
    )


def test_gate_covers_every_job_that_runs_on_a_pull_request(jobs):
    expected = {
        name for name, job in jobs.items()
        if name != GATE_ID and not _only_runs_on_tags(job)
    }
    declared = set(jobs[GATE_ID].get("needs", []))

    missing = expected - declared
    assert not missing, (
        f"these jobs run on pull requests but the gate does not wait for them: "
        f"{sorted(missing)}. A job outside the gate is a job the required "
        f"check does not cover."
    )

    unknown = declared - set(jobs)
    assert not unknown, f"the gate needs jobs that do not exist: {sorted(unknown)}"


def test_jobs_left_out_of_the_gate_are_genuinely_tag_only(jobs):
    """Excluding a job from the gate must be justified, not just convenient."""
    declared = set(jobs[GATE_ID].get("needs", []))
    for name, job in jobs.items():
        if name == GATE_ID or name in declared:
            continue
        assert _only_runs_on_tags(job), (
            f"job {name!r} is not in the gate and is not tag-only; either add "
            f"it to `needs` or give it an `if:` that explains why it cannot run "
            f"on a pull request"
        )


def test_gate_fails_on_any_non_success_result(jobs):
    """A skipped or cancelled job must fail the gate, not pass it."""
    steps = jobs[GATE_ID]["steps"]
    script = "\n".join(str(s.get("run", "")) for s in steps)

    assert '!= "success"' in script, (
        "the gate must require success specifically. Checking only for "
        "'failure' lets a skipped or cancelled job through, which is the "
        "fail-open shape this repository has been removing elsewhere"
    )
    assert "exit 1" in script, "the gate must actually fail the job"
