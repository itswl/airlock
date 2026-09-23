from __future__ import annotations

import copy

import pytest

from airlock.config import WorkerProfile
from airlock.plans import (
    PlanError,
    extract_plan,
    groups,
    has_plan,
    parse_plan,
    plan_hash,
    strip_plans,
    targets,
    validate_plan,
)
from tests.conftest import fenced, plan_doc

WORKERS = {
    "ops": WorkerProfile(
        name="ops",
        modes=("commands",),
        allowed_permissions=("svc:restart", "svc:read"),
        command_allowlist=(r"echo [a-z0-9 .:-]+", "true", r"rm -rf /tmp/[a-z]+"),
    ),
    "agent-ops": WorkerProfile(name="agent-ops", modes=("task",), allowed_permissions=("svc:restart",)),
}


def test_a_good_plan_has_no_errors_and_a_stable_hash() -> None:
    plan = parse_plan(plan_doc())
    assert validate_plan(plan, WORKERS) == []
    reordered = parse_plan(dict(reversed(list(plan_doc().items()))))
    assert plan_hash(plan) == plan_hash(reordered)


def test_one_character_is_a_different_plan() -> None:
    changed = plan_doc()
    changed["steps"][0]["argv"][2] = "apj"
    assert plan_hash(parse_plan(plan_doc())) != plan_hash(parse_plan(changed))


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda p: p["steps"][0].update(worker="nobody"), "no worker profile named 'nobody'"),
        (
            lambda p: p["steps"][0].update(argv=["kubectl", "delete", "ns", "prod"]),
            "not on worker ops's command allowlist",
        ),
        (lambda p: p["steps"][0].update(argv=None, task="restart it"), "does not run task steps"),
        (lambda p: p.update(permissions={"ops": ["svc:restart", "iam:admin"]}), "may not have iam:admin"),
        (lambda p: p.update(permissions={}), "does not say what it needs"),
        (lambda p: p["permissions"].update({"agent-ops": []}), "listed but runs no step"),
    ],
)
def test_validation_names_what_is_wrong(mutate, expected: str) -> None:  # noqa: ANN001
    doc = copy.deepcopy(plan_doc())
    mutate(doc)
    errors = validate_plan(parse_plan(doc), WORKERS)
    assert any(expected in e for e in errors), errors


def test_the_catastrophe_floor_holds_even_when_the_allowlist_matches() -> None:
    doc = plan_doc(steps=[{"worker": "ops", "target": "host", "argv": ["rm", "-rf", "/tmp/x"]}])
    errors = validate_plan(parse_plan(doc), WORKERS)
    assert len(errors) == 1 and "danger guard: rm -rf" in errors[0]
    wide = dict(WORKERS, ops=WorkerProfile(name="ops", allowed_permissions=("svc:restart",), command_allowlist=(".*",)))
    doc = plan_doc(steps=[{"worker": "ops", "target": "prod", "argv": ["kubectl", "delete", "namespace", "prod"]}])
    assert any("namespace-wide delete" in e for e in validate_plan(parse_plan(doc), wide))


def test_schema_errors_are_plan_errors() -> None:
    for doc in [
        plan_doc(risk="extreme"),
        plan_doc(steps=[]),
        plan_doc(steps=[{"worker": "ops", "target": "t", "argv": ["true"], "task": "both"}]),
        plan_doc(steps=[{"worker": "ops", "target": "t"}]),
        plan_doc(surprise=True),
    ]:
        with pytest.raises(PlanError):
            parse_plan(doc)


def test_extract_takes_the_last_plan_fence() -> None:
    first, second = plan_doc(summary="first"), plan_doc(summary="second")
    text = fenced(first) + "\nOn reflection:\n" + fenced(second)
    assert extract_plan(text).summary == "second"
    with pytest.raises(PlanError, match="no ```plan block"):
        extract_plan("just prose")
    with pytest.raises(PlanError, match="not valid JSON"):
        extract_plan("```plan\n{nope\n```")


def test_groups_are_consecutive_runs_of_one_worker() -> None:
    doc = plan_doc(
        permissions={"ops": ["svc:restart"], "agent-ops": ["svc:restart"]},
        steps=[
            {"worker": "ops", "target": "a", "argv": ["true"]},
            {"worker": "ops", "target": "b", "argv": ["true"]},
            {"worker": "agent-ops", "target": "b", "task": "check it"},
            {"worker": "ops", "target": "a", "argv": ["true"]},
        ],
    )
    plan = parse_plan(doc)
    assert [(g["worker"], [s["index"] for s in g["steps"]]) for g in groups(plan)] == [
        ("ops", [1, 2]),
        ("agent-ops", [3]),
        ("ops", [4]),
    ]
    assert targets(plan) == ["a", "b"]


def test_evidence_in_json_blocks_is_not_mistaken_for_a_plan() -> None:
    report = 'The pods:\n\n```json\n{"items": [{"name": "api-1"}]}\n```\n\nNothing to change.'
    assert not has_plan(report) and strip_plans(report) == report
    with_plan = report + "\n\n" + fenced(plan_doc(), "And the fix:")
    assert has_plan(with_plan) and '"items"' in strip_plans(with_plan) and '"steps"' not in strip_plans(with_plan)
