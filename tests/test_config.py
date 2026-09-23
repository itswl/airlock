from __future__ import annotations

import copy
from typing import Any

import pytest

from airlock.config import ConfigError, load_control, load_launcher


def test_the_full_example_loads(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = load_control(config_dict, env)
    assert set(config.sources) == {"github", "alerts", "ci"}
    assert config.sources["github"].event_header == "X-GitHub-Event"
    assert config.investigators["infra"].may_consult == ("code",)
    assert config.workers["ops"].allows_command("echo restarting api")
    assert not config.workers["ops"].allows_command("echo restarting api; rm -rf /")
    launcher = load_launcher(config_dict, env)
    assert launcher.runtime == "local" and set(launcher.workers) == {"ops", "agent-ops"}


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda c, e: e.pop("T_GITHUB"), "T_GITHUB is unset"),
        (lambda c, e: c["sources"][0].pop("accept"), "say which events become work"),
        (lambda c, e: c["sources"][0].update(verify="none"), "verify must be one of"),
        (lambda c, e: c.update(routes=[]), "at least one route"),
        (lambda c, e: c["routes"].append({"investigator": "ghost"}), "no investigator by that name"),
        (lambda c, e: c["investigators"][0].update(may_consult=["infra"]), "not another investigator"),
        (lambda c, e: c["workers"][0].update(command_allowlist=[]), "needs a command_allowlist"),
        (lambda c, e: c["workers"][0].update(command_allowlist=["(unclosed"]), "is invalid"),
        (lambda c, e: c["workers"][0].update(name="Bad Name"), "must be lowercase"),
        (lambda c, e: e.update(T_PASSWORD_HASH="plaintext"), "password hash"),
        (lambda c, e: c["launcher"].pop("url"), "launcher: url is required"),
    ],
)
def test_mistakes_fail_at_load(config_dict: dict[str, Any], env: dict[str, str], mutate, message: str) -> None:  # noqa: ANN001
    config, values = copy.deepcopy(config_dict), dict(env)
    mutate(config, values)
    with pytest.raises(ConfigError, match=message):
        load_control(config, values)


def test_launcher_needs_its_control_url(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = copy.deepcopy(config_dict)
    config["launcher"].pop("control_url")
    with pytest.raises(ConfigError, match="control_url"):
        load_launcher(config, env)


def test_the_shipped_example_loads(env: dict[str, str]) -> None:
    from pathlib import Path

    import yaml

    example = Path(__file__).parent.parent / "config.example.yaml"
    names: set[str] = set()

    def collect(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).endswith("_env") and isinstance(value, str):
                    names.add(value)
                collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(yaml.safe_load(example.read_text()))
    values = {name: "x" * 32 for name in names} | {"AIRLOCK_OPERATOR_PASSWORD_HASH": env["T_PASSWORD_HASH"]}
    control = load_control(example, values)
    launcher = load_launcher(example, values)
    assert set(control.workers) == set(launcher.workers) == {"k8s-ops", "aws-ops", "code"}
    assert set(launcher.workers["code"].repos) == {"payments-api"} and launcher.workers["code"].instructions
    assert control.sources["jira"].event_header is None and control.routes[-1].when is None
    assert control.workers["k8s-ops"].allows_command("kubectl -n payments rollout restart deployment/api")
    assert not control.workers["k8s-ops"].allows_command("kubectl -n kube-system rollout restart deployment/api")
