"""The core does not depend on anything around it."""

from __future__ import annotations

import ast
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "airlock"


def test_no_core_module_imports_the_extras() -> None:
    offenders = []
    for path in sorted(CORE.rglob("*.py")):
        if "extras" in path.relative_to(CORE).parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(name == "airlock.extras" or name.startswith("airlock.extras.") for name in names):
                offenders.append(str(path.relative_to(CORE)))
    assert offenders == []


def test_the_shipped_examples_load(tmp_path: Path) -> None:
    import yaml

    from airlock.extras.feishu.config import load_feishu
    from airlock.extras.mirrors import load_mirrors
    from airlock.extras.selfcheck import load_selfcheck
    from airlock.extras.watch.config import load_watch

    examples = CORE.parent / "deploy" / "extras"

    def names(node: object) -> set[str]:
        if isinstance(node, dict):
            found = {str(v) for k, v in node.items() if str(k).endswith("_env")}
            return found.union(*(names(v) for v in node.values()))
        if isinstance(node, list):
            return set().union(*(names(v) for v in node))
        return set()

    loaded = {}
    for name, load in (
        ("watch", load_watch),
        ("feishu", load_feishu),
        ("selfcheck", load_selfcheck),
        ("mirrors", load_mirrors),
    ):
        data = yaml.safe_load((examples / f"{name}.example.yaml").read_text(encoding="utf-8"))
        if name == "watch":
            data["brief_file"] = str(examples / "watch-brief.example.md")
        env = {variable: "x" * 32 for variable in names(data)}
        loaded[name] = load(data, env)
    assert loaded["watch"].chat is not None and loaded["watch"].jira is not None
    assert loaded["feishu"].plans_chat and loaded["feishu"].people
    assert [c.kind for c in loaded["selfcheck"].checks].count("url") == 5
    assert loaded["mirrors"].repos[0].name == "payments-api"
