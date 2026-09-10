"""
Minimal Sigma rule evaluation engine used for local testing.

This intentionally implements a small, dependency-free subset of the Sigma
spec (dotted-path field lookup, list-of-values-as-OR, the `|contains`
modifier, and `and`/`or` between named selections) — enough to unit test
that a rule's detection logic actually matches the log it's meant to catch
and does NOT match a similar-but-benign log. In the CI/CD pipeline, the
real conversion to a deployable query is done by sigma-cli against the
Elastic backend (see scripts/deploy_rules.py) — this harness is just the
fast, offline test layer.
"""
from __future__ import annotations
import yaml


def _get_path(event: dict, dotted_key: str):
    node = event
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _field_matches(event: dict, field: str, expected) -> bool:
    modifier = None
    if "|" in field:
        field, modifier = field.split("|", 1)

    actual = _get_path(event, field)
    if actual is None:
        return False

    values = expected if isinstance(expected, list) else [expected]

    if modifier == "contains":
        return any(str(v) in str(actual) for v in values)
    return any(str(actual) == str(v) for v in values)


def _selection_matches(event: dict, selection: dict) -> bool:
    return all(_field_matches(event, field, expected) for field, expected in selection.items())


def evaluate(rule: dict, event: dict) -> bool:
    """Evaluate a Sigma rule's `detection` block against a single log event."""
    detection = rule["detection"]
    condition = detection["condition"].strip()
    selections = {k: v for k, v in detection.items() if k != "condition"}

    results = {name: _selection_matches(event, sel) for name, sel in selections.items()}

    # Support "X", "X and Y", "X or Y" — sufficient for this rule set.
    if " and " in condition:
        parts = [p.strip() for p in condition.split(" and ")]
        return all(results.get(p, False) for p in parts)
    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(results.get(p, False) for p in parts)
    return results.get(condition, False)


def load_rule(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_event(path: str) -> dict:
    import json
    with open(path, "r") as f:
        return json.load(f)
