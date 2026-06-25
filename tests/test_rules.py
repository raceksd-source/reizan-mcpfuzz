from __future__ import annotations

from pathlib import Path

import pytest

from reizan_mcpfuzz.rules import RuleLoadError, load_rules


def test_load_seed_rules():
    rules = load_rules(Path(".mcpfuzz/rules.yaml"))

    assert len(rules) >= 10
    assert {rule.pattern_type for rule in rules} >= {"regex", "hidden_char", "imperative"}


def test_rule_loader_rejects_duplicate_ids(tmp_path: Path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
rules:
  - id: duplicate
    category: one
    pattern_type: regex
    signature: one
    severity: low
  - id: duplicate
    category: two
    pattern_type: regex
    signature: two
    severity: low
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError):
        load_rules(path)
