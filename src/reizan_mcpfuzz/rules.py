"""Portable .mcpfuzz rule loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from reizan_mcpfuzz.models import Rule


VALID_PATTERN_TYPES = {"regex", "hidden_char", "imperative"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}


DEFAULT_RULES: tuple[dict[str, str], ...] = (
    {
        "id": "inj.ignore_previous",
        "category": "instruction_injection",
        "pattern_type": "regex",
        "signature": r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|directions|messages|rules)\b",
        "severity": "high",
    },
    {
        "id": "inj.system_marker",
        "category": "instruction_injection",
        "pattern_type": "regex",
        "signature": r"(?m)(?:^|[\s<\[])(?:system|developer|assistant)\s*:",
        "severity": "high",
    },
    {
        "id": "inj.you_must",
        "category": "instruction_injection",
        "pattern_type": "regex",
        "signature": r"\byou\s+must\b",
        "severity": "medium",
    },
    {
        "id": "inj.before_responding",
        "category": "instruction_injection",
        "pattern_type": "regex",
        "signature": r"\bbefore\s+(?:responding|answering|you\s+(?:respond|answer|reply))\b",
        "severity": "high",
    },
    {
        "id": "egress.exfiltrate",
        "category": "exfiltration",
        "pattern_type": "regex",
        "signature": r"\b(?:exfiltrat\w*|leak|send\s+(?:the\s+)?(?:secret|token|credential|credentials|key|data))\b",
        "severity": "high",
    },
    {
        "id": "egress.fetch_url",
        "category": "exfiltration",
        "pattern_type": "regex",
        "signature": r"\b(?:fetch|post|send|call|open|retrieve|get)\s+https?://[^\s\"'<>]+",
        "severity": "high",
    },
    {
        "id": "obfuscation.base64_blob",
        "category": "obfuscation",
        "pattern_type": "regex",
        "signature": r"\b(?:[A-Za-z0-9+/]{80,}={0,2})\b",
        "severity": "medium",
    },
    {
        "id": "hidden.zero_width",
        "category": "hidden_content",
        "pattern_type": "hidden_char",
        "signature": "zero_width",
        "severity": "medium",
    },
    {
        "id": "hidden.ansi_escape",
        "category": "hidden_content",
        "pattern_type": "hidden_char",
        "signature": "ansi_escape",
        "severity": "medium",
    },
    {
        "id": "hidden.unicode_confusable",
        "category": "hidden_content",
        "pattern_type": "hidden_char",
        "signature": "unicode_hyphen_or_nfkc",
        "severity": "medium",
    },
    {
        "id": "imperative.tool_call_combo",
        "category": "instruction_injection",
        "pattern_type": "imperative",
        "signature": "tool_call_combo",
        "severity": "medium",
    },
    {
        "id": "permissions.destructive",
        "category": "permissions",
        "pattern_type": "regex",
        "signature": r"\b(?:delete|drop|truncate|destroy|wipe|overwrite|rm\s+-rf|execute\s+shell|shell\s+command|subprocess|arbitrary\s+code)\b",
        "severity": "medium",
    },
    {
        "id": "permissions.additional_properties",
        "category": "permissions",
        "pattern_type": "regex",
        "signature": r'"additionalProperties"\s*:\s*true',
        "severity": "medium",
    },
    {
        "id": "permissions.sensitive_target",
        "category": "permissions",
        "pattern_type": "regex",
        "signature": r"\b(?:/etc/passwd|~/\.ssh|id_rsa|aws_secret|api[_-]?key|secrets?/|credentials?)\b",
        "severity": "high",
    },
)


class RuleLoadError(ValueError):
    pass


def load_rules(path: Path | None = None) -> tuple[Rule, ...]:
    if path is None:
        default_path = Path(".mcpfuzz/rules.yaml")
        if default_path.exists():
            path = default_path

    if path is None:
        raw_rules: Any = list(DEFAULT_RULES)
    else:
        raw_rules = _load_yaml(path)

    if isinstance(raw_rules, dict):
        raw_rules = raw_rules.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleLoadError("rules file must be a non-empty list or an object with non-empty 'rules'")

    rules = tuple(_rule_from_mapping(index, raw) for index, raw in enumerate(raw_rules, start=1))
    _validate_unique_rule_ids(rules)
    return rules


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleLoadError(f"could not read rules: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML rules: {exc}") from exc


def _rule_from_mapping(index: int, raw: Any) -> Rule:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"rule {index} must be a mapping")
    required = ("id", "category", "pattern_type", "signature", "severity")
    missing = [field for field in required if field not in raw]
    if missing:
        raise RuleLoadError(f"rule {index} missing required field(s): {', '.join(missing)}")
    rule = Rule(
        id=_required_string(raw["id"], f"rule {index} id"),
        category=_required_string(raw["category"], f"rule {index} category"),
        pattern_type=_required_string(raw["pattern_type"], f"rule {index} pattern_type"),
        signature=_required_string(raw["signature"], f"rule {index} signature"),
        severity=_required_string(raw["severity"], f"rule {index} severity").lower(),
    )
    if rule.pattern_type not in VALID_PATTERN_TYPES:
        expected = ", ".join(sorted(VALID_PATTERN_TYPES))
        raise RuleLoadError(f"rule {index} pattern_type must be one of: {expected}")
    if rule.severity not in VALID_SEVERITIES:
        expected = ", ".join(sorted(VALID_SEVERITIES))
        raise RuleLoadError(f"rule {index} severity must be one of: {expected}")
    return rule


def _validate_unique_rule_ids(rules: tuple[Rule, ...]) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in rules:
        if rule.id in seen:
            duplicates.append(rule.id)
        seen.add(rule.id)
    if duplicates:
        raise RuleLoadError(f"duplicate rule id(s): {', '.join(sorted(set(duplicates)))}")


def _required_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleLoadError(f"{field_name} must be a non-empty string")
    return value.strip()
