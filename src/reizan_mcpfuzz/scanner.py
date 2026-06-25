"""Deterministic MCP tool-poisoning scanner."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from reizan_mcpfuzz.models import Finding, Rule, SourceReport, ToolRecord, ToolReport, verdict_for_findings
from reizan_mcpfuzz.normalize import hidden_spans, normalize_with_map


@dataclass(frozen=True)
class TextSurface:
    path: str
    text: str


class ScannerError(ValueError):
    pass


def scan_tool(tool: ToolRecord, rules: tuple[Rule, ...]) -> ToolReport:
    findings: list[Finding] = []
    surfaces = tuple(_surfaces_for_tool(tool))
    for surface in surfaces:
        for rule in rules:
            if rule.pattern_type == "regex":
                findings.extend(_regex_findings(rule, surface))
            elif rule.pattern_type == "hidden_char":
                findings.extend(_hidden_findings(rule, surface))
            elif rule.pattern_type == "imperative":
                findings.extend(_imperative_findings(rule, surface))
            else:
                raise ScannerError(f"unsupported pattern_type: {rule.pattern_type}")

    if not isinstance(tool.input_schema, dict):
        raw_span = json.dumps(tool.input_schema, ensure_ascii=False, sort_keys=True)
        findings.append(
            Finding(
                rule_id="schema.invalid_input_schema",
                category="schema",
                pattern_type="structural",
                severity="medium",
                path="inputSchema",
                span=raw_span,
                start=0,
                end=len(raw_span),
                message="inputSchema is not a JSON object; MCP tools require an object schema",
            )
        )

    unique = _dedupe_findings(findings)
    return ToolReport(tool=tool, verdict=verdict_for_findings(unique), findings=unique)


def scan_tools(tools: tuple[ToolRecord, ...], rules: tuple[Rule, ...]) -> tuple[ToolReport, ...]:
    return tuple(scan_tool(tool, rules) for tool in tools)


def error_source(kind: str, target: str, error: str) -> SourceReport:
    return SourceReport(kind=kind, target=target, error=error)


def _surfaces_for_tool(tool: ToolRecord) -> Iterable[TextSurface]:
    yield TextSurface("name", tool.name)
    yield TextSurface("description", tool.description)
    yield from _schema_string_surfaces(tool.input_schema, "inputSchema")
    try:
        schema_json = json.dumps(
            tool.input_schema,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except TypeError:
        schema_json = repr(tool.input_schema)
    yield TextSurface("inputSchema", schema_json)


def _schema_string_surfaces(value: Any, path: str) -> Iterable[TextSurface]:
    if isinstance(value, str):
        yield TextSurface(path, value)
    elif isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if _safe_path_token(str(key)) else f"{path}[{key!r}]"
            yield from _schema_string_surfaces(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _schema_string_surfaces(child, f"{path}[{index}]")


def _safe_path_token(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", value))


def _regex_findings(rule: Rule, surface: TextSurface) -> list[Finding]:
    if surface.path == "inputSchema" and rule.id != "permissions.additional_properties":
        return []
    try:
        regex = re.compile(rule.signature, flags=re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise ScannerError(f"invalid regex in rule {rule.id}: {exc}") from exc

    normalized = normalize_with_map(surface.text)
    findings: list[Finding] = []
    for match in regex.finditer(normalized.text):
        if match.start() == match.end():
            continue
        start, end = normalized.original_span(match.start(), match.end(), surface.text)
        span = surface.text[start:end]
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                pattern_type=rule.pattern_type,
                severity=rule.severity,
                path=surface.path,
                span=span,
                normalized_span=match.group(0),
                start=start,
                end=end,
                message=f"matched {rule.id}",
            )
        )
    return findings


def _hidden_findings(rule: Rule, surface: TextSurface) -> list[Finding]:
    findings: list[Finding] = []
    for hidden in hidden_spans(surface.text, rule.signature):
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                pattern_type=rule.pattern_type,
                severity=rule.severity,
                path=surface.path,
                span=hidden.span,
                start=hidden.start,
                end=hidden.end,
                message=hidden.message,
            )
        )
    return findings


def _imperative_findings(rule: Rule, surface: TextSurface) -> list[Finding]:
    if rule.signature != "tool_call_combo":
        return []
    if surface.path == "inputSchema":
        return []
    normalized = normalize_with_map(surface.text)
    pattern = re.compile(
        r"\b(?:call|invoke|execute|run|use|fetch|read|send|post)\b"
        r"[\s\S]{0,140}?"
        r"(?:tools/call|TOOL\s*:|[A-Za-z_][A-Za-z0-9_.-]{1,80}\s*\(|https?://)",
        flags=re.IGNORECASE,
    )
    findings: list[Finding] = []
    for match in pattern.finditer(normalized.text):
        sentence_start, sentence_end = _sentence_bounds(normalized.text, match.start(), match.end())
        start, end = normalized.original_span(sentence_start, sentence_end, surface.text)
        span = surface.text[start:end].strip()
        if not span:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                pattern_type=rule.pattern_type,
                severity=rule.severity,
                path=surface.path,
                span=span,
                normalized_span=normalized.text[sentence_start:sentence_end].strip(),
                start=start,
                end=end,
                message="imperative language is paired with a tool call, URL, or function-call shape",
            )
        )
    return findings


def _sentence_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    left = max(text.rfind("\n", 0, start), text.rfind(";", 0, start))
    right_candidates = [pos for pos in (text.find("\n", end), text.find(";", end)) if pos != -1]
    sentence_start = left + 1 if left != -1 else 0
    sentence_end = min(right_candidates) + 1 if right_candidates else len(text)
    return sentence_start, sentence_end


def _dedupe_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    seen: set[tuple[str, str, int, int, str]] = set()
    unique: list[Finding] = []
    for finding in sorted(findings, key=lambda item: (item.path, item.start, item.end, item.rule_id)):
        key = (finding.rule_id, finding.path, finding.start, finding.end, finding.span)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return tuple(unique)
