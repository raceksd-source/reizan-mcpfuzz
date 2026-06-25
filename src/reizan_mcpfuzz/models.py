"""Shared data models for reizan-mcpfuzz."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    POISONED = "POISONED"


VERDICT_RANK = {
    Verdict.CLEAN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.POISONED: 2,
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern_type: str
    signature: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "pattern_type": self.pattern_type,
            "signature": self.signature,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ToolRecord:
    name: str
    description: str
    input_schema: Any
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "raw": self.raw,
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    pattern_type: str
    severity: str
    path: str
    span: str
    start: int
    end: int
    message: str
    normalized_span: str | None = None

    @property
    def verdict(self) -> Verdict:
        return verdict_for_severity(self.severity)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_id": self.rule_id,
            "category": self.category,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "verdict": self.verdict.value,
            "path": self.path,
            "span": self.span,
            "span_display": display_span(self.span),
            "start": self.start,
            "end": self.end,
            "message": self.message,
        }
        if self.normalized_span is not None and self.normalized_span != self.span:
            data["normalized_span"] = self.normalized_span
        return data


@dataclass(frozen=True)
class ToolReport:
    tool: ToolRecord
    verdict: Verdict
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.name,
            "verdict": self.verdict.value,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class SourceReport:
    kind: str
    target: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {"kind": self.kind, "target": self.target}
        if self.error:
            data["error"] = self.error
        return data


@dataclass(frozen=True)
class DynamicReport:
    verdict: str
    evidence_sha256: str
    canary_sha256: str
    reason: str
    transcript: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "evidence_sha256": self.evidence_sha256,
            "canary_sha256": self.canary_sha256,
            "reason": self.reason,
            "transcript": list(self.transcript),
        }


@dataclass(frozen=True)
class ScanReport:
    source: SourceReport
    rules_loaded: int
    tools: tuple[ToolReport, ...]
    dynamic: DynamicReport | None = None

    @property
    def overall_verdict(self) -> Verdict:
        verdict = Verdict.SUSPICIOUS if self.source.error else Verdict.CLEAN
        for tool in self.tools:
            if VERDICT_RANK[tool.verdict] > VERDICT_RANK[verdict]:
                verdict = tool.verdict
        return verdict

    def counts(self) -> dict[str, int]:
        counts = {verdict.value: 0 for verdict in Verdict}
        for tool in self.tools:
            counts[tool.verdict.value] += 1
        if self.source.error and not self.tools:
            counts[Verdict.SUSPICIOUS.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": "reizan-mcpfuzz.report.v0",
            "overall_verdict": self.overall_verdict.value,
            "source": self.source.to_dict(),
            "rules_loaded": self.rules_loaded,
            "counts": self.counts(),
            "tools": [tool.to_dict() for tool in self.tools],
        }
        if self.dynamic is not None:
            data["dynamic"] = self.dynamic.to_dict()
        return data


def verdict_for_severity(severity: str) -> Verdict:
    normalized = severity.strip().lower()
    if normalized in {"critical", "high"}:
        return Verdict.POISONED
    if normalized in {"medium", "low", "info", "informational"}:
        return Verdict.SUSPICIOUS
    return Verdict.SUSPICIOUS


def verdict_for_findings(findings: tuple[Finding, ...]) -> Verdict:
    verdict = Verdict.CLEAN
    for finding in findings:
        if VERDICT_RANK[finding.verdict] > VERDICT_RANK[verdict]:
            verdict = finding.verdict
    return verdict


def display_span(span: str, limit: int = 160) -> str:
    rendered = span.encode("unicode_escape").decode("ascii")
    rendered = rendered.replace("\\x1b", "\\u001b")
    if len(rendered) <= limit:
        return rendered
    return f"{rendered[: limit - 3]}..."
