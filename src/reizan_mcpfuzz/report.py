"""Terminal and JSON report rendering."""

from __future__ import annotations

import json

from reizan_mcpfuzz.models import ScanReport, Verdict, display_span


def render_json_report(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def render_text_report(report: ScanReport) -> str:
    counts = report.counts()
    lines = [
        "REIZAN-MCPFUZZ SCAN",
        f"source: {report.source.kind} {report.source.target}",
        f"overall: {report.overall_verdict.value}",
        (
            "tools: "
            f"{len(report.tools)} "
            f"(clean={counts[Verdict.CLEAN.value]}, "
            f"suspicious={counts[Verdict.SUSPICIOUS.value]}, "
            f"poisoned={counts[Verdict.POISONED.value]})"
        ),
        f"rules: {report.rules_loaded}",
    ]
    if report.source.error:
        lines.extend(["", "SOURCE ERROR", f"- SUSPICIOUS: {report.source.error}"])

    if report.tools:
        lines.extend(["", "TOOLS"])
        name_width = max(4, *(len(tool.tool.name) for tool in report.tools))
        verdict_width = max(7, *(len(tool.verdict.value) for tool in report.tools))
        lines.append(f"{'verdict'.ljust(verdict_width)} | {'tool'.ljust(name_width)} | findings")
        lines.append(f"{'-' * verdict_width}-+-{'-' * name_width}-+-{'-' * 8}")
        for tool in report.tools:
            lines.append(
                f"{tool.verdict.value.ljust(verdict_width)} | "
                f"{tool.tool.name.ljust(name_width)} | {len(tool.findings)}"
            )
            for finding in tool.findings:
                span = display_span(finding.span)
                lines.append(
                    f"  - {finding.rule_id} [{finding.severity}] "
                    f"{finding.path}[{finding.start}:{finding.end}] span={span!r}"
                )
                if finding.normalized_span and finding.normalized_span != finding.span:
                    lines.append(f"    normalized={display_span(finding.normalized_span)!r}")

    if report.dynamic is not None:
        lines.extend(
            [
                "",
                "DYNAMIC",
                f"- verdict: {report.dynamic.verdict}",
                f"- evidence_sha256: {report.dynamic.evidence_sha256}",
                f"- canary_sha256: {report.dynamic.canary_sha256}",
                f"- reason: {report.dynamic.reason}",
            ]
        )

    return "\n".join(lines) + "\n"
