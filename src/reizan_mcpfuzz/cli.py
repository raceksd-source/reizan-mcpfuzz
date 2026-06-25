"""Command line interface for reizan-mcpfuzz."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reizan_mcpfuzz.dynamic import DynamicConfig, DynamicError, error_report, run_dynamic_confirmation
from reizan_mcpfuzz.manifest import ManifestError, load_manifest_tools
from reizan_mcpfuzz.mcp_client import MCPClientError, list_tools_stdio
from reizan_mcpfuzz.models import ScanReport, SourceReport, Verdict
from reizan_mcpfuzz.report import render_json_report, render_text_report
from reizan_mcpfuzz.rules import RuleLoadError, load_rules
from reizan_mcpfuzz.scanner import scan_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reizan-mcpfuzz")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an MCP server command or static tools manifest.")
    scan.add_argument("server_cmd", nargs=argparse.REMAINDER, help="MCP server command; use '--' before it.")
    scan.add_argument("--manifest", type=Path, help="Read tools from a static MCP tools JSON manifest.")
    scan.add_argument("--rules", type=Path, help="Path to a portable .mcpfuzz YAML rules file.")
    scan.add_argument("--timeout", type=float, default=10.0, help="stdio MCP request timeout in seconds.")
    scan.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of terminal text.")
    scan.add_argument(
        "--fail-on",
        choices=("suspicious", "poisoned"),
        default="suspicious",
        help="Exit non-zero on SUSPICIOUS or only on POISONED findings.",
    )
    scan.add_argument("--dynamic", action="store_true", help="Run optional OpenAI-compatible dynamic canary probe.")
    scan.add_argument("--dynamic-base-url", default="mock://susceptible")
    scan.add_argument("--dynamic-model", default="mock")
    scan.add_argument("--dynamic-api-key", default=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    raise AssertionError(f"unhandled command: {args.command}")


def _scan(args: argparse.Namespace) -> int:
    source = _source_for_args(args)
    rules_loaded = 0
    dynamic = None
    try:
        rules = load_rules(args.rules)
        rules_loaded = len(rules)
        tools = _load_tools(args)
        tool_reports = scan_tools(tools, rules)
        report = ScanReport(source=source, rules_loaded=rules_loaded, tools=tool_reports)
    except (RuleLoadError, ManifestError, MCPClientError, ValueError) as exc:
        report = ScanReport(
            source=SourceReport(source.kind, source.target, error=str(exc)),
            rules_loaded=rules_loaded,
            tools=(),
        )

    if args.dynamic:
        config = DynamicConfig.from_args(
            base_url=args.dynamic_base_url,
            model=args.dynamic_model,
            api_key=args.dynamic_api_key,
            timeout_seconds=args.timeout,
        )
        try:
            dynamic = run_dynamic_confirmation(config)
        except DynamicError as exc:
            dynamic = error_report(str(exc))
        if dynamic.verdict == "ERROR":
            report = ScanReport(
                source=SourceReport(report.source.kind, report.source.target, error=dynamic.reason),
                rules_loaded=report.rules_loaded,
                tools=report.tools,
                dynamic=dynamic,
            )
        else:
            report = ScanReport(
                source=report.source,
                rules_loaded=report.rules_loaded,
                tools=report.tools,
                dynamic=dynamic,
            )

    if args.as_json:
        print(render_json_report(report))
    else:
        print(render_text_report(report), end="")

    return _exit_code(report, args.fail_on)


def _source_for_args(args: argparse.Namespace) -> SourceReport:
    if args.manifest:
        return SourceReport("manifest", str(args.manifest))
    command = _server_command(args.server_cmd)
    return SourceReport("stdio", " ".join(command) if command else "(missing)")


def _load_tools(args: argparse.Namespace):
    command = _server_command(args.server_cmd)
    if args.manifest and command:
        raise ValueError("choose either --manifest or a stdio server command, not both")
    if args.manifest:
        return load_manifest_tools(args.manifest)
    if not command:
        raise ValueError("missing MCP server command; use --manifest or 'scan -- <command> [args...]'")
    return list_tools_stdio(command, timeout_seconds=args.timeout)


def _server_command(values: list[str]) -> list[str]:
    if values and values[0] == "--":
        return values[1:]
    return values


def _exit_code(report: ScanReport, fail_on: str) -> int:
    if fail_on == "poisoned":
        return 2 if report.overall_verdict is Verdict.POISONED else 0
    if report.overall_verdict is Verdict.POISONED:
        return 2
    if report.overall_verdict is Verdict.SUSPICIOUS:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
