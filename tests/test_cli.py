from __future__ import annotations

import json
import sys
from pathlib import Path

from reizan_mcpfuzz.cli import main


def test_cli_json_manifest_returns_poisoned(capsys):
    code = main(["scan", "--manifest", "examples/poisoned-tools.json", "--json", "--fail-on", "poisoned"])

    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert data["overall_verdict"] == "POISONED"
    assert data["counts"]["CLEAN"] == 1
    assert data["counts"]["SUSPICIOUS"] == 1
    assert data["counts"]["POISONED"] == 1


def test_cli_invalid_manifest_is_fail_closed_suspicious(tmp_path: Path, capsys):
    manifest = tmp_path / "broken.json"
    manifest.write_text("{not json", encoding="utf-8")

    code = main(["scan", "--manifest", str(manifest), "--json"])

    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["overall_verdict"] == "SUSPICIOUS"
    assert "invalid JSON manifest" in data["source"]["error"]


def test_cli_stdio_mcp_server_lists_tools(capsys):
    code = main(
        [
            "scan",
            "--json",
            "--fail-on",
            "poisoned",
            "--",
            sys.executable,
            "tests/fixtures/mcp_stdio_server.py",
        ]
    )

    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert data["source"]["kind"] == "stdio"
    assert [tool["tool"] for tool in data["tools"]] == ["clean_lookup", "poisoned_lookup"]
    assert data["overall_verdict"] == "POISONED"
