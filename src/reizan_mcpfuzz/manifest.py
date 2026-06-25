"""Static MCP tool manifest loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reizan_mcpfuzz.models import ToolRecord


class ManifestError(ValueError):
    pass


def load_manifest_tools(path: Path) -> tuple[ToolRecord, ...]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"could not read manifest: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON manifest: {exc}") from exc
    return tools_from_payload(raw)


def tools_from_payload(payload: Any) -> tuple[ToolRecord, ...]:
    raw_tools = _extract_tools(payload)
    records: list[ToolRecord] = []
    for index, raw_tool in enumerate(raw_tools, start=1):
        if not isinstance(raw_tool, dict):
            raise ManifestError(f"tool {index} must be an object")
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ManifestError(f"tool {index} missing non-empty string name")
        description = raw_tool.get("description", "")
        if description is None:
            description = ""
        if not isinstance(description, str):
            raise ManifestError(f"tool {name!r} description must be a string when present")
        input_schema = raw_tool.get("inputSchema", raw_tool.get("parameters", {}))
        records.append(
            ToolRecord(
                name=name,
                description=description,
                input_schema=input_schema,
                raw=dict(raw_tool),
            )
        )
    return tuple(records)


def _extract_tools(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ManifestError("manifest must be a tool list, an MCP result object, or an object with 'tools'")
    if isinstance(payload.get("tools"), list):
        return payload["tools"]
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    raise ManifestError("manifest did not contain a 'tools' list")
