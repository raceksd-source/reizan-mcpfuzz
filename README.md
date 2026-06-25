# reizan-mcpfuzz

`reizan-mcpfuzz` is a deterministic, fail-closed auditor for MCP server
tool-poisoning. Run it before trusting or installing a third-party MCP server.
It enumerates the server's tools, scans tool descriptions and input schemas for
instruction-injection and obfuscation patterns, and emits per-tool verdicts:
`CLEAN`, `SUSPICIOUS`, or `POISONED`.

There is no LLM judge in the static verdict.

## Ethical Line

This is a self-run / authorized component evaluation tool. Use it on an MCP
server command you are about to trust, install, or operate, or on a static tools
manifest you already possess. Do not use it to scan someone else's deployed
infrastructure or to probe services without authorization.

`reizan-mcpfuzz` speaks stdio MCP only for local child processes and reads local
JSON manifests. It is not a remote internet scanner.

## Why

MCP clients list server tools before an agent decides what it can call. That
means a malicious server can hide prompt-injection text in `description` or
`inputSchema`, and the agent may read that text as trusted operational context.
Conventional dependency and supply-chain tools usually inspect packages,
versions, and vulnerabilities; they do not inspect the instruction surface that
the agent consumes at tool-list time.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make demo
make test
```

Scan a static manifest:

```bash
reizan-mcpfuzz scan --manifest examples/poisoned-tools.json
reizan-mcpfuzz scan --manifest examples/poisoned-tools.json --json
```

Scan a local stdio MCP server:

```bash
reizan-mcpfuzz scan -- python -m your_mcp_server
```

Use `--fail-on poisoned` when you only want CI to fail on `POISONED`. The
default is stricter: any `SUSPICIOUS` or `POISONED` result exits non-zero.

## Rules

Rules are portable YAML under `.mcpfuzz/rules.yaml`:

```yaml
rules:
  - id: inj.ignore_previous
    category: instruction_injection
    pattern_type: regex
    signature: '\bignore\s+previous\s+instructions\b'
    severity: high
```

Required fields are:

- `id`
- `category`
- `pattern_type`: `regex`, `hidden_char`, or `imperative`
- `signature`
- `severity`: `critical`, `high`, `medium`, `low`, or `info`

`critical` and `high` findings produce `POISONED`; lower severities produce
`SUSPICIOUS`.

The v0 seed rules cover:

- `ignore previous` / `disregard` / `override` instruction patterns
- `you must`, `before responding`, and fake `system:` markers
- exfiltration language and imperative `fetch https://...` patterns
- base64-like blobs
- zero-width characters, ANSI escapes, and Unicode hyphen/lookalike tricks
- imperative language paired with tool-call syntax or URLs
- destructive or over-broad schema signals such as shell commands and
  `additionalProperties: true`
- sensitive targets such as `secrets/`, credentials, API keys, and SSH keys

## MCP Behavior

The stdio scanner starts the target command as a local child process, sends
JSON-RPC `initialize`, sends the `notifications/initialized` notification, then
calls `tools/list`. Paginated `nextCursor` results are followed.

Parse, load, or connection errors are fail-closed: the scan result becomes
`SUSPICIOUS`, never silently `CLEAN`.

Relevant MCP spec references:

- [Lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)
- [Transports / stdio](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [Tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

## Optional Dynamic Mode

Static scanning is the primary verdict. Dynamic mode is opt-in:

```bash
reizan-mcpfuzz scan --manifest examples/poisoned-tools.json --dynamic
```

By default, dynamic mode uses `mock://susceptible`, so it is key-free and
deterministic. To call a real OpenAI-compatible endpoint:

```bash
export MCPFUZZ_OPENAI_API_KEY=...
reizan-mcpfuzz scan --manifest tools.json \
  --dynamic \
  --dynamic-base-url https://api.example.test/v1 \
  --dynamic-model your-model
```

The dynamic harness feeds a poisoned MCP tool-result into a small
OpenAI-compatible agent loop. A SHA-256 canary oracle returns `CONFIRMED` if the
canary appears in final output or if the model requests an out-of-scope fixture
fetch. The fixture tool is guarded by a ScopeGate-style allowlist and never
performs real URL fetches.

## OWASP Agentic Top 10 Mapping

The findings map most directly to OWASP Agentic AI risks around prompt
injection, tool misuse, excessive agency, sensitive information disclosure, and
supply-chain compromise. `reizan-mcpfuzz` sits before trust/install time: it
checks whether the tool metadata itself is a hostile instruction surface before
an agent sees it.

OWASP reference:
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## GitHub Actions

`.github/workflows/mcpfuzz.yml` is a skeleton workflow. It installs this package
and runs:

```bash
reizan-mcpfuzz scan --manifest "$MANIFEST" --json --fail-on poisoned
```

That policy fails CI only when any tool is `POISONED`.

## License

MIT.
