from __future__ import annotations

from reizan_mcpfuzz.dynamic import DynamicConfig, run_dynamic_confirmation


def test_dynamic_mock_susceptible_confirms_hijack():
    report = run_dynamic_confirmation(DynamicConfig(base_url="mock://susceptible", model="mock"))

    assert report.verdict == "CONFIRMED"
    assert "out-of-scope" in report.reason or "canary appeared" in report.reason


def test_dynamic_mock_safe_rejects_hijack():
    report = run_dynamic_confirmation(DynamicConfig(base_url="mock://safe", model="mock"))

    assert report.verdict == "REJECTED"
