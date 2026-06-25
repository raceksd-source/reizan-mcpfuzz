.PHONY: demo demo-json demo-dynamic test

PYTHON ?= python3

demo:
	$(PYTHON) -m reizan_mcpfuzz scan --manifest examples/poisoned-tools.json --fail-on poisoned || test $$? -eq 2

demo-json:
	$(PYTHON) -m reizan_mcpfuzz scan --manifest examples/poisoned-tools.json --json --fail-on poisoned || test $$? -eq 2

demo-dynamic:
	$(PYTHON) -m reizan_mcpfuzz scan --manifest examples/poisoned-tools.json --dynamic --dynamic-base-url mock://susceptible --fail-on poisoned || test $$? -eq 2

test:
	$(PYTHON) -m pytest -q
