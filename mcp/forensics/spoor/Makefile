# Spoor — repro harness. Judges: `make demo` end to end, no setup beyond uv + a key.

UV ?= uv

.PHONY: help install test demo real verify-audit guardrails accuracy clean

help:
	@echo "Spoor targets:"
	@echo "  make install        sync deps (incl. the 'forensics' extra: Volatility 3)"
	@echo "  make test           run the full test suite"
	@echo "  make demo           full multi-agent live run on the canned Case-001 demo scenario"
	@echo "                      (needs SPOOR_OPENROUTER_API_KEY or OPENROUTER_API_KEY in ./.env)"
	@echo "  make real           REAL run: actual Volatility 3 over the real DC01 memory image"
	@echo "                      (fetch evidence first — see datasets/README.md) + accuracy report"
	@echo "  make guardrails     attempt 4 guardrail bypasses live; each must be rejected"
	@echo "  make verify-audit   verify the newest run's hash chain"
	@echo "  make clean          remove caches (never touches evidence/ or runs/)"

install:
	$(UV) sync --extra forensics

test:
	$(UV) run pytest -q

demo:
	$(UV) run python scripts/live_supervisor_run.py

real:
	$(UV) run python scripts/real_case_run.py

guardrails:
	$(UV) run spoor demo-guardrails

verify-audit:
	@latest=$$(ls -td runs/*/ 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then echo "no runs/ yet — make demo first"; exit 1; fi; \
	echo "verifying $$latest"audit.jsonl; \
	$(UV) run spoor verify-audit "$$latest"audit.jsonl

clean:
	rm -rf .pytest_cache **/__pycache__
