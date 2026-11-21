# Developer entry points. Everything runs offline unless noted.
PY ?= python3
export PYTHONPATH := src

.PHONY: help install test lint format typecheck check demo benchmark reproduce report doctor clean

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

install:         ## editable install with dev tools (ruff, mypy)
	$(PY) -m pip install -e ".[dev]"

test:            ## 46 offline unit tests (no Ollama needed)
	$(PY) -m unittest discover -s tests

lint:            ## style + bug-pattern checks
	ruff check .
	ruff format --check .

format:          ## auto-format
	ruff check --fix .
	ruff format .

typecheck:       ## static types
	mypy

check: lint typecheck test   ## everything CI would run

demo:            ## presenter walkthrough, offline (replays the cached guard answers)
	$(PY) -m agentguard demo --pause

benchmark:       ## original 70-case benchmark (regex, no LLM)
	$(PY) -m agentguard benchmark

reproduce:       ## re-derive the headline numbers from the response cache, offline
	$(PY) -m agentguard redteam --split test3 --llm-mode replay \
	  --configs "regex,llm=llama3.1:8b#v1,llm=llama3.1:8b#v1p,llm=llama3.1:8b#v3"
	$(PY) -m agentguard adaptive --llm-mode replay

report:          ## regenerate docs/results.md from the per-case CSVs
	$(PY) -m agentguard report

doctor:          ## environment check (cache, Ollama)
	$(PY) -m agentguard doctor

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf build dist src/*.egg-info .mypy_cache .ruff_cache
