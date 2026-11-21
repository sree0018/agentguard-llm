# Contributing

## Setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"      # ruff + mypy; the package itself has no dependencies
make check                   # ruff, mypy, 46 unit tests
```

## Standards

* PEP 8 / PEP 257, enforced by `ruff` (rules E, F, W, I, B, UP, SIM, RUF; line length 100).
* Public API in `core/` and `llm/{factory,guard}` is fully typed and checked by `mypy --strict`-style
  rules (`disallow_untyped_defs`). New public functions need type hints and a docstring.
* Standard library only at runtime. Dev tools are optional.
* Tests are `unittest` (pytest-compatible), offline, and must not need Ollama; use `MockBackend`.

## Frozen artefacts (read before editing)

Published numbers are tied to hashes of: the prompt texts (`llm/prompts.py`), the evidence pre-pass
source (`llm/preprocess.py`), and the datasets (`data/`). A test pins the v1 hash. If you must change
one, **add a new version** instead of editing, evaluate it on a split it never influenced, and log it.

## Evaluation discipline

* Tune prompts on DEV-type data only. Once a set has influenced a prompt it is no longer held out.
* Never report a number that was not produced by `agentguard redteam|adaptive|benchmark`; regenerate
  `docs/results.md` with `agentguard report`.
* Report errors and misses; do not hide them.

## Commits

Small, focused commits; run `make check` first.
