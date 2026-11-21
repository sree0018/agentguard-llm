# AgentGuard-LLM

*A local-LLM payload guard for AI-agent tool calls.* Course project by Aditya, Gopika, Meera and Sreeranj.

Output-side authorization of AI-agent tool calls against indirect prompt injection,
with a **local-LLM payload guard** (check 4) that replaces the original regex.

```
agent proposes a tool call ──► 1 tool admission ─► 2 scope ─► 3 read-only ─► 4 payload consistency ──► ALLOW / BLOCK
                                  (deterministic rules)                       regex  |  local LLM
```

The guard sees only the **pinned task** and the **proposed call** — never the retrieved content.

## Headline result

Three independent held-out sets, 139 attacks and 82 benign payloads (details: [docs/results.md](docs/results.md)):

| Check 4 | Attacks that got through | Benign wrongly blocked |
|---|---|---|
| Regex (original) | **96%** (134/139) | 2% (2/82) |
| Local LLM, strict `v1` | **12%** (16/139) | 12% (10/82) |

It is a trade-off, not a free win: relaxed variants cut false alarms to ~0% but leak 25–42%, and an
adaptive attacker with verdict feedback still breaks every guard. See the limits in
[docs/results.md](docs/results.md) and [docs/evaluation_protocol.md](docs/evaluation_protocol.md).

## Quick start

Requires Python ≥ 3.10. **No third-party packages** are needed to run anything.

```bash
cd agentguard
export PYTHONPATH=src            # or: pip install -e .   (then use the `agentguard` command)

python3 -m agentguard demo       # 9-step walkthrough, offline
python3 -m agentguard benchmark  # original 70-case benchmark, no LLM
python3 -m unittest discover -s tests
```

Library use:

```python
from agentguard import AgentGuard, make_payload_checker

_, checker = make_payload_checker("llm=llama3.1:8b#v1", llm_mode="replay")  # offline
decision = AgentGuard(payload_checker=checker).authorize(action, spec)
```

## Command line

| Command | What it does |
|---|---|
| `agentguard demo [--live] [--pause] [--scenario K]` | presenter walkthrough ([guide](docs/DEMO_GUIDE.md)) |
| `agentguard check --action JSON --spec JSON [--guard CFG]` | authorize one tool call, print each stage |
| `agentguard benchmark` | original 70-case benchmark (`--guard llm` for the LLM check) |
| `agentguard redteam --split test3 --configs ...` | ASR/FPR with Wilson CIs on a split |
| `agentguard adaptive` | adaptive attacker, query-budgeted |
| `agentguard report` | regenerate `docs/results.md` from the per-case CSVs |
| `agentguard versions` | guard prompt versions and hashes |
| `agentguard doctor` | environment check (cache, Ollama) |

Guard configuration syntax: `regex`, `llm=<model>[@analysis|@verdict][#version]`, `union=<model>[#version]`
(regex first, then LLM). Versions: `v1` (default, strict, frozen), `v1p`, `v2`, `v2np`, `v3`, `v3np`.

## Reproducibility

* Default pipeline: standard library only; reproduces the original report's ASR/FPR numbers.
* LLM mode: either a local [Ollama](https://ollama.com) server (`ollama pull llama3.1:8b`, ~5 GB)
  **or** `--llm-mode replay`, which answers every guard call from the committed cache
  (`results/llm/llm_cache.json`, 1,314 responses) and fails closed on a miss.
* Decoding is temperature 0, fixed seed. Prompt and dataset hashes are logged with every result.
* `make reproduce` re-derives the headline numbers offline.

## Layout

```
src/agentguard/
  core/        types, the four checks, AgentGuard pipeline (no LLM dependency)
  llm/         backends + cache, prompts (versions), verdict parser, guard, evidence pre-pass
  data/        70-case benchmark, ADV sets, red-team sets DEV/TEST/TEST2/TEST3
  simulation/  deterministic agent simulation, Liu et al. adapter
  evaluation/  benchmark, redteam, adaptive, report, stats
  demo/        scenarios + terminal renderer
  cli.py       `agentguard` command
tests/         46 offline tests          docs/      protocol, results, tuning log, architecture, demo guide
examples/      quickstart + blind-case template      results/   committed outputs and the response cache
```

Architecture and extension points: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Contributing and the
rules for frozen artefacts: [CONTRIBUTING.md](CONTRIBUTING.md).

## Honest scoping

One author wrote both the guard and the tests (independent cases are supported via
`examples/blind_cases_template.json`); the agent is simulated; sample sizes are small (hence CIs);
the adaptive attacker is a structured search, not an LLM; the LLM guard is itself an attack surface;
and each LLM check costs ~4 s (p50) on an M-series laptop versus microseconds for the regex.

## Migrating from the flat scripts

| Before | Now |
|---|---|
| `python3 run_experiment.py` | `python3 -m agentguard benchmark` |
| `python3 run_redteam.py …` | `python3 -m agentguard redteam …` |
| `python3 run_adaptive.py …` | `python3 -m agentguard adaptive …` |
| `python3 make_results_table.py` | `python3 -m agentguard report` |
| `python3 -m unittest test_llm_guard` | `python3 -m unittest discover -s tests` |
| `import agentguard; agentguard.authorize` | `from agentguard import authorize` (unchanged API) |
| `import llm_guard` | `from agentguard import llm` |
