# Demo guide

A 10-minute live demo plus everything else you can show. Every step works **offline**; the live
mode is an optional extra.

## Before you start (2 minutes, once)

```bash
cd agentguard && export PYTHONPATH=src
python3 -m agentguard doctor          # cache present? Ollama reachable? (Ollama is optional)
python3 -m unittest discover -s tests # 46 tests, <1 s
```

For the *live* parts only: `ollama serve` in another terminal, then warm the model with one check.
The **first** call loads the model (~20 s measured); later calls take 2–5 s. Do this before the
audience arrives.

## Three ways to demo

| Mode | Command | Needs | Use when |
|---|---|---|---|
| **Replay** (default) | `python3 -m agentguard demo --pause` | nothing | always safe; identical output every time |
| **Live** | `python3 -m agentguard demo --live` | Ollama + llama3.1:8b | you want to prove it's a real model |
| **Your own input** | `python3 -m agentguard check --guard "llm=llama3.1:8b#v1" --llm-mode live --action '…' --spec '…'` | Ollama | taking an audience suggestion |

`--pause` waits for Enter between scenarios so you control the pace. `--scenario KEY` runs one.
`agentguard demo --list` shows the keys.

## Run of show (10 min)

| Min | Scenario (`--scenario`) | What the audience sees | What you say |
|---|---|---|---|
| 0–1 | — | the header line | "An agent reads untrusted pages and then uses tools. We don't try to stop it being fooled; we check what it tries to *do*. The guard never sees the page." |
| 1–2 | `benign` | four green checks | "A good guard stays out of the way." |
| 2–4 | `tool`, `scope`, `readonly` | one red ✘ each, later checks skipped | "Checks 1–3 are one-line deterministic rules. Right tool wrong recipient, side effects in a read-only task. Microseconds." |
| 4–6 | `blindspot` | regex ✔ vs LLM ✘ | "This is the gap. A secret hidden as a base32 blob; no keyword. Regex passes it. The LLM sees an opaque string that has no business in a summary." |
| 6–7 | `prose`, `guard-attack` | LLM blocks both | "No encoding at all, and a payload that tries to talk to the guard. Using an LLM adds an attack surface; we tested it." |
| 7–9 | `miss`, `false-alarm` | both ALLOW; then regex ✔ vs LLM ✘ on a harmless hash | "This is the honest part. 12% of attacks still get through and 12% of benign text is blocked. We report both." |
| 9–10 | — | scoreboard | "Pooled over 139 held-out attacks: regex lets 96% through, the strict guard 12%. It's a trade-off, and an adaptive attacker still beats it — next slide / report." |

Recorded latency (the ms column on LLM rows) is the model's own time, even in replay mode.

## What else you can showcase

| Asset | Where | Shows |
|---|---|---|
| Pictorial report | `docs/report.html` (also published as an artifact) | architecture, results, trade-off, failure analysis in pictures |
| Slide deck | published artifact (23 slides + speaker notes) | the talk |
| Results tables | `docs/results.md` | every number with Wilson 95% CIs, generated from the CSVs |
| Per-case audit trail | `results/llm/*.csv` | every decision, reason and latency |
| Held-out discipline | `docs/evaluation_protocol.md`, `results/llm/test_runs.json` | dataset and prompt hashes, who saw what when |
| Tuning history | `docs/prompt_iterations.md` | including the iteration we reverted |
| Reproducibility | `make reproduce` | headline numbers re-derived offline from 1,314 cached responses |
| Code quality | `make check` | ruff, mypy, 46 tests |
| Framework | `examples/quickstart.py`, `docs/ARCHITECTURE.md` | 10-line library use, extension points |

### 60-second proofs

```bash
python3 -m agentguard versions                         # prompt hashes: results are tied to exact prompts
python3 -m agentguard benchmark | tail -15             # original report numbers, still reproduced
python3 -m agentguard redteam --split test3 --llm-mode replay \
    --configs "regex,llm=llama3.1:8b#v1"               # headline numbers, offline
python3 -m agentguard adaptive --llm-mode replay       # adaptive attacker: every guard falls
```

## If something goes wrong

| Symptom | Cause / fix |
|---|---|
| `no cached response for key …` and a BLOCK | replay mode with a payload that was never run. Correct behaviour (fails closed). Use `--llm-mode live`. |
| `Ollama request failed` | server not running: `ollama serve`. Also fails closed. |
| First live call takes ~20 s | model loading; warm it up beforehand. |
| Colour codes look garbled | `--no-color` or `NO_COLOR=1`. |
| `ModuleNotFoundError: agentguard` | `export PYTHONPATH=src` (or `pip install -e .`). |

## Likely questions

* *Why is v1 the default if v3 has zero false alarms?* v1 stops 3–4× more attacks on held-out data;
  a false alarm costs a confirmation, a leak can't be undone.
* *Why not more regex?* The encoding space is open-ended: regex let 134/139 held-out attacks through.
* *Is 0% on the original benchmark meaningful?* Only partly — small and partly written to match the checks.
* *Can't an attacker just try again?* Yes: the adaptive search broke v1 on 7/8 targets in a median of
  3 queries. Pair the guard with allowlists, DLP, and alerting on repeated blocks.
