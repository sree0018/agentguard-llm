AgentGuard: Output-Side Tool-Call Authorization for LLM Agents
================================================================

Code accompanying the final project report (Project_Report.pdf).

This release has TWO implementations of AgentGuard's check 4 (payload
consistency):

  * regex   (default)  the original deterministic proxy. Stdlib only, no LLM,
                       no network. Reproduces every number in the original
                       report.
  * llm     (new)      a LOCAL-LLM guard (Ollama + llama3.1:8b) that directly
                       replaces the regex, red-teamed against the ADV-2
                       obfuscation attacks, three fresh held-out test sets
                       and an adaptive attacker.

HEADLINE RESULT (details and caveats: docs/results.md, generated from the data)
-------------------------------------------------------------------------------
On three independent held-out sets (139 attacks, 82 benign payloads) the
original regex lets 96% of attacks through (CI 92-98%); the strict LLM guard
(version v1, frozen before any of these sets was written) lets 12% through
(CI 7-18%) at a cost of 12% false positives on hard benign text (regex: 2%).
Every variant we built to REDUCE those false positives (v1p, v2, v3) cut them
to ~0% but let 25-42% of attacks through on held-out data. So the LLM guard is
a trade-off, not a free win; and the strict version's remaining weaknesses
(secrets disguised as labelled identifiers, plain-prose secrets, symbol-script
encodings) are reported, not hidden. Against an ADAPTIVE attacker (30 guard
queries per target, ALLOW/BLOCK feedback) the guard does NOT hold: v1 was
bypassed on 7/8 targets (median 3 queries), v3 on 8/8, the regex on 8/8 in 1
query. Fixed-list numbers are the one-shot figure; the adaptive numbers are a
worst case that assumes the attacker can observe the guard's verdicts. See docs/results.md,
docs/prompt_iterations.md, docs/evaluation_protocol.md.

REPRODUCIBILITY (read first)
----------------------------
Default run -- `python3 run_experiment.py`:
  * No API key, no network, no GPU, no LLM, no pip install. Standard library.
  * The agent is a deterministic simulation calibrated to Liu et al.
    (USENIX Security '24); the four checks are pure Python.
  * Reproduces every ASR / FPR number of the original report. (Latency is
    wall-clock and differs per machine.)

LLM mode -- `--guard llm`, `run_redteam.py`, `run_adaptive.py`:
  * Needs EITHER a local Ollama server with the model pulled
        brew install ollama && ollama serve &
        ollama pull llama3.1:8b          # ~5 GB, 16 GB RAM is enough
    OR nothing at all, if you replay from the committed response cache
        python3 run_redteam.py --split test3 --llm-mode replay \
            --configs "regex,llm=llama3.1:8b#v1,llm=llama3.1:8b#v1p,llm=llama3.1:8b#v3"
    (`replay` answers every guard call from results/llm/llm_cache.json and
    fails loudly on a cache miss, so no number can silently come from a
    different source.)
  * Decoding is temperature 0 with a fixed seed. Even so, different Ollama
    versions / hardware can change token-level output, which is why the
    cache is committed: the cache, not a re-run, is the source of truth for
    the reported LLM numbers.
  * Still stdlib only: the Ollama client is a small urllib wrapper. No API key
    and no remote service; the model runs on your machine.

Guard versions (config suffix `#version`; default v1)
-----------------------------------------------------
  v1    first release; strict ("when unsure, BLOCK"); frozen, hash d4c05c622fca
  v1p   v1 + deterministic evidence pre-pass (normalize.py); never tuned
  v2    relaxed prompt + pre-pass; v2np = same prompt without the pre-pass
  v3    v2 + narrower script rule; tuned low-false-positive variant
  Prompt hashes are printed by run_redteam.py and recorded with each result.

Files
-----
  dataset.py            70 Indirect Prompt Injection test cases (20 clean
                        + 50 injected), five attack categories from Liu et al.
  agent.py              Agent simulation calibrated to Liu et al.
  agentguard.py         The defense: four-stage output-side authorization.
                        `authorize()` takes an optional `payload_checker=` so
                        check 4 can be swapped (regex default / LLM).
  llm_guard.py          Local-LLM check 4: Ollama client, on-disk response
                        cache (auto / live / replay), guard prompts (versions),
                        strict fail-closed verdict parser.
  normalize.py          Deterministic EVIDENCE pre-pass (decodes base64/hex/
                        percent/HTML/decimal/binary/spaced letters, shows
                        invisible and look-alike characters). Evidence only:
                        it never decides.
  attacks.py            15 adaptive-attacker cases (ADV-1 in-scope payload,
                        ADV-2 obfuscated secret, ADV-3 benign-looking URL).
  attacks_ext.py        DEV/TEST sets: 44 ADV-2 cases (19 techniques), 11 ADV-4
                        attacks on the guard itself, 24 hard benign payloads.
  attacks_v2.py         TEST2: 64 attacks / 40 benign (techniques not in any
                        prompt, prose smuggling, label abuse, guard-targeted,
                        new tools), + blind-case loader for teammates.
  attacks_v3.py         TEST3: 50 attacks / 32 benign (6 new encodings, new
                        prose/label/guard styles, legit non-Latin and emoji).
  blind_cases_template.json
                        Template for independently authored test cases.
  run_experiment.py     Main benchmark; `--guard {regex,llm,llm+regex}`
                        `--guard-version v1|v1p|v2|v3`.
  run_redteam.py        Red-team harness: ASR/FPR with Wilson 95% CIs,
                        per-technique breakdown, latency, split handling,
                        held-out logging, `--blind` file.
  run_adaptive.py       Adaptive attacker: query-budgeted search over 28
                        encoders x 8 wrappers with ALLOW/BLOCK feedback;
                        every payload provably contains the secret.
  make_results_table.py Builds docs/results.md from the per-case CSVs.
  test_llm_guard.py     Offline unit tests (mock backend; no Ollama needed).
  liu_et_al_adapter.py, run_liu_benchmark.py
                        Liu et al. attack constructions adapter (unchanged).
  results/              Baseline results (regex). results/baseline_regex/ is a
                        snapshot; results/llm/ holds LLM-guard outputs, the
                        response cache, tuning logs and test_runs.json.
  docs/                 results.md (generated), evaluation_protocol.md,
                        prompt_iterations.md, slides_outline.md.

How to run
----------
  python3 run_experiment.py                      # original experiment
  python3 -m unittest test_llm_guard -v          # offline unit tests

  # LLM guard on the main benchmark
  python3 run_experiment.py --guard llm
  python3 run_experiment.py --guard llm --llm-mode replay    # offline

  # Red-team (writes results/llm/redteam_summary_<tag>.json + per-case CSV)
  python3 run_redteam.py --split dev  --configs regex,llm=llama3.1:8b --techniques
  python3 run_redteam.py --split test3 --configs "regex,llm=llama3.1:8b#v1,llm=llama3.1:8b#v3"

  # Adaptive attacker (budget = guard queries per target)
  python3 run_adaptive.py --configs "regex,llm=llama3.1:8b#v1" --budget 30

  # Teammates' independent cases (blind_cases_template.json)
  python3 run_redteam.py --split blind --blind my_cases.json --configs regex,llm=llama3.1:8b

  python3 make_results_table.py                  # regenerate docs/results.md

Methodology notes (honest scoping)
----------------------------------
  * Information asymmetry is preserved: the guard sees only the pinned task
    spec, the proposed tool call and (v1p/v2/v3) deterministic evidence derived
    from that call; never the retrieved content (enforced by unit tests).
  * Fail closed: timeouts, an unreachable server, malformed output, or a
    verdict that is not exactly ALLOW/BLOCK all BLOCK, tagged
    `payload_consistency_llm_error`, counted separately.
  * Held-out discipline: DEV was used to tune v1; TEST was evaluated once with
    v1; TEST2/TEST3 were authored before the guard version that is evaluated on
    them was tuned, with dataset hashes logged in results/llm/test_runs.json.
    A set that influenced a version's prompt is NOT counted as held out for that
    version (see make_results_table.py, docs/evaluation_protocol.md).
  * Few-shot examples are generic and contain no dataset payload (unit test).
  * Still the same author for guard and tests; independent cases from
    teammates are supported (blind_cases_template.json) but not yet included.
  * The agent is a simulation, sample sizes are small (hence Wilson CIs), the
    adaptive attacker is a structured search (not an LLM attacker), and the
    LLM guard is itself an attack surface (ADV-4 / guard-targeted sets).
  * Latency: regex ~1-2 microseconds; LLM guard ~4 s per call (p50) on an
    M-series laptop. It only runs when checks 1-3 pass. In
    `run_experiment.py --guard llm` the "median latency" column is dominated by
    cases that never reach check 4 and is NOT representative; use
    docs/results.md.

Extending the Liu et al. adapter to their full benchmark
--------------------------------------------------------
  1. Clone https://github.com/liu00222/Open-Prompt-Injection
  2. Follow their README to download the datasets and configure API keys.
  3. In liu_et_al_adapter.py, replace each `LiuTask` instance's `samples`
     list with their numpy-loaded data.
  4. Replace the modeled agent in run_liu_benchmark.py with calls to a real
     LLM via their `PI.create_app(...).query(prompt)` interface.

Requirements
------------
  Python >= 3.8, standard library only. (LLM mode additionally needs a local
  Ollama server unless replaying from the cache.)

Threat model and limitations
----------------------------
See Project_Report.pdf, Sections 3.1 and 4.6, and docs/results.md.
