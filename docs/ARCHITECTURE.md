# Architecture

## Data flow

```
 user task ──► spec {intent, allowed_tools, scope, read_only}   (pinned, trusted)
 agent     ──► action {tool, to, body, url, ...}                 (untrusted: may be injected)

 AgentGuard.authorize(action, spec)
   1 check_tool_admission      tool ∈ spec.allowed_tools
   2 check_scope_containment   recipient / repo / path inside spec.scope
   3 check_read_only           read-only task ⇒ no side-effecting tool
   4 payload_checker           regex proxy  |  LLM guard  |  regex ▸ LLM (union)
 first block wins ─► Decision(allowed, reason, check, meta)
```

The retrieved content (web page, PDF, email) never reaches the guard. That information
asymmetry is a design rule, enforced by unit tests.

## Packages

| Package | Responsibility | Depends on |
|---|---|---|
| `agentguard.core` | `Decision`, checks 1–3, regex check 4, `AgentGuard` pipeline | stdlib |
| `agentguard.llm` | `OllamaBackend`, `CachedBackend`, `MockBackend`; prompt versions; strict verdict parser; `check_payload_llm`; config-string factory; evidence pre-pass | `core` |
| `agentguard.data` | benchmark cases, ADV-1…4, DEV/TEST/TEST2/TEST3 | — |
| `agentguard.simulation` | deterministic agent calibrated to Liu et al. | `data` |
| `agentguard.evaluation` | benchmark, red-team, adaptive attacker, report, statistics | all of the above |
| `agentguard.demo` | scenarios and terminal renderer | `core`, `llm`, `evaluation` |

Dependencies point inward: `core` never imports `llm`.

## The LLM guard in one call

```
check_payload_llm(action, spec, backend, version)
  build_messages ─► (system prompt v1…v3, user = task + action [+ evidence notes])
  backend.complete ─► CachedBackend ─► (hit) disk cache | (miss) OllamaBackend /api/chat
                        temperature 0, seed 42, JSON-schema output {analysis, verdict}
  parse_verdict ─► strict: exactly "ALLOW"/"BLOCK" else fail closed
  any error ─► BLOCK tagged payload_consistency_llm_error (counted separately)
```

Cache key = sha256(model options, system prompt, user prompt). Modes: `auto` (cache, then live),
`live`, `replay` (cache only; a miss fails closed).

## Extension points

* **New check 4:** any `Callable[[Action, Spec], Decision]` → `AgentGuard(payload_checker=fn)`.
* **New structural check:** pass `structural_checks=[*STRUCTURAL_CHECKS, my_check]`.
* **New model/backend:** implement `LLMBackend.complete(system, user) -> str` (a `Protocol`).
* **New guard prompt:** add it to `GUARD_VERSIONS`; evaluate on a *fresh* split; record its hash.
* **New attack set:** add a module in `data/`, register it in `evaluation/redteam.build_items`, and
  give it a split name (never reuse a set that influenced a prompt as held-out).

## Frozen artefacts

`llm/prompts.py` (prompt text), `llm/preprocess.py` (part of the v1p/v2/v3 hash) and `data/`
(dataset hashes) are hashed byte-for-byte into published results. They are exempt from formatting and
must not be edited without bumping a version.

## Extending the Liu et al. adapter to their full benchmark

  1. Clone https://github.com/liu00222/Open-Prompt-Injection
  2. Follow their README to download the datasets and configure API keys.
  3. In simulation/liu_adapter.py, replace each `LiuTask` instance's `samples`
     list with their numpy-loaded data.
  4. Replace the modeled agent in evaluation/liu.py with calls to a real
     LLM via their `PI.create_app(...).query(prompt)` interface.

