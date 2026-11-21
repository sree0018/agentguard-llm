"""
run_liu_benchmark.py - evaluate AgentGuard against Liu et al.'s attack
constructions on classification-style tasks.

This complements run_experiment.py (which evaluates AgentGuard on agentic
tool-call scenarios). Here we run AgentGuard against attack strings produced
by direct porting of Liu et al.'s 5 attack strategies, on synthetic samples
in their dataset format. The point is to demonstrate that AgentGuard's
defense logic is not specific to the 70 agentic cases we hand-wrote.

What this script does?
----------------------
For each attack strategy in {naive, escape, ignore, fake_completion, combine}
and each (target_task, injected_task) pair:
  1. Build attack strings using Liu et al.'s injection logic (verbatim port).
  2. Simulate an undefended agent: it would call the malicious_action.
  3. Pass that proposed action to each defense:
       - no defense
       - input-side baselines (paraphrase / sandwich / instruction prevention)
       - AgentGuard (structural only)
       - AgentGuard (full)
  4. Compute Attack Success Value (ASV) per Liu et al.'s definition.

What it does NOT do (honest scoping)
------------------------------------
* It does not call a real LLM. The undefended agent's behavior is modeled,
  consistent with our other experiments and with Liu et al.'s qualitative
  findings. Running their full benchmark with a real LLM requires their
  Open-Prompt-Injection repo (with API keys configured) and is left as
  future work; see README.txt for instructions.
* The synthetic datasets here have ~10 samples each. The structure is
  identical so swapping in their data is mechanical.
"""

import json
import os
from collections import defaultdict

from liu_et_al_adapter import (
    LIU_TASK_PAIRS,
    SST2_LIKE,
    SMS_SPAM_LIKE,
    HSOL_LIKE,
    LIU_ATTACKERS,
    build_bridged_cases,
    LiuMetrics,
)
from agentguard import authorize
from agent import _injection_succeeds  # for modeling input-side defenses

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Defense pipelines, mirroring run_experiment.py
# ---------------------------------------------------------------------------

# Mapping from Liu attack strategy names to our agent.py calibration keys
_LIU_TO_AGENT_CATEGORY = {
    "naive":           "naive",
    "escape":          "escape",
    "ignore":          "context_ignoring",
    "fake_completion": "fake_completion",
    "combine":         "combined",
}


def _make_pseudo_case(case, attack_strategy):
    """
    Built a tiny shim object compatible with `_injection_succeeds` from
    agent.py, so we can reuse the input-side defense calibration.
    """
    class _C:
        pass
    c = _C()
    c.label = "injected"
    c.attack_category = _LIU_TO_AGENT_CATEGORY[attack_strategy]
    # Hardness mirrors what we used in agent.py: combined attacks always
    # win against input-side defenses and others depend on difficulty. For the
    # Liu adapter we use "medium" difficulty by default, which matches the
    # qualitative findings reported in their paper Table 4-6.
    c.difficulty = "hard" if attack_strategy == "combine" else "medium"
    return c


def run_no_defense(case, attack_strategy):
    return case.malicious_action, True


def run_input_defense(case, attack_strategy, defense_name):
    pc = _make_pseudo_case(case, attack_strategy)
    if _injection_succeeds(pc, defense_name):
        return case.malicious_action, True
    return case.benign_action, True


def run_agentguard(case, attack_strategy, payload_check=True):
    proposed = case.malicious_action  # undefended agent emits malicious
    decision = authorize(proposed, case.user_task, payload_check=payload_check)
    return proposed, decision.allowed


DEFENSES = {
    "(a) No defense":              lambda c, s: run_no_defense(c, s),
    "(b) Paraphrase":              lambda c, s: run_input_defense(c, s, "paraphrase"),
    "(c) Sandwich":                lambda c, s: run_input_defense(c, s, "sandwich"),
    "(d) Instruction prevention":  lambda c, s: run_input_defense(c, s, "instruction_prevention"),
    "(e) AgentGuard (structural)": lambda c, s: run_agentguard(c, s, payload_check=False),
    "(f) AgentGuard (full)":       lambda c, s: run_agentguard(c, s, payload_check=True),
}


# ---------------------------------------------------------------------------
# ASV computation per Liu et al.
#
# In their paper: ASV = fraction of injected cases whose final response is
# the injected task's correct label. In our agentic mapping: the attacker
# wins iff the malicious_action actually executes (allowed=True AND the
# emitted action is the malicious one).
# ---------------------------------------------------------------------------

def attack_succeeded(case, executed_action, allowed):
    if not allowed:
        return False
    return executed_action == case.malicious_action


def evaluate_pair(target_task_obj, injected_task_obj):
    rows = {}
    for strat in ["naive", "escape", "ignore", "fake_completion", "combine"]:
        cases = build_bridged_cases(target_task_obj, injected_task_obj, strat)
        rows[strat] = {}
        for dname, runner in DEFENSES.items():
            n_succ = 0
            for c in cases:
                action, allowed = runner(c, strat)
                if attack_succeeded(c, action, allowed):
                    n_succ += 1
            asv = n_succ / max(1, len(cases))
            rows[strat][dname] = {
                "ASV": round(asv * 100, 1),
                "n_succ": n_succ,
                "n_total": len(cases),
            }
    return rows


def main():
    print("=" * 76)
    print("AgentGuard vs. Liu et al. attack constructions (standalone adapter)")
    print("=" * 76)

    all_results = {}

    for tgt_name, inj_name, tgt_task, inj_task in LIU_TASK_PAIRS:
        pair_key = f"{tgt_name} -> {inj_name}"
        print(f"\nTarget = {tgt_name},  Injected = {inj_name}")
        print(f"  (target task: {tgt_task.task!r}, "
              f"injected task: {inj_task.task!r})")
        print("-" * 76)

        rows = evaluate_pair(tgt_task, inj_task)
        all_results[pair_key] = rows

        # Pretty print: rows = attack strategies, columns = defenses
        defenses = list(DEFENSES.keys())
        print(f"\n  {'Attack':<18}", *[f"{d[:24]:>26}" for d in defenses])
        for strat in ["naive", "escape", "ignore", "fake_completion", "combine"]:
            cells = [f"{rows[strat][d]['ASV']:>5.1f}% ({rows[strat][d]['n_succ']:>2}/{rows[strat][d]['n_total']:>2})"
                     for d in defenses]
            print(f"  {strat:<18}", *[f"{c:>26}" for c in cells])

    # Save JSON
    out_path = os.path.join(RESULTS_DIR, "liu_benchmark.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)

    # Aggregate ASV across all (strategy, pair) combinations per defense
    print("\n" + "=" * 76)
    print("AGGREGATE ASV across all attack strategies and task pairs")
    print("=" * 76)
    agg = defaultdict(lambda: [0, 0])  # defense -> [n_succ, n_total]
    for pair_rows in all_results.values():
        for strat_rows in pair_rows.values():
            for dname, r in strat_rows.items():
                agg[dname][0] += r["n_succ"]
                agg[dname][1] += r["n_total"]
    print(f"\n  {'Defense':<32} {'ASV':>10} {'n_succ / n_total':>20}")
    print("  " + "-" * 64)
    for dname, (s, t) in agg.items():
        asv = s / max(1, t)
        print(f"  {dname:<32} {asv*100:>9.1f}% {f'{s} / {t}':>20}")

    # Also save aggregate
    with open(os.path.join(RESULTS_DIR, "liu_benchmark_agg.json"), "w") as f:
        json.dump({d: {"ASV_pct": round(s/max(1,t)*100, 1),
                       "n_succ": s, "n_total": t}
                   for d, (s, t) in agg.items()}, f, indent=2)
    print(f"\nWrote results to {out_path}")
    print(f"Wrote aggregate to {os.path.join(RESULTS_DIR, 'liu_benchmark_agg.json')}")


if __name__ == "__main__":
    main()
