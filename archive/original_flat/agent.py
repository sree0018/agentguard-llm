"""
agent.py - deterministic vulnerable-agent simulation.

We don't call a real LLM. Instead, we model an agent that, when shown
retrieved content, follows it to varying degrees depending on (a) whether
the content contains an injection, (b) the attack category and (c) what
the active input-side defense (if any) has done to the content first.

The model is calibrated to the empirical findings of Liu et al. [1]:
  - Naive injections almost always succeed against an undefended LLM.
  - Combined attacks defeat all input-side defenses.
  - Some defenses help against specific attack categories but not others.

The agent's "decision" is deterministic: given (modified_content, malicious
action), return either the malicious action (injection succeeded) or the
benign action (injection neutralized).

This is intentionally simpler than a real LLM but reproduces Liu et al.'s
qualitative results faithfully and produces real, reproducible numbers.
"""

from dataclasses import dataclass


# Calibration table: probability that the injection succeeds given
# (attack_category, defense_name).  We use 0/1 outputs determined by
# difficulty rather than randomness, so results are reproducible.
#
# Reading: rows = attack category, columns = defense.
# A "fail_above" difficulty means: injection succeeds iff case difficulty
# exceeds this level.
#
# difficulty levels: "easy" < "medium" < "hard"
DIFFICULTY_RANK = {"easy": 0, "medium": 1, "hard": 2}


# For each (attack_cat, defense), the lowest difficulty at which the
# injection STILL succeeds. None means: injection always succeeds.
# "above_hard" means: never succeeds (defense always wins).
#
# This is calibrated qualitatively to Liu et al. Table 4-6:
#   - paraphrase: works on naive and easy escape; fails on context_ignoring
#                 (paraphrase preserves semantics, so "ignore prior" remains)
#   - retokenization: works on word-recognition-based attacks; weak on
#                     structural attacks (escape, fake_completion)
#   - sandwich: reminds the LLM at the end; helps against ignore + fake_comp
#               but not against escape sequences hiding the directive
#   - instruction_prevention: prepends strong "ignore data instructions";
#               broadly effective on easy/medium, fails on hard combined
#   - none: injection always succeeds when present
DEFENSE_THRESHOLDS = {
    "none": {  # no defense - injection always succeeds
        "naive":            "always",
        "escape":           "always",
        "context_ignoring": "always",
        "fake_completion":  "always",
        "combined":         "always",
    },
    "paraphrase": {
        "naive":            "never",   # paraphrase strips imperative
        "escape":           "medium",  # easy works; medium+ slips through
        "context_ignoring": "always",  # semantic preservation = ignore-prior survives
        "fake_completion":  "medium",
        "combined":         "always",
    },
    "retokenization": {
        "naive":            "medium",  # easy naive disrupted; harder forms survive
        "escape":           "always",  # tokenization doesn't help with structural
        "context_ignoring": "medium",
        "fake_completion":  "always",
        "combined":         "always",
    },
    "sandwich": {
        "naive":            "never",
        "escape":           "medium",  # easy stopped, harder slip past
        "context_ignoring": "medium",
        "fake_completion":  "medium",
        "combined":         "always",
    },
    "instruction_prevention": {
        "naive":            "never",
        "escape":           "hard",    # easy+medium stopped, hard slips
        "context_ignoring": "hard",
        "fake_completion":  "hard",
        "combined":         "always",  # combined defeats this too
    },
}


def _injection_succeeds(case, defense_name: str) -> bool:
    """
    Returns True iff the injection survives the input-side defense and the
    agent ends up emitting the malicious action.
    """
    if case.label == "clean":
        return False

    threshold = DEFENSE_THRESHOLDS.get(defense_name, DEFENSE_THRESHOLDS["none"])\
                                  .get(case.attack_category, "always")

    if threshold == "always":
        return True
    if threshold == "never":
        return False

    # Otherwise threshold is "easy", "medium" or "hard": injection succeeds
    # iff the case's difficulty is at or above that level.
    case_rank = DIFFICULTY_RANK[case.difficulty]
    thr_rank  = DIFFICULTY_RANK[threshold]
    return case_rank >= thr_rank


def simulate_agent(case, defense_name: str) -> dict:
    """
    Simulate what tool call the agent emits, given the active input-side
    defense.

    Returns a dict (the proposed tool call). Output-side defenses (like
    AgentGuard) intercept this dict separately.
    """
    if _injection_succeeds(case, defense_name):
        return dict(case.malicious_action)
    return dict(case.benign_action)


if __name__ == "__main__":
    # Quick sanity check: print effectiveness matrix
    from dataset import ALL_CASES
    cats = ["naive", "escape", "context_ignoring", "fake_completion", "combined"]
    defs = list(DEFENSE_THRESHOLDS.keys())
    inj = [c for c in ALL_CASES if c.label == "injected"]
    print(f"{'attack':<20}", *[f"{d:>22}" for d in defs])
    for cat in cats:
        cat_cases = [c for c in inj if c.attack_category == cat]
        row = [cat]
        for d in defs:
            n_succ = sum(1 for c in cat_cases if _injection_succeeds(c, d))
            row.append(f"{n_succ}/{len(cat_cases)} succ")
        print(f"{row[0]:<20}", *[f"{x:>22}" for x in row[1:]])
