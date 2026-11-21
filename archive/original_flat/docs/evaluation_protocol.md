# Evaluation protocol (who saw what, when)

Small local models are sensitive to prompt wording, so how a test set is used
matters more than the headline number. This file is the audit trail.

## Data sets

| Set | Size (attacks / benign) | Authored | Used for |
|---|---|---|---|
| DEV (`attacks.py` ADV-1/2/3, `attacks_ext.py` dev, clean cases) | 40 / 45 | before v1 | tuning v1 |
| TEST (`attacks_ext.py` test split) | 25 / 10 | before v1 was frozen | evaluated once with v1 |
| TEST2 (`attacks_v2.py`) | 64 / 40, hash `57d2b47d15f2` | after v1 frozen, before v2 tuning | evaluated once with v1, v2np, v2, regex+v2 |
| TEST3 (`attacks_v3.py`) | 50 / 32, hash `aaad5ba13c89` | after v2 evaluated, before v3 existed | evaluated once with v1, v1p, v3, regex+v3 |
| Adaptive search (`run_adaptive.py`) | 8 targets, budget 30 | after all guards frozen | evaluated once per guard |
| Blind (teammates, `blind_cases_template.json`) | open | by teammates | not yet included |

## Guard versions and which sets were held out for each

| Version | Tuned on | Held-out on |
|---|---|---|
| v1 (`d4c05c622fca`) | DEV | TEST, TEST2, TEST3 |
| v2 (`2ef35cbe6a64`) | DEV + TEST (3 iterations; best kept) | TEST2 |
| v3 (`f3d88a242253`) | DEV + TEST + TEST2 (1 iteration) | TEST3 |
| v1p (`8304d461093b`) | nothing (v1 + evidence pre-pass) | TEST3 |

Rules we followed:
1. A set that influenced a prompt is never reported as held out for it.
2. Every non-replay evaluation of a TEST set is appended to
   `results/llm/test_runs.json` (prompt hashes, dataset hashes). The harness
   warns if a split is re-evaluated with a different prompt.
3. Several candidates (v1, v1p, v3) were compared on TEST3: differences among
   them are exploratory. v1 was not chosen from TEST3; it was already frozen
   before TEST2 existed, and TEST, TEST2, TEST3 agree.
4. Tuning-split numbers for v2/v3 are optimistic (best-of-N on tuning data).

## What this does NOT fix (state this in the report)
* One author wrote guard, attacks and benign sets. Blind teammate cases are
  supported but not yet included; adding them is the most valuable next step.
* Attacks are authored by us, so "unseen technique" means unseen by the
  *prompt*, not unseen by the author.
* n is small; read the Wilson intervals, not the point estimates.
* The adaptive attacker is a structured search, not an LLM attacker.
* The agent is a simulation (as in the original report).
