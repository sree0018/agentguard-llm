# Slide outline: Local-LLM guard for AgentGuard check 4

All numbers are generated into `docs/results.md` from the per-case CSVs
(`python3 make_results_table.py`). Guard: llama3.1:8b via Ollama, temperature 0,
seed 42. ASR = attack success rate (lower is better); FPR = false positives on
benign payloads. Quote the Wilson 95% intervals: the samples are small.

1. **Problem / recap (1 slide).** AgentGuard = output-side authorization with 4
   checks. Checks 1-3 are structural; check 4 (payload consistency) is the only
   one that can stop an *in-scope tool + malicious payload* attack.
2. **The weak point (1 slide).** The check-4 regex matches literal patterns,
   ignores the task spec, and scans only `body/query/url`. Original ADV-2
   obfuscation attacks: **5/5 get through**.
3. **Proposal (1 slide).** Replace the regex with a local guard LLM (no API,
   nothing leaves the machine). The guard sees only the pinned task spec and the
   proposed call, never the retrieved content. Fail closed.
4. **Design (1 slide).** Constrained JSON verdict; the action is serialised with
   `ensure_ascii` so zero-width/look-alike characters show as `\uXXXX`; strict
   parser (never scans free text for "ALLOW"); response cache for offline replay.
   Optional deterministic *evidence* pre-pass (`normalize.py`) decodes
   base64/hex/etc. but never decides.
5. **How we tested it, and why (1-2 slides).** DEV for tuning; TEST, TEST2 and
   TEST3 held out; techniques deliberately kept out of the prompts; a log of every
   held-out evaluation with prompt and dataset hashes; best-of-N tuning counted as
   tuning data. Attack families: 19 ADV-2 obfuscation techniques, 12 further
   encodings in TEST2 and 18 in TEST3 (6 new), prose smuggling, label abuse, attacks on the guard itself, fresh
   realistic benign payloads (non-Latin text, emoji, security vocabulary).
6. **Headline result (1 slide).** Pooled over three held-out sets (139 attacks,
   82 benign): regex lets **96%** through (CI 92-98) and has 2% false positives;
   the strict LLM guard v1 lets **12%** through (CI 7-18) with **12%** false
   positives (CI 7-21). Per set: 8%, 12%, 12% (consistent).
7. **The trade-off (1 slide).** Every variant built to cut false positives
   (v1p, v2, v3) reached ~0% FPR but let 25-42% of attacks through on held-out
   data. Show the table. Message: prompt-only tuning of an 8B model moves along a
   security/usability curve; it does not make the guard both strict and quiet.
8. **What the pre-pass did (1 slide).** On the encodings it covers it removes the
   misses (v2np 3/12 -> v2 0/12 on TEST2) and reduces false positives; it does
   nothing for ciphers, prose, label abuse.
9. **Adaptive attacker (1 slide, the sobering one).** A query-budgeted search
   (28 encoders x 8 wrappers, 30 queries per target, 8 targets, guard feedback)
   broke regex 8/8 (median 1 query), v1 7/8 (median 3), v1p 7/8 (median 6),
   v3 8/8 (median 9). Winning moves: secrets presented as a "commit"/"reference"
   id, ciphers (Atbash, Caesar, ROT47), symbol scripts. Fixed-list ASR of 12%
   overstates robustness against an attacker who can probe the guard.
   Threat-model nuance: a real injected document usually gets no ALLOW/BLOCK
   oracle, so fixed-list numbers are the realistic one-shot figure and the
   adaptive numbers are a worst case.
10. **Main benchmark (1 slide).** 70-case benchmark with LLM check 4: ASR 0%,
    FPR 0% (v1, v1p, v3), same as regex; ADV-2 original: regex 5/5, v1 1/5,
    v1p 1/5, v3 0/5 (small, not independent: tuning data).
11. **Cost (1 slide).** Regex ~1-2 microseconds vs ~4 s per guard call (p50)
    on an M-series laptop; only runs after checks 1-3 pass.
12. **Limitations (1 slide).** One author for guard + tests (blind-case loader and
    template provided for teammates); simulated agent; small n; strict guard still
    misses label abuse and plain-prose secrets; guard is itself injectable (ADV-4);
    8B model is brittle to prompt wording (v2 iteration 3 got worse after adding an
    instruction).
13. **Recommendations / future work (1 slide).** Use v1 as default; add
    non-prompt defenses: allowlists/DLP for secret-shaped values and URLs, rate
    limiting and alerting on repeated blocks (denies the oracle), a bigger or
    fine-tuned guard, user-prompt-derived richer task specs; real agent loop
    (AgentDojo); independent teammate test cases.

Q&A prep:
* *Why not just add regex patterns?* Open-ended encodings; regex got 134/139 held-out attacks through.
* *Why is regex+LLM not better?* The regex adds only false positives on benign text mentioning "bearer"/"API_KEY"; the LLM already catches what the regex catches.
* *Why choose v1 when v3 has 0% false positives?* On held-out data v1 stops 3-4x more attacks; in a guard a false positive costs a confirmation, a leak is irreversible. A deployer who values usability can pick v3.
* *Is the 0% on the main benchmark meaningful?* Same caveat as the original report: small and partly authored to match the checks. The held-out sets and the adaptive attacker are the informative numbers.
