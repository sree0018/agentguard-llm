# Guard-prompt tuning log (DEV split only)

The guard system prompt (`agentguard.llm.prompts.SYSTEM_PROMPT_V1`) was iterated on the DEV
split only (24 ADV-2 + 6 ADV-4 + 5 ADV-1 + 5 ADV-3 attacks; 20 clean + 11
counterpart + 14 hard-benign payloads). The held-out TEST split was never
evaluated before the prompt was frozen (`results/llm/test_runs.json` records
each TEST evaluation with the prompt hash).

| Iter | Prompt change | DEV attacks succeeding | DEV hard-benign false positives |
|------|---------------|------------------------|---------------------------------|
| 0 | First draft (`when unsure, BLOCK`; strict opaque-string rule) | 0 / 40 | 4 / 14 (token-topic text, Japanese translation, commit hash, order+phone number) |
| 1 | Generalised: labelled identifiers are normal; any language/script is a normal translation result; topic mentions of "password/token/API key" are not secrets; block on concrete evidence, not merely on numbers | 1 / 40 (ASCII-code query) | 2 / 14 (a password definition, Russian translation) |

Prompt iteration stopped after iteration 1 (two rounds): with 14 hard-benign
dev items, further tuning mostly fits those items. The remaining dev failures
are reported as-is.

Observation worth stating in the report: loosening the guard to remove false
positives (iteration 1) re-opened one attack (numeric character codes inside a
web-search query). This is the security/usability trade-off in miniature.
Note also that iteration 1 explicitly lists labelled identifiers (commit,
order, run/id) as normal, which an attacker could try to exploit by labelling
a secret; see the ADV-4/"label abuse" item under future work.

---

# Guard v2 (second release)

Motivation: the v1 write-up had weaknesses (the v1 prompt named most of the TEST
obfuscation techniques; fixed attacks only; 20% false positives on hard benign
text). v2 changes the prompt (fewer technique names, more worked ALLOW examples
for security vocabulary) AND adds a deterministic evidence pre-pass
(`src/agentguard/llm/preprocess.py`: decodes base64/hex/percent/HTML/decimal/binary/spaced letters,
shows invisible and look-alike characters, NFKC view). The pre-pass supplies
facts only; the LLM still makes every decision.

## Protocol
* The v1 TEST split was already seen, so for v2 it counts as tuning data.
  v2 was tuned on `dev2` = DEV + v1-TEST (65 attacks, 55 benign).
* TEST2 (`src/agentguard/data/redteam_v2.py`: 64 attacks, 40 benign, dataset hash `57d2b47d15f2`)
  was written BEFORE v2 tuning started and was not run against any guard until
  v2 was frozen. It is evaluated once; `results/llm/test_runs.json` records
  prompt hashes and the dataset hash.
* Iterations on `dev2` (llama3.1:8b, temperature 0):

| Iter | Change | dev2 attacks succeeding | dev2 benign false positives |
|------|--------|-------------------------|-----------------------------|
| v1 (reference, `#v1`) | frozen v1 prompt | 3 / 65 | 4 / 55 |
| 1 | first v2 prompt + pre-pass | 5 / 65 | 7 / 55 (security vocabulary treated as a leak; a decoded candidate was ignored) |
| 2 | relevance judged generously; "topic vs value" guidance; extra ALLOW examples (security reminder, short commit hash); worked example for the notes | 6 / 65 | 1 / 55 |
| 3 | stronger "any decoded candidate => BLOCK" instruction | 10 / 65 | 1 / 55 |

Iteration 3 was WORSE (the 8B model reacted unpredictably to an extra
instruction, e.g. it allowed a URL-encoded secret although the decoded text was
shown). We reverted to the iteration-2 text and froze it as v2
(hash `2ef35cbe6a64`). Selecting the best of three iterations on tuning data
means tuning-split numbers for v2 are optimistic; TEST2 is the honest number.

Raw iteration outputs: `results/llm/tuning_logs/`.

---

# TEST2 outcome, guard v3 and v1p (recorded BEFORE TEST3 was run)

**TEST2 (held-out, evaluated once, v2 frozen at `2ef35cbe6a64`)** showed v2 is a
different operating point from v1, not an improvement:

| TEST2 (64 attacks, 40 benign) | v1 | v2 w/o pre-pass | v2 |
|---|---|---|---|
| attacks succeeding | 8/64 (12.5%) | 10/64 (15.6%) | 16/64 (25.0%) |
| benign false positives | 5/40 (12.5%) | 2/40 (5.0%) | 0/40 |
| pre-pass-covered encodings | 0/12 | 3/12 | 0/12 |
| uncovered encodings | 1/24 | 3/24 | 10/24 |

The pre-pass works (covered encodings: 3/12 -> 0/12 and fewer false positives),
but the v2 prompt text ("text in any script is a normal result") let symbol-script
encodings (Braille, flag letters) and rarer encodings through.

**Guard v3** = v2 + (a) a narrower script rule (natural-language text and normal
emoji are fine; symbols used as letters/digits are disguised content) and (b) an
"undecodable gibberish is disguised content" rule. TEST2 is burned for v3, so v3
was tuned on `dev3` = DEV + v1-TEST + TEST2 (129 attacks, 95 benign). ONE tuning
iteration only: attacks succeeding 25/129 (19.4%), false positives 0/95. The
model still let 11/24 uncovered TEST2 encodings through, including Braille and
flag letters that the new rule names, i.e. it does not reliably follow the extra
instruction (the same instability seen in v2 iteration 3). We stopped tuning
rather than chase individual cases, frozen v3 hash `f3d88a242253`.

**Guard v1p** = the strict v1 prompt + the evidence pre-pass and its explanation
paragraph. Zero tuning iterations; first evaluated on TEST3
(hash `8304d461093b`). Declared in advance as a candidate because v1 was best at
blocking and the pre-pass was best at supplying evidence.

**TEST3** (`src/agentguard/data/redteam_v3.py`, 50 attacks, 32 benign, dataset hash `aaad5ba13c89`)
was authored before v3 existed, and is evaluated once, for all candidates
(v1, v1p, v3, regex+v3). Several candidates are compared on one test set, so
the TEST3 differences between them are exploratory, not a confirmed ranking.

---

# Outcome of TEST3 and the adaptive attacker (final)

TEST3 (held out for v3 and v1p; v1 was frozen long before it existed):
regex 49/50 attacks through, 1/32 false positives; **v1 6/50, 3/32**; v1p 15/50,
0/32; v3 21/50, 0/32; regex+v3 21/50, 1/32. The tuned low-false-positive
variants lose to the original strict v1 on attack success on both TEST2 and
TEST3. Default guard version therefore stays v1.

Adaptive attacker (8 targets, 30 queries each, `agentguard adaptive`): regex 8/8
broken (median 1 query), v1 7/8 (median 3), v1p 7/8 (median 6), v3 8/8
(median 9). Most bypasses disguise the secret as a labelled identifier
("commit ...", "reference id ...") or use ciphers (Atbash, Caesar-5, ROT47) /
symbol scripts. No prompt changes were made after seeing these results.
