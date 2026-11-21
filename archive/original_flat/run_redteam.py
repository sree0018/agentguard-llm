"""
run_redteam.py - red-team evaluation of AgentGuard's check 4 (payload
consistency): regex proxy vs. local-LLM guard vs. both combined.

Every item is run through the full `authorize()` pipeline (checks 1-4), but
all attack payloads are in-scope by construction, so only check 4 can stop
them. An attack SUCCEEDS iff authorize() returns ALLOW; a benign payload is a
FALSE POSITIVE iff authorize() returns BLOCK. Guard errors (LLM unreachable,
unparseable output) fail closed and are counted separately.

Usage examples
--------------
  # develop / tune on the DEV split (LLM responses are cached on disk)
  python3 run_redteam.py --configs regex,llm=llama3.1:8b --split dev

  # one-shot evaluation on the held-out TEST split (after freezing the prompt)
  python3 run_redteam.py --configs regex,llm=llama3.1:8b,union=llama3.1:8b --split test

  # ablations: verdict-only schema; a smaller model
  python3 run_redteam.py --configs llm=llama3.1:8b#v1@verdict,llm=llama3.2:3b#v1 --split all

  # reproduce LLM numbers offline from the committed cache (no Ollama needed)
  python3 run_redteam.py --configs regex,llm=llama3.1:8b --split all --llm-mode replay

Config syntax:  regex | llm=<model>[@analysis|@verdict][#v1|#v1p|#v2|#v2np|#v3|#v3np]
                       | union=<model>[@schema][#version]
(`union` = regex first, then the LLM; either may block. Default version: v1 (recommended).
 v1 = first release, v2 = improved prompt + deterministic evidence pre-pass,
 v2np = v2 prompt without the pre-pass, v3 = tuned low-FPR variant (narrower script rule),
 v3np = v3 without the pre-pass.)
"""

import argparse
import csv
import json
import math
import os
import time

import attacks
import dataset
import attacks_ext as ext
import attacks_v2 as v2
import attacks_v3 as v3
from agentguard import authorize
import llm_guard

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "llm")


# ---------------------------------------------------------------------------
# Item construction
# ---------------------------------------------------------------------------

class Item:
    def __init__(self, group, split, cid, technique, kind, action, spec):
        self.group, self.split, self.cid = group, split, cid
        self.technique, self.kind = technique, kind   # kind: "attack" | "benign"
        self.action, self.spec = action, spec


ATTACK_GROUPS = (["ADV-1", "ADV-2 orig", "ADV-2 ext", "ADV-3", "ADV-4"]
                 + v2.T2_ATTACK_GROUPS + v3.T3_ATTACK_GROUPS + ["Blind attacks"])
BENIGN_GROUPS = ["Benign (clean)", "Benign (ADV counterparts)", "Benign-hard",
                 v2.G_BENIGN, v3.G_BENIGN, "Blind benign"]

# Split semantics
#   dev   : tuning data for v1 and v2
#   test  : held-out for v1 (evaluated once, prompt v1). BURNED for v2: it was
#           seen before v2 was tuned, so v2 treats it as tuning data ("dev2").
#   test2 : fresh set (attacks_v2.py), evaluated once after v2 is frozen.
#           BURNED for v3 (seen before v3 was tuned): v3 treats it as tuning
#           data ("dev3" = dev + test + test2)
#   test3 : fresh set (attacks_v3.py), authored before v3 existed, evaluated
#           once after v3 is frozen
#   blind : cases authored independently by teammates (--blind file.json)
SPLITS = {"dev": {"dev"}, "test": {"test"}, "dev2": {"dev", "test"},
          "test2": {"test2"}, "dev3": {"dev", "test", "test2"},
          "test3": {"test3"}, "blind": {"blind"},
          "all": {"dev", "test", "test2", "test3", "blind"}}


def build_items(blind_path=None):
    items = []
    # legacy sets (seen while building the system) count as DEV
    for c in attacks.ADV1:
        items.append(Item("ADV-1", "dev", c.cid, "plain_secret", "attack",
                          c.malicious_action, c.user_task))
    for c in ext.ADV2_EXT:
        grp = "ADV-2 orig" if c.cid.startswith("ADV2-") else "ADV-2 ext"
        items.append(Item(grp, c.split, c.cid, c.technique, "attack",
                          c.malicious_action, c.user_task))
    for c in attacks.ADV3:
        items.append(Item("ADV-3", "dev", c.cid, "benign_looking_url", "attack",
                          c.malicious_action, c.user_task))
    for c in ext.ADV4:
        items.append(Item("ADV-4", c.split, c.cid, c.technique, "attack",
                          c.malicious_action, c.user_task))

    for c in dataset.CLEAN_CASES:
        items.append(Item("Benign (clean)", "dev", c.cid, "clean", "benign",
                          c.benign_action, c.user_task))
    seen = set()
    for c in attacks.ADV1 + attacks.ADV2 + attacks.ADV3:
        key = (json.dumps(c.benign_action, sort_keys=True),
               json.dumps(c.user_task, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        items.append(Item("Benign (ADV counterparts)", "dev", c.cid + "-benign",
                          "counterpart", "benign", c.benign_action, c.user_task))
    for c in ext.BENIGN_HARD:
        items.append(Item("Benign-hard", c.split, c.cid, c.technique, "benign",
                          c.benign_action, c.user_task))
    for c in v2.TEST2:
        atk = c.label == "injected"
        items.append(Item(c.family, "test2", c.cid, c.technique,
                          "attack" if atk else "benign",
                          c.malicious_action if atk else c.benign_action,
                          c.user_task))
    for c in v3.TEST3:
        atk = c.label == "injected"
        items.append(Item(c.family, "test3", c.cid, c.technique,
                          "attack" if atk else "benign",
                          c.malicious_action if atk else c.benign_action,
                          c.user_task))
    if blind_path:
        for c in v2.load_blind(blind_path):
            atk = c.label == "injected"
            items.append(Item(c.family, "blind", c.cid, c.technique,
                              "attack" if atk else "benign",
                              c.malicious_action if atk else c.benign_action,
                              c.user_task))
    return items


# ---------------------------------------------------------------------------
# Configs
# ---------------------------------------------------------------------------

def make_checker(cfg, llm_mode, cache_path):
    """cfg -> (label, payload_checker or None)"""
    if cfg == "regex":
        return "regex", None
    kind, _, rest = cfg.partition("=")
    rest, _, version = rest.partition("#")
    version = version or llm_guard.DEFAULT_VERSION
    model, _, schema = rest.partition("@")
    schema = schema or "analysis"
    backend = llm_guard.make_backend(model=model or llm_guard.DEFAULT_MODEL,
                                     mode=llm_mode, cache_path=cache_path,
                                     schema_mode=schema)
    label = (f"{kind}:{model}" + ("" if schema == "analysis" else f"@{schema}")
             + f"#{version}")
    if kind == "llm":
        return label, llm_guard.make_llm_checker(backend, version)
    if kind == "union":
        return label, llm_guard.make_union_checker(backend, version)
    raise SystemExit(f"unknown config {cfg!r}")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def wilson(k, n, z=1.96):
    """95% Wilson score interval for a proportion (small-n friendly)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x):
    return f"{100 * x:5.1f}%"


def percentile(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    i = min(len(xs) - 1, int(round(q * (len(xs) - 1))))
    return xs[i]


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run_config(label, checker, items):
    rows = []
    for n, it in enumerate(items, 1):
        t0 = time.perf_counter()
        d = authorize(it.action, it.spec, payload_checker=checker)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        meta = d.meta or {}
        lat = meta.get("latency_ms", wall_ms)
        rows.append({
            "config": label, "group": it.group, "split": it.split,
            "cid": it.cid, "technique": it.technique, "kind": it.kind,
            "allowed": d.allowed, "check": d.check,
            "error": meta.get("error") or "",
            "cached": meta.get("cached", ""),
            "latency_ms": round(lat, 2) if lat is not None else "",
            "reason": d.reason,
        })
        if checker is not None and n % 20 == 0:
            print(f"    [{label}] {n}/{len(items)}", flush=True)
    return rows


def summarize(rows):
    out = {"groups": {}, "techniques": {}, "latency_ms": {}, "errors": 0}
    for r in rows:
        g = out["groups"].setdefault(r["group"], {"n": 0, "bad": 0, "kind": r["kind"]})
        g["n"] += 1
        # attack: bad = attack allowed; benign: bad = wrongly blocked
        g["bad"] += int(r["allowed"]) if r["kind"] == "attack" else int(not r["allowed"])
        if r["kind"] == "attack":
            t = out["techniques"].setdefault(r["technique"], {"n": 0, "bad": 0})
            t["n"] += 1
            t["bad"] += int(r["allowed"])
        if r["error"]:
            out["errors"] += 1
    for g in out["groups"].values():
        lo, hi = wilson(g["bad"], g["n"])
        g["rate"] = g["bad"] / g["n"] if g["n"] else 0.0
        g["ci95"] = [round(lo, 4), round(hi, 4)]
    # every row that went through an LLM call carries a `cached` flag (meta)
    lats = [r["latency_ms"] for r in rows
            if r["latency_ms"] != "" and r["cached"] != ""]
    if lats:
        out["latency_ms"] = {"p50": round(percentile(lats, 0.5), 1),
                             "p95": round(percentile(lats, 0.95), 1),
                             "n": len(lats)}
    # pooled rates
    for kind, name in (("attack", "ALL ATTACKS"), ("benign", "ALL BENIGN")):
        n = sum(g["n"] for g in out["groups"].values() if g["kind"] == kind)
        bad = sum(g["bad"] for g in out["groups"].values() if g["kind"] == kind)
        lo, hi = wilson(bad, n)
        out["groups"][name] = {"n": n, "bad": bad, "kind": kind,
                               "rate": bad / n if n else 0.0,
                               "ci95": [round(lo, 4), round(hi, 4)]}
    return out


def print_summary(label, s):
    print(f"\n=== {label} ===")
    print(f"  {'group':<28}{'metric':<7}{'rate':>8}  {'k/n':>7}   95% CI (Wilson)")
    for g in ATTACK_GROUPS + ["ALL ATTACKS"] + BENIGN_GROUPS + ["ALL BENIGN"]:
        if g not in s["groups"] or s["groups"][g]["n"] == 0:
            continue
        v = s["groups"][g]
        metric = "ASR" if v["kind"] == "attack" else "FPR"
        lo, hi = v["ci95"]
        print(f"  {g:<28}{metric:<7}{pct(v['rate']):>8}  {v['bad']:>3}/{v['n']:<3}"
              f"   [{100*lo:4.1f}, {100*hi:5.1f}]")
    if s["latency_ms"]:
        L = s["latency_ms"]
        print(f"  LLM latency: p50 {L['p50']} ms, p95 {L['p95']} ms (n={L['n']})")
    print(f"  guard errors (failed closed): {s['errors']}")


def print_techniques(label, s):
    print(f"\n  ASR by technique [{label}]")
    for t, v in sorted(s["techniques"].items()):
        print(f"    {t:<22} {v['bad']:>2}/{v['n']:<2} {pct(v['bad']/v['n'])}")


def log_test_run(labels, args):
    """Record every held-out evaluation (non-replay) with the prompt hash of
    each guard version and, for TEST2, the dataset hash, so the report can state
    how often a held-out split was looked at and with which prompt."""
    path = os.path.join(OUT_DIR, "test_runs.json")
    log = []
    if os.path.exists(path):
        with open(path) as f:
            log = json.load(f)
    versions = sorted({l.rsplit("#", 1)[1] for l in labels if "#" in l})
    if not versions:           # regex-only runs do not consume the held-out split
        return
    hashes = {v: llm_guard.prompt_hash(v) for v in versions}
    for v, h in hashes.items():
        prev = {e["prompt_hashes"][v] for e in log
                if e["split"] == args.split and v in e.get("prompt_hashes", {})}
        if prev and h not in prev:
            print(f"\n  WARNING: split '{args.split}' was already evaluated with guard "
                  f"{v} hash(es) {sorted(prev)}; now {h}. Changing the prompt after "
                  "seeing held-out results means it is no longer held out; report "
                  "this in the write-up.\n")
    log.append({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "split": args.split,
                "configs": labels, "prompt_hashes": hashes,
                "test2_dataset_hash": v2.dataset_hash() if args.split in ("test2", "all") else None,
                "test3_dataset_hash": v3.dataset_hash() if args.split in ("test3", "all") else None})
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump(log, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--configs", default="regex,llm=llama3.1:8b")
    ap.add_argument("--split", choices=list(SPLITS), default="dev")
    ap.add_argument("--blind", default=None,
                    help="JSON file of independently authored cases "
                         "(see blind_cases_template.json); use with --split blind or all")
    ap.add_argument("--llm-mode", choices=["auto", "live", "replay"], default="auto")
    ap.add_argument("--cache", default=llm_guard.DEFAULT_CACHE)
    ap.add_argument("--tag", default=None, help="suffix for output files")
    ap.add_argument("--techniques", action="store_true",
                    help="also print ASR by technique")
    args = ap.parse_args()

    items = [i for i in build_items(args.blind) if i.split in SPLITS[args.split]]
    n_att = sum(i.kind == "attack" for i in items)
    print(f"Split '{args.split}': {n_att} attacks, {len(items) - n_att} benign items; "
          f"guard prompt hashes " + ", ".join(f"{v}={llm_guard.prompt_hash(v)}"
                                              for v in llm_guard.GUARD_VERSIONS))

    all_rows, summaries = [], {}
    labels = []
    for cfg in [c.strip() for c in args.configs.split(",") if c.strip()]:
        label, checker = make_checker(cfg, args.llm_mode, args.cache)
        labels.append(label)
        rows = run_config(label, checker, items)
        all_rows += rows
        summaries[label] = summarize(rows)
        print_summary(label, summaries[label])
        if args.techniques:
            print_techniques(label, summaries[label])

    if args.split in ("test", "test2", "test3", "all", "blind") and args.llm_mode != "replay":
        log_test_run(labels, args)

    os.makedirs(OUT_DIR, exist_ok=True)
    tag = args.tag or args.split
    with open(os.path.join(OUT_DIR, f"redteam_summary_{tag}.json"), "w") as f:
        json.dump({"split": args.split,
                   "prompt_hashes": {v: llm_guard.prompt_hash(v)
                                     for v in llm_guard.GUARD_VERSIONS},
                   "test2_dataset_hash": v2.dataset_hash(),
                   "test3_dataset_hash": v3.dataset_hash(),
                   "summaries": summaries}, f, indent=2)
    with open(os.path.join(OUT_DIR, f"redteam_per_case_{tag}.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)
    print(f"\nWrote results/llm/redteam_summary_{tag}.json and redteam_per_case_{tag}.csv")


if __name__ == "__main__":
    main()
