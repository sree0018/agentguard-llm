"""
test_llm_guard.py - offline unit tests for the local-LLM payload guard.

Run:  python3 -m unittest test_llm_guard -v
No Ollama, no network and no model are needed (a MockBackend is used).
"""

import csv
import json
import os
import tempfile
import unittest

import agentguard
import attacks
import attacks_ext as ext
import attacks_v2 as v2
import attacks_v3 as v3
import dataset
import normalize
import llm_guard as lg
from agent import simulate_agent

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOW = json.dumps({"analysis": "ok", "verdict": "ALLOW"})
BLOCK = json.dumps({"analysis": "bad", "verdict": "BLOCK"})

SPEC = dataset.task("summarize_pdf", ["read_pdf", "respond"],
                    {"recipients": ["self"]}, read_only=True)
ACTION = {"tool": "respond", "to": "self", "body": "Summary."}


class ParseVerdict(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(lg.parse_verdict(ALLOW)[0], "ALLOW")
        self.assertEqual(lg.parse_verdict(BLOCK)[0], "BLOCK")
        self.assertEqual(lg.parse_verdict('{"verdict": "block"}')[0], "BLOCK")

    def test_json_embedded_in_text(self):
        self.assertEqual(lg.parse_verdict('Sure! {"verdict": "ALLOW"} done')[0], "ALLOW")

    def test_strict_no_free_text_scan(self):
        # An echoed/attacker-influenced bare word must NOT count as a verdict.
        for bad in ["ALLOW", "Verdict: ALLOW", "", "{}", "[1,2]", "null",
                    '{"verdict": "MAYBE"}', '{"verdict": 1}', '{"verdict": ["ALLOW"]}']:
            self.assertIsNone(lg.parse_verdict(bad)[0], bad)
        self.assertIsNone(lg.parse_verdict(None)[0])


class FailClosed(unittest.TestCase):
    def test_backend_error(self):
        def boom(s, u):
            raise lg.BackendError("down")
        d = lg.check_payload_llm(ACTION, SPEC, lg.MockBackend(boom))
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, lg.CHECK_NAME_ERR)
        self.assertEqual(d.meta["error"], "backend")

    def test_garbage_output(self):
        d = lg.check_payload_llm(ACTION, SPEC, lg.MockBackend(lambda s, u: "ALLOW"))
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, lg.CHECK_NAME_ERR)
        self.assertEqual(d.meta["error"], "parse")

    def test_allow_and_block(self):
        d = lg.check_payload_llm(ACTION, SPEC, lg.MockBackend(lambda s, u: ALLOW))
        self.assertTrue(d.allowed)
        self.assertEqual(d.check, lg.CHECK_NAME)
        d = lg.check_payload_llm(ACTION, SPEC, lg.MockBackend(lambda s, u: BLOCK))
        self.assertFalse(d.allowed)


class PromptConstruction(unittest.TestCase):
    def test_never_contains_retrieved_content(self):
        """Information asymmetry: the guard must not see retrieved content."""
        cases = dataset.ALL_CASES + attacks.ADAPTIVE_ALL + ext.ALL_ATTACKS
        for c in cases:
            for a in (c.benign_action, c.malicious_action):
                if a is None:
                    continue
                system, user = lg.build_messages(a, c.user_task)
                if len(c.retrieved) > 12:
                    self.assertNotIn(c.retrieved, user + system, c.cid)

    def test_unicode_is_escaped_visibly(self):
        a = {"tool": "respond", "to": "self", "body": "A​Pі"}
        _, user = lg.build_messages(a, SPEC)
        self.assertIn("\\u200b", user)
        self.assertIn("\\u0456", user)
        self.assertNotIn("​", user)

    def test_spec_fields_present(self):
        _, user = lg.build_messages(ACTION, SPEC)
        self.assertIn("summarize pdf", user)
        self.assertIn("read_only", user)
        self.assertIn("proposed_tool_call", user)

    def test_no_test_payload_leaks_into_prompt(self):
        """Few-shot examples must not contain any dev/test attack or benign
        payload verbatim (otherwise the held-out claim is void)."""
        for c in ext.ALL_ATTACKS + ext.BENIGN_HARD + v2.TEST2 + v3.TEST3:
            a = c.malicious_action or c.benign_action
            text = a.get("body") or a.get("query") or a.get("path") or ""
            if len(text) > 15:
                for ver, (prompt, _) in lg.GUARD_VERSIONS.items():
                    self.assertNotIn(text, prompt, f"{c.cid} in {ver}")

    def test_v1_prompt_is_frozen(self):
        """v1 must stay byte-identical so its cached results keep replaying."""
        self.assertEqual(lg.prompt_hash("v1"), "d4c05c622fca")

    def test_v2_notes_only_in_v2(self):
        a = {"tool": "respond", "to": "self", "body": "aGVsbG8gd29ybGQgaGVsbG8="}
        _, u1 = lg.build_messages(a, SPEC, "v1")
        _, u2 = lg.build_messages(a, SPEC, "v2")
        _, u3 = lg.build_messages(a, SPEC, "v2np")
        self.assertNotIn("preprocessing_notes", u1)
        self.assertNotIn("preprocessing_notes", u3)
        self.assertIn("preprocessing_notes", u2)
        self.assertIn("hello world", u2)

    def test_v2_prompts_never_see_retrieved(self):
        for c in dataset.ALL_CASES:
            for a in (c.benign_action, c.malicious_action):
                if a and len(c.retrieved) > 12:
                    system, user = lg.build_messages(a, c.user_task, "v2")
                    self.assertNotIn(c.retrieved, system + user, c.cid)


class Cache(unittest.TestCase):
    def test_cache_hit_persist_and_replay(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "c.json")
            inner = lg.MockBackend(lambda s, u: ALLOW)
            cb = lg.CachedBackend(inner, path=path, mode="auto")
            cb.complete("sys", "user")
            cb.complete("sys", "user")
            self.assertEqual(inner.calls, 1)          # second call served from cache
            self.assertTrue(cb.last_cached)
            # new process-like instance, replay mode, no inner call allowed
            inner2 = lg.MockBackend(lambda s, u: self.fail("must not be called"))
            rb = lg.CachedBackend(inner2, path=path, mode="replay")
            self.assertEqual(rb.complete("sys", "user"), ALLOW)
            with self.assertRaises(lg.CacheMiss):
                rb.complete("sys", "different user prompt")

    def test_key_depends_on_model_options(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "c.json")
            a = lg.CachedBackend(lg.MockBackend(lambda s, u: ALLOW, model="m1"), path=path)
            b = lg.CachedBackend(lg.MockBackend(lambda s, u: BLOCK, model="m2"), path=path)
            self.assertEqual(a.complete("s", "u"), ALLOW)
            self.assertEqual(b.complete("s", "u"), BLOCK)   # not served from m1's entry


class Integration(unittest.TestCase):
    def test_default_authorize_unchanged_vs_baseline(self):
        """With payload_checker=None, authorize() must reproduce the original
        regex-based decisions recorded in results/baseline_regex/per_case.csv."""
        path = os.path.join(HERE, "results", "baseline_regex", "per_case.csv")
        if not os.path.exists(path):
            self.skipTest("baseline snapshot not present")
        with open(path) as f:
            base = {r["cid"]: r["executed"] == "True"
                    for r in csv.DictReader(f)
                    if r["defense"] == "(g) AgentGuard (full)"}
        self.assertEqual(len(base), 70)
        for c in dataset.ALL_CASES:
            d = agentguard.authorize(simulate_agent(c, "none"), c.user_task)
            self.assertEqual(d.allowed, base[c.cid], c.cid)

    def test_llm_checker_plugs_into_authorize(self):
        mal = {"tool": "respond", "to": "self", "body": "Summary. c2VjcmV0"}
        d = agentguard.authorize(mal, SPEC,
                                 payload_checker=lg.make_llm_checker(
                                     lg.MockBackend(lambda s, u: BLOCK)))
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, lg.CHECK_NAME)
        # structural checks still run first and short-circuit before the LLM
        bad = {"tool": "send_email", "to": "x@y.z", "body": "hi"}
        be = lg.MockBackend(lambda s, u: self.fail("LLM must not be called"))
        d = agentguard.authorize(bad, SPEC, payload_checker=lg.make_llm_checker(be))
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "tool_admission")

    def test_union_short_circuits_on_regex(self):
        be = lg.MockBackend(lambda s, u: self.fail("LLM must not be called"))
        mal = {"tool": "respond", "to": "self", "body": "API_KEY=sk-live-ABC"}
        d = agentguard.authorize(mal, SPEC, payload_checker=lg.make_union_checker(be))
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "payload_consistency")   # the regex decided
        # regex passes -> LLM decides
        ok = lg.make_union_checker(lg.MockBackend(lambda s, u: BLOCK))
        d = agentguard.authorize({"tool": "respond", "to": "self", "body": "hi"},
                                 SPEC, payload_checker=ok)
        self.assertEqual(d.check, lg.CHECK_NAME)

    def test_skeleton_delegate(self):
        d = agentguard.payload_check_llm_skeleton(ACTION, SPEC,
                                                  lg.MockBackend(lambda s, u: ALLOW))
        self.assertTrue(d.allowed)


class Prepass(unittest.TestCase):
    """normalize.preprocess supplies evidence only; it never decides."""

    def dec(self, body):
        n = normalize.preprocess({"tool": "respond", "to": "self", "body": body})
        c = n["decoded_candidates"]
        return [x["text"] for x in c] if c != "none" else []

    def test_decodes_unambiguous_encodings(self):
        import base64
        self.assertIn("password=hunter2",
                      self.dec("x " + base64.b64encode(b"password=hunter2").decode()))
        self.assertIn("sk-live-ABC", self.dec("736b2d6c6976652d414243"))
        self.assertIn("password=x1", self.dec("%70%61%73%73%77%6f%72%64%3d%78%31"))
        self.assertIn("sk-live", self.dec("115 107 045 108 105 118 101"))
        self.assertIn("sk-live-AB", self.dec("s k - l i v e - A B"))

    def test_nested_decoding(self):
        import base64
        inner = base64.b64encode(b"password=hunter2").decode().encode().hex()
        self.assertIn("password=hunter2", self.dec(inner))

    def test_benign_identifiers_not_decoded(self):
        for t in ["commit 3f2a9c1d8b7e4a5f6c0d1e2f3a4b5c6d7e8f9a0b",
                  "run 123e4567-e89b-12d3-a456-426614174000",
                  "Order #A1B2C3-98765 call 214-555-0143",
                  "SHA-256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "color #FF5733 and version 3.1.4"]:
            self.assertEqual(self.dec(t), [], t)

    def test_hidden_and_lookalike_characters(self):
        n = normalize.preprocess({"tool": "respond", "body": "pa\u200bss\u200bword"})
        self.assertNotEqual(n["hidden_or_lookalike_characters"], "none")
        self.assertIn("password", json.dumps(n["normalized_text"]))
        n = normalize.preprocess({"tool": "respond", "body": "p\u0430ssword"})   # Cyrillic a
        self.assertIn("latin_words_with_lookalike_letters",
                      json.dumps(n["hidden_or_lookalike_characters"]))

    def test_pure_non_latin_text_not_flagged(self):
        for t in ["\u041f\u0440\u0438\u0432\u0435\u0442, \u043a\u0430\u043a \u0434\u0435\u043b\u0430?",
                  "\u3053\u3093\u306b\u3061\u306f\u3001\u304a\u5143\u6c17\u3067\u3059\u304b\uff1f"]:
            n = normalize.preprocess({"tool": "respond", "body": t})
            self.assertEqual(n["hidden_or_lookalike_characters"], "none")
            self.assertEqual(n["normalized_text"], "same as raw")


class TestSet2(unittest.TestCase):
    def test_sizes_and_groups(self):
        self.assertGreaterEqual(len(v2.T2_ATTACKS), 60)
        self.assertGreaterEqual(len(v2.T2_BENIGN), 40)
        self.assertEqual({c.family for c in v2.T2_ATTACKS}, set(v2.T2_ATTACK_GROUPS))

    def test_attacks_only_stoppable_by_check4(self):
        for c in v2.T2_ATTACKS:
            for chk in (agentguard.check_tool_admission,
                        agentguard.check_scope_containment,
                        agentguard.check_read_only):
                self.assertTrue(chk(c.malicious_action, c.user_task).allowed,
                                f"{c.cid} blocked by {chk.__name__}")

    def test_uncovered_group_has_no_prepass_decoding(self):
        for c in v2.T2_ATTACKS:
            if c.family == v2.G_UNCOV:
                self.assertEqual(
                    normalize.preprocess(c.malicious_action)["decoded_candidates"],
                    "none", c.cid)

    def test_blind_loader(self):
        import json as _j, tempfile as _t
        doc = {"author": "x", "cases": [
            {"id": "a", "label": "attack", "task": {"intent": "translate",
             "allowed_tools": ["respond"], "scope": {"recipients": ["self"]},
             "read_only": True}, "action": {"tool": "respond", "to": "self", "body": "hi"}},
            {"id": "b", "label": "benign", "task": {"intent": "translate",
             "allowed_tools": ["respond"]}, "action": {"tool": "respond", "to": "self", "body": "ok"}}]}
        with _t.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            _j.dump(doc, f)
        cs = v2.load_blind(f.name)
        os.unlink(f.name)
        self.assertEqual([c.family for c in cs], ["Blind attacks", "Blind benign"])
        self.assertEqual(cs[0].malicious_action["body"], "hi")


class RedTeamSet(unittest.TestCase):
    def test_unique_ids_and_sizes(self):
        ids = [c.cid for c in ext.ALL_ATTACKS + ext.BENIGN_HARD]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ext.ADV2_EXT), 40)

    def test_attacks_only_stoppable_by_check4(self):
        for c in ext.ALL_ATTACKS:
            for chk in (agentguard.check_tool_admission,
                        agentguard.check_scope_containment,
                        agentguard.check_read_only):
                self.assertTrue(chk(c.malicious_action, c.user_task).allowed,
                                f"{c.cid} blocked by {chk.__name__}")

    def test_unseen_techniques_only_in_test(self):
        unseen = {"morse", "binary", "nato", "acrostic"}
        dev_t = {c.technique for c in ext.ALL_ATTACKS if c.split == "dev"}
        test_t = {c.technique for c in ext.ALL_ATTACKS if c.split == "test"}
        self.assertFalse(unseen & dev_t)
        self.assertTrue(unseen <= test_t)

    def test_regex_baseline_on_orig_adv2(self):
        """Original ADV-2 attacks defeat the regex (the motivation)."""
        for c in attacks.ADV2:
            self.assertTrue(agentguard.check_payload(c.malicious_action, c.user_task).allowed)


if __name__ == "__main__":
    unittest.main()
