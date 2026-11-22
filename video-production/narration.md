# AgentGuard-LLM narration

Extracted from the existing speaker notes. Presenter cues are omitted from the spoken text.

## 1. cover

Hi everyone, we're Aditya, Gopika, Meera and Sreeranj, and this is AgentGuard-LLM. In one line: we took a defence for AI agents, replaced its weakest part with a language model that runs on a laptop, and then spent most of our time trying to break it. The honest result is a trade-off, and we'll show you the numbers.

## 2. anatomy

AI agents read content they don't control: web pages, emails, documents. Then they use tools, like sending an email. A prompt injection hides instructions in that content to hijack the agent. AgentGuard doesn't try to stop the agent from being fooled. It checks what the agent is about to do, just before the tool runs. There are four checks. One: is this tool allowed for this task? Two: is the recipient, repository or file inside the allowed scope? Three: if the task is read-only, is it trying something with side effects? Those three are fixed rules, instant and cheap. Check four asks: is the content of this message what the task would produce? It is the only check that reads the payload, so it is the only one that can stop a malicious message sent through an allowed tool to an allowed recipient. And the guard never sees the untrusted document, so the document can't talk to it directly.

## 3. weakspot

In the original project, check four was a regex: six patterns such as API key, password and bearer token, plus a list of bad host names. It never looks at the task. So if an attacker spaces out the letters, base64-encodes the secret, or writes it as character codes, it walks straight past. In the original report, all five obfuscation attacks got through. That is the gap our project closes. Now, let's look at how we addressed this weakness.

## 4. proposal

We replaced the regex with a language model, llama 3.1 8B through Ollama. It runs on the laptop, so nothing leaves the machine and there's no API key. It gets two inputs: the pinned description of the task, and the proposed tool call. It answers in a fixed format, a short analysis and then a verdict, ALLOW or BLOCK. Four design rules. It never sees the retrieved document. It fails closed: a timeout, garbled output or any error counts as BLOCK. A strict parser: only an exact ALLOW counts. And it's replayable: fixed seed and saved responses, so anyone can reproduce our numbers offline.

## 5. prepass

One more piece. Small models can't reliably decode base64 or notice an invisible character, so we added a deterministic helper. It only gives evidence: it decodes what can be decoded mechanically and flags look-alike or zero-width characters. It has no secret patterns and it never decides. The model still makes the call.

## 6. demo

First case: a secret hidden as an encoded blob in the reply to a PDF-summary task. The regex step says allow, it has no keyword to match. The model step blocks it: an opaque string has no business in a summary. The model time on screen is from the original recorded calls. Second case: the payload tries to talk to the guard, claiming a verdict of ALLOW. Using a language model adds that attack surface, so we tested it. The guard blocks it. Next, let's see how the guard performs across the full evaluation.

**Production cue** Switch to the terminal on slide 6. Hold on the blindspot verdict, advance to guard-attack, then return to the deck for slide 7.

## 7. method

Anyone can show two cases working, so here's how we tested properly. We wrote four test sets. One was used to tune the prompt. The other three, TEST, TEST2 and TEST3, were written after the relevant prompt was frozen. They contain encodings and ciphers, secrets in plain sentences, secrets disguised as reference IDs, attacks aimed at the guard itself, and hard harmless text like Hindi, hashes and emoji to measure false alarms. One rule: a set that shaped a prompt is never called held out for it. Every run is logged with hashes, and every rate has a 95 percent confidence interval.

## 8. headline

The headline. Pooled over the three held-out sets, 139 attacks. The old regex lets 134 of them through, 96 percent. The strict LLM guard lets 16 through, 12 percent. The confidence intervals don't overlap: 92 to 98 percent against 7 to 18. Same frozen prompt, three independently written sets, similar result each time. This is the one-shot picture: each attack is tried once, with no feedback.

## 9. fpcost

It has a cost. On 82 harmless held-out payloads the regex wrongly blocks 2. The strict LLM guard wrongly blocks 10, about 12 percent. It gets suspicious of non-Latin scripts, hashes and anything that looks encoded, even a legitimate translation. A wrongly blocked call costs a confirmation click. A leaked key can't be taken back.

## 10. tradeoff

We tried to remove the false alarms. We built three relaxed versions: one with the evidence helper, one with a relaxed prompt, and one tuned further. All reached about zero false alarms, and all let 25 to 42 percent of attacks through. Within what prompt changes can do on an 8-billion-parameter model, that's a security versus usability dial, not a free win. That's why we ship the strict version as the default. Now, let's look at where the strict guard still fails.

## 11. fails

Breaking the strict guard's misses down by type. It's very good at encodings, even ones it can't decode, because an opaque string tacked onto a normal sentence looks wrong. It stops every attack aimed at the guard: 0 of 14 get through. It's weakest in two places: secrets in plain prose, 4 of 20 get through, and secrets labelled as a commit hash or reference ID, 8 of 14. The guard can't know what the document contained, so a secret dressed as an identifier looks fine.

## 12. adaptive

Fixed attack lists only show that those attacks fail. So we built an adaptive attacker. It sees ALLOW or BLOCK, searches 28 encoders and 8 wrappers, and has 30 tries per target, with a check that every payload really contains the secret. Result: against the regex it broke 8 of 8 targets, usually on the first try. Against our strict guard, 7 of 8, after about three tries. So the guard stops one-shot attacks well, but it does not stop a determined attacker who can probe it. In real life an injected document rarely sees the verdict, so the earlier numbers are the realistic one-shot figure, but you shouldn't rely on this guard alone.

## 13. limits

What these results don't prove. The test sets are small, hence the intervals. The agent is simulated, not a live one. One person wrote both the guard and most of the tests; blind cases from teammates are the best next step. And an 8B model is brittle: in one tuning round, adding an instruction made things worse, and we reverted it and wrote that down.

## 14. takeaways

Three things to remember. One: a local language model cut one-shot leaks from 96 percent to 12 percent against the regex it replaces. Two: it's a trade-off: strict means 12 percent false alarms, relaxing it leaks 25 to 42 percent. Three: it doesn't stop a probing attacker, so use it as one layer in a defence, alongside allowlists and secret detection, not as the wall.

## 15. questions

Everything is reproducible offline from the saved model answers, and it's all in our public repository, sree0018/agentguard-llm. Thank you, we're happy to take questions.
