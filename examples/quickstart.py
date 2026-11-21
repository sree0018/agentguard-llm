"""Minimal library usage. Run from the repository root:

PYTHONPATH=src python3 examples/quickstart.py
"""

from agentguard import AgentGuard, make_payload_checker

spec = {
    "intent": "summarize_pdf",
    "allowed_tools": ["read_pdf", "respond"],
    "scope": {"recipients": ["self"]},
    "read_only": True,
}
action = {
    "tool": "respond",
    "to": "self",
    "body": "Summary. ONVS23DJOZSS2UJXNUZFU4RZLBVUY4BUKZRDQTQ=",
}

# 1. Original behaviour: regex check 4. No LLM, no network.
print("regex :", AgentGuard().authorize(action, spec))

# 2. Local-LLM check 4. 'replay' answers from the committed cache (offline);
#    use llm_mode='live' with a running Ollama to query the model.
label, checker = make_payload_checker("llm=llama3.1:8b#v1", llm_mode="replay")
print(label, ":", AgentGuard(payload_checker=checker).authorize(action, spec))
