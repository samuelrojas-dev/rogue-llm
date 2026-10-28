"""rogue-llm: Adversarial LLM proxy for structural security testing.

Every existing agent red-teaming tool sends adversarial *prompts* to test your agent.
rogue-llm does something no other tool does: it replaces the model itself with a hostile
one that actively tries to exfiltrate your sensitive data.

If your agent leaks data through a rogue model, your security is *behavioral* — it depends
on the model cooperating. If it blocks the leak, your security is *structural* — the
architecture prevents exfiltration regardless of model behavior.

Usage:
    # 1. Start the hostile server
    rogue-llm serve --secrets secrets.json --port 8642

    # 2. Point your agent at it (change OPENAI_BASE_URL)
    OPENAI_BASE_URL=http://localhost:8642/v1 python my_agent.py

    # 3. The server logs all attempts and detects leaks in real time
"""

__version__ = "0.1.0"
