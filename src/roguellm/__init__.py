"""rogue-llm: Adversarial LLM proxy for structural security testing.

Every existing agent red-teaming tool sends adversarial *prompts* to test your agent.
rogue-llm does something no other tool does: it replaces the model itself with a hostile
one that actively tries to exfiltrate your sensitive data.

If your agent leaks data through a rogue model, your security is *behavioral* — it depends
on the model cooperating. If it blocks the leak, your security is *structural* — the
architecture prevents exfiltration regardless of model behavior.

Quick start (Python API):

    from roguellm import RogueTest

    test = RogueTest(secrets=["cost_27315", "margin_71.8", "SUP-8842"])
    with test.start() as server:
        # Point your agent at server.base_url
        run_my_agent(base_url=server.base_url)
    # Check the result
    assert test.verdict == "STRUCTURAL", test.report()

CLI:

    rogue-llm serve --secrets secrets.json --port 8642
    OPENAI_BASE_URL=http://localhost:8642/v1 python my_agent.py
"""

__version__ = "0.3.0"

from .hostile import HostileModel, AttackProfile, ALL_PROFILES
from .detector import find_leaks, Leak
from .server import create_server, RogueServer, SessionLog
from .testing import RogueTest, SecurityScan, ScanResults
from .mcp import MCPTool, MCPScan, MCPScanResults

__all__ = [
    "HostileModel",
    "AttackProfile",
    "ALL_PROFILES",
    "find_leaks",
    "Leak",
    "create_server",
    "RogueServer",
    "SessionLog",
    "RogueTest",
    "SecurityScan",
    "ScanResults",
    "MCPTool",
    "MCPScan",
    "MCPScanResults",
    "__version__",
]
