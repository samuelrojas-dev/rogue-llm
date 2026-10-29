"""Zero-config security testing wrappers for popular agent frameworks.

Each function takes an agent object (from LangChain, OpenAI, CrewAI, etc.) and
runs it against the hostile model. No configuration needed — just call it.

    from roguellm.frameworks import test_langchain
    result = test_langchain(my_chain, secrets=["cost_27315"])
    assert result.verdict == "STRUCTURAL"

All wrappers return a ScanResults or RogueTest with the verdict.
"""

from __future__ import annotations

from typing import Any, Callable

from .hostile import AttackProfile
from .testing import RogueTest, SecurityScan, ScanResults


def test_agent(
    agent_fn: Callable[[str], Any],
    secrets: list[str],
    profile: AttackProfile = AttackProfile.FULL_ATTACK,
) -> RogueTest:
    """Test any agent function against the hostile model.

    The simplest wrapper: takes a callable that accepts a base_url string.

    Args:
        agent_fn: Function that takes an OpenAI base_url and runs the agent.
        secrets: Sensitive values to test for leakage.
        profile: Attack profile (default: FULL_ATTACK).

    Returns:
        RogueTest with verdict, leaked, report().

    Example::

        def my_agent(base_url):
            client = openai.OpenAI(base_url=base_url, api_key="test")
            client.chat.completions.create(...)

        result = test_agent(my_agent, secrets=["cost_27315"])
        assert result.verdict == "STRUCTURAL"
    """
    test = RogueTest(secrets=secrets, profile=profile)
    with test.start() as server:
        agent_fn(server.base_url)
    return test


def scan_agent(
    agent_fn: Callable[[str], Any],
    secrets: list[str],
    profiles: list[AttackProfile] | None = None,
) -> ScanResults:
    """Run ALL attack profiles against an agent function.

    Args:
        agent_fn: Function that takes an OpenAI base_url.
        secrets: Sensitive values to test.
        profiles: Which profiles to run (default: all 7).

    Returns:
        ScanResults with score (0-100), grade, per-profile breakdown.
    """
    scan = SecurityScan(secrets=secrets, profiles=profiles)
    return scan.run(agent_fn)


def test_langchain(
    chain: Any,
    secrets: list[str],
    input_text: str = "What products do you have? My email is test@example.com",
    profile: AttackProfile = AttackProfile.FULL_ATTACK,
) -> RogueTest:
    """Test a LangChain chain/agent against the hostile model.

    Works with any LangChain Runnable (chains, agents, LCEL pipelines).
    Temporarily patches the chain's LLM to point at the hostile server.

    Args:
        chain: A LangChain Runnable (chain, agent, or LCEL pipeline).
        secrets: Sensitive values to test for leakage.
        input_text: Input to send to the chain.
        profile: Attack profile.

    Example::

        from langchain_openai import ChatOpenAI
        from roguellm.frameworks import test_langchain

        llm = ChatOpenAI(model="gpt-4")
        chain = prompt | llm | parser
        result = test_langchain(chain, secrets=["cost_27315"])
    """
    test = RogueTest(secrets=secrets, profile=profile)
    with test.start() as server:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError:
            raise ImportError(
                "langchain-openai required: pip install langchain-openai"
            )
        # Create a hostile LLM pointing at our server
        hostile_llm = ChatOpenAI(
            model="rogue-hostile-1",
            openai_api_key="rogue-test",  # noqa: S106
            openai_api_base=server.base_url,
            temperature=0,
        )
        # Try to swap the LLM in the chain
        _run_with_patched_llm(chain, hostile_llm, input_text)
    return test


def test_openai(
    agent_fn: Callable[..., Any],
    secrets: list[str],
    profile: AttackProfile = AttackProfile.FULL_ATTACK,
) -> RogueTest:
    """Test an agent that uses the OpenAI SDK.

    Your agent_fn receives an openai.OpenAI client pre-configured to talk
    to the hostile server.

    Args:
        agent_fn: Function that takes an openai.OpenAI client.
        secrets: Sensitive values to test.

    Example::

        def my_agent(client):
            response = client.chat.completions.create(
                model="gpt-4", messages=[...]
            )

        result = test_openai(my_agent, secrets=["cost_27315"])
    """
    test = RogueTest(secrets=secrets, profile=profile)
    with test.start() as server:
        try:
            import openai
        except ImportError:
            raise ImportError("openai required: pip install openai")
        client = openai.OpenAI(
            base_url=server.base_url,
            api_key="rogue-test",
        )
        agent_fn(client)
    return test


def _run_with_patched_llm(chain: Any, hostile_llm: Any, input_text: str):
    """Try to run a LangChain chain with a patched LLM."""
    # Strategy 1: If the chain has a .llm attribute, swap it
    if hasattr(chain, "llm"):
        original = chain.llm
        chain.llm = hostile_llm
        try:
            chain.invoke(input_text)
        finally:
            chain.llm = original
        return

    # Strategy 2: If it's an LCEL pipeline, try invoke with the hostile LLM
    # bound as the first step
    if hasattr(chain, "first") and hasattr(chain.first, "llm"):
        original = chain.first.llm
        chain.first.llm = hostile_llm
        try:
            chain.invoke(input_text)
        finally:
            chain.first.llm = original
        return

    # Strategy 3: Just invoke it as-is (user is responsible for setup)
    chain.invoke(input_text)
