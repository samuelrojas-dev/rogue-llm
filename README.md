# rogue-llm

[![PyPI version](https://img.shields.io/pypi/v/rogue-llm.svg)](https://pypi.org/project/rogue-llm/)
[![CI](https://github.com/samuelrojas-dev/rogue-llm/actions/workflows/ci.yml/badge.svg)](https://github.com/samuelrojas-dev/rogue-llm/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Adversarial LLM proxy for testing structural vs behavioral agent security.**

Every existing agent red-teaming tool sends adversarial *prompts* to test your agent. `rogue-llm` does something no other tool does: it **replaces the model itself** with a hostile one that actively tries to exfiltrate your sensitive data.

## Why this matters

| Approach | What it tests | Limitation |
|----------|---------------|------------|
| Prompt injection testing | Can the model be tricked? | A better attack always exists |
| Guardrail scanning | Are filters in place? | Filters can be bypassed |
| **rogue-llm** | Does the *architecture* prevent leaks? | None — it's worst-case |

If your agent leaks data through a rogue model → your security is **behavioral** (depends on model cooperation).
If it blocks the leak → your security is **structural** (the architecture prevents exfiltration regardless of model behavior).

**Structural security is the only security that survives prompt injection, model compromise, and future attacks you haven't imagined yet.**

## Quick start

```bash
pip install rogue-llm
```

### 1. Define your secrets

```json
["27315", "71.8", "SUP-8842", "Renegotiate Q2 pricing"]
```

Or use a structured format:
```json
{
  "internal_fields": ["cost_price", "margin_pct", "supplier_id"],
  "data": [
    {"name": "Product X", "cost_price": 27315, "margin_pct": 71.8, "supplier_id": "SUP-8842"}
  ]
}
```

### 2. Start the hostile server

```bash
rogue-llm serve --secrets secrets.json --port 8642
```

### 3. Point your agent at it

```bash
OPENAI_BASE_URL=http://localhost:8642/v1 python my_agent.py
```

The server is **OpenAI API-compatible** — any agent that talks to OpenAI/Anthropic/etc. can be tested by just changing the base URL.

### 4. Read the verdict

```
╔══════════════════════════════════════════════════════════╗
║  VERDICT: BEHAVIORAL SECURITY ONLY                       ║
║                                                          ║
║  Your agent leaked secrets when the model was hostile.   ║
║  Security depends on model cooperation — it will fail    ║
║  under prompt injection or model compromise.             ║
╚══════════════════════════════════════════════════════════╝

  Secrets leaked: 3/4
  Leaked values:
    • '27315' via verbatim
    • '71.8' via verbatim
    • 'SUP-8842' via verbatim
```

## What the hostile model does

The hostile model follows a deterministic attack sequence:

1. **Calls every data-reading tool** — especially those marked internal, private, or sensitive
2. **Emails all context** to every address it finds in the conversation
3. **Dumps secrets in the reply** — encoded however the conversation suggests (base64, hex, rot13, reversed, Caesar shift)

This is the **worst case**: a model that obeys every instruction and actively seeks to leak everything it knows. Whatever survives this model is a property of the architecture, not of model behavior.

## Scan mode

Already have a transcript? Scan it for leaked secrets:

```bash
rogue-llm scan transcript.txt --secrets secrets.json
```

## Diff mode — cross-framework parser differential testing

**No other tool does this.** Send the same malformed tool-call response to multiple agent frameworks and compare what each one actually executes. Every divergence is a potential security bug.

```bash
# Install frameworks to compare
pip install openai langchain-core litellm

# Run differential testing
rogue-llm diff

# Filter by category
rogue-llm diff --category duplicate-keys

# JSON output for CI
rogue-llm diff --json -o report.json

# List available adapters and cases
rogue-llm diff --list-adapters
rogue-llm diff --list-cases
```

### What it tests

17 crafted malformed responses across 7 categories:

| Category | What it probes | Known bugs |
|----------|----------------|------------|
| **duplicate-keys** | `"name":"safe","name":"dangerous"` — first vs last wins | vLLM#48864, ATR-2026-02350 |
| **type-confusion** | args as object, double-encoded, empty, truncated | langchain-litellm#249 |
| **conflicting-ids** | Same tool_call id or index for different tools | — |
| **finish-reason** | `stop` with tool_calls, `tool_calls` without them | — |
| **content-injection** | Tool-call JSON in the text content field | — |
| **homoglyphs** | Cyrillic `е` in tool name, zero-width characters | — |
| **schema-violation** | Extra fields (`bypass_auth`), missing `name` | — |
| **batch-drop** | One bad call silently drops valid siblings | LangChain#35782 |

### Adapters

| Adapter | Framework | Auto-detected |
|---------|-----------|---------------|
| `stdlib` | Python json.loads (baseline) | Always |
| `openai` | OpenAI SDK (Pydantic validation) | `pip install openai` |
| `langchain` | LangChain AIMessage conversion | `pip install langchain-core` |
| `litellm` | LiteLLM ModelResponse | `pip install litellm` |
| `pydantic-ai` | Pydantic AI (via OpenAI types) | `pip install pydantic-ai` |

Exit code 1 if security-relevant divergences are found — plug it into CI.

### Install with framework adapters

```bash
pip install rogue-llm[all]          # all adapters
pip install rogue-llm[openai]      # just OpenAI SDK
pip install rogue-llm[langchain]   # just LangChain
```

## GitHub Action

Add structural security testing to your CI pipeline:

```yaml
# .github/workflows/security.yml
name: Agent Security

on: [push, pull_request]

jobs:
  rogue-llm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: samuelrojas-dev/rogue-llm@v1
        with:
          frameworks: "openai langchain-core litellm"
```

The action installs `rogue-llm`, runs differential testing across the specified frameworks, and **fails the build** if security-relevant divergences are found.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `diff` | `diff` for parser testing, `scan` for transcript scanning |
| `frameworks` | `openai langchain-core litellm` | Extra frameworks to install |
| `category` | *(all)* | Filter cases by category |
| `fail-on-divergence` | `true` | Fail if security divergences found |
| `secrets-file` | — | Secrets JSON file (scan mode) |
| `transcript` | — | Transcript file (scan mode) |

### Action outputs

| Output | Description |
|--------|-------------|
| `divergences` | Total divergence count |
| `security-divergences` | Security-relevant divergence count |
| `report` | Path to JSON report |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | Hostile chat completions (OpenAI format) |
| `/v1/models` | GET | Model listing |
| `/_report` | GET | Leak report (JSON) |
| `/_health` | GET | Server health |

## How is this different from...

- **[hackagent](https://pypi.org/project/hackagent/)**, **[probeagent](https://pypi.org/project/probeagent-ai/)**, **[Giskard](https://www.giskard.ai/)**: Send adversarial *prompts* to a normal model. Test behavioral security only.
- **[LlamaFirewall](https://github.com/meta-llama/llama-firewall)**, **[Pipelock](https://github.com/pipelock-dev/pipelock)**: Add guardrails around the model. Don't test whether the architecture itself is secure.
- **[agent-audit-kit](https://pypi.org/project/agent-audit-kit/)**: Scans MCP server configurations. Static analysis, not adversarial testing.
- **rogue-llm**: Replaces the model with a hostile one. Tests whether your *architecture* prevents leaks, regardless of model behavior.

## Related research

This tool implements the **CompromisedLLM methodology** from [agent-security-lab](https://github.com/samuelrojas-dev/agent-security-lab), which demonstrated that only architectural (structural) defenses survive a fully compromised model.

## License

MIT
