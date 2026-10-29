# Your Agent Framework Disagrees With Itself: Tool Call Parsing Divergences Across Python LLM Frameworks

**Samuel Rojas · October 2026**

## TL;DR

We sent 17 malformed OpenAI-format tool call responses to 5 Python LLM frameworks and found **34 parsing divergences, 20 of which are security-relevant**. The same hostile model response produces different tool executions depending on which framework your agent uses. This means your security testing is only valid for the specific framework you tested on.

## The problem nobody talks about

Everyone testing LLM agents focuses on prompt injection: can you trick the *model* into doing something bad? But there's a layer below the model that nobody audits — the **tool call parser**.

When a model returns a response saying "call function X with arguments Y," your framework has to parse that response and decide what to actually execute. The OpenAI chat completion format is the de facto standard, but the spec has gaps. What happens when:

- The `arguments` field is a dict instead of a string?
- The JSON is truncated mid-value?
- Two tool calls share the same ID?
- The function `name` key appears twice with different values?

We built [rogue-llm](https://github.com/samuelrojas-dev/rogue-llm) to answer these questions systematically.

## Methodology

**rogue-llm diff** sends identical malformed responses to multiple framework parsers and flags every disagreement. Each test case is a raw JSON string representing an OpenAI-format chat completion response with a specific malformation.

Frameworks tested:

| Framework | Version | Parser type |
|-----------|---------|-------------|
| Python `json` (stdlib) | 3.11+ | Baseline — `json.loads` + manual extraction |
| OpenAI SDK | 1.41.0 | Pydantic model validation (`ChatCompletion`) |
| LangChain | 0.3.47 | `AIMessage` conversion via `convert_openai_messages` |
| LiteLLM | 1.106.6 | `ModelResponse` wrapper with JSON repair |
| Pydantic AI | 2.63.0 | OpenAI SDK's `ChatCompletion` validation |

17 test cases across 7 categories:

| Category | Cases | What it probes |
|----------|-------|----------------|
| duplicate-keys | 3 | First-vs-last key wins, case-variant keys |
| type-confusion | 4 | Args as object/string/empty/truncated/double-encoded |
| conflicting-ids | 2 | Same tool_call ID or index for different tools |
| finish-reason | 2 | Contradictory finish_reason vs. actual content |
| content-injection | 1 | Tool-call JSON embedded in text content |
| homoglyphs | 2 | Cyrillic homoglyphs, zero-width chars in tool names |
| schema-violation | 2 | Extra fields (`bypass_auth`), missing `name` |
| batch-drop | 1 | One bad call drops valid siblings |

## Results

### The divergence matrix

```
                 stdlib-json   openai-sdk    langchain      litellm  pydantic-ai
  stdlib-json              ·        2(2!)        6(2!)            1        2(2!)
  openai-sdk               ·            ·        6(4!)        3(2!)            0
  langchain                ·            ·            ·        5(2!)        6(4!)
  litellm                  ·            ·            ·            ·        3(2!)
```

Numbers show total divergences; `(N!)` marks security-relevant ones.

**Key observation**: OpenAI SDK and Pydantic AI agree on every case (0 divergences) — because Pydantic AI delegates to the same `ChatCompletion` Pydantic model. LangChain diverges from *everything else*, which is expected given its completely independent parsing path.

### Finding 1: LangChain drops truncated tool calls entirely

**Case**: `type-args-truncated-01` — arguments JSON is `{"to":"attacker@evil.com","body":"secre` (truncated)

| Framework | Result |
|-----------|--------|
| stdlib, OpenAI SDK, LiteLLM, Pydantic AI | **1 call** — `send_email` with unparseable args |
| LangChain | **0 calls** — silently dropped |

**Security impact**: If your agent uses LangChain and you're testing with another framework's parser, you won't catch the silent drop. An attacker who controls the model output could use truncation to selectively suppress tool calls they don't want executed, while keeping the ones that exfiltrate data.

This confirms [langchain-litellm#249](https://github.com/langchain-ai/langchain/issues/249): LangChain's `convert_openai_messages` drops tool calls when argument parsing fails, instead of preserving them with raw arguments.

### Finding 2: Three-way split on `arguments` as object

**Case**: `type-args-object-01` — `"arguments": {"query": "test"}` (dict instead of string)

| Framework | Result |
|-----------|--------|
| stdlib, LiteLLM | **Accept** — `search({"query": "test"})` |
| LangChain | **Accept with data loss** — `search({})` (empty args!) |
| OpenAI SDK, Pydantic AI | **Reject** — Pydantic `ValidationError` |

**Security impact**: A hostile model that sends arguments as a dict instead of a string gets three different behaviors. LangChain's is arguably worst — it *executes the tool* but with **empty arguments**, which could bypass validation that depends on specific argument values.

### Finding 3: Missing function name — four different answers

**Case**: `missing-name-01` — function object has no `name` key

| Framework | Result |
|-----------|--------|
| stdlib, LiteLLM | `None({"q": "test"})` — name is `None`, call preserved |
| LangChain | `""({"q": "test"})` — name is empty string, call preserved |
| OpenAI SDK, Pydantic AI | **Reject** — `ValidationError` |

**Security impact**: A nameless function call that reaches a tool dispatcher with `None` or `""` as the name could match a fallback or default tool — or crash the dispatcher in a way that leaks the error message to the attacker.

### Finding 4: LangChain correctly isolates batch corruption

**Case**: `batch-drop-01` — three tool calls, middle one has invalid JSON arguments

| Framework | Result |
|-----------|--------|
| stdlib, OpenAI SDK, LiteLLM, Pydantic AI | **3 calls** — all three preserved, bad args kept as-is |
| LangChain | **2 calls** — only `safe_tool` and `another_safe_tool` |

Interestingly, this is a case where LangChain's behavior is **more secure**: it drops the malformed call but preserves the valid siblings. The other frameworks preserve a call with invalid arguments, which could crash the tool executor or cause unexpected behavior.

This is related to [LangChain#35782](https://github.com/langchain-ai/langchain/issues/35782) — previous versions dropped *all* calls when *one* was malformed. The current behavior (drop only the bad one) is an improvement, though still different from every other framework.

### Finding 5: Double-encoded arguments — silent unwrapping

**Case**: `type-args-double-encoded-01` — arguments is a JSON string containing another JSON string

| Framework | Result |
|-----------|--------|
| stdlib, OpenAI SDK, LiteLLM, Pydantic AI | `search("\"{ ... }\"")` — parse the outer layer, args is a string |
| LangChain | `search({})` — empty args |

No framework rejects double-encoded arguments. stdlib/OpenAI/LiteLLM/Pydantic AI all parse one layer and end up with a string value. LangChain loses the data entirely. If any framework did a double-unwrap (parse, check if result is string, parse again), an attacker could hide a payload inside double encoding that only surfaces on specific frameworks.

## What this means for agent security

### 1. Framework-specific security testing is not transferable

If you test your agent's structural security using stdlib JSON parsing (the common baseline), your results say nothing about how it behaves under LangChain, and vice versa. **20 of 34 divergences are security-relevant** — meaning one framework executes a tool call that another rejects or drops.

### 2. Migration breaks security assumptions

Switching from one framework to another changes your security surface without changing your code. A tool call that was safely rejected by OpenAI SDK's Pydantic validation will silently execute under stdlib or LiteLLM.

### 3. The "permissive parsing" problem

Most frameworks err on the side of accepting malformed inputs rather than rejecting them. Only OpenAI SDK and Pydantic AI (which uses the same validation) consistently reject schema violations. This permissiveness means a hostile model has more room to exploit parser behavior.

### 4. LangChain is an outlier — sometimes safer, sometimes more dangerous

LangChain disagrees with every other framework on 5-6 cases. In batch-drop, it's *more* secure (drops only the bad call). In truncated args, it's *less* secure (silently drops the entire call). This inconsistency makes it the hardest framework to reason about from a security perspective.

## Recommendations

1. **Test with your actual framework.** Don't assume stdlib JSON parsing behavior applies to your production stack.

2. **Add strict validation after parsing.** Regardless of framework, validate tool names against your allowed set, check argument schemas, and reject calls with missing or empty names.

3. **Treat parser disagreements as bugs.** If your agent can run under multiple frameworks (common with LiteLLM as a router), the divergences *between* frameworks are your attack surface.

4. **Use `rogue-llm diff` in CI.** The tool exits with code 1 when security-relevant divergences are found. As frameworks update, new divergences can appear silently.

```bash
pip install rogue-llm openai langchain-core litellm
rogue-llm diff  # exits 1 if security divergences found
```

## Try it yourself

```bash
pip install rogue-llm
rogue-llm diff --list-cases    # see all 17 test cases
rogue-llm diff --list-adapters # see available adapters
rogue-llm diff                 # run the full matrix
rogue-llm diff --json -o report.json  # machine-readable output
```

The tool auto-detects installed frameworks. Install more to widen the comparison.

Full source and methodology: [github.com/samuelrojas-dev/rogue-llm](https://github.com/samuelrojas-dev/rogue-llm)

## Known upstream issues

| Issue | Framework | Status |
|-------|-----------|--------|
| [vLLM#48864](https://github.com/vllm-project/vllm/issues/48864) | vLLM | First-vs-last key divergence in streaming vs non-streaming |
| [LangChain#35782](https://github.com/langchain-ai/langchain/issues/35782) | LangChain | Batch drop behavior (improved but still divergent) |
| [langchain-litellm#249](https://github.com/langchain-ai/langchain/issues/249) | LangChain/LiteLLM | Truncated args → empty dict or dropped call |
| [ATR-2026-02350](https://github.com/samuelrojas-dev/agent-security-lab) | Multiple | Case-variant duplicate keys bypass |

---

*This research was conducted using the [CompromisedLLM methodology](https://github.com/samuelrojas-dev/agent-security-lab) — the model itself is the adversary, and structural security is the only kind that survives.*
