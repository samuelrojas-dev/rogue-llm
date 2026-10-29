"""Tests for the differential testing engine.

All offline — only uses the stdlib adapter (always available).
Tests the case catalog, diff engine, report formatting, and CLI.
"""

import json

import pytest

from roguellm.cases import ALL_CASES, Case, ExpectedCall, get_cases, CATEGORIES
from roguellm.adapters.base import ParsedCall, ParseResult, Adapter
from roguellm.adapters.stdlib_adapter import StdlibAdapter
from roguellm.diff import run_diff, format_report, Divergence


# ── Case catalog ────────────────────────────────────────────────

class TestCaseCatalog:

    def test_all_cases_have_unique_ids(self):
        ids = [c.id for c in ALL_CASES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[i for i in ids if ids.count(i) > 1]}"

    def test_all_cases_have_valid_category(self):
        for c in ALL_CASES:
            assert c.category, f"Case {c.id} has no category"

    def test_all_cases_have_title(self):
        for c in ALL_CASES:
            assert c.title, f"Case {c.id} has no title"

    def test_all_cases_have_valid_raw_json(self):
        """The raw field must be parseable JSON (duplicate keys are fine — json.loads handles them)."""
        for c in ALL_CASES:
            try:
                data = json.loads(c.raw)
                assert "choices" in data, f"Case {c.id}: no 'choices' in response"
            except json.JSONDecodeError:
                pytest.fail(f"Case {c.id}: raw is not valid JSON")

    def test_all_cases_have_expected(self):
        for c in ALL_CASES:
            assert c.expected is not None, f"Case {c.id} has no expected"
            if c.expected != "reject":
                assert isinstance(c.expected, list), \
                    f"Case {c.id}: expected must be 'reject' or list of ExpectedCall"

    def test_get_cases_filters_by_category(self):
        for cat in CATEGORIES:
            cases = get_cases(cat)
            assert len(cases) > 0, f"No cases for category {cat}"
            assert all(c.category == cat for c in cases)

    def test_get_cases_returns_all(self):
        assert get_cases() == ALL_CASES

    def test_minimum_case_count(self):
        assert len(ALL_CASES) >= 15, "Need a decent number of test cases"


# ── Stdlib adapter ──────────────────────────────────────────────

class TestStdlibAdapter:

    def setup_method(self):
        self.adapter = StdlibAdapter()

    def test_is_always_available(self):
        assert self.adapter.available()

    def test_parses_normal_tool_call(self):
        raw = json.dumps({
            "id": "chatcmpl-1", "object": "chat.completion",
            "created": 1700000000, "model": "test",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {"name": "search", "arguments": '{"q":"test"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        })
        result = self.adapter.parse(raw)
        assert result.error is None
        assert len(result.calls) == 1
        assert result.calls[0].name == "search"
        assert result.calls[0].arguments == {"q": "test"}

    def test_handles_invalid_json(self):
        result = self.adapter.parse("not json")
        assert result.error is not None
        assert "JSONDecodeError" in result.error

    def test_handles_no_choices(self):
        raw = json.dumps({"choices": []})
        result = self.adapter.parse(raw)
        assert result.calls == []

    def test_handles_no_tool_calls(self):
        raw = json.dumps({"choices": [{"message": {"role": "assistant", "content": "hi"}}]})
        result = self.adapter.parse(raw)
        assert result.calls == []

    def test_duplicate_name_keeps_last(self):
        """json.loads keeps the last duplicate key — this is the baseline behavior."""
        result = self.adapter.parse(ALL_CASES[0].raw)  # dup-name-01
        # json.loads gives last key, so 'dangerous_tool' wins
        assert len(result.calls) == 1
        assert result.calls[0].name == "dangerous_tool"

    def test_args_as_object(self):
        """stdlib adapter should handle arguments as dict (not string)."""
        from roguellm.cases import ARGS_AS_OBJECT
        result = self.adapter.parse(ARGS_AS_OBJECT.raw)
        assert len(result.calls) == 1
        assert result.calls[0].arguments == {"query": "test"}

    def test_empty_args(self):
        from roguellm.cases import ARGS_EMPTY_STRING
        result = self.adapter.parse(ARGS_EMPTY_STRING.raw)
        assert len(result.calls) == 1


# ── Fake adapter for diff testing ───────────────────────────────

class FakeRejectAdapter(Adapter):
    """Always returns an error — simulates a strict parser."""
    name = "fake-strict"
    version = "1.0"

    def parse(self, raw_json: str) -> ParseResult:
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")
        msg = data["choices"][0]["message"]
        tool_calls = msg.get("tool_calls", [])

        # Reject anything with duplicate keys (we can't detect this from parsed JSON,
        # but we can reject based on other heuristics)
        if not tool_calls:
            return ParseResult(adapter=self.name, calls=[])

        # Accept only well-formed calls
        calls = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name")
            raw_args = fn.get("arguments", "")
            if not name:
                return ParseResult(adapter=self.name, calls=[], error="Missing function name")
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args else {}
                except json.JSONDecodeError:
                    return ParseResult(adapter=self.name, calls=[], error="Bad arguments JSON")
            else:
                # Reject non-string arguments
                return ParseResult(adapter=self.name, calls=[], error="Arguments must be a string")
            calls.append(ParsedCall(name=name, arguments=args, id=tc.get("id")))

        return ParseResult(adapter=self.name, calls=calls)


class FakePermissiveAdapter(Adapter):
    """Accepts everything — simulates a permissive parser."""
    name = "fake-permissive"
    version = "1.0"

    def parse(self, raw_json: str) -> ParseResult:
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")
        msg = data["choices"][0]["message"]
        tool_calls = msg.get("tool_calls", [])

        calls = []
        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name") or fn.get("Name") or "unknown"
            raw_args = fn.get("arguments", "")
            if isinstance(raw_args, dict):
                args = raw_args
            elif isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args else {}
                except json.JSONDecodeError:
                    args = {}  # auto-repair: bad JSON → empty dict
            else:
                args = {}
            calls.append(ParsedCall(name=name, arguments=args, id=tc.get("id")))

        return ParseResult(adapter=self.name, calls=calls)


# ── Diff engine ─────────────────────────────────────────────────

class TestDiffEngine:

    def test_no_divergence_with_single_adapter(self):
        """One adapter can't diverge from itself."""
        adapters = [StdlibAdapter()]
        report = run_diff(adapters)
        # With 1 adapter there are no pairs to compare
        assert report.total_divergences == 0

    def test_finds_divergences_between_strict_and_permissive(self):
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters)
        # These must disagree on type-confusion and schema-violation cases
        assert report.total_divergences > 0

    def test_args_object_diverges(self):
        """Strict rejects object args, permissive accepts them."""
        from roguellm.cases import ARGS_AS_OBJECT
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters, cases=[ARGS_AS_OBJECT])
        assert report.total_divergences == 1

    def test_missing_name_diverges(self):
        from roguellm.cases import MISSING_FUNCTION_NAME
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters, cases=[MISSING_FUNCTION_NAME])
        assert report.total_divergences == 1
        # Should be security relevant (one executes, other rejects)
        assert report.security_divergences >= 1

    def test_security_relevant_detection(self):
        d = Divergence(
            case_id="test", case_title="test", category="test",
            adapter_a="a", adapter_b="b",
            outcome_a="1 calls", outcome_b="no_calls",
            calls_a=[("dangerous_tool", {"q": "x"})],
            calls_b=[],
        )
        assert d.security_relevant

    def test_non_security_divergence(self):
        d = Divergence(
            case_id="test", case_title="test", category="test",
            adapter_a="a", adapter_b="b",
            outcome_a="1 calls", outcome_b="1 calls",
            calls_a=[("search", {"q": "test"})],
            calls_b=[("search", {"q": "test", "extra": True})],
        )
        # Same tool name, just different args — could be security relevant
        # but our heuristic checks names first
        assert not d.security_relevant

    def test_category_filter(self):
        adapters = [StdlibAdapter()]
        report = run_diff(adapters, category="duplicate-keys")
        assert all(cr.case.category == "duplicate-keys" for cr in report.case_results)
        assert len(report.case_results) >= 2


# ── Report formatting ──────────────────────────────────────────

class TestReportFormatting:

    def test_format_no_divergences(self):
        adapters = [StdlibAdapter()]
        report = run_diff(adapters)
        text = format_report(report)
        assert "ROGUE-LLM DIFF" in text
        assert "No divergences found" in text

    def test_format_with_divergences(self):
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters)
        text = format_report(report)
        assert "DIVERGENCES" in text
        assert "DIVERGENCE MATRIX" in text

    def test_json_report(self):
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters)
        data = report.to_dict()
        assert "adapters" in data
        assert "cases" in data
        assert data["total_cases"] == len(ALL_CASES)
        assert data["total_divergences"] > 0

    def test_verbose_shows_notes(self):
        adapters = [FakeRejectAdapter(), FakePermissiveAdapter()]
        report = run_diff(adapters)
        text = format_report(report, verbose=True)
        assert "Notes:" in text


# ── ParsedCall normalization ────────────────────────────────────

class TestParsedCall:

    def test_normalize_dict_args(self):
        c = ParsedCall(name="search", arguments={"q": "test"})
        assert c.normalized() == ("search", {"q": "test"})

    def test_normalize_string_args(self):
        c = ParsedCall(name="search", arguments='{"q":"test"}')
        assert c.normalized() == ("search", {"q": "test"})

    def test_normalize_bad_string_args(self):
        c = ParsedCall(name="search", arguments="not json")
        assert c.normalized() == ("search", None)

    def test_normalize_none_args(self):
        c = ParsedCall(name="search", arguments=None)
        assert c.normalized() == ("search", None)
