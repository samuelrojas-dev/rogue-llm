"""Differential testing engine.

Feeds every case through every available adapter and compares outcomes.
A divergence is when two adapters produce different tool calls for the same input.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from roguellm.adapters.base import Adapter, ParseResult
from roguellm.cases import Case, ALL_CASES


@dataclass(frozen=True)
class Divergence:
    """A difference in how two adapters parsed the same case."""
    case_id: str
    case_title: str
    category: str
    adapter_a: str
    adapter_b: str
    outcome_a: str
    outcome_b: str
    calls_a: list[tuple[str | None, dict | None]]
    calls_b: list[tuple[str | None, dict | None]]
    notes: str = ""
    cve_refs: list[str] = field(default_factory=list)

    @property
    def security_relevant(self) -> bool:
        """Is this divergence security-relevant?"""
        # Different tool names or different arguments = security relevant
        names_a = {n for n, _ in self.calls_a if n}
        names_b = {n for n, _ in self.calls_b if n}
        if names_a != names_b:
            return True
        # One executes, other rejects = relevant
        if ("error" in self.outcome_a) != ("error" in self.outcome_b):
            return True
        if ("no_calls" in self.outcome_a) != ("no_calls" in self.outcome_b):
            return True
        return False


@dataclass
class CaseResult:
    """Result of running one case through all adapters."""
    case: Case
    results: dict[str, ParseResult]  # adapter_name -> result
    divergences: list[Divergence] = field(default_factory=list)

    @property
    def has_divergence(self) -> bool:
        return len(self.divergences) > 0

    @property
    def security_divergences(self) -> list[Divergence]:
        return [d for d in self.divergences if d.security_relevant]


@dataclass
class DiffReport:
    """Full report of a differential testing run."""
    adapters: list[str]
    case_results: list[CaseResult]

    @property
    def total_cases(self) -> int:
        return len(self.case_results)

    @property
    def total_divergences(self) -> int:
        return sum(len(cr.divergences) for cr in self.case_results)

    @property
    def security_divergences(self) -> int:
        return sum(len(cr.security_divergences) for cr in self.case_results)

    @property
    def divergent_cases(self) -> list[CaseResult]:
        return [cr for cr in self.case_results if cr.has_divergence]

    def to_dict(self) -> dict:
        """Serialize report to dict for JSON output."""
        return {
            "adapters": self.adapters,
            "total_cases": self.total_cases,
            "total_divergences": self.total_divergences,
            "security_divergences": self.security_divergences,
            "cases": [
                {
                    "id": cr.case.id,
                    "title": cr.case.title,
                    "category": cr.case.category,
                    "expected": (
                        "reject" if cr.case.expected == "reject"
                        else [{"name": e.name, "arguments": e.arguments}
                              for e in cr.case.expected]
                    ),
                    "results": {
                        name: {
                            "outcome": r.outcome,
                            "calls": [
                                {"name": c.name, "arguments": c.arguments, "id": c.id}
                                for c in r.calls
                            ],
                            "error": r.error,
                            "warnings": r.warnings,
                        }
                        for name, r in cr.results.items()
                    },
                    "divergences": [
                        {
                            "adapter_a": d.adapter_a,
                            "adapter_b": d.adapter_b,
                            "outcome_a": d.outcome_a,
                            "outcome_b": d.outcome_b,
                            "security_relevant": d.security_relevant,
                        }
                        for d in cr.divergences
                    ],
                }
                for cr in self.case_results
            ],
        }


def _find_divergences(case: Case, results: dict[str, ParseResult]) -> list[Divergence]:
    """Compare all pairs of adapters for divergences on a single case."""
    divergences = []
    adapter_names = sorted(results.keys())

    for i, name_a in enumerate(adapter_names):
        for name_b in adapter_names[i + 1:]:
            ra = results[name_a]
            rb = results[name_b]

            calls_a = ra.call_summary()
            calls_b = rb.call_summary()

            # Compare outcomes
            if calls_a != calls_b or ra.outcome != rb.outcome:
                divergences.append(Divergence(
                    case_id=case.id,
                    case_title=case.title,
                    category=case.category,
                    adapter_a=name_a,
                    adapter_b=name_b,
                    outcome_a=ra.outcome,
                    outcome_b=rb.outcome,
                    calls_a=calls_a,
                    calls_b=calls_b,
                    notes=case.notes,
                    cve_refs=list(case.cve_refs),
                ))

    return divergences


def run_diff(
    adapters: list[Adapter],
    cases: list[Case] | None = None,
    category: str | None = None,
) -> DiffReport:
    """Run all cases through all adapters and find divergences.

    Args:
        adapters: list of Adapter instances to test
        cases: specific cases to run (default: all)
        category: filter cases by category
    """
    if cases is None:
        from roguellm.cases import get_cases
        cases = get_cases(category)

    case_results = []
    for case in cases:
        results: dict[str, ParseResult] = {}
        for adapter in adapters:
            results[adapter.name] = adapter.parse(case.raw)

        divergences = _find_divergences(case, results)
        case_results.append(CaseResult(
            case=case,
            results=results,
            divergences=divergences,
        ))

    return DiffReport(
        adapters=[a.name for a in adapters],
        case_results=case_results,
    )


def format_report(report: DiffReport, verbose: bool = False) -> str:
    """Format a diff report as a human-readable string."""
    lines = []
    lines.append("=" * 70)
    lines.append("  ROGUE-LLM DIFF: Tool Call Parser Differential Testing")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Adapters tested: {', '.join(report.adapters)}")
    lines.append(f"  Cases run:       {report.total_cases}")
    lines.append(f"  Divergences:     {report.total_divergences}")
    lines.append(f"  Security-relevant: {report.security_divergences}")
    lines.append("")

    if not report.divergent_cases:
        lines.append("  No divergences found. All adapters agree on every case.")
        lines.append("")
        return "\n".join(lines)

    lines.append("-" * 70)
    lines.append("  DIVERGENCES")
    lines.append("-" * 70)

    for cr in report.divergent_cases:
        lines.append("")
        sec_divs = cr.security_divergences
        marker = " [SECURITY]" if sec_divs else ""
        lines.append(f"  Case: {cr.case.id} — {cr.case.title}{marker}")
        lines.append(f"  Category: {cr.case.category}")
        if cr.case.cve_refs:
            lines.append(f"  Refs: {', '.join(cr.case.cve_refs)}")
        lines.append("")

        for name, result in sorted(cr.results.items()):
            if result.error:
                lines.append(f"    {name:20s} → ERROR: {result.error[:60]}")
            elif not result.calls:
                lines.append(f"    {name:20s} → no calls")
            else:
                for c in result.calls:
                    n, a = c.normalized()
                    args_str = json.dumps(a) if a else "(none)"
                    lines.append(f"    {name:20s} → {n}({args_str})")

        if cr.case.notes and verbose:
            lines.append(f"    Notes: {cr.case.notes}")

    lines.append("")
    lines.append("=" * 70)

    # Summary matrix
    lines.append("")
    lines.append("  DIVERGENCE MATRIX")
    lines.append("")

    # Header
    names = report.adapters
    col_w = max(len(n) for n in names) + 2
    header = " " * (col_w + 2)
    for n in names:
        header += f"{n:>{col_w}}"
    lines.append(header)

    for i, na in enumerate(names):
        row = f"  {na:<{col_w}}"
        for j, nb in enumerate(names):
            if j <= i:
                row += f"{'·':>{col_w}}"
            else:
                # Count divergences between this pair
                count = 0
                sec_count = 0
                for cr in report.case_results:
                    for d in cr.divergences:
                        if {d.adapter_a, d.adapter_b} == {na, nb}:
                            count += 1
                            if d.security_relevant:
                                sec_count += 1
                if count == 0:
                    row += f"{'0':>{col_w}}"
                elif sec_count > 0:
                    row += f"{f'{count}({sec_count}!)':>{col_w}}"
                else:
                    row += f"{str(count):>{col_w}}"
        lines.append(row)

    lines.append("")
    lines.append("  (N) = total divergences, (M!) = security-relevant")
    lines.append("")

    return "\n".join(lines)
