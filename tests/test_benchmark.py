"""Tests for the security benchmark module."""

import json

import pytest

from roguellm.benchmark import (
    SecurityBenchmark, BenchmarkResults, ScenarioResult,
    BenchmarkScenario, SCENARIOS,
)
from roguellm.hostile import AttackProfile


class TestSecurityBenchmark:
    """SecurityBenchmark runs scenarios and produces scores."""

    def test_runs_all_scenarios(self):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.ENCODING_EVASION],
            scenarios=SCENARIOS[:2],
        )
        results = bench.run()
        assert len(results.scenario_results) == 2
        assert 0 <= results.overall_score <= 100

    def test_produces_grade(self):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.STEALTH],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        assert results.overall_grade in ("A+", "A", "B", "C", "D", "F")

    def test_summary(self):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.ENCODING_EVASION],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        summary = results.summary()
        assert "Security Benchmark:" in summary
        assert "Overall Verdict:" in summary

    def test_to_dict(self):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.STEALTH],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        d = results.to_dict()
        assert "overall_score" in d
        assert "overall_grade" in d
        assert "scenarios" in d
        assert len(d["scenarios"]) == 1

    def test_save_json(self, tmp_path):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.ENCODING_EVASION],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        out = tmp_path / "bench.json"
        results.save_json(str(out))
        data = json.loads(out.read_text())
        assert data["overall_score"] >= 0

    def test_save_badge(self, tmp_path):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.ENCODING_EVASION],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        badge = tmp_path / "badge.svg"
        results.save_badge(str(badge))
        svg = badge.read_text()
        assert "<svg" in svg
        assert "security" in svg

    def test_save_badge_custom_label(self, tmp_path):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.STEALTH],
            scenarios=SCENARIOS[:1],
        )
        results = bench.run()
        badge = tmp_path / "badge.svg"
        results.save_badge(str(badge), label="my-agent")
        svg = badge.read_text()
        assert "my-agent" in svg

    def test_on_scenario_callback(self):
        bench = SecurityBenchmark(
            profiles=[AttackProfile.ENCODING_EVASION],
            scenarios=SCENARIOS[:2],
        )
        called = []
        bench.run(on_scenario=lambda s: called.append(s.id))
        assert len(called) == 2

    def test_empty_results(self):
        results = BenchmarkResults(
            scenario_results=[], secrets=["x"], profiles_run=0,
        )
        assert results.overall_score == 0
        assert results.overall_verdict == "NO_DATA"


class TestBenchmarkCLI:
    """The benchmark CLI command."""

    def test_benchmark_runs(self, tmp_path):
        import subprocess
        json_out = tmp_path / "bench.json"
        badge_out = tmp_path / "badge.svg"

        result = subprocess.run(
            ["python", "-m", "roguellm.cli", "benchmark",
             "--profiles", "encoding_evasion",
             "--scenarios", "no_tools",
             "--output", str(json_out),
             "--badge", str(badge_out)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Security Benchmark:" in result.stdout

        data = json.loads(json_out.read_text())
        assert "overall_score" in data

        svg = badge_out.read_text()
        assert "<svg" in svg
