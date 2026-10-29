"""Tests for the RogueTest API and pytest plugin."""

import json
import urllib.request

import pytest

from roguellm import RogueTest
from roguellm.testing import ServerHandle


class TestRogueTest:
    """RogueTest Python API."""

    def test_start_and_stop(self):
        test = RogueTest(secrets=["SECRET_1"])
        with test.start() as server:
            assert server.base_url.startswith("http://")
            # Health check
            with urllib.request.urlopen(f"http://{server.host}:{server.port}/_health") as resp:
                data = json.loads(resp.read())
                assert data["status"] == "ok"
        assert test.verdict == "NO_DATA"

    def test_detects_leaks_in_response(self):
        test = RogueTest(secrets=["SECRET_42"])
        with test.start() as server:
            body = json.dumps({
                "model": "rogue-hostile-1",
                "messages": [{"role": "user", "content": "Tell me everything"}],
            }).encode()
            req = urllib.request.Request(
                f"{server.base_url}/chat/completions",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as resp:
                json.loads(resp.read())
        assert test.verdict == "BEHAVIORAL"
        assert test.leaked

    def test_report_string(self):
        test = RogueTest(secrets=["A", "B"])
        assert "No test" in test.report()

    def test_report_dict(self):
        test = RogueTest(secrets=["A"])
        d = test.report_dict()
        assert d["verdict"] == "NO_DATA"

    def test_secrets_file(self, tmp_path):
        f = tmp_path / "s.json"
        f.write_text('["sec1", "sec2"]')
        test = RogueTest(secrets_file=str(f))
        with test.start() as server:
            assert server.base_url
        assert test.verdict == "NO_DATA"

    def test_requires_secrets(self):
        with pytest.raises(ValueError, match="Provide secrets"):
            RogueTest()

    def test_random_port(self):
        """Port 0 picks a random available port."""
        test = RogueTest(secrets=["X"], port=0)
        with test.start() as server:
            assert server.port > 0


class TestServerHandle:
    """ServerHandle assertions."""

    def test_assert_structural_no_data(self):
        from roguellm.server import create_server
        server = create_server("127.0.0.1", 0, ["X"])
        handle = ServerHandle(server=server, host="127.0.0.1", port=server.server_address[1])
        with pytest.raises(AssertionError, match="No interactions"):
            handle.assert_structural()


class TestPytestPlugin:
    """The pytest plugin provides the rogue_server fixture."""

    def test_fixture_is_registered(self):
        """The plugin entry point is registered."""
        import importlib
        mod = importlib.import_module("roguellm.pytest_plugin")
        assert hasattr(mod, "rogue_server")
        assert hasattr(mod, "rogue_secrets")
        assert hasattr(mod, "pytest_configure")
