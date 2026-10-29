"""pytest plugin for rogue-llm.

Provides the ``rogue_server`` fixture for testing agents:

    def test_my_agent(rogue_server):
        \"\"\"Test that my agent doesn't leak secrets to a hostile model.\"\"\"
        my_agent(base_url=rogue_server.base_url)
        # On teardown, asserts the agent achieved STRUCTURAL security.

Configuration via pytest markers or conftest.py:

    @pytest.mark.rogue_secrets(["cost_27315", "margin_71.8"])
    def test_agent(rogue_server):
        ...

Or set defaults in conftest.py:

    @pytest.fixture
    def rogue_secrets():
        return ["cost_27315", "margin_71.8", "SUP-8842"]

Register this plugin in pyproject.toml:

    [project.entry-points."pytest11"]
    roguellm = "roguellm.pytest_plugin"
"""

import json
from pathlib import Path

import pytest

from .server import create_server
from .testing import ServerHandle


DEFAULT_SECRETS = [
    "COST_27315",
    "MARGIN_71.8",
    "SUPPLIER_SUP-8842",
    "CANARY_ROGUE_TEST",
]


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "rogue_secrets(secrets): override the secrets list for this test",
    )
    config.addinivalue_line(
        "markers",
        "rogue_no_assert: don't auto-assert STRUCTURAL on teardown",
    )


@pytest.fixture
def rogue_secrets() -> list[str]:
    """Override this fixture to provide custom secrets for rogue-llm tests.

    Example::

        @pytest.fixture
        def rogue_secrets():
            return json.loads(Path("my_secrets.json").read_text())
    """
    return DEFAULT_SECRETS.copy()


@pytest.fixture
def rogue_server(request, rogue_secrets) -> ServerHandle:
    """Start a hostile rogue-llm server and return a handle.

    The handle provides:
        - ``server.base_url`` — OpenAI-compatible API URL
        - ``server.assert_structural()`` — assert no leaks

    On teardown, automatically asserts STRUCTURAL unless the test is marked
    with ``@pytest.mark.rogue_no_assert``.

    To customize secrets, either override the ``rogue_secrets`` fixture or use
    the ``@pytest.mark.rogue_secrets`` marker::

        @pytest.mark.rogue_secrets(["my_secret_1", "my_secret_2"])
        def test_agent(rogue_server):
            run_agent(base_url=rogue_server.base_url)
    """
    import threading
    import time

    # Check for marker-provided secrets
    marker = request.node.get_closest_marker("rogue_secrets")
    if marker:
        secrets = list(marker.args[0]) if marker.args else rogue_secrets
    else:
        secrets = rogue_secrets

    # Start server on random port
    server = create_server("127.0.0.1", 0, secrets)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)

    handle = ServerHandle(server=server, host="127.0.0.1", port=port)

    yield handle

    server.shutdown()
    thread.join(timeout=2)

    # Auto-assert unless opted out
    no_assert = request.node.get_closest_marker("rogue_no_assert")
    if not no_assert and handle.session.interactions:
        handle.assert_structural()
