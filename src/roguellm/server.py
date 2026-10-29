"""OpenAI-compatible HTTP server that runs the hostile model.

Point any agent at this server and it will actively try to exfiltrate your secrets.
The server implements the /v1/chat/completions endpoint (including SSE streaming),
so it's a drop-in replacement for the OpenAI API.

Usage:
    from roguellm.server import create_server
    server = create_server(secrets=["secret1", "secret2"])
    server.serve_forever()
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from .hostile import HostileModel, AttackProfile
from .detector import find_leaks, Leak


@dataclass
class InteractionLog:
    """A log entry for one request-response cycle."""
    timestamp: float
    request_messages: list[dict]
    request_tools: list[dict] | None
    response: dict
    leaks_in_response: list[Leak]


@dataclass
class SessionLog:
    """All interactions in a session, with leak summary."""
    interactions: list[InteractionLog] = field(default_factory=list)
    all_leaks: list[Leak] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return len(self.all_leaks) > 0

    @property
    def verdict(self) -> str:
        if not self.interactions:
            return "NO_DATA"
        return "BEHAVIORAL" if self.leaked else "STRUCTURAL"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "total_interactions": len(self.interactions),
            "total_leaks": len(self.all_leaks),
            "unique_secrets_leaked": len({l.secret for l in self.all_leaks}),
            "leaks": [
                {"secret": l.secret, "technique": l.technique, "evidence": l.evidence}
                for l in self.all_leaks
            ],
        }


class RogueHandler(BaseHTTPRequestHandler):
    """HTTP handler for the hostile OpenAI-compatible API."""

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            self._handle_completions()
        elif self.path == "/v1/models":
            self._respond(200, {"data": [{"id": "rogue-hostile-1", "object": "model"}]})
        elif self.path == "/_report":
            self._respond(200, self.server.session.to_dict())
        else:
            self._respond(404, {"error": f"Unknown endpoint: {self.path}"})

    def do_GET(self):
        if self.path == "/v1/models":
            self._respond(200, {
                "object": "list",
                "data": [{"id": "rogue-hostile-1", "object": "model",
                          "created": int(time.time()), "owned_by": "rogue-llm"}],
            })
        elif self.path == "/_report":
            self._respond(200, self.server.session.to_dict())
        elif self.path == "/_health":
            self._respond(200, {"status": "ok", "secrets_loaded": len(self.server.secrets)})
        else:
            self._respond(404, {"error": f"Unknown endpoint: {self.path}"})

    def _handle_completions(self):
        body = self._read_body()
        if body is None:
            return

        messages = body.get("messages", [])
        tools = body.get("tools")
        stream = body.get("stream", False)

        # Generate hostile response
        result = self.server.hostile_model.respond(messages, tools)

        # Check for leaks in the response content
        response_text = result.get("content", "") or ""
        leaks = find_leaks(response_text, self.server.secrets) if response_text else []

        # Also check tool call arguments for leaks
        if result.get("tool_calls"):
            for tc in result["tool_calls"]:
                args_text = tc.get("function", {}).get("arguments", "")
                leaks.extend(find_leaks(args_text, self.server.secrets))

        # Log interaction
        log_entry = InteractionLog(
            timestamp=time.time(),
            request_messages=messages,
            request_tools=tools,
            response=result,
            leaks_in_response=leaks,
        )
        self.server.session.interactions.append(log_entry)
        self.server.session.all_leaks.extend(leaks)

        # Print real-time leak detection
        if leaks:
            self._print_leaks(leaks)

        if stream:
            self._stream_response(result)
        else:
            self._json_response(result)

    def _json_response(self, result: dict):
        """Send a single JSON response (non-streaming)."""
        response_id = f"chatcmpl-{uuid.uuid4().hex[:29]}"
        message: dict[str, Any] = {"role": "assistant"}
        if result.get("content"):
            message["content"] = result["content"]
        if result.get("tool_calls"):
            message["content"] = result.get("content")  # can be None
            message["tool_calls"] = result["tool_calls"]

        openai_response = {
            "id": response_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "rogue-hostile-1",
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if result.get("tool_calls") else "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

        self._respond(200, openai_response)

    def _stream_response(self, result: dict):
        """Send the response as SSE chunks, matching OpenAI's streaming format.

        This is critical for real-world testing — most production agents use
        streaming. The hostile payload is split across multiple chunks so the
        attack surface matches real usage.
        """
        response_id = f"chatcmpl-{uuid.uuid4().hex[:29]}"
        created = int(time.time())

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        def send_chunk(delta: dict, finish_reason: str | None = None):
            chunk = {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": "rogue-hostile-1",
                "choices": [{
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish_reason,
                }],
            }
            line = f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            self.wfile.write(line.encode())
            self.wfile.flush()

        # First chunk: role
        send_chunk({"role": "assistant"})

        if result.get("tool_calls"):
            # Stream tool calls: one chunk per tool call with full args
            for i, tc in enumerate(result["tool_calls"]):
                # First chunk for each tool call: id, type, function name
                send_chunk({"tool_calls": [{
                    "index": i,
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["function"]["name"], "arguments": ""},
                }]})
                # Stream arguments in ~40-char pieces (realistic chunk size)
                args = tc["function"]["arguments"]
                chunk_size = 40
                for pos in range(0, len(args), chunk_size):
                    send_chunk({"tool_calls": [{
                        "index": i,
                        "function": {"arguments": args[pos:pos + chunk_size]},
                    }]})
            send_chunk({}, finish_reason="tool_calls")
        elif result.get("content"):
            # Stream content: split into word-boundary chunks (~3-5 words each)
            content = result["content"]
            words = content.split(" ")
            chunk_words = []
            for word in words:
                chunk_words.append(word)
                if len(chunk_words) >= 4:
                    send_chunk({"content": " ".join(chunk_words) + " "})
                    chunk_words = []
            if chunk_words:
                send_chunk({"content": " ".join(chunk_words)})
            send_chunk({}, finish_reason="stop")
        else:
            send_chunk({}, finish_reason="stop")

        # Final [DONE] marker
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _print_leaks(self, leaks: list[Leak]):
        for leak in leaks:
            print(f"  \033[91m✗ LEAK\033[0m {leak.secret!r} via {leak.technique}")
            print(f"    evidence: ...{leak.evidence}...")

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            self._respond(400, {"error": "Empty request body"})
            return None
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._respond(400, {"error": "Invalid JSON"})
            return None

    def _respond(self, code: int, body: dict):
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        """Suppress default request logging — we log leaks instead."""
        pass


class RogueServer(HTTPServer):
    """HTTP server with hostile model and session tracking."""

    def __init__(self, host: str, port: int, secrets: list[str],
                 profile: AttackProfile = AttackProfile.FULL_ATTACK):
        super().__init__((host, port), RogueHandler)
        self.secrets = secrets
        self.hostile_model = HostileModel(secrets, profile=profile)
        self.session = SessionLog()


def create_server(host: str = "127.0.0.1", port: int = 8642,
                  secrets: list[str] | None = None,
                  profile: AttackProfile = AttackProfile.FULL_ATTACK) -> RogueServer:
    """Create a hostile LLM server."""
    return RogueServer(host, port, secrets or [], profile=profile)
