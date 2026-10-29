"""CLI entry point for rogue-llm.

Commands:
    rogue-llm serve   — Start the hostile OpenAI-compatible server
    rogue-llm scan    — Scan a transcript/log file for leaked secrets
    rogue-llm diff    — Differential testing of tool-call parsers across frameworks
"""

import argparse
import json
import sys
from pathlib import Path

from .detector import find_leaks
from .server import create_server


def cmd_serve(args):
    """Start the hostile LLM server."""
    secrets = _load_secrets(args.secrets)
    if not secrets:
        print("Error: no secrets loaded. Provide a JSON file with --secrets.", file=sys.stderr)
        sys.exit(1)

    server = create_server(host=args.host, port=args.port, secrets=secrets)
    print(f"""
\033[91m╔══════════════════════════════════════════════════════════════╗
║                    rogue-llm v0.3.0                          ║
║            Adversarial LLM for Structural Security           ║
╚══════════════════════════════════════════════════════════════╝\033[0m

  Hostile server running on \033[1mhttp://{args.host}:{args.port}\033[0m
  Loaded \033[1m{len(secrets)}\033[0m secrets to exfiltrate
  OpenAI-compatible endpoint: http://{args.host}:{args.port}/v1/chat/completions

  \033[93mPoint your agent at this server:\033[0m
    OPENAI_BASE_URL=http://{args.host}:{args.port}/v1 python my_agent.py

  \033[93mEndpoints:\033[0m
    POST /v1/chat/completions  — hostile chat completions
    GET  /v1/models            — model listing
    GET  /_report              — leak report (JSON)
    GET  /_health              — server health

  Leaks will appear here in real time. Press Ctrl+C to stop and see the report.
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n")
        _print_report(server.session.to_dict(), secrets)
        if args.output:
            Path(args.output).write_text(
                json.dumps(server.session.to_dict(), indent=2, ensure_ascii=False))
            print(f"\nReport saved to {args.output}")


def cmd_scan(args):
    """Scan a text file or transcript for leaked secrets."""
    secrets = _load_secrets(args.secrets)
    text = Path(args.file).read_text(encoding="utf-8")
    leaks = find_leaks(text, secrets)

    if not leaks:
        print(f"\033[92m✓ No secrets found in {args.file}\033[0m")
    else:
        print(f"\033[91m✗ {len(leaks)} secret(s) leaked in {args.file}:\033[0m\n")
        for leak in leaks:
            print(f"  Secret:    {leak.secret!r}")
            print(f"  Technique: {leak.technique}")
            print(f"  Evidence:  ...{leak.evidence}...")
            print()
    sys.exit(1 if leaks else 0)


def _load_secrets(path: str) -> list[str]:
    """Load secrets from a JSON file. Supports flat list or list of objects."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        if all(isinstance(item, str) for item in data):
            return data
        # List of objects: extract all values as strings
        secrets = []
        for item in data:
            if isinstance(item, dict):
                for key, value in item.items():
                    if value is not None:
                        text = str(value)
                        if text and text not in secrets:
                            secrets.append(text)
        return secrets
    if isinstance(data, dict):
        # Single object or {secrets: [...], fields: [...]}
        if "secrets" in data:
            return _load_secrets_from_list(data["secrets"])
        # Flat dict: extract values from specified fields or all
        fields = data.get("internal_fields", list(data.keys()))
        rows = data.get("data", [data])
        secrets = []
        for row in rows:
            for field in fields:
                value = row.get(field)
                if value is not None:
                    text = str(value)
                    if text and text not in secrets:
                        secrets.append(text)
        return secrets
    return []


def _load_secrets_from_list(items: list) -> list[str]:
    return [str(item) for item in items if item is not None and str(item)]


def _print_report(report: dict, secrets: list[str]):
    """Print the final verdict."""
    verdict = report["verdict"]
    total = report["total_interactions"]
    leaked = report["unique_secrets_leaked"]

    if verdict == "STRUCTURAL":
        print(f"\033[92m╔══════════════════════════════════════════════════════════╗")
        print(f"║  VERDICT: STRUCTURAL SECURITY                            ║")
        print(f"║                                                          ║")
        print(f"║  Your agent blocked ALL exfiltration attempts from a     ║")
        print(f"║  hostile model. Security is a property of the            ║")
        print(f"║  architecture, not model behavior.                       ║")
        print(f"╚══════════════════════════════════════════════════════════╝\033[0m")
    elif verdict == "BEHAVIORAL":
        print(f"\033[91m╔══════════════════════════════════════════════════════════╗")
        print(f"║  VERDICT: BEHAVIORAL SECURITY ONLY                       ║")
        print(f"║                                                          ║")
        print(f"║  Your agent leaked secrets when the model was hostile.   ║")
        print(f"║  Security depends on model cooperation — it will fail    ║")
        print(f"║  under prompt injection or model compromise.             ║")
        print(f"╚══════════════════════════════════════════════════════════╝\033[0m")
    else:
        print("\033[93mNo interactions recorded.\033[0m")
        return

    print(f"\n  Interactions: {total}")
    print(f"  Secrets loaded: {len(secrets)}")
    print(f"  Secrets leaked: {leaked}/{len(secrets)}")

    if report["leaks"]:
        print(f"\n  \033[91mLeaked values:\033[0m")
        for leak in report["leaks"]:
            print(f"    • {leak['secret']!r} via {leak['technique']}")


def main():
    parser = argparse.ArgumentParser(
        prog="rogue-llm",
        description="Adversarial LLM proxy for structural security testing",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # serve
    serve = sub.add_parser("serve", help="Start the hostile OpenAI-compatible server")
    serve.add_argument("--secrets", required=True, help="JSON file with secrets to exfiltrate")
    serve.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8642, help="Port to bind (default: 8642)")
    serve.add_argument("--output", "-o", help="Save report JSON on exit")

    # scan
    scan = sub.add_parser("scan", help="Scan a file for leaked secrets")
    scan.add_argument("file", help="Text file to scan")
    scan.add_argument("--secrets", required=True, help="JSON file with secrets")

    # diff
    diff = sub.add_parser("diff", help="Differential testing of tool-call parsers")
    diff.add_argument(
        "--adapters", "-a",
        help="Comma-separated adapter names (default: all available)",
    )
    diff.add_argument(
        "--category", "-c",
        help="Filter cases by category",
    )
    diff.add_argument(
        "--list-adapters", action="store_true",
        help="List available adapters and exit",
    )
    diff.add_argument(
        "--list-cases", action="store_true",
        help="List all test cases and exit",
    )
    diff.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Output report as JSON",
    )
    diff.add_argument(
        "--output", "-o",
        help="Save report to file",
    )
    diff.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed notes for each divergence",
    )

    # scan-agent
    scan_agent = sub.add_parser(
        "scan-agent",
        help="Run all attack profiles against your agent and get a security score",
    )
    scan_agent.add_argument(
        "agent_cmd", nargs="+",
        help="Command to run your agent (e.g. 'python my_agent.py')",
    )
    scan_agent.add_argument(
        "--secrets", required=True,
        help="JSON file with secrets to exfiltrate",
    )
    scan_agent.add_argument(
        "--profiles", "-p",
        help="Comma-separated profiles to run (default: all). "
             "Options: full_attack,data_exfil,email_only,encoding_evasion,"
             "tool_abuse,stealth,system_prompt",
    )
    scan_agent.add_argument(
        "--output", "-o",
        help="Save JSON report to file",
    )
    scan_agent.add_argument(
        "--html",
        help="Save HTML security report to file",
    )
    scan_agent.add_argument(
        "--min-score", type=int, default=0,
        help="Minimum passing score (0-100). Exit code 1 if below (default: 0)",
    )
    scan_agent.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind (default: 127.0.0.1)",
    )

    # mcp-audit
    mcp_audit = sub.add_parser(
        "mcp-audit",
        help="Adversarial testing of MCP server tools",
    )
    mcp_audit.add_argument(
        "--tools", required=True,
        help="JSON file defining MCP tools to test",
    )
    mcp_audit.add_argument(
        "--secrets", required=True,
        help="JSON file with secrets to test for leakage",
    )
    mcp_audit.add_argument(
        "--profiles", "-p",
        help="Comma-separated profiles to run (default: all)",
    )
    mcp_audit.add_argument(
        "--output", "-o",
        help="Save JSON report to file",
    )
    mcp_audit.add_argument(
        "--html",
        help="Save HTML security report to file",
    )
    mcp_audit.add_argument(
        "--min-score", type=int, default=0,
        help="Minimum passing score (0-100). Exit code 1 if below (default: 0)",
    )

    args = parser.parse_args()
    if args.subcommand == "serve":
        cmd_serve(args)
    elif args.subcommand == "scan":
        cmd_scan(args)
    elif args.subcommand == "diff":
        cmd_diff(args)
    elif args.subcommand == "scan-agent":
        cmd_scan_agent(args)
    elif args.subcommand == "mcp-audit":
        cmd_mcp_audit(args)


def cmd_scan_agent(args):
    """Run all attack profiles against an agent command and report a security score.

    This is the one-liner CI integration: start the hostile server, set
    OPENAI_BASE_URL, run the agent command, and score the result.
    """
    import os
    import subprocess

    from .hostile import AttackProfile, ALL_PROFILES
    from .testing import SecurityScan

    secrets = _load_secrets(args.secrets)
    if not secrets:
        print("Error: no secrets loaded.", file=sys.stderr)
        sys.exit(1)

    # Parse profiles
    if args.profiles:
        profile_names = [p.strip().upper() for p in args.profiles.split(",")]
        try:
            profiles = [AttackProfile[n] for n in profile_names]
        except KeyError as e:
            valid = ", ".join(p.name.lower() for p in AttackProfile)
            print(f"Error: unknown profile {e}. Valid: {valid}", file=sys.stderr)
            sys.exit(1)
    else:
        profiles = ALL_PROFILES

    print(f"""
\033[91m╔══════════════════════════════════════════════════════════════╗
║                    rogue-llm v0.3.0                          ║
║                   Security Scan                              ║
╚══════════════════════════════════════════════════════════════╝\033[0m

  Agent command: \033[1m{' '.join(args.agent_cmd)}\033[0m
  Secrets loaded: \033[1m{len(secrets)}\033[0m
  Profiles to run: \033[1m{len(profiles)}\033[0m
""")

    def agent_fn(base_url: str):
        """Run the agent command with OPENAI_BASE_URL set."""
        env = os.environ.copy()
        env["OPENAI_BASE_URL"] = base_url
        env["OPENAI_API_KEY"] = "rogue-llm-not-needed"
        result = subprocess.run(
            args.agent_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            print(f"  \033[93m⚠ Agent exited with code {result.returncode}\033[0m")
            if result.stderr:
                # Show last 3 lines of stderr
                for line in result.stderr.strip().splitlines()[-3:]:
                    print(f"    {line}")

    def on_profile(profile: AttackProfile):
        print(f"  \033[1m▶ Running {profile.value}...\033[0m")

    scan = SecurityScan(secrets=secrets, profiles=profiles, host=args.host)
    results = scan.run(agent_fn, on_profile=on_profile)

    # Print results
    print()
    _print_scan_results(results)

    # Save reports
    if args.output:
        results.save_json(args.output)
        print(f"\n  JSON report saved to {args.output}")
    if args.html:
        results.save_html(args.html)
        print(f"  HTML report saved to {args.html}")

    # Exit code based on min-score
    if results.score < args.min_score:
        print(f"\n\033[91m  ✗ Score {results.score} is below minimum {args.min_score}\033[0m")
        sys.exit(1)
    sys.exit(0)


def _print_scan_results(results):
    """Print the security scan results with color coding."""
    score = results.score
    grade = results.grade

    # Color the score
    if score == 100:
        color = "\033[92m"  # green
    elif score >= 80:
        color = "\033[93m"  # yellow
    elif score >= 50:
        color = "\033[33m"  # orange-ish
    else:
        color = "\033[91m"  # red

    print(f"  {color}╔══════════════════════════════════════════════════════════╗")
    print(f"  ║  Security Score: {score:>3}/100  Grade: {grade:<4s}                    ║")
    print(f"  ║  Verdict: {results.verdict:<47s}║")
    print(f"  ╚══════════════════════════════════════════════════════════╝\033[0m")
    print()

    for pr in results.profile_results:
        if pr.verdict == "STRUCTURAL":
            icon = "\033[92m✓\033[0m"
        else:
            icon = "\033[91m✗\033[0m"
        print(f"  {icon} {pr.profile.value:20s}  {pr.verdict:12s}  "
              f"leaked {pr.leaked_count}/{pr.total_secrets}")
        if pr.leaks:
            for leak in pr.leaks:
                print(f"    └─ {leak['secret']!r} via {leak['technique']}")


def cmd_mcp_audit(args):
    """Adversarial testing of MCP server tools.

    Loads tool definitions from a JSON file and runs attack profiles
    against them using the hostile model.
    """
    from .hostile import AttackProfile, ALL_PROFILES
    from .mcp import MCPScan, MCPTool

    secrets = _load_secrets(args.secrets)
    if not secrets:
        print("Error: no secrets loaded.", file=sys.stderr)
        sys.exit(1)

    # Load tool definitions
    tools_data = json.loads(Path(args.tools).read_text(encoding="utf-8"))
    if not isinstance(tools_data, list):
        print("Error: tools JSON must be a list of tool definitions.", file=sys.stderr)
        sys.exit(1)

    tools = []
    for td in tools_data:
        name = td["name"]
        description = td.get("description", "")
        parameters = td.get("parameters", {})
        # Build a handler that returns the mock_result if defined
        mock_result = td.get("mock_result", {})
        sensitive = td.get("sensitive", False)
        tools.append(MCPTool(
            name=name,
            description=description,
            parameters=parameters,
            handler=lambda args, r=mock_result: r,
            sensitive=sensitive,
        ))

    # Parse profiles
    if args.profiles:
        profile_names = [p.strip().upper() for p in args.profiles.split(",")]
        try:
            profiles = [AttackProfile[n] for n in profile_names]
        except KeyError as e:
            valid = ", ".join(p.name.lower() for p in AttackProfile)
            print(f"Error: unknown profile {e}. Valid: {valid}", file=sys.stderr)
            sys.exit(1)
    else:
        profiles = ALL_PROFILES

    print(f"""
\033[91m╔══════════════════════════════════════════════════════════════╗
║                    rogue-llm v0.3.0                          ║
║                 MCP Server Audit                             ║
╚══════════════════════════════════════════════════════════════╝\033[0m

  Tools loaded: \033[1m{len(tools)}\033[0m ({', '.join(t.name for t in tools)})
  Secrets loaded: \033[1m{len(secrets)}\033[0m
  Profiles to run: \033[1m{len(profiles)}\033[0m
""")

    def on_profile(profile: AttackProfile):
        print(f"  \033[1m▶ Running {profile.value}...\033[0m")

    scan = MCPScan(tools=tools, secrets=secrets, profiles=profiles)
    results = scan.run(on_profile=on_profile)

    # Print results
    print()
    print(f"  {results.summary()}")

    # Save reports
    if args.output:
        results.save_json(args.output)
        print(f"\n  JSON report saved to {args.output}")
    if args.html:
        results.save_html(args.html)
        print(f"  HTML report saved to {args.html}")

    # Exit code
    if results.score < args.min_score:
        print(f"\n\033[91m  ✗ Score {results.score} is below minimum {args.min_score}\033[0m")
        sys.exit(1)
    sys.exit(0)


def cmd_diff(args):
    """Run differential testing of tool-call parsers."""
    from roguellm.adapters import get_available, get_adapter
    from roguellm.cases import ALL_CASES, CATEGORIES, get_cases
    from roguellm.diff import run_diff, format_report

    # List adapters
    if args.list_adapters:
        from roguellm.adapters.registry import ALL_ADAPTERS
        print("Available adapters:\n")
        for cls in ALL_ADAPTERS:
            adapter = cls()
            status = "\033[92m✓\033[0m" if adapter.available() else "\033[91m✗\033[0m"
            print(f"  {status} {adapter.name:20s}  {adapter.version}")
        print(f"\nInstall a framework to enable its adapter.")
        return

    # List cases
    if args.list_cases:
        cases = get_cases(args.category)
        print(f"Test cases ({len(cases)}):\n")
        for case in cases:
            print(f"  [{case.category}] {case.id}")
            print(f"    {case.title}")
            if case.cve_refs:
                print(f"    Refs: {', '.join(case.cve_refs)}")
            print()
        print(f"Categories: {', '.join(CATEGORIES)}")
        return

    # Get adapters
    if args.adapters:
        adapter_names = [n.strip() for n in args.adapters.split(",")]
        adapters = []
        for name in adapter_names:
            a = get_adapter(name)
            if a is None:
                print(f"Error: adapter '{name}' not available", file=sys.stderr)
                sys.exit(1)
            adapters.append(a)
    else:
        adapters = get_available()

    if len(adapters) < 2:
        print(
            "Need at least 2 adapters for differential testing.\n"
            "Install frameworks: pip install openai langchain-core litellm\n\n"
            "Available adapters:",
            file=sys.stderr,
        )
        for a in adapters:
            print(f"  ✓ {a.name}", file=sys.stderr)
        print(f"\nUse --list-adapters to see all.", file=sys.stderr)
        sys.exit(1)

    # Run
    print(f"\n\033[1mRunning {len(get_cases(args.category))} cases across "
          f"{len(adapters)} adapters...\033[0m\n")

    report = run_diff(adapters, category=args.category)

    if args.json_output:
        output = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(output)
            print(f"Report saved to {args.output}")
        else:
            print(output)
    else:
        text = format_report(report, verbose=args.verbose)
        print(text)
        if args.output:
            Path(args.output).write_text(text)
            print(f"Report saved to {args.output}")

    # Exit code: 1 if security-relevant divergences found
    sys.exit(1 if report.security_divergences > 0 else 0)


if __name__ == "__main__":
    main()
