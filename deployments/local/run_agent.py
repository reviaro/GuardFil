#!/usr/bin/env python3
"""Run an agent inside the GuardFil executor.

    deployments/local/guardfil-local.sh run-agent --runtime RUNTIME --workspace DIR [runtime options]

Every runtime runs in the same executor (deployments/local/executor.py): no
network except the relay to the host model broker, no credentials, read-only
root, all capabilities dropped, process, memory and CPU limits, and only the
workspace writable.  GuardFil decides every tool call the runtime makes.

Runtimes:
  codex        native Codex (app-server); options as for run-codex
  claude-code  Claude Code (claude -p) with a managed GuardFil hook; --prompt TEXT [--max-turns N]
  python       a plain-Python agent (default: python_agent_example.py); --task TEXT [--agent-file FILE] [--model P:M]
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _codex(argv: List[str]) -> int:
    import run_codex
    return run_codex.main(argv)


def _claude(argv: List[str]) -> int:
    import run_claude
    return run_claude.main(argv)


def _python(argv: List[str]) -> int:
    import run_python
    return run_python.main(argv)


RUNTIMES: Dict[str, Callable[[List[str]], int]] = {"codex": _codex, "claude-code": _claude, "python": _python}


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    runtime = None
    if len(argv) >= 2 and argv[0] == "--runtime":
        runtime, argv = argv[1], argv[2:]
    elif argv and argv[0].startswith("--runtime="):
        runtime, argv = argv[0].split("=", 1)[1], argv[1:]
    if runtime not in RUNTIMES:
        print(__doc__.strip(), file=sys.stderr)
        print(f"\nrun-agent: --runtime must come first and be one of: {', '.join(sorted(RUNTIMES))}",
              file=sys.stderr)
        return 2
    return RUNTIMES[runtime](argv)


if __name__ == "__main__":
    sys.exit(main())
