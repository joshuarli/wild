#!/usr/bin/env python3
"""Run a profile-driven ARM64 Mach-O Cargo-link benchmark using only stdlib Python.

The implementation lives in `pi_agent_headless.py` until its first user-facing profile is renamed;
the module is configuration-driven and this is the stable generic entry point for later workloads.
"""

from __future__ import annotations

import sys
import subprocess

from pi_agent_headless import main


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
