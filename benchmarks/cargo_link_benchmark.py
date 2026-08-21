#!/usr/bin/env python3
"""Run a profile-driven ARM64 Mach-O Cargo-link benchmark using only stdlib Python."""

from __future__ import annotations

import sys
import subprocess

from cargo_link_benchmark_impl import main


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
