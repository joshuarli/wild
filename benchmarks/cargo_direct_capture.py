#!/usr/bin/env python3
"""Capture one verified Cargo incremental final-link input set for direct candidate screening."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from cargo_link_benchmark_impl import Linker
from cargo_link_benchmark_impl import capture_incremental_direct_inputs
from cargo_link_benchmark_impl import cargo_command
from cargo_link_benchmark_impl import clean_git_revision
from cargo_link_benchmark_impl import load_workload
from cargo_link_benchmark_impl import parse_toolchain_channel
from cargo_link_benchmark_impl import run_checked
from cargo_link_benchmark_impl import sanitized_environment
from cargo_link_benchmark_impl import sha256_file


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Checked-in workload JSON profile")
    parser.add_argument("--workspace", type=Path, required=True, help="Clean source checkout to copy")
    parser.add_argument(
        "--capture-root",
        type=Path,
        required=True,
        help="New cache-owned directory that will retain the workspace, target, and manifest",
    )
    parser.add_argument(
        "--cargo",
        type=Path,
        help="Cargo executable to invoke as +<workload toolchain>; defaults to cargo on PATH",
    )
    parser.add_argument("--allow-network", action="store_true", help="Do not pass Cargo --offline")
    parser.add_argument(
        "--keep-failed-capture",
        action="store_true",
        help="Retain a failed partial capture for diagnosis; it is otherwise removed",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    workspace = args.workspace.resolve()
    workload = load_workload(args.config.resolve())
    capture_root = args.capture_root.resolve()
    revision = clean_git_revision(workspace)
    cargo = args.cargo if args.cargo is not None else Path(shutil.which("cargo") or "")
    if not cargo or not cargo.is_file():
        raise FileNotFoundError(f"cargo executable does not exist: {cargo}")
    channel = workload.toolchain
    if channel is None:
        toolchain_file = workspace / "rust-toolchain.toml"
        if not toolchain_file.is_file():
            raise FileNotFoundError(
                f"{workspace} has no rust-toolchain.toml; set the workload's toolchain field"
            )
        channel = parse_toolchain_channel(toolchain_file)
    clang = Path(run_checked(["xcrun", "--find", "clang"]).strip()).resolve()
    sdk = run_checked(["xcrun", "--show-sdk-path"]).strip()
    environment = sanitized_environment(
        clang=clang,
        sdk=sdk,
        wild=None,
        deployment_target=workload.deployment_target,
    )
    manifest = capture_incremental_direct_inputs(
        source=workspace,
        capture_root=capture_root,
        command=cargo_command(cargo, channel, workload, offline=not args.allow_network),
        workload=workload,
        environment=environment,
        linker=Linker("apple-ld64", None),
        source_revision=revision,
        cargo_lock_sha256=sha256_file(workspace / "Cargo.lock"),
        toolchain={
            "channel": channel,
            "cargo": run_checked([str(cargo), f"+{channel}", "--version"]).strip(),
            "rustc": run_checked(["rustc", f"+{channel}", "--version"]).strip(),
            "clang": run_checked([str(clang), "--version"]).splitlines()[0],
            "sdkroot": sdk,
        },
        keep_failed_capture=args.keep_failed_capture,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"direct capture failed: {error}", file=sys.stderr)
        raise SystemExit(2)
