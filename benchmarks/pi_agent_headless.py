#!/usr/bin/env python3
"""Repeatable cold and incremental Cargo-link benchmark for ARM64 Mach-O repositories.

This script intentionally uses only Python's standard library. A workload JSON file describes a
Cargo target, output artifact, controlled source mutation, and comparison thresholds. It compares
Apple ld64 with Wild while keeping Rust's compiler driver as Xcode Clang in both cases.
"Incremental" means Cargo rebuilds after one controlled source-file change with the same target
directory. By default it does not claim that Wild implements incremental linking; the explicit
`--wild-incremental-cache` mode instead measures Wild's separately verified stable-layout cache.

The benchmark never mutates the supplied checkout. Each sample copies it to a temporary sibling
directory, so relative path dependencies outside the source tree retain their relationship. A
fresh target directory is used for each linker/sample, but cold and incremental builds for that
sample share it. This is a cold-Cargo-target benchmark, not an attempt to flush the OS file cache.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Callable


SCHEMA_VERSION = "cargo-link-build-benchmark/v1"
MACHO_64_MAGIC = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 2
STABLE_LAYOUT_CACHE_HIT_PREFIX = "wild: Mach-O stable-layout cache hit:"


@dataclass(frozen=True)
class Linker:
    name: str
    path: Path | None


@dataclass(frozen=True)
class SourceMutation:
    """One reversible changed-source operation used to make Cargo relink a real object."""

    path: str
    append: bytes | None = None
    replace_before: bytes | None = None
    replace_after: bytes | None = None


@dataclass(frozen=True)
class Workload:
    """Stable benchmark contract supplied by a checked-in JSON workload profile."""

    name: str
    target: str
    profile: str
    cargo_arguments: tuple[str, ...]
    artifact: str
    macho_file_type: int
    mutation: SourceMutation
    cold_max: float
    incremental_max: float
    deployment_target: str


def load_workload(path: Path) -> Workload:
    """Loads the deliberately small JSON schema used for future repository workloads."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != "cargo-link-workload/v1":
        raise ValueError(f"Unsupported workload schema in {path}")
    mutation = raw.get("incremental_mutation")
    goals = raw.get("goals")
    if not isinstance(mutation, dict) or not isinstance(goals, dict):
        raise ValueError(f"Workload {path} needs incremental_mutation and goals objects")
    try:
        if "append" in mutation:
            source_mutation = SourceMutation(
                path=str(mutation["path"]), append=str(mutation["append"]).encode("utf-8")
            )
        elif "replace_before" in mutation and "replace_after" in mutation:
            source_mutation = SourceMutation(
                path=str(mutation["path"]),
                replace_before=str(mutation["replace_before"]).encode("utf-8"),
                replace_after=str(mutation["replace_after"]).encode("utf-8"),
            )
        else:
            raise ValueError("incremental_mutation must specify append or replace_before/replace_after")
        workload = Workload(
            name=str(raw["name"]),
            target=str(raw["target"]),
            profile=str(raw["profile"]),
            cargo_arguments=tuple(str(argument) for argument in raw["cargo_arguments"]),
            artifact=str(raw["artifact"]),
            macho_file_type=int(raw["macho_file_type"]),
            mutation=source_mutation,
            cold_max=float(goals["cold_wild_over_apple_max"]),
            incremental_max=float(goals["incremental_wild_over_apple_max"]),
            deployment_target=str(raw.get("deployment_target", "11.0")),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid workload {path}: {error}") from error
    if not workload.cargo_arguments or not workload.mutation.path:
        raise ValueError(f"Workload {path} has an empty Cargo target or mutation contract")
    if workload.macho_file_type != MH_EXECUTE:
        raise ValueError(f"Workload {path} must currently name an MH_EXECUTE artifact")
    return workload


def run_checked(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    """Runs a small discovery command and returns its UTF-8 output."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_toolchain_channel(rust_toolchain: Path) -> str:
    match = re.search(r'^\s*channel\s*=\s*"([^"]+)"\s*$', rust_toolchain.read_text(), re.MULTILINE)
    if match is None:
        raise ValueError(f"No toolchain channel in {rust_toolchain}")
    return match.group(1)


def parse_macho_arm64_executable(path: Path, expected_file_type: int = MH_EXECUTE) -> dict[str, Any]:
    """Validates the output with the Mach-O header rather than a non-stdlib Python package."""
    data = path.read_bytes()[:32]
    if len(data) < 16:
        raise ValueError(f"{path} is too short for a Mach-O header")
    magic, cpu_type, _cpu_subtype, file_type = struct.unpack_from("<IiiI", data)
    if magic != MACHO_64_MAGIC:
        raise ValueError(f"{path} is not a 64-bit little-endian Mach-O executable")
    if cpu_type != CPU_TYPE_ARM64:
        raise ValueError(f"{path} is not ARM64 (cputype={cpu_type:#x})")
    if file_type != expected_file_type:
        raise ValueError(f"{path} has filetype={file_type}, expected {expected_file_type}")
    stat = path.stat()
    return {
        "path": str(path),
        "size_bytes": stat.st_size,
        "sha256": sha256_file(path),
        "macho_magic": f"{magic:#x}",
        "cpu_type": f"{cpu_type:#x}",
        "file_type": file_type,
    }


def clean_git_revision(workspace: Path) -> str:
    if run_checked(["git", "-C", str(workspace), "status", "--porcelain"]):
        raise RuntimeError(f"Refusing to benchmark a dirty source checkout: {workspace}")
    return run_checked(["git", "-C", str(workspace), "rev-parse", "HEAD"]).strip()


def copy_workspace_to_sibling(source: Path) -> Path:
    """Copies source to a sibling, preserving Pi's relative external path dependencies."""
    copied = Path(tempfile.mkdtemp(prefix=".wild-cargo-link-benchmark-", dir=source.parent))
    for entry in source.iterdir():
        if entry.name in {".git", "target"}:
            continue
        destination = copied / entry.name
        if entry.is_dir():
            shutil.copytree(entry, destination, symlinks=True)
        else:
            shutil.copy2(entry, destination, follow_symlinks=False)
    return copied


def sanitized_environment(
    *,
    clang: Path,
    sdk: str,
    wild: Path | None,
    deployment_target: str,
    wild_timing_json: bool,
) -> dict[str, str]:
    """Builds a deterministic Cargo environment with no inherited linker/wrapper override."""
    retained = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR")
    environment = {key: os.environ[key] for key in retained if key in os.environ}
    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "SDKROOT": sdk,
            "MACOSX_DEPLOYMENT_TARGET": deployment_target,
            # Release Cargo builds otherwise disable incremental compilation by default.
            "CARGO_INCREMENTAL": "1",
        }
    )
    flags = [f"-C linker={clang}", "-C link-arg=-v"]
    if wild is not None:
        flags.insert(1, f"-C link-arg=--ld-path={wild}")
        if wild_timing_json:
            # Clang owns the command line here, so use its linker-forwarding spelling.
            flags.append("-C link-arg=-Wl,--time=json")
    environment["RUSTFLAGS"] = " ".join(flags)
    return environment


def with_wild_incremental_cache(environment: dict[str, str], cache_dir: Path) -> dict[str, str]:
    """Enables Wild's opt-in Mach-O stable-layout cache for one disposable sample.

    Rustflags are space-delimited, so reject whitespace in this particular cache root instead of
    silently passing a different linker argument. The benchmark creates its own per-sample
    subdirectories underneath the supplied root.
    """
    if any(character.isspace() for character in str(cache_dir)):
        raise ValueError(f"--wild-incremental-cache path must not contain whitespace: {cache_dir}")
    updated = dict(environment)
    updated["RUSTFLAGS"] = (
        updated["RUSTFLAGS"]
        # Rust invokes Clang, which must forward ld64-style single-dash arguments rather than
        # interpreting them as compiler options itself.
        + f" -C link-arg=-Wl,-incremental_cache -C link-arg=-Wl,{cache_dir}"
    )
    return updated


def cargo_command(cargo: Path, channel: str, workload: Workload, *, offline: bool) -> list[str]:
    command = [
        str(cargo),
        f"+{channel}",
        "build",
        "--locked",
        "--target",
        workload.target,
        "--profile",
        workload.profile,
        "-vv",
    ]
    command.extend(workload.cargo_arguments)
    if offline:
        command.append("--offline")
    return command


def run_cargo_build(
    command: list[str], *, workspace: Path, environment: dict[str, str], target_dir: Path, log_path: Path
) -> tuple[int, int]:
    environment = dict(environment)
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    start = time.perf_counter_ns()
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    elapsed = time.perf_counter_ns() - start
    if completed.returncode:
        raise RuntimeError(
            f"Cargo build failed with status {completed.returncode}; see {log_path}"
        )
    return completed.returncode, elapsed


def linker_selection_evidence(log_path: Path, linker: Linker) -> list[str]:
    """Extracts actual-driver evidence while rejecting a no-op incremental build."""
    lines = log_path.read_text(errors="replace").splitlines()
    if linker.path is None:
        evidence = [
            line
            for line in lines
            if "PROGRAM:ld PROJECT:ld64-" in line or (" -arch arm64" in line and "ld" in line)
        ]
    else:
        marker = f"--ld-path={linker.path}"
        evidence = [line for line in lines if marker in line or (" -arch arm64" in line and "wild" in line)]
    if not evidence:
        raise RuntimeError(
            f"No {linker.name} ARM64 linker invocation found in {log_path}; refusing to record a no-op build"
        )
    if any("x86_64" in line for line in evidence):
        raise RuntimeError(f"x86_64 linker invocation appeared in {log_path}")
    return evidence


def final_link_command(log_path: Path, linker: Linker) -> list[str]:
    """Extracts Clang's final ARM64 linker child from a verbose Cargo log.

    Cargo's changed-source build produces many Rust compiler invocations. Clang `-v` emits the
    final direct linker argv in shell quoting, which lets the benchmark separately measure only
    the incremental final-link operation without attributing Rust's LTO work to the linker.
    """
    for line in reversed(log_path.read_text(errors="replace").splitlines()):
        try:
            command = shlex.split(line.strip())
        except ValueError:
            continue
        if "-arch" not in command or "arm64" not in command or "-o" not in command:
            continue
        executable = Path(command[0])
        expected = linker.path
        if expected is None:
            if executable.name != "ld":
                continue
        elif executable != expected:
            continue
        return command
    raise RuntimeError(f"No direct final {linker.name} ARM64 linker command found in {log_path}")


def replay_incremental_link(
    *,
    command: list[str],
    environment: dict[str, str],
    output_dir: Path,
    linker: Linker,
    repetitions: int,
    expected_file_type: int,
    fixed_output: Path | None = None,
    prepare_replay: Callable[[], None] | None = None,
    require_stable_layout_cache_hit: bool = False,
) -> list[dict[str, Any]]:
    """Reruns the final changed-source linker argv without invoking Cargo or rustc."""
    output_index = command.index("-o") + 1
    output_dir.mkdir(parents=True, exist_ok=True)
    samples: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        if prepare_replay is not None:
            prepare_replay()
        output = fixed_output if fixed_output is not None else output_dir / f"{linker.name}-{repetition}"
        replay = list(command)
        if fixed_output is None:
            replay[output_index] = str(output)
        elif Path(replay[output_index]) != fixed_output:
            raise RuntimeError("Cache replay command did not retain its cached output path")
        log_path = output_dir / f"{linker.name}-{repetition}.log"
        start = time.perf_counter_ns()
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                replay,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        elapsed = time.perf_counter_ns() - start
        if completed.returncode:
            raise RuntimeError(f"{linker.name} incremental replay failed; see {log_path}")
        cache_hits = stable_layout_cache_hit_evidence(log_path)
        if require_stable_layout_cache_hit and not cache_hits:
            raise RuntimeError(
                f"Wild stable-layout cache missed during incremental replay; see {log_path}"
            )
        samples.append(
            {
                "elapsed_ns": elapsed,
                "log": str(log_path),
                "command": replay,
                "artifact": parse_macho_arm64_executable(output, expected_file_type),
                "stable_layout_cache_hits": cache_hits,
            }
        )
    return samples


def stable_layout_cache_hit_evidence(log_path: Path) -> list[str]:
    """Returns cache hits, including records Cargo indents in a linker-stderr warning."""
    return [
        line.strip()
        for line in log_path.read_text(errors="replace").splitlines()
        if line.strip().startswith(STABLE_LAYOUT_CACHE_HIT_PREFIX)
    ]


def restore_cached_direct_baseline(
    *,
    baseline_output: Path,
    baseline_output_snapshot: Path,
    cache_dir: Path,
    cache_snapshot: Path,
    stale_published_output: Path | None = None,
) -> None:
    """Restores the exact pre-change output and sidecars before a cache-hit replay.

    Cargo gives a changed crate a new hashed output path. Each sample therefore restores the old
    output named by the sidecar, then lets Wild atomically publish the changed command's real
    `-o` path. Rewriting either path to a benchmark-only name would invalidate this contract.
    """
    baseline_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(baseline_output_snapshot, baseline_output)
    if stale_published_output is not None and stale_published_output != baseline_output:
        stale_published_output.unlink(missing_ok=True)
    shutil.rmtree(cache_dir, ignore_errors=True)
    shutil.copytree(cache_snapshot, cache_dir)


def mutate_incremental_source(path: Path, mutation: SourceMutation) -> tuple[str, str]:
    before = path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    if mutation.append is not None:
        if mutation.append in before:
            raise RuntimeError(f"Benchmark marker unexpectedly already present in {path}")
        after = before + mutation.append
    else:
        assert mutation.replace_before is not None and mutation.replace_after is not None
        occurrences = before.count(mutation.replace_before)
        if occurrences != 1:
            raise RuntimeError(
                f"Expected exactly one replacement target in {path}, found {occurrences}"
            )
        after = before.replace(mutation.replace_before, mutation.replace_after, 1)
    path.write_bytes(after)
    after_hash = sha256_file(path)
    return before_hash, after_hash


def append_capture_marker(path: Path, marker: bytes) -> tuple[str, str]:
    """Adds a second disposable edit solely to retain Rustc's final temporary object."""
    return mutate_incremental_source(path, SourceMutation(path=str(path), append=marker))


def restore_source(path: Path, before: bytes, before_hash: str) -> str:
    path.write_bytes(before)
    restored_hash = sha256_file(path)
    if restored_hash != before_hash:
        raise RuntimeError(f"Failed to restore benchmark mutation in {path}")
    return restored_hash


def median_ns(samples: list[int]) -> int:
    return int(statistics.median(samples))


def run_sample(
    *,
    source: Path,
    result_root: Path,
    cargo: Path,
    channel: str,
    command: list[str],
    workload: Workload,
    environment: dict[str, str],
    linker: Linker,
    sample_index: int,
    link_repetitions: int,
    keep_workspaces: bool,
    wild_incremental_cache_root: Path | None,
) -> dict[str, Any]:
    workspace = copy_workspace_to_sibling(source)
    target_dir = result_root / "targets" / f"{linker.name}-{sample_index}"
    logs_dir = result_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=False)
    cache_enabled = linker.path is not None and wild_incremental_cache_root is not None
    cache_dir = (
        wild_incremental_cache_root / f"{linker.name}-{sample_index}"
        if cache_enabled
        else None
    )
    cache_environment = (
        with_wild_incremental_cache(environment, cache_dir) if cache_dir is not None else environment
    )
    cache_setup_target = (
        target_dir.parent / f"{linker.name}-{sample_index}-cache-setup"
        if cache_enabled
        else None
    )
    mutation_path = workspace / workload.mutation.path
    before = mutation_path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    cold_log = logs_dir / f"{linker.name}-{sample_index}-cold.log"
    incremental_log = logs_dir / f"{linker.name}-{sample_index}-incremental.log"

    try:
        _, cold_elapsed = run_cargo_build(
            command, workspace=workspace, environment=environment, target_dir=target_dir, log_path=cold_log
        )
        artifact_path = target_dir / workload.artifact.format(
            target=workload.target, profile=workload.profile
        )
        cold_artifact = parse_macho_arm64_executable(artifact_path, workload.macho_file_type)
        cold_evidence = linker_selection_evidence(cold_log, linker)

        cache_setup_log: Path | None = None
        incremental_target_dir = target_dir
        incremental_environment = environment
        if cache_setup_target is not None:
            # Cold wall time deliberately uses normal Wild. Establish the opt-in cache in a
            # separate, unmeasured Cargo target so its baseline and its changed rebuild share a
            # real source/object/output lineage without inflating the cold comparison.
            cache_setup_log = logs_dir / f"{linker.name}-{sample_index}-cache-setup.log"
            run_cargo_build(
                command,
                workspace=workspace,
                environment=cache_environment,
                target_dir=cache_setup_target,
                log_path=cache_setup_log,
            )
            incremental_target_dir = cache_setup_target
            incremental_environment = cache_environment

        mutation_before, mutation_after = mutate_incremental_source(mutation_path, workload.mutation)
        assert mutation_before == before_hash
        _, incremental_elapsed = run_cargo_build(
            command,
            workspace=workspace,
            environment=incremental_environment,
            target_dir=incremental_target_dir,
            log_path=incremental_log,
        )
        incremental_artifact_path = incremental_target_dir / workload.artifact.format(
            target=workload.target, profile=workload.profile
        )
        incremental_artifact = parse_macho_arm64_executable(
            incremental_artifact_path, workload.macho_file_type
        )
        incremental_evidence = linker_selection_evidence(incremental_log, linker)
        incremental_cache_hits = stable_layout_cache_hit_evidence(incremental_log)
        if cache_enabled and not incremental_cache_hits:
            raise RuntimeError(
                f"Wild stable-layout cache missed during Cargo incremental build; see {incremental_log}"
            )

        if cache_dir is None:
            # Rustc removes its temporary final codegen object after a normal Cargo link. Create a
            # separate, unmeasured changed-source build with `save-temps` solely to preserve that
            # exact final-link input for the direct incremental-link samples below. It never
            # affects the cold or Cargo-incremental wall measurements.
            capture_marker = b"\n// wild benchmark direct-link capture marker\n"
            capture_before, capture_after = append_capture_marker(mutation_path, capture_marker)
            capture_target = target_dir / "incremental-link-capture"
            capture_log = logs_dir / f"{linker.name}-{sample_index}-incremental-link-capture.log"
            capture_environment = dict(environment)
            capture_environment["RUSTFLAGS"] = capture_environment["RUSTFLAGS"] + " -C save-temps"
            run_cargo_build(
                command,
                workspace=workspace,
                environment=capture_environment,
                target_dir=capture_target,
                log_path=capture_log,
            )
            incremental_link = replay_incremental_link(
                command=final_link_command(capture_log, linker),
                environment=capture_environment,
                output_dir=logs_dir / f"{linker.name}-{sample_index}-incremental-link",
                linker=linker,
                repetitions=link_repetitions,
                expected_file_type=workload.macho_file_type,
            )
            incremental_link_capture: dict[str, Any] = {
                "capture_log": str(capture_log),
                "capture_mutation": {
                    "before_sha256": capture_before,
                    "after_sha256": capture_after,
                    "uses_rustc_save_temps": True,
                },
                "samples": incremental_link,
            }
        else:
            # Cargo gives the changed object/output fresh hashes. Build a separate baseline with
            # save-temps, snapshot its output/sidecars, then rebuild exactly once with the source
            # mutation. Each direct sample restores that baseline and publishes the changed `-o`.
            restore_source(mutation_path, before, before_hash)
            direct_target = target_dir / "incremental-link-cache"
            direct_cache_dir = cache_dir / "direct"
            capture_environment = with_wild_incremental_cache(environment, direct_cache_dir)
            capture_environment["RUSTFLAGS"] += " -C save-temps"
            baseline_log = logs_dir / f"{linker.name}-{sample_index}-incremental-link-baseline.log"
            run_cargo_build(
                command,
                workspace=workspace,
                environment=capture_environment,
                target_dir=direct_target,
                log_path=baseline_log,
            )
            baseline_command = final_link_command(baseline_log, linker)
            baseline_output = Path(baseline_command[baseline_command.index("-o") + 1])
            baseline_output_snapshot = logs_dir / f"{linker.name}-{sample_index}-cache-baseline-output"
            shutil.copy2(baseline_output, baseline_output_snapshot)
            cache_snapshot = logs_dir / f"{linker.name}-{sample_index}-cache-baseline-sidecars"
            shutil.copytree(direct_cache_dir, cache_snapshot)

            capture_before, capture_after = mutate_incremental_source(mutation_path, workload.mutation)
            assert capture_before == before_hash and capture_after == mutation_after
            capture_log = logs_dir / f"{linker.name}-{sample_index}-incremental-link-capture.log"
            run_cargo_build(
                command,
                workspace=workspace,
                environment=capture_environment,
                target_dir=direct_target,
                log_path=capture_log,
            )
            changed_command = final_link_command(capture_log, linker)
            changed_output = Path(changed_command[changed_command.index("-o") + 1])
            capture_hits = stable_layout_cache_hit_evidence(capture_log)
            if not capture_hits:
                raise RuntimeError(
                    f"Wild stable-layout cache missed while capturing the changed direct link; see {capture_log}"
                )
            incremental_link = replay_incremental_link(
                command=changed_command,
                environment=capture_environment,
                output_dir=logs_dir / f"{linker.name}-{sample_index}-incremental-link",
                linker=linker,
                repetitions=link_repetitions,
                expected_file_type=workload.macho_file_type,
                fixed_output=changed_output,
                prepare_replay=lambda: restore_cached_direct_baseline(
                    baseline_output=baseline_output,
                    baseline_output_snapshot=baseline_output_snapshot,
                    cache_dir=direct_cache_dir,
                    cache_snapshot=cache_snapshot,
                    stale_published_output=changed_output,
                ),
                require_stable_layout_cache_hit=True,
            )
            incremental_link_capture = {
                "baseline_log": str(baseline_log),
                "capture_log": str(capture_log),
                "capture_mutation": {
                    "before_sha256": capture_before,
                    "after_sha256": capture_after,
                    "uses_rustc_save_temps": True,
                },
                "cache": {
                    "baseline_output": str(baseline_output),
                    "changed_output": str(changed_output),
                    "baseline_sidecars": str(cache_snapshot),
                    "capture_hits": capture_hits,
                    "direct_samples_require_hits": True,
                },
                "samples": incremental_link,
            }
        restored_hash = restore_source(mutation_path, before, before_hash)
        return {
            "sample": sample_index,
            "linker": linker.name,
            "target_dir": str(target_dir),
            "cold": {
                "elapsed_ns": cold_elapsed,
                "log": str(cold_log),
                "selection_evidence": cold_evidence,
                "artifact": cold_artifact,
            },
            "incremental": {
                "elapsed_ns": incremental_elapsed,
                "log": str(incremental_log),
                "selection_evidence": incremental_evidence,
                "stable_layout_cache_hits": incremental_cache_hits,
                "cache_setup_log": str(cache_setup_log) if cache_setup_log is not None else None,
                "mutation": {
                    "path": str(mutation_path.relative_to(workspace)),
                    "before_sha256": mutation_before,
                    "after_sha256": mutation_after,
                    "restored_sha256": restored_hash,
                },
                "artifact": incremental_artifact,
            },
            "incremental_link": incremental_link_capture,
        }
    finally:
        # The original supplied checkout never changes. The copy should also be clean before it
        # is deleted, even if Cargo fails after the mutation.
        if mutation_path.exists() and mutation_path.read_bytes() != before:
            restore_source(mutation_path, before, before_hash)
        if not keep_workspaces:
            shutil.rmtree(workspace, ignore_errors=True)
            shutil.rmtree(target_dir, ignore_errors=True)
            if cache_setup_target is not None:
                shutil.rmtree(cache_setup_target, ignore_errors=True)


def comparison(runs: list[dict[str, Any]], workload: Workload) -> dict[str, Any]:
    by_linker: dict[str, list[dict[str, Any]]] = {"apple-ld64": [], "wild": []}
    for run in runs:
        by_linker[run["linker"]].append(run)
    if not by_linker["apple-ld64"] or not by_linker["wild"]:
        raise ValueError("Both Apple ld64 and Wild samples are required")
    medians = {
        linker: {
            "cold": median_ns([run["cold"]["elapsed_ns"] for run in samples]),
            "incremental_cargo": median_ns(
                [run["incremental"]["elapsed_ns"] for run in samples]
            ),
            "incremental_link": median_ns(
                [
                    sample["elapsed_ns"]
                    for run in samples
                    for sample in run["incremental_link"]["samples"]
                ]
            ),
        }
        for linker, samples in by_linker.items()
    }
    cold_ratio = medians["wild"]["cold"] / medians["apple-ld64"]["cold"]
    cargo_incremental_ratio = (
        medians["wild"]["incremental_cargo"] / medians["apple-ld64"]["incremental_cargo"]
    )
    incremental_link_ratio = (
        medians["wild"]["incremental_link"] / medians["apple-ld64"]["incremental_link"]
    )
    return {
        "medians_ns": medians,
        "cold_wild_over_apple": cold_ratio,
        "incremental_cargo_wild_over_apple": cargo_incremental_ratio,
        "incremental_link_wild_over_apple": incremental_link_ratio,
        "thresholds": {"cold_max": workload.cold_max, "incremental_max": workload.incremental_max},
        "goals_met": cold_ratio <= workload.cold_max
        and incremental_link_ratio <= workload.incremental_max,
    }


def default_wild_path() -> Path:
    # Linker wall-time comparisons must use an optimized Wild binary; the repository's `ci`
    # profile disables debug info but otherwise inherits Cargo's unoptimized defaults.
    return Path(__file__).resolve().parents[1] / "target/release/wild"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Checked-in workload JSON profile")
    parser.add_argument("--workspace", type=Path, required=True, help="Clean source checkout to copy and build")
    parser.add_argument("--wild", type=Path, default=default_wild_path())
    parser.add_argument(
        "--cargo",
        type=Path,
        help="Cargo executable to invoke as +<workload toolchain>; defaults to cargo on PATH",
    )
    parser.add_argument("--output", type=Path, required=True, help="JSON result path")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument(
        "--link-repetitions",
        type=int,
        default=5,
        help="Direct final-link replays after each changed-source Cargo build",
    )
    parser.add_argument("--allow-network", action="store_true", help="Do not pass Cargo --offline")
    parser.add_argument("--keep-workspaces", action="store_true")
    parser.add_argument(
        "--wild-timing-json",
        action="store_true",
        help="Pass Wild --time=json and retain phase records in Wild Cargo logs",
    )
    parser.add_argument(
        "--wild-incremental-cache",
        type=Path,
        help=(
            "Opt-in root for per-sample Wild stable-layout cache sidecars. The runner requires "
            "a verified cache hit for changed-source Wild samples."
        ),
    )
    parser.add_argument("--enforce-goals", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.repetitions < 1 or args.link_repetitions < 1:
        raise ValueError("--repetitions and --link-repetitions must be positive")
    workspace = args.workspace.resolve()
    workload = load_workload(args.config.resolve())
    wild = args.wild.resolve()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite benchmark result: {output}")
    if not wild.is_file():
        raise FileNotFoundError(f"Wild binary not found: {wild}")
    channel = parse_toolchain_channel(workspace / "rust-toolchain.toml")
    revision = clean_git_revision(workspace)
    clang = Path(run_checked(["xcrun", "--find", "clang"]).strip()).resolve()
    sdk = run_checked(["xcrun", "--show-sdk-path"]).strip()
    cargo_path = args.cargo if args.cargo is not None else Path(shutil.which("cargo") or "")
    if not cargo_path:
        raise FileNotFoundError("cargo was not found on PATH")
    if not cargo_path.is_file():
        raise FileNotFoundError(f"cargo executable does not exist: {cargo_path}")
    command = cargo_command(cargo_path, channel, workload, offline=not args.allow_network)
    result_root = output.with_suffix("").with_name(f"{output.stem}-artifacts")
    if result_root.exists():
        raise FileExistsError(f"Refusing to overwrite benchmark artifacts: {result_root}")
    result_root.mkdir(parents=True)
    wild_incremental_cache_root: Path | None = None
    if args.wild_incremental_cache is not None:
        wild_incremental_cache_root = args.wild_incremental_cache.resolve()
        if wild_incremental_cache_root.exists():
            if any(wild_incremental_cache_root.iterdir()):
                raise FileExistsError(
                    "Refusing to mix benchmark cache state with an existing directory: "
                    f"{wild_incremental_cache_root}"
                )
        else:
            wild_incremental_cache_root.mkdir(parents=True)

    linkers = [Linker("apple-ld64", None), Linker("wild", wild)]
    runs: list[dict[str, Any]] = []
    try:
        # Interleave and alternate linker order so build-cache warmth, thermal drift, and unrelated
        # host load do not systematically favour whichever linker happens to run first or last.
        # Each sample still owns a separate Cargo target directory.
        for sample_index in range(args.repetitions):
            sample_linkers = linkers if sample_index % 2 == 0 else list(reversed(linkers))
            for linker in sample_linkers:
                environment = sanitized_environment(
                    clang=clang,
                    sdk=sdk,
                    wild=linker.path,
                    deployment_target=workload.deployment_target,
                    wild_timing_json=args.wild_timing_json and linker.path is not None,
                )
                runs.append(
                    run_sample(
                        source=workspace,
                        result_root=result_root,
                        cargo=cargo_path,
                        channel=channel,
                        command=command,
                        workload=workload,
                        environment=environment,
                        linker=linker,
                        sample_index=sample_index,
                        link_repetitions=args.link_repetitions,
                        keep_workspaces=args.keep_workspaces,
                        wild_incremental_cache_root=(
                            wild_incremental_cache_root if linker.path is not None else None
                        ),
                    )
                )
        summary = comparison(runs, workload)
        result = {
            "schema_version": SCHEMA_VERSION,
            "workload": {
                "workspace": str(workspace),
                "git_revision": revision,
                "cargo_lock_sha256": sha256_file(workspace / "Cargo.lock"),
                "name": workload.name,
                "target": workload.target,
                "cargo_arguments": list(workload.cargo_arguments),
                "artifact": workload.artifact,
                "profile": workload.profile,
            },
            "toolchain": {
                "channel": channel,
                "cargo": run_checked([str(cargo_path), f"+{channel}", "--version"]).strip(),
                "rustc": run_checked(["rustc", f"+{channel}", "--version"]).strip(),
                "clang": run_checked([str(clang), "--version"]).splitlines()[0],
                "wild": {"path": str(wild), "sha256": sha256_file(wild)},
            },
            "environment": {
                "sdkroot": sdk,
                "deployment_target": workload.deployment_target,
                "cargo_incremental": "1",
                "link_repetitions": args.link_repetitions,
                "offline": not args.allow_network,
                "wild_timing_json": args.wild_timing_json,
                "wild_incremental_cache_root": (
                    str(wild_incremental_cache_root)
                    if wild_incremental_cache_root is not None
                    else None
                ),
                "result_artifacts": str(result_root),
            },
            "runs": runs,
            "comparison": summary,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 1 if args.enforce_goals and not summary["goals_met"] else 0
    finally:
        # Keep logs and JSON-ready data even on a later sample failure; caller can inspect them.
        pass


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
