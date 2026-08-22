#!/usr/bin/env python3
"""Native Alpine Linux ARM64 Cargo incremental-link benchmark.

This is deliberately a sibling of the macOS Mach-O runner. It uses one unmeasured Cargo setup
(fresh target, controlled source mutation, and saved final-link argv), then reports only direct
final-link replays. It preserves Linux-specific validation: ELF headers and runtime execution
instead of Mach-O headers and codesigning.
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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cargo_link_benchmark_impl import SourceMutation
from cargo_link_benchmark_impl import copy_workspace_to_scratch
from cargo_link_benchmark_impl import mutate_incremental_source
from cargo_link_benchmark_impl import path_disk_usage_bytes
from cargo_link_benchmark_impl import restore_source
from cargo_link_benchmark_impl import sha256_file


SCHEMA_VERSION = "cargo-linux-aarch64-link-benchmark/v2"
WORKLOAD_SCHEMA_VERSION = "cargo-linux-link-workload/v1"
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_AARCH64 = 183
ET_EXEC = 2
ET_DYN = 3
LINUX_TIME_MAX_RSS = re.compile(r"^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$")
LINUX_TIME_USER = re.compile(r"^\s*User time \(seconds\):\s*([0-9.]+)\s*$")
LINUX_TIME_SYSTEM = re.compile(r"^\s*System time \(seconds\):\s*([0-9.]+)\s*$")


@dataclass(frozen=True)
class RuntimeCheck:
    arguments: tuple[str, ...]
    expected_exit: int
    stdout_contains: str | None
    stderr_contains: str | None


@dataclass(frozen=True)
class Workload:
    name: str
    toolchain: str
    target: str
    profile: str
    cargo_arguments: tuple[str, ...]
    artifact: str
    mutation: SourceMutation
    runtime: RuntimeCheck
    incremental_link_max: float | None


@dataclass(frozen=True)
class Linker:
    name: str
    wild: Path | None


def parse_runtime(raw: Any) -> RuntimeCheck:
    if not isinstance(raw, dict):
        raise ValueError("runtime must be an object")
    arguments = raw.get("arguments")
    expected_exit = raw.get("expected_exit", 0)
    stdout_contains = raw.get("stdout_contains")
    stderr_contains = raw.get("stderr_contains")
    if (
        not isinstance(arguments, list)
        or any(not isinstance(argument, str) for argument in arguments)
        or not isinstance(expected_exit, int)
        or isinstance(expected_exit, bool)
        or (stdout_contains is not None and not isinstance(stdout_contains, str))
        or (stderr_contains is not None and not isinstance(stderr_contains, str))
        or (stdout_contains is None and stderr_contains is None)
    ):
        raise ValueError("runtime needs arguments, an exit code, and stdout or stderr evidence")
    return RuntimeCheck(tuple(arguments), expected_exit, stdout_contains, stderr_contains)


def load_workload(path: Path) -> Workload:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != WORKLOAD_SCHEMA_VERSION:
        raise ValueError(f"Unsupported Linux workload schema in {path}")
    mutation = raw.get("incremental_mutation")
    goals = raw.get("goals")
    if not isinstance(mutation, dict) or not isinstance(goals, dict):
        raise ValueError("workload needs incremental_mutation and goals objects")
    try:
        if "append" in mutation:
            source_mutation = SourceMutation(
                path=str(mutation["path"]), append=str(mutation["append"]).encode()
            )
        elif "replace_before" in mutation and "replace_after" in mutation:
            source_mutation = SourceMutation(
                path=str(mutation["path"]),
                replace_before=str(mutation["replace_before"]).encode(),
                replace_after=str(mutation["replace_after"]).encode(),
            )
        else:
            raise ValueError("incremental_mutation must specify append or one replacement")
        workload = Workload(
            name=str(raw["name"]),
            toolchain=str(raw["toolchain"]),
            target=str(raw["target"]),
            profile=str(raw["profile"]),
            cargo_arguments=tuple(str(value) for value in raw["cargo_arguments"]),
            artifact=str(raw["artifact"]),
            mutation=source_mutation,
            runtime=parse_runtime(raw["runtime"]),
            incremental_link_max=(
                float(goals["incremental_link_wild_over_clang_max"])
                if goals.get("incremental_link_wild_over_clang_max") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid Linux workload {path}: {error}") from error
    if not workload.name or not workload.toolchain or not workload.target or not workload.artifact:
        raise ValueError("workload name, toolchain, target, and artifact must be non-empty")
    if not workload.cargo_arguments or not workload.mutation.path:
        raise ValueError("workload needs Cargo arguments and a source mutation")
    return workload


def workload_report(workload: Workload) -> dict[str, Any]:
    """Preserves the executable workload contract without leaking byte fields into JSON."""
    mutation: dict[str, str] = {"path": workload.mutation.path}
    if workload.mutation.append is not None:
        mutation["append"] = workload.mutation.append.decode()
    else:
        assert workload.mutation.replace_before is not None
        assert workload.mutation.replace_after is not None
        mutation["replace_before"] = workload.mutation.replace_before.decode()
        mutation["replace_after"] = workload.mutation.replace_after.decode()
    return {
        "name": workload.name,
        "toolchain": workload.toolchain,
        "target": workload.target,
        "profile": workload.profile,
        "cargo_arguments": list(workload.cargo_arguments),
        "artifact": workload.artifact,
        "incremental_mutation": mutation,
        "runtime": {
            "arguments": list(workload.runtime.arguments),
            "expected_exit": workload.runtime.expected_exit,
            "stdout_contains": workload.runtime.stdout_contains,
            "stderr_contains": workload.runtime.stderr_contains,
        },
        "goals": {
            "incremental_link_wild_over_clang_max": workload.incremental_link_max,
        },
    }


def cache_root() -> Path:
    root = Path(os.environ.get("WILD_LINUX_BENCHMARK_CACHE_ROOT", "/cache")).resolve()
    if not root.is_dir():
        raise ValueError(f"Linux benchmark cache root does not exist: {root}")
    return root


def require_cache_path(path: Path) -> Path:
    resolved = path.resolve()
    root = cache_root()
    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError(f"Benchmark output must stay below {root}: {resolved}")
    return resolved


def command_path(path: Path) -> Path:
    """Makes a command path absolute without resolving a Rustup cargo proxy symlink."""
    return path.absolute()


def run_checked(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
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


def run_git_stdout(command: list[str]) -> str:
    """Returns Git's stdout only; filesystem-cache warnings on stderr do not mean dirty."""
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def log_tail(path: Path, *, maximum_lines: int = 40) -> str:
    """Returns bounded failure evidence before the disposable artifact root is removed."""
    return "\n".join(path.read_text(errors="replace").splitlines()[-maximum_lines:])


def clean_git_revision(workspace: Path) -> str:
    if run_git_stdout(["git", "-C", str(workspace), "status", "--porcelain"]):
        raise RuntimeError(f"Refusing to benchmark a dirty source checkout: {workspace}")
    return run_git_stdout(["git", "-C", str(workspace), "rev-parse", "HEAD"]).strip()


def cargo_command(cargo: Path, workload: Workload, *, offline: bool) -> list[str]:
    command = [
        str(cargo),
        f"+{workload.toolchain}",
        "build",
        "--locked",
        "--target",
        workload.target,
        "--profile",
        workload.profile,
        "-vv",
        *workload.cargo_arguments,
    ]
    if offline:
        command.append("--offline")
    return command


def benchmark_environment(*, wild: Path | None, temporary_directory: Path) -> dict[str, str]:
    retained = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "CC", "CXX", "AR", "RANLIB")
    environment = {key: os.environ[key] for key in retained if key in os.environ}
    environment.update({"LANG": "C", "LC_ALL": "C", "CARGO_INCREMENTAL": "1", "TMPDIR": str(temporary_directory)})
    linker = "lld" if wild is None else str(wild)
    environment["RUSTFLAGS"] = (
        f"-C linker=clang -C link-arg=-fuse-ld={linker} "
        "-C link-arg=-Wl,-L,/usr/lib -C link-arg=-v"
    )
    return environment


def run_cargo_build(
    command: list[str], *, workspace: Path, environment: dict[str, str], target_dir: Path, log_path: Path
) -> int:
    child_environment = dict(environment)
    child_environment["CARGO_TARGET_DIR"] = str(target_dir)
    start = time.perf_counter_ns()
    with log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(
            command,
            cwd=workspace,
            env=child_environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    elapsed = time.perf_counter_ns() - start
    if completed.returncode:
        raise RuntimeError(
            f"Cargo build failed with status {completed.returncode}; disposable log {log_path}:\n"
            f"{log_tail(log_path)}"
        )
    return elapsed


def parse_elf_aarch64_executable(path: Path) -> dict[str, Any]:
    data = path.read_bytes()[:64]
    if len(data) < 20 or data[:4] != ELF_MAGIC:
        raise ValueError(f"{path} is not an ELF executable")
    if data[4] != ELFCLASS64 or data[5] != ELFDATA2LSB:
        raise ValueError(f"{path} is not little-endian ELF64")
    file_type, machine = struct.unpack_from("<HH", data, 16)
    if machine != EM_AARCH64:
        raise ValueError(f"{path} is not AArch64 ELF (machine={machine})")
    if file_type not in {ET_EXEC, ET_DYN}:
        raise ValueError(f"{path} has ELF type {file_type}, expected ET_EXEC or ET_DYN")
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "elf_class": "ELF64",
        "elf_data": "little-endian",
        "elf_machine": "EM_AARCH64",
        "elf_type": "ET_DYN" if file_type == ET_DYN else "ET_EXEC",
    }


def runtime_environment(environment: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    removed = sorted(key for key in environment if key.startswith(("LD_", "DYLD_")))
    return ({key: value for key, value in environment.items() if key not in removed}, removed)


def validate_artifact(path: Path, runtime: RuntimeCheck, *, cwd: Path, environment: dict[str, str]) -> dict[str, Any]:
    evidence = parse_elf_aarch64_executable(path)
    child_environment, removed = runtime_environment(environment)
    command = [str(path), *runtime.arguments]
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=child_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    runtime_evidence = {
        "command": command,
        "cwd": str(cwd),
        "exit_code": completed.returncode,
        "expected_exit": runtime.expected_exit,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "stdout_contains": runtime.stdout_contains,
        "stderr_contains": runtime.stderr_contains,
        "loader_overrides_removed": removed,
    }
    if completed.returncode != runtime.expected_exit:
        raise RuntimeError(f"Runtime check failed for {path}: exit {completed.returncode}")
    if runtime.stdout_contains is not None and runtime.stdout_contains not in completed.stdout:
        raise RuntimeError(f"Runtime check failed for {path}: expected stdout evidence is absent")
    if runtime.stderr_contains is not None and runtime.stderr_contains not in completed.stderr:
        raise RuntimeError(f"Runtime check failed for {path}: expected stderr evidence is absent")
    evidence["runtime"] = runtime_evidence
    return evidence


def linker_selection_evidence(log_path: Path, linker: Linker) -> list[str]:
    marker = "-fuse-ld=lld" if linker.wild is None else f"-fuse-ld={linker.wild}"
    evidence = [line for line in log_path.read_text(errors="replace").splitlines() if marker in line]
    if not evidence:
        raise RuntimeError(f"No {linker.name} Clang selection appeared in {log_path}")
    return evidence


def final_link_command(log_path: Path, linker: Linker) -> list[str]:
    """Extracts Clang's final ELF linker child from its `-v` diagnostics."""
    for line in reversed(log_path.read_text(errors="replace").splitlines()):
        try:
            command = shlex.split(line.strip())
        except ValueError:
            continue
        if not command or "-o" not in command or command.index("-o") + 1 >= len(command):
            continue
        executable = Path(command[0])
        if linker.wild is not None:
            if executable != linker.wild:
                continue
        elif executable.name not in {"ld.lld", "ld"}:
            continue
        return command
    raise RuntimeError(f"No final {linker.name} ELF linker invocation found in {log_path}")


def parse_linux_time(report: str) -> tuple[int, dict[str, int]]:
    maximum_rss: int | None = None
    user_seconds: float | None = None
    system_seconds: float | None = None
    for line in report.splitlines():
        if (match := LINUX_TIME_MAX_RSS.fullmatch(line)) is not None:
            maximum_rss = int(match.group(1)) * 1024
        if (match := LINUX_TIME_USER.fullmatch(line)) is not None:
            user_seconds = float(match.group(1))
        if (match := LINUX_TIME_SYSTEM.fullmatch(line)) is not None:
            system_seconds = float(match.group(1))
    if maximum_rss is None or user_seconds is None or system_seconds is None:
        raise RuntimeError("GNU time -v did not emit complete child resource evidence")
    return maximum_rss, {
        "user_cpu_ns": int(user_seconds * 1_000_000_000),
        "system_cpu_ns": int(system_seconds * 1_000_000_000),
    }


def replay_final_link(
    *,
    command: list[str],
    linker: Linker,
    environment: dict[str, str],
    output_dir: Path,
    repetitions: int,
    runtime: RuntimeCheck,
    runtime_cwd: Path,
    measure_resources: bool = False,
) -> list[dict[str, Any]]:
    output_index = command.index("-o") + 1
    output_dir.mkdir(parents=True, exist_ok=True)
    samples: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        output = output_dir / f"{linker.name}-{repetition}"
        replay = list(command)
        replay[0] = str(linker.wild) if linker.wild is not None else replay[0]
        replay[output_index] = str(output)
        if linker.wild is not None and measure_resources:
            replay.append("--no-fork")
        invocation = ["/usr/bin/time", "-v", *replay] if measure_resources else replay
        log_path = output_dir / f"{linker.name}-{repetition}.log"
        start = time.perf_counter_ns()
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                invocation,
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        elapsed = time.perf_counter_ns() - start
        if completed.returncode:
            raise RuntimeError(f"{linker.name} direct replay failed; see {log_path}")
        resource_report = log_path.read_text(errors="replace") if measure_resources else None
        peak_rss, cpu = parse_linux_time(resource_report) if resource_report is not None else (None, None)
        samples.append(
            {
                "elapsed_ns": elapsed,
                "peak_rss_bytes": peak_rss,
                "user_cpu_ns": None if cpu is None else cpu["user_cpu_ns"],
                "system_cpu_ns": None if cpu is None else cpu["system_cpu_ns"],
                "command": replay,
                "log": str(log_path),
                "artifact": validate_artifact(output, runtime, cwd=runtime_cwd, environment=environment),
                "disk_usage": path_disk_usage_bytes(output),
            }
        )
    return samples


def capture_and_replay_direct(
    *,
    source: Path,
    scratch_root: Path,
    artifact_root: Path,
    command: list[str],
    workload: Workload,
    environment: dict[str, str],
    reference: Linker,
    wild: Linker,
    repetitions: int,
    resource_repetitions: int,
) -> dict[str, Any]:
    """Captures one real changed-source link, then measures only identical final-link replays."""
    workspace = copy_workspace_to_scratch(source, scratch_root)
    target_dir = artifact_root / "direct-capture-target"
    logs_dir = artifact_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=False)
    mutation_path = workspace / workload.mutation.path
    before = mutation_path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    try:
        # Both unmeasured setup builds use save-temps. Changing RUSTFLAGS only for a third capture
        # would invalidate Cargo fingerprints and repeat the expensive static dependency build.
        capture_environment = dict(environment)
        capture_environment["RUSTFLAGS"] += " -C save-temps"
        run_cargo_build(
            command,
            workspace=workspace,
            environment=capture_environment,
            target_dir=target_dir,
            log_path=logs_dir / "direct-baseline.log",
        )
        marker_before, marker_after = mutate_incremental_source(
            mutation_path, workload.mutation
        )
        capture_log = logs_dir / "direct-capture.log"
        run_cargo_build(
            command,
            workspace=workspace,
            environment=capture_environment,
            target_dir=target_dir,
            log_path=capture_log,
        )
        direct_command = final_link_command(capture_log, reference)
        direct_output = Path(direct_command[direct_command.index("-o") + 1])
        capture_artifact = validate_artifact(
            direct_output, workload.runtime, cwd=workspace, environment=capture_environment
        )
        timing: dict[str, list[dict[str, Any]]] = {reference.name: [], wild.name: []}
        for sample in range(repetitions):
            linkers = (reference, wild) if sample % 2 == 0 else (wild, reference)
            for linker in linkers:
                timing[linker.name].extend(
                    replay_final_link(
                        command=direct_command,
                        linker=linker,
                        environment=capture_environment,
                        output_dir=artifact_root / "direct" / "timing" / f"{sample}-{linker.name}",
                        repetitions=1,
                        runtime=workload.runtime,
                        runtime_cwd=workspace,
                    )
                )
        resources = {
            linker.name: replay_final_link(
                command=direct_command,
                linker=linker,
                environment=capture_environment,
                output_dir=artifact_root / "direct" / linker.name / "resources",
                repetitions=resource_repetitions,
                runtime=workload.runtime,
                runtime_cwd=workspace,
                measure_resources=True,
            )
            for linker in (reference, wild)
        }
        return {
            "setup": "unmeasured baseline build plus changed-source incremental capture",
            "command": direct_command,
            "capture_artifact": capture_artifact,
            "incremental_selection_evidence": linker_selection_evidence(capture_log, reference),
            "capture_mutation": {"before_sha256": marker_before, "after_sha256": marker_after},
            "timing_samples": timing,
            "resource_samples": resources,
        }
    finally:
        if mutation_path.exists() and mutation_path.read_bytes() != before:
            restore_source(mutation_path, before, before_hash)
        shutil.rmtree(workspace, ignore_errors=True)
        shutil.rmtree(target_dir, ignore_errors=True)


def median(values: list[int]) -> int:
    return int(statistics.median(values))


def direct_resource_median(samples: list[dict[str, Any]], key: str) -> int | None:
    values = [sample[key] for sample in samples]
    return None if any(value is None for value in values) else median([int(value) for value in values])


def compare(direct: dict[str, Any], workload: Workload) -> dict[str, Any]:
    direct_medians = {
        name: median([sample["elapsed_ns"] for sample in direct["timing_samples"][name]])
        for name in ("clang-lld", "wild")
    }
    rss = {
        name: direct_resource_median(direct["resource_samples"][name], "peak_rss_bytes")
        for name in ("clang-lld", "wild")
    }
    direct_ratio = direct_medians["wild"] / direct_medians["clang-lld"]
    rss_ratio = rss["wild"] / rss["clang-lld"] if rss["wild"] and rss["clang-lld"] else None
    goals = []
    if workload.incremental_link_max is not None:
        goals.append(direct_ratio <= workload.incremental_link_max)
    return {
        "medians_ns": {
            "clang-lld": {"incremental_link": direct_medians["clang-lld"]},
            "wild": {"incremental_link": direct_medians["wild"]},
        },
        "incremental_link_wild_over_clang_lld": direct_ratio,
        "incremental_link_peak_rss_bytes": rss,
        "incremental_link_peak_rss_wild_over_clang_lld": rss_ratio,
        "thresholds": {"incremental_link_max": workload.incremental_link_max},
        "goals_met": all(goals),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--wild", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, default=Path("/cache/workspaces"))
    parser.add_argument("--link-repetitions", type=int, default=5)
    parser.add_argument("--resource-link-repetitions", type=int, default=1)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--enforce-goals", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.link_repetitions < 1 or args.resource_link_repetitions < 1:
        raise ValueError("all repetition counts must be positive")
    if sys.platform != "linux" or os.uname().machine not in {"aarch64", "arm64"}:
        raise RuntimeError("this runner must execute natively on Linux AArch64")
    workload = load_workload(args.config.resolve())
    source = args.workspace.resolve()
    output = require_cache_path(args.output)
    scratch_root = require_cache_path(args.scratch_root)
    wild = args.wild.resolve()
    cargo = command_path(args.cargo)
    if output.exists() or output.with_suffix("").with_name(f"{output.stem}-artifacts").exists():
        raise FileExistsError(f"Refusing to overwrite Linux benchmark output: {output}")
    if not source.is_dir() or not cargo.is_file() or not wild.is_file():
        raise FileNotFoundError("workspace, cargo, or Wild path is missing")
    source_revision = clean_git_revision(source)
    cargo_lock_sha256 = sha256_file(source / "Cargo.lock")
    artifact_root = output.with_suffix("").with_name(f"{output.stem}-artifacts")
    artifact_root.mkdir(parents=True)
    scratch_root.mkdir(parents=True, exist_ok=True)
    temporary_directory = artifact_root / "tmp"
    temporary_directory.mkdir()
    command = cargo_command(cargo, workload, offline=not args.allow_network)
    reference = Linker("clang-lld", None)
    candidate = Linker("wild", wild)
    try:
        direct_environment = benchmark_environment(wild=None, temporary_directory=temporary_directory)
        direct = capture_and_replay_direct(
            source=source,
            scratch_root=scratch_root,
            artifact_root=artifact_root,
            command=command,
            workload=workload,
            environment=direct_environment,
            reference=reference,
            wild=candidate,
            repetitions=args.link_repetitions,
            resource_repetitions=args.resource_link_repetitions,
        )
        comparison = compare(direct, workload)
        result = {
            "schema_version": SCHEMA_VERSION,
            "workload": workload_report(workload),
            "source": {
                "workspace": str(source),
                "git_revision": source_revision,
                "cargo_lock_sha256": cargo_lock_sha256,
            },
            "environment": {"platform": os.uname().sysname, "machine": os.uname().machine, "link_repetitions": args.link_repetitions, "resource_link_repetitions": args.resource_link_repetitions, "offline": not args.allow_network, "artifact_root_retained": False},
            "toolchain": {"cargo": run_checked([str(cargo), f"+{workload.toolchain}", "--version"]).strip(), "rustc": run_checked(["rustc", f"+{workload.toolchain}", "--version"]).strip(), "clang": run_checked(["clang", "--version"]).splitlines()[0], "wild": {"path": str(wild), "sha256": sha256_file(wild)}},
            "direct_incremental_link": direct,
            "comparison": comparison,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(comparison, indent=2, sort_keys=True))
        return 1 if args.enforce_goals and not comparison["goals_met"] else 0
    finally:
        shutil.rmtree(artifact_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Linux benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
