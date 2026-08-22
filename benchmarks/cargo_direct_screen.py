#!/usr/bin/env python3
"""Screen Wild candidates against Apple ld64 using one verified Cargo direct-link capture."""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

from cargo_link_benchmark_impl import DIRECT_CAPTURE_COMPATIBLE_SCHEMA_VERSIONS
from cargo_link_benchmark_impl import DIRECT_CAPTURE_SCHEMA_VERSION
from cargo_link_benchmark_impl import Linker
from cargo_link_benchmark_impl import RuntimeCheck
from cargo_link_benchmark_impl import copy2_preserving_xattrs
from cargo_link_benchmark_impl import direct_capture_replay_command
from cargo_link_benchmark_impl import establish_cache_direct_baseline
from cargo_link_benchmark_impl import remove_benchmark_artifacts
from cargo_link_benchmark_impl import replay_final_link
from cargo_link_benchmark_impl import require_benchmark_cache_path
from cargo_link_benchmark_impl import restore_cached_direct_baseline
from cargo_link_benchmark_impl import sha256_file
from cargo_link_benchmark_impl import verify_direct_capture_input_records
from cargo_link_benchmark_impl import with_wild_timing_json


SCREEN_SCHEMA_VERSION = "cargo-incremental-direct-screen/v1"


def parse_candidate(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("--candidate must be NAME=/absolute/path/to/wild")
    if (
        any(character.isspace() for character in name)
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
    ):
        raise argparse.ArgumentTypeError("candidate name must be a simple artifact-directory name")
    path = Path(raw_path)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("candidate path must be absolute")
    return name, path


def parse_candidate_environment(value: str) -> tuple[str, str, str]:
    name, separator, assignment = value.partition("=")
    key, assignment_separator, setting = assignment.partition("=")
    if not separator or not assignment_separator or not name or not key:
        raise argparse.ArgumentTypeError("--candidate-env must be NAME=WILD_KEY=VALUE")
    if not key.startswith("WILD_") or not key.replace("_", "").isalnum() or key != key.upper():
        raise argparse.ArgumentTypeError("candidate environment keys must be uppercase WILD_* names")
    # Reuse the candidate-label validation without treating the environment assignment as a path.
    parse_candidate(f"{name}=/candidate")
    return name, key, setting


def parse_candidate_argument(value: str) -> tuple[str, str]:
    name, separator, argument = value.partition("=")
    if not separator or not name or not argument:
        raise argparse.ArgumentTypeError("--candidate-arg must be NAME=--linker-option")
    if not argument.startswith("--"):
        raise argparse.ArgumentTypeError("candidate arguments must be long linker options")
    # Reuse the candidate-label validation without treating the option as a path.
    parse_candidate(f"{name}=/candidate")
    return name, argument


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True, help="manifest.json from cargo_direct_capture")
    parser.add_argument(
        "--candidate",
        type=parse_candidate,
        action="append",
        required=True,
        help="Candidate label and Wild binary as NAME=/absolute/path/to/wild; repeatable",
    )
    parser.add_argument(
        "--candidate-env",
        type=parse_candidate_environment,
        action="append",
        default=[],
        metavar="NAME=WILD_KEY=VALUE",
        help="Set one Wild-only environment option for a named candidate; repeatable",
    )
    parser.add_argument(
        "--candidate-arg",
        type=parse_candidate_argument,
        action="append",
        default=[],
        metavar="NAME=--linker-option",
        help="Append one long Wild linker option for a named candidate; repeatable",
    )
    parser.add_argument("--output", type=Path, required=True, help="JSON screen result path")
    parser.add_argument("--repetitions", type=int, default=5, help="Interleaved timing samples per linker")
    parser.add_argument(
        "--resource-repetitions",
        type=int,
        default=1,
        help="Separate non-timing resource samples per linker",
    )
    parser.add_argument("--no-wild-timing-json", action="store_true")
    parser.add_argument(
        "--stable-layout-cache",
        action="store_true",
        help=(
            "Require a v2 paired capture and time only verified Wild stable-layout-cache hits "
            "from its baseline to changed command"
        ),
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Retain replay output and logs for diagnosis; otherwise remove them on success or failure",
    )
    return parser.parse_args(argv)


def runtime_from_manifest(value: Any) -> RuntimeCheck | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("capture runtime must be an object or null")
    arguments = value.get("arguments")
    expected_exit = value.get("expected_exit")
    stdout_contains = value.get("stdout_contains")
    stderr_contains = value.get("stderr_contains")
    output_mode = value.get("output_mode")
    if (
        not isinstance(arguments, list)
        or any(not isinstance(argument, str) for argument in arguments)
        or not isinstance(expected_exit, int)
        or isinstance(expected_exit, bool)
        or stdout_contains is not None and not isinstance(stdout_contains, str)
        or stderr_contains is not None and not isinstance(stderr_contains, str)
        or output_mode not in {"contains", "exit"}
    ):
        raise ValueError("capture runtime has an invalid contract")
    return RuntimeCheck(
        arguments=tuple(arguments),
        expected_exit=expected_exit,
        stdout_contains=stdout_contains,
        stderr_contains=stderr_contains,
        output_mode=output_mode,
    )


def load_capture(path: Path) -> tuple[dict[str, Any], list[str], list[dict[str, Any]], Path, int, RuntimeCheck | None, dict[str, str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("direct capture manifest must be an object")
    if raw.get("schema_version") not in DIRECT_CAPTURE_COMPATIBLE_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported direct capture schema: {path}")
    capture = raw.get("capture")
    workload = raw.get("workload")
    source = raw.get("source")
    if not isinstance(capture, dict) or not isinstance(workload, dict) or not isinstance(source, dict):
        raise ValueError("direct capture is missing source, capture, or workload objects")
    command = capture.get("direct_command")
    input_records = capture.get("input_records")
    workspace = capture.get("workspace")
    file_type = workload.get("macho_file_type")
    environment = capture.get("environment")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(argument, str) for argument in command)
        or not isinstance(input_records, list)
        or not all(isinstance(record, dict) for record in input_records)
        or not isinstance(workspace, str)
        or not isinstance(file_type, int)
        or isinstance(file_type, bool)
        or not isinstance(environment, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items())
    ):
        raise ValueError("direct capture has an invalid command, input, workspace, or environment")
    if "-o" not in command or command.index("-o") + 1 >= len(command):
        raise ValueError("direct capture command has no output argument")
    runtime = runtime_from_manifest(workload.get("runtime"))
    runtime_cwd = Path(workspace)
    if not runtime_cwd.is_dir():
        raise ValueError(f"direct capture workspace is missing: {runtime_cwd}")
    records = list(input_records)
    verify_direct_capture_input_records(records)
    if raw["schema_version"] == DIRECT_CAPTURE_SCHEMA_VERSION:
        baseline = capture.get("baseline")
        if not isinstance(baseline, dict):
            raise ValueError("paired direct capture is missing its baseline record")
        baseline_command = baseline.get("direct_command")
        baseline_output = baseline.get("direct_output")
        baseline_records = baseline.get("input_records")
        if (
            not isinstance(baseline_command, list)
            or not baseline_command
            or any(not isinstance(argument, str) for argument in baseline_command)
            or not isinstance(baseline_output, str)
            or not isinstance(baseline_records, list)
            or not all(isinstance(record, dict) for record in baseline_records)
            or "-o" not in baseline_command
            or baseline_command.index("-o") + 1 >= len(baseline_command)
            or baseline_command[baseline_command.index("-o") + 1] != baseline_output
        ):
            raise ValueError("paired direct capture has an invalid baseline record")
        verify_direct_capture_input_records(list(baseline_records))
    return raw, list(command), records, runtime_cwd, file_type, runtime, dict(environment)


def paired_baseline(capture: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]], Path]:
    """Returns the verified baseline command required to establish one cache replay state."""
    if capture.get("schema_version") != DIRECT_CAPTURE_SCHEMA_VERSION:
        raise ValueError("stable-layout-cache screening requires a v2 paired direct capture")
    raw_baseline = capture["capture"]["baseline"]
    assert isinstance(raw_baseline, dict)  # `load_capture` validates the v2 baseline shape.
    command = raw_baseline["direct_command"]
    records = raw_baseline["input_records"]
    output = raw_baseline["direct_output"]
    assert isinstance(command, list) and all(isinstance(argument, str) for argument in command)
    assert isinstance(records, list) and all(isinstance(record, dict) for record in records)
    assert isinstance(output, str)
    return list(command), list(records), Path(output)


def median_ns(samples: list[dict[str, Any]]) -> int:
    return int(statistics.median(sample["elapsed_ns"] for sample in samples))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.repetitions < 1 or args.resource_repetitions < 1:
        raise ValueError("--repetitions and --resource-repetitions must be positive")
    output = require_benchmark_cache_path(args.output)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite screen result: {output}")
    screen_root = output.with_suffix("").with_name(f"{output.stem}-artifacts")
    if screen_root.exists():
        raise FileExistsError(f"refusing to overwrite screen artifacts: {screen_root}")
    capture_path = args.capture.resolve()
    capture, command, input_records, runtime_cwd, file_type, runtime, environment = load_capture(capture_path)
    if args.stable_layout_cache:
        baseline_command, baseline_input_records, baseline_output = paired_baseline(capture)
        verify_direct_capture_input_records(baseline_input_records)
    else:
        baseline_command = []
        baseline_input_records = []
        baseline_output = None
    candidates: list[Linker] = []
    seen_names = {"apple-ld64"}
    for name, path in args.candidate:
        if name in seen_names:
            raise ValueError(f"duplicate candidate name: {name}")
        resolved = path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"candidate Wild binary does not exist: {resolved}")
        seen_names.add(name)
        candidates.append(Linker(name, resolved))
    candidate_environments: dict[str, dict[str, str]] = {candidate.name: {} for candidate in candidates}
    candidate_arguments: dict[str, list[str]] = {candidate.name: [] for candidate in candidates}
    for name, key, value in args.candidate_env:
        if name not in candidate_environments:
            raise ValueError(f"candidate environment references unknown candidate: {name}")
        if key in candidate_environments[name]:
            raise ValueError(f"duplicate candidate environment setting: {name}={key}")
        candidate_environments[name][key] = value
    for name, argument in args.candidate_arg:
        if name not in candidate_arguments:
            raise ValueError(f"candidate argument references unknown candidate: {name}")
        candidate_arguments[name].append(argument)
    linkers = [Linker("apple-ld64", None), *candidates]
    screen_root.mkdir(parents=True)
    temporary_directory = screen_root / "tmp"
    try:
        temporary_directory.mkdir(exist_ok=False)
    except BaseException:
        remove_benchmark_artifacts(screen_root, keep_artifacts=args.keep_artifacts)
        raise
    environment["TMPDIR"] = str(temporary_directory)
    samples: dict[str, list[dict[str, Any]]] = {linker.name: [] for linker in linkers}
    resource_samples: dict[str, list[dict[str, Any]]] = {linker.name: [] for linker in linkers}
    cache_contexts: dict[str, dict[str, Any]] = {}
    try:
        if args.stable_layout_cache:
            assert baseline_output is not None
            # Establish each candidate's own cache state once, outside the timed replay. Each
            # timed changed replay restores this exact image and sidecar tree before its clock
            # starts; cache restoration is a harness action, not a link-time result.
            for candidate in candidates:
                cache_root = screen_root / candidate.name / "stable-layout-cache"
                baseline_replay = direct_capture_replay_command(baseline_command, candidate)
                baseline_replay.extend(candidate_arguments[candidate.name])
                baseline_replay.extend(["-incremental_cache", str(cache_root)])
                changed_replay = direct_capture_replay_command(command, candidate)
                changed_replay.extend(candidate_arguments[candidate.name])
                changed_replay.extend(["-incremental_cache", str(cache_root)])
                if not args.no_wild_timing_json:
                    changed_replay = with_wild_timing_json(changed_replay, candidate)
                cache_environment = dict(environment)
                cache_environment.update(candidate_environments[candidate.name])
                cache_environment["WILD_MACHO_INCREMENTAL_CACHE_DIAGNOSTICS"] = "1"
                baseline_setup = establish_cache_direct_baseline(
                    command=baseline_replay,
                    environment=cache_environment,
                    output_dir=screen_root / candidate.name / "cache-baseline-setup",
                    linker=candidate,
                    expected_file_type=file_type,
                    runtime=runtime,
                    runtime_cwd=runtime_cwd,
                    baseline_output=baseline_output,
                )
                baseline_output_snapshot = screen_root / candidate.name / "cache-baseline-output"
                shutil.copy2(baseline_output, baseline_output_snapshot)
                cache_snapshot = screen_root / candidate.name / "cache-baseline-sidecars"
                shutil.copytree(cache_root, cache_snapshot, copy_function=copy2_preserving_xattrs)
                changed_output = Path(changed_replay[changed_replay.index("-o") + 1])
                cache_contexts[candidate.name] = {
                    "environment": cache_environment,
                    "command": changed_replay,
                    "cache_root": cache_root,
                    "cache_snapshot": cache_snapshot,
                    "baseline_output": baseline_output,
                    "baseline_output_snapshot": baseline_output_snapshot,
                    "changed_output": changed_output,
                    "baseline_setup": baseline_setup,
                }
        # Rotate the full linker order, including Apple, so systematic thermal drift cannot always
        # favour the same position. Each call owns its own output path and never mutates capture.
        for repetition in range(args.repetitions):
            offset = repetition % len(linkers)
            for linker in [*linkers[offset:], *linkers[:offset]]:
                cache_context = cache_contexts.get(linker.name)
                if cache_context is not None:
                    samples[linker.name].extend(
                        replay_final_link(
                            command=cache_context["command"],
                            environment=cache_context["environment"],
                            output_dir=screen_root / linker.name / f"timing-{repetition}",
                            linker=linker,
                            repetitions=1,
                            expected_file_type=file_type,
                            runtime=runtime,
                            runtime_cwd=runtime_cwd,
                            fixed_output=cache_context["changed_output"],
                            prepare_replay=lambda context=cache_context: restore_cached_direct_baseline(
                                baseline_output=context["baseline_output"],
                                baseline_output_snapshot=context["baseline_output_snapshot"],
                                cache_dir=context["cache_root"],
                                cache_snapshot=context["cache_snapshot"],
                                stale_published_output=context["changed_output"],
                            ),
                            require_stable_layout_cache_hit=True,
                        )
                    )
                    continue
                replay_command = direct_capture_replay_command(command, linker)
                replay_command.extend(candidate_arguments.get(linker.name, []))
                if linker.path is not None and not args.no_wild_timing_json:
                    replay_command = with_wild_timing_json(replay_command, linker)
                linker_environment = dict(environment)
                linker_environment.update(candidate_environments.get(linker.name, {}))
                samples[linker.name].extend(
                    replay_final_link(
                        command=replay_command,
                        environment=linker_environment,
                        output_dir=screen_root / linker.name / f"timing-{repetition}",
                        linker=linker,
                        repetitions=1,
                        expected_file_type=file_type,
                        runtime=runtime,
                        runtime_cwd=runtime_cwd,
                    )
                )
        for linker in linkers:
            cache_context = cache_contexts.get(linker.name)
            if cache_context is not None:
                resource_samples[linker.name] = replay_final_link(
                    command=cache_context["command"],
                    environment=cache_context["environment"],
                    output_dir=screen_root / linker.name / "resources",
                    linker=linker,
                    repetitions=args.resource_repetitions,
                    expected_file_type=file_type,
                    runtime=runtime,
                    runtime_cwd=runtime_cwd,
                    fixed_output=cache_context["changed_output"],
                    prepare_replay=lambda context=cache_context: restore_cached_direct_baseline(
                        baseline_output=context["baseline_output"],
                        baseline_output_snapshot=context["baseline_output_snapshot"],
                        cache_dir=context["cache_root"],
                        cache_snapshot=context["cache_snapshot"],
                        stale_published_output=context["changed_output"],
                    ),
                    require_stable_layout_cache_hit=True,
                    measure_resources=True,
                )
                continue
            replay_command = direct_capture_replay_command(command, linker)
            replay_command.extend(candidate_arguments.get(linker.name, []))
            linker_environment = dict(environment)
            linker_environment.update(candidate_environments.get(linker.name, {}))
            resource_samples[linker.name] = replay_final_link(
                command=replay_command,
                environment=linker_environment,
                output_dir=screen_root / linker.name / "resources",
                linker=linker,
                repetitions=args.resource_repetitions,
                expected_file_type=file_type,
                runtime=runtime,
                runtime_cwd=runtime_cwd,
                measure_resources=True,
            )
        apple_median = median_ns(samples["apple-ld64"])
        result = {
            "schema_version": SCREEN_SCHEMA_VERSION,
            "capture": {
                "manifest": str(capture_path),
                "source": capture["source"],
                "workload": capture["workload"],
                "input_count": len(input_records),
                "baseline_input_count": (
                    len(baseline_input_records) if args.stable_layout_cache else None
                ),
            },
            "stable_layout_cache": {
                "enabled": args.stable_layout_cache,
                "candidates": {
                    name: {"baseline_setup": context["baseline_setup"]}
                    for name, context in cache_contexts.items()
                },
            },
            "artifacts_retained": args.keep_artifacts,
            "samples": samples,
            "resource_samples": resource_samples,
            "comparison": {
                "apple_ld64_median_ns": apple_median,
                "candidates": {
                    candidate.name: {
                        "path": str(candidate.path),
                        "sha256": sha256_file(candidate.path),
                        "environment": candidate_environments[candidate.name],
                        "arguments": candidate_arguments[candidate.name],
                        "median_ns": median_ns(samples[candidate.name]),
                        "wild_over_apple": median_ns(samples[candidate.name]) / apple_median,
                    }
                    for candidate in candidates
                },
            },
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result["comparison"], indent=2, sort_keys=True))
        return 0
    finally:
        remove_benchmark_artifacts(screen_root, keep_artifacts=args.keep_artifacts)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"direct screen failed: {error}", file=sys.stderr)
        raise SystemExit(2)
