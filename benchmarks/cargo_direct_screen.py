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

from cargo_link_benchmark_impl import DIRECT_CAPTURE_SCHEMA_VERSION
from cargo_link_benchmark_impl import Linker
from cargo_link_benchmark_impl import RuntimeCheck
from cargo_link_benchmark_impl import direct_capture_replay_command
from cargo_link_benchmark_impl import replay_final_link
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
    parser.add_argument("--keep-artifacts", action="store_true")
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
    if raw.get("schema_version") != DIRECT_CAPTURE_SCHEMA_VERSION:
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
    return raw, list(command), records, runtime_cwd, file_type, runtime, dict(environment)


def median_ns(samples: list[dict[str, Any]]) -> int:
    return int(statistics.median(sample["elapsed_ns"] for sample in samples))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.repetitions < 1 or args.resource_repetitions < 1:
        raise ValueError("--repetitions and --resource-repetitions must be positive")
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite screen result: {output}")
    screen_root = output.with_suffix("").with_name(f"{output.stem}-artifacts")
    if screen_root.exists():
        raise FileExistsError(f"refusing to overwrite screen artifacts: {screen_root}")
    capture_path = args.capture.resolve()
    capture, command, input_records, runtime_cwd, file_type, runtime, environment = load_capture(capture_path)
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
    temporary_directory.mkdir(exist_ok=False)
    environment["TMPDIR"] = str(temporary_directory)
    samples: dict[str, list[dict[str, Any]]] = {linker.name: [] for linker in linkers}
    resource_samples: dict[str, list[dict[str, Any]]] = {linker.name: [] for linker in linkers}
    succeeded = False
    try:
        # Rotate the full linker order, including Apple, so systematic thermal drift cannot always
        # favour the same position. Each call owns its own output path and never mutates capture.
        for repetition in range(args.repetitions):
            offset = repetition % len(linkers)
            for linker in [*linkers[offset:], *linkers[:offset]]:
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
        succeeded = True
        print(json.dumps(result["comparison"], indent=2, sort_keys=True))
        return 0
    finally:
        if succeeded and not args.keep_artifacts:
            shutil.rmtree(screen_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"direct screen failed: {error}", file=sys.stderr)
        raise SystemExit(2)
