"""Stdlib tests for the Cargo-link benchmark's safety-critical helpers."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("cargo_link_benchmark_impl.py")
SPEC = importlib.util.spec_from_file_location("cargo_link_benchmark_impl", MODULE_PATH)
assert SPEC and SPEC.loader
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)

SCREEN_MODULE_PATH = Path(__file__).with_name("cargo_direct_screen.py")
SCREEN_SPEC = importlib.util.spec_from_file_location("cargo_direct_screen", SCREEN_MODULE_PATH)
assert SCREEN_SPEC and SCREEN_SPEC.loader
SCREEN = importlib.util.module_from_spec(SCREEN_SPEC)
sys.modules[SCREEN_SPEC.name] = SCREEN
SCREEN_SPEC.loader.exec_module(SCREEN)


class CargoLinkBenchmarkTests(unittest.TestCase):
    def test_default_wild_path_uses_arm64_dist_artifact(self) -> None:
        self.assertEqual(
            BENCHMARK.default_wild_path().as_posix().split("/target/")[-1],
            "aarch64-apple-darwin/dist/wild",
        )

    def test_copy_workspace_can_use_a_configured_scratch_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Cargo.toml").write_text("[package]\nname = 'fixture'\n")
            (source / ".git").mkdir()
            (source / "target").mkdir()
            scratch_root = root / "scratch"

            copied = BENCHMARK.copy_workspace_to_scratch(source, scratch_root)

            self.assertTrue(copied.is_relative_to(scratch_root))
            self.assertEqual((copied / "Cargo.toml").read_text(), "[package]\nname = 'fixture'\n")
            self.assertFalse((copied / ".git").exists())
            self.assertFalse((copied / "target").exists())

    def test_sanitized_environment_uses_configured_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_directory = Path(temporary) / "compiler-tmp"

            environment = BENCHMARK.sanitized_environment(
                clang=Path("/tmp/clang"),
                sdk="/tmp/sdk",
                wild=None,
                deployment_target="15.0",
                temporary_directory=temporary_directory,
            )

            self.assertEqual(environment["TMPDIR"], str(temporary_directory))
            self.assertTrue(temporary_directory.is_dir())

    def test_benchmark_output_paths_must_be_cache_owned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache_root = root / "cache" / "wild"
            owned = cache_root / "reports" / "result.json"

            self.assertEqual(
                BENCHMARK.require_benchmark_cache_path(owned, cache_root=cache_root),
                owned.resolve(),
            )
            with self.assertRaisesRegex(ValueError, "cache-owned"):
                BENCHMARK.require_benchmark_cache_path(
                    root / "outside" / "result.json", cache_root=cache_root
                )

    def test_artifact_cleanup_is_opt_in_for_retention(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / "cache" / "wild"
            artifacts = cache_root / "artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / "raw.log").write_text("benchmark output")

            BENCHMARK.remove_benchmark_artifacts(
                artifacts, keep_artifacts=False, cache_root=cache_root
            )
            self.assertFalse(artifacts.exists())

            artifacts.mkdir()
            BENCHMARK.remove_benchmark_artifacts(
                artifacts, keep_artifacts=True, cache_root=cache_root
            )
            self.assertTrue(artifacts.exists())

    def test_failed_direct_capture_removes_its_partial_cache_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache_root = root / "cache" / "wild"
            capture_root = cache_root / "captures" / "partial"

            with patch.object(BENCHMARK, "default_benchmark_cache_root", return_value=cache_root):
                with self.assertRaises(FileNotFoundError):
                    BENCHMARK.capture_incremental_direct_inputs(
                        source=root / "missing-source",
                        capture_root=capture_root,
                        command=[],
                        workload=None,
                        environment={},
                        linker=BENCHMARK.Linker("apple-ld64", None),
                        source_revision="revision",
                        cargo_lock_sha256="lock",
                        toolchain={},
                    )

            self.assertFalse(capture_root.exists())

    def test_parse_toolchain_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rust-toolchain.toml"
            path.write_text('[toolchain]\nchannel = "nightly-2026-07-24"\n')
            self.assertEqual(BENCHMARK.parse_toolchain_channel(path), "nightly-2026-07-24")

    def test_direct_capture_records_and_verifies_linker_file_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "cargo"
            first_input = root / "first.o"
            second_input = root / "libsecond.rlib"
            first_input.write_bytes(b"first input")
            second_input.write_bytes(b"second input")
            command = [
                "/usr/bin/ld",
                "-o",
                str(output),
                str(first_input),
                "-framework",
                "Foundation",
                str(second_input),
            ]

            records = BENCHMARK.direct_capture_input_records(command)

            self.assertEqual(
                [record["path"] for record in records],
                [str(first_input.resolve()), str(second_input.resolve())],
            )
            BENCHMARK.verify_direct_capture_input_records(records)
            second_input.write_bytes(b"altered data")
            with self.assertRaisesRegex(ValueError, "digest changed"):
                BENCHMARK.verify_direct_capture_input_records(records)

    def test_direct_capture_replaces_only_the_linker_executable_for_a_candidate(self) -> None:
        command = ["/usr/bin/ld", "-o", "/tmp/cargo", "/tmp/input.o"]

        replay = BENCHMARK.direct_capture_replay_command(
            command, BENCHMARK.Linker("candidate", Path("/tmp/wild-candidate"))
        )

        self.assertEqual(replay, ["/tmp/wild-candidate", "-o", "/tmp/cargo", "/tmp/input.o"])
        self.assertEqual(
            BENCHMARK.direct_capture_replay_command(
                command, BENCHMARK.Linker("apple-ld64", None)
            ),
            command,
        )

    def test_direct_screen_candidates_are_cache_path_safe_and_support_wild_settings(self) -> None:
        self.assertEqual(
            SCREEN.parse_candidate("groups-96=/tmp/wild"),
            ("groups-96", Path("/tmp/wild")),
        )
        self.assertEqual(
            SCREEN.parse_candidate_environment("groups-96=WILD_FILES_PER_GROUP=96"),
            ("groups-96", "WILD_FILES_PER_GROUP", "96"),
        )
        self.assertEqual(
            SCREEN.parse_candidate_argument("threads-8=--threads=8"),
            ("threads-8", "--threads=8"),
        )
        for value in ("../escape=/tmp/wild", "nested/name=/tmp/wild", "candidate=relative/wild"):
            with self.assertRaisesRegex(argparse.ArgumentTypeError, "candidate"):
                SCREEN.parse_candidate(value)
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "WILD_"):
            SCREEN.parse_candidate_environment("groups-96=PATH=/bin")
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "long linker"):
            SCREEN.parse_candidate_argument("threads-8=-threads=8")

    def test_linker_selection_accepts_xcode_response_file_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "link.log"
            path.write_text(
                '         "/Applications/Xcode.app/Contents/Developer/Toolchains/'
                'XcodeDefault.xctoolchain/usr/bin/ld" @/var/folders/response.txt\n'
            )
            evidence = BENCHMARK.linker_selection_evidence(
                path, BENCHMARK.Linker(name="apple-ld64", path=None)
            )
            self.assertEqual(len(evidence), 1)

    def test_load_workload_keeps_target_and_goals_in_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "other-repository",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "other"],
                  "artifact": "{target}/{profile}/other",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": ["--version"], "stdout_contains": "other "},
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            workload = BENCHMARK.load_workload(path)
            self.assertEqual(workload.name, "other-repository")
            self.assertEqual(workload.cargo_arguments, ("--bin", "other"))
            self.assertEqual(workload.incremental_max, 0.5)

    def test_load_workload_allows_incremental_only_normal_link_goals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "normal-incremental",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "normal"],
                  "artifact": "{target}/{profile}/normal",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": ["--version"], "stdout_contains": "normal "},
                  "stable_layout_cache_eligible": false,
                  "goals": {
                    "incremental_cargo_wild_over_apple_max": 1.0,
                    "incremental_link_wild_over_apple_max": 1.0
                  }
                }"""
            )

            workload = BENCHMARK.load_workload(path)

        self.assertIsNone(workload.cold_max)
        self.assertIsNone(workload.incremental_max)
        self.assertEqual(workload.incremental_cargo_max, 1.0)
        self.assertEqual(workload.incremental_link_max, 1.0)

    def test_load_workload_can_pin_toolchain_without_a_source_toolchain_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "cargo",
                  "toolchain": "nightly-2026-07-24",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "cargo"],
                  "artifact": "{target}/{profile}/cargo",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/version.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": ["--version"], "stdout_contains": "cargo "},
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            self.assertEqual(BENCHMARK.load_workload(path).toolchain, "nightly-2026-07-24")

    def test_load_workload_can_exclude_a_normal_link_topology_from_cache_goals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "native-static-library",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "native"],
                  "artifact": "{target}/{profile}/native",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": [], "output": "exit"},
                  "stable_layout_cache_eligible": false,
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            workload = BENCHMARK.load_workload(path)
            self.assertFalse(workload.stable_layout_cache_eligible)

    def test_mutation_is_restored_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "cargo.rs"
            original = b"fn main() {}\n"
            path.write_bytes(original)
            before, after = BENCHMARK.mutate_incremental_source(
                path,
                BENCHMARK.SourceMutation(
                    path="cargo.rs", append=b"\n// benchmark incremental marker\n"
                ),
            )
            self.assertEqual(before, hashlib.sha256(original).hexdigest())
            self.assertNotEqual(before, after)
            self.assertEqual(BENCHMARK.restore_source(path, original, before), before)
            self.assertEqual(path.read_bytes(), original)

    def test_replacement_mutation_requires_one_exact_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "main.rs"
            original = b'fn main() { println!("e"); }\n'
            path.write_bytes(original)
            mutation = BENCHMARK.SourceMutation(
                path="src/main.rs", replace_before=b'println!("e")', replace_after=b'println!("E")'
            )
            before, _ = BENCHMARK.mutate_incremental_source(path, mutation)
            self.assertEqual(path.read_bytes(), b'fn main() { println!("E"); }\n')
            BENCHMARK.restore_source(path, original, before)
            self.assertEqual(path.read_bytes(), original)

    def test_comparison_enforces_both_goals(self) -> None:
        runs = [
            {
                "sample": 0,
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "cold_link": {
                    "samples": [
                        {
                            "elapsed_ns": 40,
                            "peak_rss_bytes": 120,
                            "user_cpu_ns": 31,
                            "system_cpu_ns": 9,
                            "disk_usage": {
                                "output": {"apparent_bytes": 80, "allocated_bytes": 96},
                                "incremental_cache": None,
                            },
                            "transient_disk_usage": {
                                "peak_transient": {
                                    "apparent_bytes": 8,
                                    "allocated_bytes": 16,
                                },
                                "complete": True,
                            },
                        }
                    ]
                },
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {
                    "samples": [
                        {
                            "elapsed_ns": 20,
                            "peak_rss_bytes": 100,
                            "user_cpu_ns": 15,
                            "system_cpu_ns": 5,
                            "disk_usage": {
                                "output": {"apparent_bytes": 80, "allocated_bytes": 96},
                                "incremental_cache": None,
                            },
                            "transient_disk_usage": {
                                "peak_transient": {
                                    "apparent_bytes": 8,
                                    "allocated_bytes": 16,
                                },
                                "complete": True,
                            },
                        }
                    ]
                },
            },
            {
                "sample": 0,
                "linker": "wild",
                "cold": {"elapsed_ns": 105},
                "cold_link": {
                    "samples": [
                        {
                            "elapsed_ns": 30,
                            "peak_rss_bytes": 60,
                            "user_cpu_ns": 20,
                            "system_cpu_ns": 5,
                            "disk_usage": {
                                "output": {"apparent_bytes": 100, "allocated_bytes": 128},
                                "incremental_cache": None,
                            },
                            "transient_disk_usage": {
                                "peak_transient": {
                                    "apparent_bytes": 20,
                                    "allocated_bytes": 32,
                                },
                                "complete": True,
                            },
                        }
                    ]
                },
                "incremental": {"elapsed_ns": 25},
                "incremental_link": {
                    "samples": [
                        {
                            "elapsed_ns": 10,
                            "peak_rss_bytes": 50,
                            "user_cpu_ns": 7,
                            "system_cpu_ns": 3,
                            "disk_usage": {
                                "output": {"apparent_bytes": 100, "allocated_bytes": 128},
                                "incremental_cache": {
                                    "apparent_bytes": 150,
                                    "allocated_bytes": 160,
                                },
                            },
                            "transient_disk_usage": {
                                "peak_transient": {
                                    "apparent_bytes": 20,
                                    "allocated_bytes": 32,
                                },
                                "complete": True,
                            },
                        }
                    ]
                },
            },
        ]
        workload = BENCHMARK.Workload(
            name="test",
            target="aarch64-apple-darwin",
            profile="release",
            cargo_arguments=("--bin", "test"),
            artifact="{target}/{profile}/test",
            macho_file_type=2,
            mutation=BENCHMARK.SourceMutation(path="src/main.rs", append=b"\n// test\n"),
            cold_max=1.05,
            incremental_max=0.5,
            deployment_target="11.0",
            runtime=BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="test "),
        )
        result = BENCHMARK.comparison(runs, workload)
        self.assertTrue(result["goals_met"])
        self.assertEqual(result["cold_wild_over_apple"], 1.05)
        self.assertEqual(result["cold_link_wild_over_apple"], 0.75)
        self.assertEqual(result["incremental_cargo_wild_over_apple"], 0.5)
        self.assertEqual(result["incremental_link_wild_over_apple"], 0.5)
        self.assertEqual(result["medians_ns"]["apple-ld64"]["cold_link"], 40)
        self.assertEqual(result["medians_ns"]["wild"]["cold_link"], 30)
        self.assertEqual(
            result["paired_wild_over_apple"]["cold_link"],
            {"ratios": [{"sample": 0, "wild_over_apple": 0.75}], "median": 0.75},
        )
        self.assertEqual(result["cold_link_peak_rss_bytes"], {"apple-ld64": 120, "wild": 60})
        self.assertEqual(result["cold_link_peak_rss_wild_over_apple"], 0.5)
        self.assertEqual(result["incremental_link_peak_rss_bytes"], {"apple-ld64": 100, "wild": 50})
        self.assertEqual(result["incremental_link_peak_rss_wild_over_apple"], 0.5)
        self.assertEqual(
            result["incremental_link_cpu_ns"],
            {
                "user_cpu_ns": {"apple-ld64": 15, "wild": 7},
                "system_cpu_ns": {"apple-ld64": 5, "wild": 3},
            },
        )
        self.assertEqual(
            result["incremental_link_disk_usage_bytes"],
            {
                "output": {
                    "apparent_bytes": {"apple-ld64": 80, "wild": 100},
                    "allocated_bytes": {"apple-ld64": 96, "wild": 128},
                },
                "incremental_cache": {
                    "apparent_bytes": {"apple-ld64": None, "wild": 150},
                    "allocated_bytes": {"apple-ld64": None, "wild": 160},
                },
            },
        )
        self.assertEqual(
            result["incremental_link_wild_cache_bytes_per_output_byte"],
            {"apparent_bytes": 1.5, "allocated_bytes": 1.25},
        )
        self.assertEqual(
            result["incremental_link_peak_transient_working_directory_bytes"],
            {
                "apparent_bytes": {"apple-ld64": 8, "wild": 20},
                "allocated_bytes": {"apple-ld64": 16, "wild": 32},
            },
        )

    def test_comparison_aggregates_cache_hit_rate_and_miss_reasons(self) -> None:
        runs = [
            {
                "sample": 0,
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "cold_link": {"samples": [{"elapsed_ns": 40}]},
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {"samples": [{"elapsed_ns": 20}]},
            },
            {
                "sample": 0,
                "linker": "wild",
                "cold": {"elapsed_ns": 100},
                "cold_link": {"samples": [{"elapsed_ns": 30}]},
                "incremental": {
                    "elapsed_ns": 50,
                    "cache_setup_misses": [
                        "wild: Mach-O stable-layout cache miss: image state is absent"
                    ],
                    "stable_layout_cache_hits": ["wild: Mach-O stable-layout cache hit: /tmp/e"],
                },
                "incremental_link": {
                    "cache": {
                        "capture_hits": ["wild: Mach-O stable-layout cache hit: /tmp/e"]
                    },
                    "samples": [
                        {
                            "elapsed_ns": 10,
                            "stable_layout_cache_hits": [
                                "wild: Mach-O stable-layout cache hit: /tmp/e"
                            ],
                        }
                    ],
                },
            },
        ]
        workload = BENCHMARK.Workload(
            name="test",
            target="aarch64-apple-darwin",
            profile="release",
            cargo_arguments=("--bin", "test"),
            artifact="{target}/{profile}/test",
            macho_file_type=2,
            mutation=BENCHMARK.SourceMutation(path="src/main.rs", append=b"\n// test\n"),
            cold_max=1.05,
            incremental_max=0.5,
            deployment_target="11.0",
            runtime=BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="test "),
        )
        result = BENCHMARK.comparison(runs, workload)
        self.assertEqual(result["cache"]["hit_count"], 3)
        self.assertEqual(result["cache"]["miss_count"], 1)
        self.assertEqual(result["cache"]["hit_rate"], 0.75)
        self.assertEqual(result["cache"]["miss_reasons"], {"image state is absent": 1})

    def test_comparison_does_not_apply_cache_link_goal_to_ineligible_topology(self) -> None:
        runs = [
            {
                "sample": 0,
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "cold_link": {"samples": [{"elapsed_ns": 40}]},
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {"samples": [{"elapsed_ns": 20}]},
            },
            {
                "sample": 0,
                "linker": "wild",
                "cold": {"elapsed_ns": 105},
                "cold_link": {"samples": [{"elapsed_ns": 30}]},
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {"samples": [{"elapsed_ns": 30}]},
            },
        ]
        workload = BENCHMARK.Workload(
            name="native-static-library",
            target="aarch64-apple-darwin",
            profile="release",
            cargo_arguments=("--bin", "native"),
            artifact="{target}/{profile}/native",
            macho_file_type=BENCHMARK.MH_EXECUTE,
            mutation=BENCHMARK.SourceMutation(path="src/main.rs", append=b"\n// test\n"),
            cold_max=1.05,
            incremental_max=0.5,
            deployment_target="11.0",
            runtime=BENCHMARK.RuntimeCheck(arguments=(), output_mode="exit"),
            stable_layout_cache_eligible=False,
        )

        result = BENCHMARK.comparison(runs, workload)

        self.assertEqual(result["incremental_link_wild_over_apple"], 1.5)
        self.assertIsNone(result["thresholds"]["incremental_max"])
        self.assertTrue(result["goals_met"])

    def test_comparison_applies_explicit_normal_incremental_goals(self) -> None:
        runs = [
            {
                "sample": 0,
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "cold_link": {"samples": [{"elapsed_ns": 40}]},
                "incremental": {"elapsed_ns": 100},
                "incremental_link": {"samples": [{"elapsed_ns": 20}]},
            },
            {
                "sample": 0,
                "linker": "wild",
                "cold": {"elapsed_ns": 160},
                "cold_link": {"samples": [{"elapsed_ns": 30}]},
                "incremental": {"elapsed_ns": 101},
                "incremental_link": {"samples": [{"elapsed_ns": 19}]},
            },
        ]
        workload = BENCHMARK.Workload(
            name="normal-incremental",
            target="aarch64-apple-darwin",
            profile="release",
            cargo_arguments=("--bin", "normal"),
            artifact="{target}/{profile}/normal",
            macho_file_type=BENCHMARK.MH_EXECUTE,
            mutation=BENCHMARK.SourceMutation(path="src/main.rs", append=b"\n// test\n"),
            cold_max=None,
            incremental_max=None,
            deployment_target="11.0",
            runtime=BENCHMARK.RuntimeCheck(arguments=(), output_mode="exit"),
            stable_layout_cache_eligible=False,
            incremental_cargo_max=1.0,
            incremental_link_max=1.0,
        )

        result = BENCHMARK.comparison(runs, workload)

        self.assertEqual(result["thresholds"]["incremental_cargo_max"], 1.0)
        self.assertEqual(result["thresholds"]["incremental_link_max"], 1.0)
        self.assertFalse(result["goals_met"])

        runs[1]["incremental"]["elapsed_ns"] = 99
        runs[1]["incremental_link"]["samples"][0]["elapsed_ns"] = 21

        self.assertFalse(BENCHMARK.comparison(runs, workload)["goals_met"])

    def test_extracts_shell_quoted_final_linker_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cargo.log"
            log.write_text(
                '  "/Applications/Xcode.app/usr/bin/ld" -dynamic -arch arm64 '
                '-o "/tmp/output with spaces" /tmp/input.o\n'
            )
            command = BENCHMARK.final_link_command(log, BENCHMARK.Linker("apple-ld64", None))
            self.assertEqual(command[0], "/Applications/Xcode.app/usr/bin/ld")
            self.assertEqual(command[command.index("-o") + 1], "/tmp/output with spaces")

    def test_extracts_response_file_final_linker_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cargo.log"
            log.write_text(
                '         "/Applications/Xcode.app/usr/bin/ld" @/tmp/response.txt\n'
                "         Arguments passed via response file:\n"
                '         "-dynamic" "-arch" "arm64" "-o" "/tmp/output" "/tmp/input.o"\n'
            )
            command = BENCHMARK.final_link_command(log, BENCHMARK.Linker("apple-ld64", None))
            self.assertEqual(command[0], "/Applications/Xcode.app/usr/bin/ld")
            self.assertEqual(command[command.index("-o") + 1], "/tmp/output")

    def test_cargo_final_output_matches_hyphenated_binary_dep_output(self) -> None:
        cargo_artifact = Path("/tmp/target/aarch64-apple-darwin/release/cargo-macho-native-cpp")
        linker_output = Path(
            "/tmp/target/aarch64-apple-darwin/release/deps/"
            "cargo_macho_native_cpp-0123456789abcdef"
        )

        self.assertTrue(BENCHMARK.cargo_final_output_matches(linker_output, cargo_artifact))

    def test_opt_in_cache_flags_and_hit_evidence_are_explicit(self) -> None:
        environment = BENCHMARK.with_wild_incremental_cache(
            {"RUSTFLAGS": "-C linker=/tmp/clang"}, Path("/tmp/wild-cache")
        )
        self.assertIn("-C link-arg=-Wl,-incremental_cache", environment["RUSTFLAGS"])
        self.assertIn("-C link-arg=-Wl,/tmp/wild-cache", environment["RUSTFLAGS"])
        self.assertEqual(environment["WILD_MACHO_INCREMENTAL_CACHE_DIAGNOSTICS"], "1")
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "link.log"
            log.write_text(
                "normal linker output\n"
                "         wild: Mach-O stable-layout cache hit: /tmp/e\n"
            )
            self.assertEqual(
                BENCHMARK.stable_layout_cache_hit_evidence(log),
                ["wild: Mach-O stable-layout cache hit: /tmp/e"],
            )
            log.write_text("wild: Mach-O stable-layout cache miss: image state is absent\n")
            self.assertEqual(
                BENCHMARK.stable_layout_cache_miss_evidence(log),
                ["wild: Mach-O stable-layout cache miss: image state is absent"],
            )

    def test_wild_timing_is_added_only_to_a_direct_wild_replay(self) -> None:
        command = ["/tmp/linker", "-o", "/tmp/e", "/tmp/e.o"]
        self.assertEqual(
            BENCHMARK.with_wild_timing_json(command, BENCHMARK.Linker("apple-ld64", None)),
            command,
        )
        self.assertEqual(
            BENCHMARK.with_wild_timing_json(command, BENCHMARK.Linker("wild", Path("/tmp/wild"))),
            [*command, "--time=json"],
        )
        environment = BENCHMARK.sanitized_environment(
            clang=Path("/tmp/clang"),
            sdk="/tmp/sdk",
            wild=Path("/tmp/wild"),
            deployment_target="11.0",
        )
        self.assertNotIn("--time=json", environment["RUSTFLAGS"])

    def test_macos_time_peak_rss_parser_requires_the_resource_record(self) -> None:
        report = (
            "        42  voluntary context switches\n"
            "  73400320  maximum resident set size\n"
        )
        self.assertEqual(BENCHMARK.macos_time_peak_rss_bytes(report), 73_400_320)
        self.assertIsNone(BENCHMARK.macos_time_peak_rss_bytes("no resource report\n"))

    def test_macos_time_cpu_parser_reads_child_user_and_system_time(self) -> None:
        report = "        2.34 real         1.25 user         0.50 sys\n"
        self.assertEqual(
            BENCHMARK.macos_time_cpu_ns(report),
            {"user_cpu_ns": 1_250_000_000, "system_cpu_ns": 500_000_000},
        )
        self.assertIsNone(BENCHMARK.macos_time_cpu_ns("no resource report\n"))

    def test_resource_replay_disables_wild_forking_only(self) -> None:
        command = ["/tmp/linker", "-o", "/tmp/e", "/tmp/e.o"]
        self.assertEqual(
            BENCHMARK.resource_replay_command(command, BENCHMARK.Linker("apple-ld64", None)),
            command,
        )
        self.assertEqual(
            BENCHMARK.resource_replay_command(command, BENCHMARK.Linker("wild", Path("/tmp/wild"))),
            [*command, "--no-fork"],
        )
        self.assertEqual(
            BENCHMARK.resource_replay_command(
                command, BENCHMARK.Linker("groups-96", Path("/tmp/wild"))
            ),
            [*command, "--no-fork"],
        )

    def test_path_disk_usage_reports_apparent_and_allocated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            cache.mkdir()
            (cache / "manifest").write_bytes(b"cache bytes")
            usage = BENCHMARK.path_disk_usage_bytes(cache)
            self.assertEqual(usage["apparent_bytes"], len(b"cache bytes"))
            self.assertGreaterEqual(usage["allocated_bytes"], usage["apparent_bytes"])

    def test_direct_replay_working_roots_exclude_nested_paths(self) -> None:
        output = Path("/tmp/target/deps/e")
        self.assertEqual(
            BENCHMARK.direct_replay_working_roots(output, Path("/tmp/target/deps/cache")),
            (Path("/tmp/target/deps"),),
        )
        self.assertEqual(
            BENCHMARK.direct_replay_working_roots(output, Path("/tmp/cache")),
            (Path("/tmp/target/deps"), Path("/tmp/cache")),
        )

    def test_peak_transient_disk_usage_excludes_baseline_and_published_bytes(self) -> None:
        self.assertEqual(
            BENCHMARK.peak_transient_disk_usage_bytes(
                {"apparent_bytes": 100, "allocated_bytes": 128},
                {"apparent_bytes": 180, "allocated_bytes": 224},
                {"apparent_bytes": 140, "allocated_bytes": 160},
            ),
            {"apparent_bytes": 40, "allocated_bytes": 64},
        )

    def test_incomplete_transient_disk_measurement_is_not_medianed(self) -> None:
        self.assertEqual(
            BENCHMARK.median_transient_disk_usage_bytes(
                [
                    {
                        "transient_disk_usage": {
                            "peak_transient": {"apparent_bytes": 8, "allocated_bytes": 16},
                            "complete": False,
                        }
                    }
                ]
            ),
            {"apparent_bytes": None, "allocated_bytes": None},
        )

    def test_cache_baseline_replays_the_raw_linker_output_after_cargo_postprocessing(self) -> None:
        """The direct cache image must match Wild's raw output, not Cargo's stripped artifact."""
        baseline_output = Path("/tmp/e-raw-link")
        baseline = {"elapsed_ns": 123}
        with patch.object(BENCHMARK, "replay_final_link", return_value=[baseline]) as replay:
            result = BENCHMARK.establish_cache_direct_baseline(
                command=["/tmp/wild", "-o", str(baseline_output), "/tmp/e.o"],
                environment={"RUSTFLAGS": "-C linker=/tmp/clang"},
                output_dir=Path("/tmp/cache-baseline-log"),
                linker=BENCHMARK.Linker("wild", Path("/tmp/wild")),
                expected_file_type=BENCHMARK.MH_EXECUTE,
                runtime=BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="e "),
                runtime_cwd=Path("/tmp"),
                baseline_output=baseline_output,
            )

        self.assertIs(result, baseline)
        replay.assert_called_once_with(
            command=["/tmp/wild", "-o", str(baseline_output), "/tmp/e.o"],
            environment={"RUSTFLAGS": "-C linker=/tmp/clang"},
            output_dir=Path("/tmp/cache-baseline-log"),
            linker=BENCHMARK.Linker("wild", Path("/tmp/wild")),
            repetitions=1,
            expected_file_type=BENCHMARK.MH_EXECUTE,
            runtime=BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="e "),
            runtime_cwd=Path("/tmp"),
            fixed_output=baseline_output,
        )

    def test_cargo_driver_can_be_pinned_independently_of_path(self) -> None:
        args = BENCHMARK.parse_args(
            [
                "--config",
                "workload.json",
                "--workspace",
                "/tmp/repository",
                "--output",
                "/tmp/result.json",
                "--scratch-root",
                "/tmp/benchmark-scratch",
                "--cargo",
                "/opt/homebrew/opt/rustup/bin/cargo",
            ]
        )
        self.assertEqual(args.cargo, Path("/opt/homebrew/opt/rustup/bin/cargo"))
        self.assertEqual(args.repetitions, 5)
        self.assertEqual(args.scratch_root, Path("/tmp/benchmark-scratch"))
        self.assertFalse(args.keep_artifacts)

    def test_artifact_retention_is_opt_in(self) -> None:
        args = BENCHMARK.parse_args(
            [
                "--config",
                "workload.json",
                "--workspace",
                "/tmp/repository",
                "--output",
                "/tmp/result.json",
                "--keep-artifacts",
            ]
        )

        self.assertTrue(args.keep_artifacts)

    def test_macho_header_rejects_wrong_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-arm64"
            path.write_bytes(bytes.fromhex("cffaedfe070000010000000002000000") + b"\0" * 16)
            with self.assertRaisesRegex(ValueError, "not ARM64"):
                BENCHMARK.parse_macho_arm64_executable(path)

    def test_load_workload_requires_runtime_output_expectation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "missing-runtime-output",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "test"],
                  "artifact": "{target}/{profile}/test",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": ["--version"]},
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            with self.assertRaisesRegex(ValueError, "stdout_contains or stderr_contains"):
                BENCHMARK.load_workload(path)

    def test_load_workload_allows_a_no_argument_runtime_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "no-argument-runtime",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--bin", "test"],
                  "artifact": "{target}/{profile}/test",
                  "macho_file_type": 2,
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "runtime": {"arguments": [], "stdout_contains": "ready"},
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            workload = BENCHMARK.load_workload(path)
            self.assertEqual(workload.runtime.arguments, ())

    def test_load_workload_supports_workspace_artifacts_and_proc_macro_dylib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "workspace-and-proc-macro",
                  "target": "aarch64-apple-darwin",
                  "profile": "release",
                  "cargo_arguments": ["--workspace"],
                  "incremental_mutation": {"path": "src/main.rs", "append": "\\n// marker\\n"},
                  "artifacts": [
                    {"path": "{target}/{profile}/app", "macho_file_type": 2,
                     "runtime": {"arguments": [], "output": "exit"}},
                    {"path": "{target}/{profile}/deps/libmacro-*.dylib", "macho_file_type": 6}
                  ],
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            workload = BENCHMARK.load_workload(path)
            self.assertEqual(len(workload.artifacts), 2)
            self.assertEqual(workload.artifacts[1].macho_file_type, BENCHMARK.MH_DYLIB)
            self.assertIsNone(workload.artifacts[1].runtime)
            self.assertEqual(workload.artifacts[0].runtime.output_mode, "exit")

    def test_host_workload_omits_cross_target_flag_for_proc_macros(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.json"
            path.write_text(
                """{
                  "schema_version": "cargo-link-workload/v1",
                  "name": "host-proc-macro",
                  "target": null,
                  "profile": "release",
                  "cargo_arguments": ["--package", "macro"],
                  "artifact": "{profile}/libmacro-*.dylib",
                  "macho_file_type": 6,
                  "incremental_mutation": {"path": "src/lib.rs", "append": "\\n// marker\\n"},
                  "runtime": null,
                  "goals": {"cold_wild_over_apple_max": 1.05, "incremental_wild_over_apple_max": 0.5}
                }"""
            )
            workload = BENCHMARK.load_workload(path)
            command = BENCHMARK.cargo_command(
                Path("cargo"), "nightly-2026-07-24", workload, offline=True
            )
            self.assertNotIn("--target", command)

    def test_resolve_artifact_requires_one_hashed_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            output_dir = target / "aarch64-apple-darwin" / "release" / "deps"
            output_dir.mkdir(parents=True)
            output = output_dir / "libmacro-abc.dylib"
            output.write_bytes(b"dylib")
            spec = BENCHMARK.ArtifactSpec(
                "{target}/{profile}/deps/libmacro-*.dylib", BENCHMARK.MH_DYLIB, None
            )
            self.assertEqual(
                BENCHMARK.resolve_artifact(
                    target,
                    spec,
                    target="aarch64-apple-darwin",
                    profile="release",
                ),
                output,
            )

    def test_final_link_command_can_select_workspace_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cargo.log"
            log.write_text(
                '"/usr/bin/ld" -arch arm64 -o /tmp/first /tmp/a.o\n'
                '"/usr/bin/ld" -arch arm64 -o /tmp/second /tmp/b.o\n'
            )
            command = BENCHMARK.final_link_command(
                log,
                BENCHMARK.Linker("apple-ld64", None),
                output=Path("/tmp/first"),
            )
            self.assertEqual(command[command.index("-o") + 1], "/tmp/first")

    def test_wild_timing_phases_keep_only_the_requested_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "wild.log"
            log.write_text(
                "not JSON\n"
                '{"schema_version":1,"event":"phase","output":"/tmp/other",'
                '"name":"Layout","wall_time_ns":50,"counters":[]}\n'
                '{"schema_version":1,"event":"phase","output":"/tmp/e",'
                '"name":"Layout","wall_time_ns":125,"counters":[{"name":"pages",'
                '"value":3}]}\n'
            )
            self.assertEqual(
                BENCHMARK.wild_timing_phases(log, Path("/tmp/e")),
                [
                    {
                        "name": "Layout",
                        "wall_time_ns": 125,
                        "counters": [{"name": "pages", "value": 3}],
                    }
                ],
            )

    def test_primary_artifact_path_uses_hashed_link_output_for_cargo_bin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            artifact = target / "aarch64-apple-darwin" / "release" / "e"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"validated Cargo artifact")
            link_output = artifact.parent / "deps" / "e-deadbeef"
            log = Path(temporary) / "cargo.log"
            log.write_text(f'"/usr/bin/ld" -arch arm64 -o "{link_output}" /tmp/e.o\n')
            workload = BENCHMARK.Workload(
                name="e",
                target="aarch64-apple-darwin",
                profile="release",
                cargo_arguments=("--bin", "e"),
                artifact="{target}/{profile}/e",
                macho_file_type=BENCHMARK.MH_EXECUTE,
                mutation=BENCHMARK.SourceMutation(path="src/main.rs", append=b"\n// marker\n"),
                cold_max=1.05,
                incremental_max=0.5,
                deployment_target="11.0",
                runtime=BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="e "),
            )

            self.assertEqual(
                BENCHMARK.primary_artifact_path(
                    target, workload, log, BENCHMARK.Linker("apple-ld64", None)
                ),
                link_output,
            )

    @patch.object(BENCHMARK.subprocess, "run")
    def test_runtime_check_removes_dyld_overrides_and_records_evidence(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = "e 0.1.13\n"
        run.return_value.stderr = ""
        runtime = BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="e ")
        evidence = BENCHMARK.run_runtime_check(
            Path("/tmp/e"),
            runtime,
            cwd=Path("/tmp/workspace"),
            environment={"PATH": "/usr/bin", "DYLD_LIBRARY_PATH": "/tmp/override"},
        )
        call_args, kwargs = run.call_args
        self.assertEqual(call_args[0], ["/tmp/e", "--version"])
        self.assertNotIn("DYLD_LIBRARY_PATH", kwargs["env"])
        self.assertEqual(evidence["dyld_overrides_removed"], ["DYLD_LIBRARY_PATH"])
        self.assertEqual(evidence["exit_code"], 0)

    @patch.object(BENCHMARK.subprocess, "run")
    def test_codesign_requires_strict_verification(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = "Executable=...\n"
        evidence = BENCHMARK.verify_codesign(Path("/tmp/e"))
        call_args, kwargs = run.call_args
        command = call_args[0]
        self.assertEqual(command[:3], ["codesign", "--verify", "--strict"])
        self.assertEqual(command[3], "--verbose=2")
        self.assertFalse(kwargs["check"])
        self.assertEqual(evidence["returncode"], 0)

    @patch.object(BENCHMARK.subprocess, "run")
    def test_codesign_rejects_failed_verification(self, run) -> None:
        run.return_value.returncode = 1
        run.return_value.stdout = "code object is not signed at all\n"
        with self.assertRaisesRegex(RuntimeError, "Strict codesign verification failed"):
            BENCHMARK.verify_codesign(Path("/tmp/unsigned"))

    @patch.object(BENCHMARK.subprocess, "run")
    def test_runtime_check_rejects_unexpected_output(self, run) -> None:
        run.return_value.returncode = 0
        run.return_value.stdout = "wrong output\n"
        run.return_value.stderr = ""
        runtime = BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="expected")
        with self.assertRaisesRegex(RuntimeError, "stdout did not contain"):
            BENCHMARK.run_runtime_check(
                Path("/tmp/e"),
                runtime,
                cwd=Path("/tmp"),
                environment={"PATH": "/usr/bin"},
            )

    @patch.object(BENCHMARK, "run_runtime_check")
    @patch.object(BENCHMARK, "verify_codesign")
    @patch.object(BENCHMARK, "parse_macho_arm64_executable")
    def test_validate_artifact_orders_header_codesign_and_runtime(
        self, parse_macho, verify, runtime
    ) -> None:
        parse_macho.return_value = {"size_bytes": 12}
        verify.return_value = {"returncode": 0}
        runtime.return_value = {"exit_code": 0}
        check = BENCHMARK.RuntimeCheck(arguments=("--version",), stdout_contains="test")
        evidence = BENCHMARK.validate_artifact(
            Path("/tmp/test"),
            BENCHMARK.MH_EXECUTE,
            check,
            cwd=Path("/tmp"),
            environment={"PATH": "/usr/bin"},
        )
        self.assertEqual(evidence["codesign"]["returncode"], 0)
        self.assertEqual(evidence["runtime"]["exit_code"], 0)
        parse_macho.assert_called_once()
        verify.assert_called_once()
        runtime.assert_called_once()


if __name__ == "__main__":
    unittest.main()
