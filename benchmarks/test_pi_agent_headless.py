"""Stdlib tests for the Pi agent build benchmark's safety-critical helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
import sys
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("pi_agent_headless.py")
SPEC = importlib.util.spec_from_file_location("pi_agent_headless", MODULE_PATH)
assert SPEC and SPEC.loader
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


class PiAgentBenchmarkTests(unittest.TestCase):
    def test_parse_toolchain_channel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rust-toolchain.toml"
            path.write_text('[toolchain]\nchannel = "nightly-2026-07-24"\n')
            self.assertEqual(BENCHMARK.parse_toolchain_channel(path), "nightly-2026-07-24")

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

    def test_mutation_is_restored_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pi-agent-headless.rs"
            original = b"fn main() {}\n"
            path.write_bytes(original)
            before, after = BENCHMARK.mutate_incremental_source(
                path,
                BENCHMARK.SourceMutation(
                    path="pi-agent-headless.rs", append=b"\n// benchmark incremental marker\n"
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
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {"samples": [{"elapsed_ns": 20}]},
            },
            {
                "linker": "wild",
                "cold": {"elapsed_ns": 105},
                "incremental": {"elapsed_ns": 25},
                "incremental_link": {"samples": [{"elapsed_ns": 10}]},
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
        self.assertEqual(result["incremental_cargo_wild_over_apple"], 0.5)
        self.assertEqual(result["incremental_link_wild_over_apple"], 0.5)

    def test_comparison_aggregates_cache_hit_rate_and_miss_reasons(self) -> None:
        runs = [
            {
                "linker": "apple-ld64",
                "cold": {"elapsed_ns": 100},
                "incremental": {"elapsed_ns": 50},
                "incremental_link": {"samples": [{"elapsed_ns": 20}]},
            },
            {
                "linker": "wild",
                "cold": {"elapsed_ns": 100},
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

    def test_cargo_driver_can_be_pinned_independently_of_path(self) -> None:
        args = BENCHMARK.parse_args(
            [
                "--config",
                "workload.json",
                "--workspace",
                "/tmp/repository",
                "--output",
                "/tmp/result.json",
                "--cargo",
                "/opt/homebrew/opt/rustup/bin/cargo",
            ]
        )
        self.assertEqual(args.cargo, Path("/opt/homebrew/opt/rustup/bin/cargo"))

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
