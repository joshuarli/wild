"""Stdlib tests for the Pi agent build benchmark's safety-critical helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
import sys


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
        )
        result = BENCHMARK.comparison(runs, workload)
        self.assertTrue(result["goals_met"])
        self.assertEqual(result["cold_wild_over_apple"], 1.05)
        self.assertEqual(result["incremental_cargo_wild_over_apple"], 0.5)
        self.assertEqual(result["incremental_link_wild_over_apple"], 0.5)

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

    def test_macho_header_rejects_wrong_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-arm64"
            path.write_bytes(bytes.fromhex("cffaedfe070000010000000002000000") + b"\0" * 16)
            with self.assertRaisesRegex(ValueError, "not ARM64"):
                BENCHMARK.parse_macho_arm64_executable(path)


if __name__ == "__main__":
    unittest.main()
