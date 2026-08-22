"""Focused contract tests for the native Alpine ARM64 Cargo benchmark."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


IMPLEMENTATION_PATH = Path(__file__).with_name("cargo_link_benchmark_impl.py")
IMPLEMENTATION_SPEC = importlib.util.spec_from_file_location(
    "cargo_link_benchmark_impl", IMPLEMENTATION_PATH
)
assert IMPLEMENTATION_SPEC and IMPLEMENTATION_SPEC.loader
IMPLEMENTATION = importlib.util.module_from_spec(IMPLEMENTATION_SPEC)
sys.modules[IMPLEMENTATION_SPEC.name] = IMPLEMENTATION
IMPLEMENTATION_SPEC.loader.exec_module(IMPLEMENTATION)

MODULE_PATH = Path(__file__).with_name("cargo_linux_link_benchmark.py")
SPEC = importlib.util.spec_from_file_location("cargo_linux_link_benchmark", MODULE_PATH)
assert SPEC and SPEC.loader
BENCHMARK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BENCHMARK
SPEC.loader.exec_module(BENCHMARK)


class CargoLinuxLinkBenchmarkTests(unittest.TestCase):
    def test_checked_in_workload_is_native_alpine_cargo(self) -> None:
        workload = BENCHMARK.load_workload(
            Path(__file__).with_name("cargo-linux-aarch64.benchmark.json")
        )

        self.assertEqual(workload.target, "aarch64-unknown-linux-musl")
        self.assertEqual(workload.profile, "linker-stress")
        self.assertEqual(workload.cargo_arguments, ("--bin", "cargo", "--features", "all-static"))
        self.assertEqual(workload.mutation.path, "src/bin/cargo/commands/search.rs")
        self.assertEqual(workload.incremental_link_max, 1.0)

    def test_elf_validation_requires_little_endian_aarch64_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "cargo"
            header = bytearray(64)
            header[:4] = b"\x7fELF"
            header[4] = BENCHMARK.ELFCLASS64
            header[5] = BENCHMARK.ELFDATA2LSB
            struct.pack_into("<HH", header, 16, BENCHMARK.ET_DYN, BENCHMARK.EM_AARCH64)
            artifact.write_bytes(header)

            evidence = BENCHMARK.parse_elf_aarch64_executable(artifact)

            self.assertEqual(evidence["elf_type"], "ET_DYN")
            struct.pack_into("<H", header, 18, 62)
            artifact.write_bytes(header)
            with self.assertRaisesRegex(ValueError, "not AArch64"):
                BENCHMARK.parse_elf_aarch64_executable(artifact)

    def test_direct_capture_accepts_the_clang_lld_child_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "link.log"
            log.write_text('"/usr/bin/ld.lld" -m aarch64linux -o /tmp/cargo /tmp/input.o\n')

            command = BENCHMARK.final_link_command(log, BENCHMARK.Linker("clang-lld", None))

            self.assertEqual(command, ["/usr/bin/ld.lld", "-m", "aarch64linux", "-o", "/tmp/cargo", "/tmp/input.o"])

    def test_failed_build_tail_is_bounded_but_keeps_the_actionable_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "build.log"
            log.write_text("prefix\nroot cause\n")

            tail = BENCHMARK.log_tail(log)
            one_line = BENCHMARK.log_tail(log, maximum_lines=1)

        self.assertIn("root cause", tail)
        self.assertNotIn("prefix", one_line)

    def test_gnu_time_report_is_normalized_to_bytes_and_nanoseconds(self) -> None:
        maximum_rss, cpu = BENCHMARK.parse_linux_time(
            "  User time (seconds): 1.25\n"
            "  System time (seconds): 0.75\n"
            "  Maximum resident set size (kbytes): 2048\n"
        )

        self.assertEqual(maximum_rss, 2 * 1024 * 1024)
        self.assertEqual(cpu, {"user_cpu_ns": 1_250_000_000, "system_cpu_ns": 750_000_000})

    def test_cache_guard_rejects_outputs_outside_the_container_cache_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            with patch.dict(os.environ, {"WILD_LINUX_BENCHMARK_CACHE_ROOT": str(cache)}):
                self.assertEqual(BENCHMARK.require_cache_path(cache / "reports" / "result.json"), (cache / "reports" / "result.json").resolve())
                with self.assertRaisesRegex(ValueError, "stay below"):
                    BENCHMARK.require_cache_path(root / "outside" / "result.json")

    def test_runtime_validation_removes_linux_and_macos_loader_overrides(self) -> None:
        environment, removed = BENCHMARK.runtime_environment(
            {"PATH": "/usr/bin", "LD_PRELOAD": "shim", "DYLD_LIBRARY_PATH": "shim"}
        )

        self.assertEqual(environment, {"PATH": "/usr/bin"})
        self.assertEqual(removed, ["DYLD_LIBRARY_PATH", "LD_PRELOAD"])

    def test_link_environment_keeps_alpine_system_libraries_visible_to_both_linkers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = BENCHMARK.benchmark_environment(
                wild=None, temporary_directory=Path(temporary)
            )

        self.assertIn("-C link-arg=-Wl,-L,/usr/lib", environment["RUSTFLAGS"])

    def test_cargo_proxy_path_is_not_resolved_away_from_its_cargo_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "rustup"
            target.write_text("proxy")
            proxy = root / "cargo"
            proxy.symlink_to(target)

            invocation = BENCHMARK.command_path(proxy)
            is_symlink = invocation.is_symlink()

        self.assertEqual(invocation.name, "cargo")
        self.assertTrue(is_symlink)

    def test_git_status_ignores_a_non_status_warning_on_stderr(self) -> None:
        with patch.object(
            BENCHMARK.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                ["git", "status", "--porcelain"], 0, stdout="", stderr="warning: cache disabled\n"
            ),
        ):
            output = BENCHMARK.run_git_stdout(["git", "status", "--porcelain"])

        self.assertEqual(output, "")

    def test_workload_report_is_json_safe_and_records_the_exact_mutation(self) -> None:
        workload = BENCHMARK.load_workload(
            Path(__file__).with_name("cargo-linux-aarch64.benchmark.json")
        )

        report = BENCHMARK.workload_report(workload)

        json.dumps(report)
        self.assertEqual(report["incremental_mutation"]["replace_before"], "min(100, limit")
        self.assertEqual(report["runtime"]["stdout_contains"], "cargo ")

    def test_comparison_reports_only_the_direct_incremental_link_metric(self) -> None:
        workload = BENCHMARK.load_workload(
            Path(__file__).with_name("cargo-linux-aarch64.benchmark.json")
        )
        direct = {
            "timing_samples": {
                "clang-lld": [{"elapsed_ns": 100}, {"elapsed_ns": 120}],
                "wild": [{"elapsed_ns": 50}, {"elapsed_ns": 60}],
            },
            "resource_samples": {
                "clang-lld": [{"peak_rss_bytes": 200}],
                "wild": [{"peak_rss_bytes": 100}],
            },
        }

        comparison = BENCHMARK.compare(direct, workload)

        self.assertEqual(comparison["incremental_link_wild_over_clang_lld"], 0.5)
        self.assertNotIn("incremental_cargo_wild_over_clang_lld", comparison)
        self.assertEqual(comparison["thresholds"], {"incremental_link_max": 1.0})


if __name__ == "__main__":
    unittest.main()
