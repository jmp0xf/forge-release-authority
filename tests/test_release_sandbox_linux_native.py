from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROBE_SOURCE = REPOSITORY_ROOT / "native" / "linux-sandbox-probe" / "probe.c"
STRICT_C_FLAGS = (
    "-std=c11",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wconversion",
    "-Wformat=2",
    "-Wshadow",
    "-Wsign-conversion",
    "-Wstrict-prototypes",
)


class LinuxSandboxNativeContractTests(unittest.TestCase):
    source: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PROBE_SOURCE.read_text(encoding="utf-8")

    def test_case_is_narrow_non_authorizing_and_silent(self) -> None:
        self.assertIn("atomically place one blocked child", self.source)
        self.assertIn("does not hide an", self.source)
        self.assertIn("does not hide an\n * inherited cgroupfs mount", self.source)
        self.assertIn("runs no candidate program", self.source)
        for forbidden in (
            "cgroup.controllers",
            "cgroup.subtree_control",
            "cgroup.kill",
            "+cpu",
            "+memory",
            "+pids",
            "execve(",
            "execv(",
            "system(",
            "popen(",
            "printf(",
            "fprintf(",
            "perror(",
            "json",
            "schema",
            "receipt",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.source.lower())

    def test_exit_contract_is_single_and_cleanup_dominates(self) -> None:
        self.assertEqual(self.source.count("enum probe_exit {"), 1)
        self.assertIn(
            "(!defined(__x86_64__) && !defined(__aarch64__))",
            self.source,
        )
        self.assertIn("defined(__ILP32__)", self.source)
        self.assertIn("__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__", self.source)
        self.assertIn(
            '_Static_assert(sizeof(void *) == 8U, "the probe requires 64-bit pointers")',
            self.source,
        )
        self.assertIn(
            '_Static_assert(sizeof(long) == 8U, "the probe requires 64-bit long")',
            self.source,
        )
        self.assertIn("PROBE_CASE_OBSERVED = 0", self.source)
        self.assertIn("PROBE_UNAVAILABLE = 2", self.source)
        self.assertIn("PROBE_UNKNOWN = 3", self.source)
        self.assertIn("PROBE_CLEANUP_UNCONFIRMED = 4", self.source)
        self.assertIn("result = run_probe(&state);", self.source)
        self.assertIn("cleaned = clean_probe_state(&state);", self.source)
        self.assertIn(
            "if (!cleaned) {\n        return PROBE_CLEANUP_UNCONFIRMED;\n    }",
            self.source,
        )

    def test_current_cgroup_and_leaf_are_identity_anchored(self) -> None:
        self.assertIn('read_absolute_file("/proc/self/cgroup"', self.source)
        self.assertIn("open_membership_directory", self.source)
        self.assertIn("O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW", self.source)
        self.assertIn("current_directory_contains_self", self.source)
        self.assertIn("geteuid() != 0U", self.source)
        self.assertIn("root_owns_nonwritable_directory", self.source)
        self.assertIn("root_owns_nonwritable_control", self.source)
        self.assertIn("root_owns_nonwritable_migration_controls", self.source)
        self.assertIn('"cgroup.threads"', self.source)
        self.assertIn("identity.st_uid == 0U", self.source)
        self.assertIn("(identity.st_mode & 0022U) == 0U", self.source)
        self.assertIn("procs_match_pid(buffer, length, getpid(), false)", self.source)
        self.assertIn("unsigned char random_value[16U]", self.source)
        self.assertIn("path_matches_directory_identity", self.source)
        self.assertIn("observed.st_dev == identity->st_dev", self.source)
        self.assertIn("observed.st_ino == identity->st_ino", self.source)
        self.assertIn(
            "if (next_descriptor < 0) {\n"
            "            (void)close_descriptor(&descriptor);",
            self.source,
        )
        self.assertLess(
            self.source.index(
                "path_matches_directory_identity(",
                self.source.index("clean_probe_state"),
            ),
            self.source.index("unlinkat(", self.source.index("clean_probe_state")),
        )

    def test_parent_observes_atomic_placement_before_release(self) -> None:
        exact_flags = "arguments.flags = (__u64)CLONE_INTO_CGROUP | (__u64)CLONE_PIDFD;"
        self.assertIn(exact_flags, self.source)
        clone = self.source.index("clone_result = syscall(SYS_clone3")
        gate = self.source.index("child_waits_for_instruction", clone)
        namespace = self.source.index("child_observes_namespace_root()", gate)
        parent_procs = self.source.index('"cgroup.procs"', namespace)
        populated = self.source.index('leaf_population_is(state, "1")', parent_procs)
        live_after = self.source.index("observe_pidfd(state->pidfd, 0", populated)
        release = self.source.index("CHILD_RELEASE_TOKEN", live_after)
        reaped = self.source.index("reap_child_normally", release)
        empty = self.source.index('leaf_population_is(state, "0")', reaped)
        self.assertLess(gate, namespace)
        self.assertLess(namespace, parent_procs)
        self.assertLess(parent_procs, populated)
        self.assertLess(populated, live_after)
        self.assertLess(live_after, release)
        self.assertLess(release, reaped)
        self.assertLess(reaped, empty)
        self.assertIn(
            "procs_match_pid(buffer, length, state->child_pid, true)",
            self.source,
        )
        child_branch = self.source[
            self.source.index("if (clone_result == 0L)") : self.source.index(
                "if (clone_result < 0L"
            )
        ]
        self.assertLess(
            child_branch.index("child_closes_inherited_descriptors"),
            child_branch.index("child_installs_default_cancellation_signals"),
        )
        self.assertLess(
            child_branch.index("child_installs_default_cancellation_signals"),
            child_branch.index("child_waits_for_instruction"),
        )
        self.assertIn("poll(&gate, 1U, CHILD_GATE_WAIT_MILLISECONDS)", self.source)
        self.assertIn("recv(descriptor", self.source)
        self.assertIn("install_cancellation_handlers", self.source)
        self.assertIn("CANCELLATION_REQUESTED", self.source)
        self.assertIn("child_default.sa_handler = SIG_DFL", self.source)
        self.assertIn("sigaddset(&unblocked, SIGCHLD)", self.source)
        self.assertIn("sigprocmask(SIG_UNBLOCK, &unblocked, NULL)", self.source)
        self.assertIn("block_cancellation_signals", self.source)
        self.assertIn("sigprocmask(SIG_BLOCK, &blocked, NULL)", self.source)
        self.assertIn("child_installs_default_cancellation_signals", self.source)
        close_body = self.source[
            self.source.index(
                "static bool child_closes_inherited_descriptors"
            ) : self.source.index("static bool child_observes_namespace_root")
        ]
        self.assertNotIn("pidfd", close_body)

    def test_cleanup_uses_cancel_then_pidfd_without_numeric_pid_kill(self) -> None:
        cleanup = self.source[
            self.source.index("static bool cancel_and_reap_child") : self.source.index(
                "static enum probe_exit start_and_observe_child"
            )
        ]
        self.assertIn("CHILD_CANCEL_TOKEN", cleanup)
        self.assertIn("SYS_pidfd_send_signal", cleanup)
        self.assertIn("wait_for_pidfd(state->pidfd)", cleanup)
        self.assertNotIn("kill(state->child_pid", cleanup)
        pidfd_branch = cleanup[cleanup.index("if (state->pidfd >= 0)") :]
        self.assertNotIn("waitpid(", pidfd_branch.split("for (attempt", 1)[0])

    def test_strict_native_compile_and_closed_runtime(self) -> None:
        compiler = Path("/usr/bin/cc")
        if not compiler.is_file():
            self.skipTest("fixed system C compiler is unavailable")
        with tempfile.TemporaryDirectory(
            prefix="forge-native-probe-test-"
        ) as directory:
            executable = Path(directory) / "probe"
            compiler_environment = {
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": "/private/tmp" if sys.platform == "darwin" else directory,
            }
            if sys.platform == "darwin":
                sdk = subprocess.run(
                    ("/usr/bin/xcrun", "--show-sdk-path"),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=compiler_environment,
                    check=False,
                    timeout=10.0,
                )
                self.assertEqual(sdk.returncode, 0)
                self.assertEqual(sdk.stderr, b"")
                sdk_root = sdk.stdout.decode("utf-8").strip()
                self.assertTrue(Path(sdk_root).is_absolute())
                self.assertTrue(Path(sdk_root).is_dir())
                compiler_environment["SDKROOT"] = sdk_root
            for forbidden_environment_variable in (
                "CPATH",
                "C_INCLUDE_PATH",
                "GCC_EXEC_PREFIX",
                "LIBRARY_PATH",
            ):
                self.assertNotIn(forbidden_environment_variable, compiler_environment)
            compiled = subprocess.run(
                (
                    os.fspath(compiler),
                    *STRICT_C_FLAGS,
                    os.fspath(PROBE_SOURCE),
                    "-o",
                    os.fspath(executable),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=compiler_environment,
                check=False,
                timeout=30.0,
            )
            self.assertEqual(compiled.returncode, 0)
            self.assertEqual(compiled.stdout, b"")
            self.assertEqual(compiled.stderr, b"")
            observed = subprocess.run(
                (os.fspath(executable),),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                check=False,
                timeout=10.0,
            )
            self.assertIn(observed.returncode, (0, 2))
            self.assertEqual(observed.stdout, b"")
            self.assertEqual(observed.stderr, b"")
            rejected_invocation = subprocess.run(
                (os.fspath(executable), "unexpected"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                check=False,
                timeout=5.0,
            )
            self.assertEqual(rejected_invocation.returncode, 3)
            self.assertEqual(rejected_invocation.stdout, b"")
            self.assertEqual(rejected_invocation.stderr, b"")


if __name__ == "__main__":
    unittest.main()
