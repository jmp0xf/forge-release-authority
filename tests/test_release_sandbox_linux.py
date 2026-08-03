from __future__ import annotations

import fcntl
import hashlib
import inspect
import io
import os
import selectors
import signal
import stat
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import release_sandbox_linux as observer


def _outcome(
    returncode: int | None,
    *,
    output_seen: bool = False,
    output_limit_exceeded: bool = False,
    timed_out: bool = False,
    runner_fault: bool = False,
    launch_failed: bool = False,
    terminated_by_observer: bool = False,
    reaped: bool = True,
) -> observer._ProcessOutcome:
    return observer._ProcessOutcome(
        returncode=returncode,
        output_seen=output_seen,
        output_limit_exceeded=output_limit_exceeded,
        timed_out=timed_out,
        runner_fault=runner_fault,
        launch_failed=launch_failed,
        terminated_by_observer=terminated_by_observer,
        reaped=reaped,
    )


def _orphaned_descendant_command(
    identity_path: Path, *, output_bytes: int
) -> tuple[str, ...]:
    descendant = "\n".join(
        (
            "import os",
            "import fcntl",
            "import signal",
            "import sys",
            "import time",
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
            "original_parent = os.getppid()",
            "descriptor = os.open(",
            "    sys.argv[1],",
            "    os.O_WRONLY | os.O_CREAT | os.O_EXCL,",
            "    0o600,",
            ")",
            "fcntl.flock(descriptor, fcntl.LOCK_EX)",
            "identity = f'{os.getpid()} {os.getpgrp()}\\n'.encode('ascii')",
            "os.write(descriptor, identity)",
            "os.fsync(descriptor)",
            "while os.getppid() == original_parent:",
            "    time.sleep(0.005)",
            "os.write(descriptor, b'orphaned\\n')",
            "os.fsync(descriptor)",
            "if int(sys.argv[2]) > 0:",
            "    time.sleep(0.15)",
            "    os.write(1, b'x' * int(sys.argv[2]))",
            "while True:",
            "    time.sleep(60.0)",
        )
    )
    leader = "\n".join(
        (
            "import os",
            "import subprocess",
            "import sys",
            "import time",
            "descendant = subprocess.Popen(",
            "    (sys.executable, '-c', sys.argv[2], sys.argv[1], sys.argv[3])",
            ")",
            "deadline = time.monotonic() + 2.0",
            "while time.monotonic() < deadline:",
            "    try:",
            "        if os.stat(sys.argv[1]).st_size > 0:",
            "            raise SystemExit(0)",
            "    except FileNotFoundError:",
            "        pass",
            "    time.sleep(0.005)",
            "raise SystemExit(70)",
        )
    )
    return (
        sys.executable,
        "-c",
        leader,
        os.fspath(identity_path),
        descendant,
        str(output_bytes),
    )


def _read_process_identity(identity_path: Path) -> tuple[int, int]:
    process_id, process_group, *_ = identity_path.read_text(encoding="ascii").split()
    return int(process_id), int(process_group)


def _descendant_holds_lock(identity_path: Path) -> bool:
    descriptor = os.open(identity_path, os.O_RDWR | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(descriptor)


def _wait_for_lock_release(identity_path: Path, timeout_seconds: float = 3.0) -> None:
    descriptor = os.open(identity_path, os.O_RDWR | os.O_CLOEXEC)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise AssertionError("descendant kept its liveness lock")
                time.sleep(0.01)
    finally:
        os.close(descriptor)


def _kill_test_descendant(process_id: int, process_group: int) -> None:
    try:
        if os.getpgid(process_id) == process_group:
            os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _recover_test_descendant(identity_path: Path) -> None:
    try:
        process_id, process_group = _read_process_identity(identity_path)
    except (FileNotFoundError, UnicodeError, ValueError):
        return
    if _descendant_holds_lock(identity_path):
        _kill_test_descendant(process_id, process_group)
        _wait_for_lock_release(identity_path)


class LinuxSandboxObserverTests(unittest.TestCase):
    def test_private_closed_result_and_no_cli_surface(self) -> None:
        self.assertEqual(
            [item.name for item in observer._Observation],
            ["CASE_OBSERVED", "UNAVAILABLE", "UNKNOWN", "CLEANUP_UNCONFIRMED"],
        )
        closed_results = (
            *observer._Observation,
            *observer._BuildStatus,
            *observer._NativeExit,
        )
        for item in closed_results:
            with self.subTest(item=item):
                with self.assertRaises(TypeError):
                    bool(item)
        self.assertEqual(
            len(inspect.signature(observer._observe_linux_sandbox_case).parameters), 0
        )
        self.assertFalse(hasattr(observer, "main"))
        module_source = Path(observer.__file__).read_text(encoding="utf-8")
        self.assertFalse(module_source.startswith("#!"))
        self.assertNotIn("Sequence", module_source)
        self.assertNotIn("if __name__", module_source)
        self.assertIn("without accepting caller-controlled inputs", module_source)

    def test_failure_cleanup_never_signals_a_reused_process_id(self) -> None:
        with (
            mock.patch.object(os, "getpgid", return_value=72),
            mock.patch.object(os, "killpg") as kill_group,
        ):
            _kill_test_descendant(71, 71)
        kill_group.assert_not_called()

    def test_host_routing_stops_before_source_access(self) -> None:
        for platform, machine in (("darwin", "arm64"), ("linux", "riscv64")):
            with self.subTest(platform=platform, machine=machine):
                with (
                    mock.patch.object(sys, "platform", platform),
                    mock.patch.object(
                        os,
                        "uname",
                        return_value=SimpleNamespace(machine=machine),
                    ),
                    mock.patch.object(
                        Path,
                        "resolve",
                        side_effect=AssertionError("source path must remain untouched"),
                    ),
                    mock.patch.object(
                        tempfile,
                        "TemporaryDirectory",
                        side_effect=AssertionError("no private directory is needed"),
                    ),
                ):
                    self.assertIs(
                        observer._observe_linux_sandbox_case(),
                        observer._Observation.UNAVAILABLE,
                    )

    def test_source_is_bounded_no_follow_digest_bound_and_privately_snapshotted(
        self,
    ) -> None:
        module_source = Path(observer.__file__).read_text(encoding="utf-8")
        self.assertIn("os.O_NOFOLLOW", module_source)
        self.assertIn("_MAX_SOURCE_BYTES", module_source)
        self.assertIn("_same_file_view", module_source)
        self.assertIn("hashlib.sha256(source).hexdigest()", module_source)
        self.assertIn("os.O_EXCL", module_source)
        source = observer._load_fixed_source()
        self.assertEqual(
            hashlib.sha256(source).hexdigest(),
            observer._PROBE_SOURCE_SHA256,
        )
        with tempfile.TemporaryDirectory(prefix="forge-source-snapshot-test-") as name:
            snapshot = observer._write_private_source_snapshot(Path(name), source)
            self.assertEqual(snapshot.read_bytes(), source)
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o400)
        with mock.patch.object(observer, "_PROBE_SOURCE_SHA256", "0" * 64):
            with self.assertRaises(ValueError):
                observer._load_fixed_source()

    def test_compiler_consumes_only_fixed_snapshot_and_closed_environment(self) -> None:
        clean = _outcome(0)
        executable_view = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o700,
            st_size=4096,
            st_uid=os.geteuid(),
            st_nlink=1,
            st_dev=10,
            st_ino=20,
            st_mtime_ns=30,
            st_ctime_ns=40,
        )
        with (
            mock.patch.object(
                observer, "_run_fixed_process", return_value=clean
            ) as run,
            mock.patch.object(os, "stat", return_value=executable_view),
        ):
            result = observer._compile_snapshot(
                Path("/private/probe.c"),
                Path("/private/probe"),
                Path("/private"),
            )
        self.assertIs(result.status, observer._BuildStatus.READY)
        self.assertIsNotNone(result.executable_view)
        run.assert_called_once_with(
            (
                "/usr/bin/cc",
                *observer._STRICT_C_FLAGS,
                "/private/probe.c",
                "-o",
                "/private/probe",
            ),
            environment={
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": "/private",
            },
            timeout_seconds=observer._COMPILE_TIMEOUT_SECONDS,
            cleanup_grace_seconds=0.0,
        )
        environment = run.call_args.kwargs["environment"]
        for forbidden in (
            "CPATH",
            "C_INCLUDE_PATH",
            "GCC_EXEC_PREFIX",
            "LIBRARY_PATH",
            "SDKROOT",
        ):
            self.assertNotIn(forbidden, environment)

    def test_every_compiler_anomaly_is_unknown(self) -> None:
        anomalies = (
            _outcome(1),
            _outcome(0, output_seen=True),
            _outcome(0, output_limit_exceeded=True),
            _outcome(None, timed_out=True, terminated_by_observer=True),
            _outcome(None, runner_fault=True, terminated_by_observer=True),
            _outcome(None, launch_failed=True),
            _outcome(None, reaped=False),
        )
        for anomaly in anomalies:
            with self.subTest(anomaly=anomaly):
                with mock.patch.object(
                    observer, "_run_fixed_process", return_value=anomaly
                ):
                    self.assertIs(
                        observer._compile_snapshot(
                            Path("/private/probe.c"),
                            Path("/private/probe"),
                            Path("/private"),
                        ).status,
                        observer._BuildStatus.UNKNOWN,
                    )

    def test_executable_view_rejects_mutable_or_ambiguous_files(self) -> None:
        valid = {
            "st_mode": stat.S_IFREG | 0o700,
            "st_size": 4096,
            "st_uid": os.geteuid(),
            "st_nlink": 1,
            "st_dev": 10,
            "st_ino": 20,
            "st_mtime_ns": 30,
            "st_ctime_ns": 40,
        }
        with mock.patch.object(os, "stat", return_value=SimpleNamespace(**valid)):
            self.assertIsNotNone(observer._executable_view(Path("/private/probe")))
        invalid_views = (
            ("symlink", {"st_mode": stat.S_IFLNK | 0o700}),
            ("group-writable", {"st_mode": stat.S_IFREG | 0o720}),
            ("multi-link", {"st_nlink": 2}),
            ("wrong-owner", {"st_uid": os.geteuid() + 1}),
            ("empty", {"st_size": 0}),
            ("not-executable", {"st_mode": stat.S_IFREG | 0o600}),
            ("set-id", {"st_mode": stat.S_IFREG | stat.S_ISUID | 0o700}),
        )
        for name, changes in invalid_views:
            with self.subTest(name=name):
                observed = {**valid, **changes}
                with mock.patch.object(
                    os, "stat", return_value=SimpleNamespace(**observed)
                ):
                    self.assertIsNone(observer._executable_view(Path("/private/probe")))

    def test_probe_mapping_preserves_cleanup_uncertainty(self) -> None:
        cases = (
            (_outcome(0), observer._Observation.CASE_OBSERVED),
            (_outcome(2), observer._Observation.UNAVAILABLE),
            (_outcome(3), observer._Observation.UNKNOWN),
            (_outcome(17), observer._Observation.UNKNOWN),
            (_outcome(0, output_seen=True), observer._Observation.UNKNOWN),
            (
                _outcome(0, output_limit_exceeded=True),
                observer._Observation.CLEANUP_UNCONFIRMED,
            ),
            (_outcome(4, output_seen=True), observer._Observation.CLEANUP_UNCONFIRMED),
            (
                _outcome(None, timed_out=True, terminated_by_observer=True),
                observer._Observation.CLEANUP_UNCONFIRMED,
            ),
            (_outcome(-9), observer._Observation.CLEANUP_UNCONFIRMED),
            (_outcome(None, reaped=False), observer._Observation.CLEANUP_UNCONFIRMED),
            (_outcome(None, launch_failed=True), observer._Observation.UNKNOWN),
        )
        for outcome, expected in cases:
            with self.subTest(outcome=outcome):
                self.assertIs(observer._interpret_probe_outcome(outcome), expected)

    def test_observer_uses_fixed_empty_probe_inputs(self) -> None:
        process_outcome = _outcome(2)
        executable_view = observer._ExecutableView(
            1, 2, 0o100700, os.geteuid(), 1, 3, 4, 5
        )
        temporary = mock.MagicMock()
        temporary.__enter__.return_value = "/tmp/private-probe"
        temporary.__exit__.return_value = False
        with (
            mock.patch.object(observer, "_is_supported_linux_host", return_value=True),
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(observer, "_load_fixed_source", return_value=b"source"),
            mock.patch.object(
                observer,
                "_write_private_source_snapshot",
                return_value=Path("/tmp/private-probe/probe.c"),
            ),
            mock.patch.object(
                observer,
                "_compile_snapshot",
                return_value=observer._BuildResult(
                    observer._BuildStatus.READY, executable_view
                ),
            ),
            mock.patch.object(
                observer, "_executable_view", return_value=executable_view
            ) as executable_views,
            mock.patch.object(
                observer, "_run_fixed_process", return_value=process_outcome
            ) as run,
            mock.patch.object(tempfile, "TemporaryDirectory", return_value=temporary),
        ):
            result = observer._observe_linux_sandbox_case()
        self.assertIs(result, observer._Observation.UNAVAILABLE)
        self.assertEqual(executable_views.call_count, 2)
        run.assert_called_once_with(
            ("/tmp/private-probe/probe",),
            environment={},
            timeout_seconds=observer._PROBE_TIMEOUT_SECONDS,
            cleanup_grace_seconds=observer._CLEANUP_GRACE_SECONDS,
        )

    def test_stream_output_is_discarded_but_helper_gets_cleanup_window(self) -> None:
        started = time.monotonic()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            outcome = observer._run_fixed_process(
                (
                    sys.executable,
                    "-c",
                    "import sys,time;sys.stdout.write('x');sys.stdout.flush();"
                    "sys.stderr.write('y');sys.stderr.flush();time.sleep(0.2)",
                ),
                environment={},
                timeout_seconds=2.0,
                cleanup_grace_seconds=0.2,
            )
        self.assertGreaterEqual(time.monotonic() - started, 0.15)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(outcome.output_seen)
        self.assertFalse(outcome.output_limit_exceeded)
        self.assertTrue(outcome.reaped)
        self.assertFalse(outcome.terminated_by_observer)
        self.assertEqual(outcome.returncode, 0)

    def test_total_output_limit_terminates_with_cleanup_uncertainty(self) -> None:
        with mock.patch.object(observer, "_MAX_PROCESS_OUTPUT_BYTES", 1):
            outcome = observer._run_fixed_process(
                (
                    sys.executable,
                    "-c",
                    "import sys,time;sys.stdout.write('xy');sys.stdout.flush();"
                    "time.sleep(10)",
                ),
                environment={},
                timeout_seconds=2.0,
                cleanup_grace_seconds=0.2,
            )
        self.assertTrue(outcome.output_seen)
        self.assertTrue(outcome.output_limit_exceeded)
        self.assertTrue(outcome.terminated_by_observer)
        self.assertTrue(outcome.reaped)
        self.assertIs(
            observer._interpret_probe_outcome(outcome),
            observer._Observation.CLEANUP_UNCONFIRMED,
        )

    def test_timeout_kills_descendant_after_group_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-timeout-tree-test-") as name:
            identity_path = Path(name) / "descendant.identity"
            cleanup_needed = True
            try:
                outcome = observer._run_fixed_process(
                    _orphaned_descendant_command(identity_path, output_bytes=0),
                    environment={},
                    timeout_seconds=2.5,
                    cleanup_grace_seconds=0.1,
                )
                process_id, process_group = _read_process_identity(identity_path)
                self.assertGreater(process_id, 0)
                self.assertGreater(process_group, 0)
                self.assertIn("orphaned", identity_path.read_text(encoding="ascii"))
                _wait_for_lock_release(identity_path)
                cleanup_needed = False
            finally:
                if cleanup_needed:
                    _recover_test_descendant(identity_path)

        self.assertTrue(outcome.timed_out)
        self.assertTrue(outcome.terminated_by_observer)
        self.assertTrue(outcome.reaped)
        self.assertEqual(outcome.returncode, 0)
        self.assertIs(
            observer._interpret_probe_outcome(outcome),
            observer._Observation.CLEANUP_UNCONFIRMED,
        )

    def test_output_cap_kills_descendant_after_group_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="forge-output-tree-test-") as name:
            identity_path = Path(name) / "descendant.identity"
            cleanup_needed = True
            try:
                with mock.patch.object(observer, "_MAX_PROCESS_OUTPUT_BYTES", 16):
                    outcome = observer._run_fixed_process(
                        _orphaned_descendant_command(identity_path, output_bytes=32),
                        environment={},
                        timeout_seconds=3.0,
                        cleanup_grace_seconds=0.1,
                    )
                process_id, process_group = _read_process_identity(identity_path)
                self.assertGreater(process_id, 0)
                self.assertGreater(process_group, 0)
                self.assertIn("orphaned", identity_path.read_text(encoding="ascii"))
                _wait_for_lock_release(identity_path)
                cleanup_needed = False
            finally:
                if cleanup_needed:
                    _recover_test_descendant(identity_path)

        self.assertTrue(outcome.output_limit_exceeded)
        self.assertTrue(outcome.terminated_by_observer)
        self.assertTrue(outcome.reaped)
        self.assertEqual(outcome.returncode, 0)
        self.assertIs(
            observer._interpret_probe_outcome(outcome),
            observer._Observation.CLEANUP_UNCONFIRMED,
        )

    def test_post_launch_setup_failure_kills_and_reaps(self) -> None:
        for target, replacement in (
            (
                "set-blocking",
                mock.patch.object(os, "set_blocking", side_effect=OSError()),
            ),
            (
                "selector",
                mock.patch.object(
                    selectors,
                    "DefaultSelector",
                    side_effect=RuntimeError(),
                ),
            ),
        ):
            with self.subTest(target=target):
                with replacement:
                    outcome = observer._run_fixed_process(
                        (sys.executable, "-c", "import time;time.sleep(10)"),
                        environment={},
                        timeout_seconds=2.0,
                        cleanup_grace_seconds=0.2,
                    )
                self.assertTrue(outcome.runner_fault)
                self.assertTrue(outcome.terminated_by_observer)
                self.assertTrue(outcome.reaped)

    def test_timeout_kills_and_reaps_without_downgrading_cleanup(self) -> None:
        outcome = observer._run_fixed_process(
            (sys.executable, "-c", "import time;time.sleep(10)"),
            environment={},
            timeout_seconds=0.1,
            cleanup_grace_seconds=0.2,
        )
        self.assertTrue(outcome.timed_out)
        self.assertTrue(outcome.terminated_by_observer)
        self.assertTrue(outcome.reaped)
        self.assertIs(
            observer._interpret_probe_outcome(outcome),
            observer._Observation.CLEANUP_UNCONFIRMED,
        )
