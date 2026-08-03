"""Privately observe one fixed, non-authorizing Linux cgroup test case.

The native helper checks atomic leaf placement and namespace-relative cgroup
membership only. It does not hide the host cgroup filesystem, execute candidate
code, create a sandbox session, or establish backend availability. Its pinned
source digest binds the two repository files together; it is not an independent
compiler or source-supply-chain proof.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from pathlib import Path
from typing import IO


_SOURCE_PARTS = ("native", "linux-sandbox-probe", "probe.c")
_PROBE_SOURCE_SHA256 = (
    "9f5dcf132dfbc62d8029734485d4585c117ae2a6e66863102d6da87f2ac10124"
)
_COMPILER = "/usr/bin/cc"
_SUPPORTED_MACHINES = frozenset(("aarch64", "x86_64"))
_MAX_SOURCE_BYTES = 128 * 1024
_MAX_EXECUTABLE_BYTES = 4 * 1024 * 1024
_STREAM_READ_BYTES = 4096
_MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
_PROCESS_POLL_SECONDS = 0.05
_COMPILE_TIMEOUT_SECONDS = 30.0
_PROBE_TIMEOUT_SECONDS = 15.0
_TERMINATION_TIMEOUT_SECONDS = 5.0
_CLEANUP_GRACE_SECONDS = 8.0
_STRICT_C_FLAGS = (
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


class _Observation(Enum):
    CASE_OBSERVED = auto()
    UNAVAILABLE = auto()
    UNKNOWN = auto()
    CLEANUP_UNCONFIRMED = auto()

    def __bool__(self) -> bool:
        raise TypeError("sandbox observation has no truth value")


class _BuildStatus(Enum):
    READY = auto()
    UNKNOWN = auto()

    def __bool__(self) -> bool:
        raise TypeError("sandbox build status has no truth value")


class _NativeExit(IntEnum):
    CASE_OBSERVED = 0
    UNAVAILABLE = 2
    UNKNOWN = 3
    CLEANUP_UNCONFIRMED = 4

    def __bool__(self) -> bool:
        raise TypeError("native probe exit has no truth value")


@dataclass(frozen=True)
class _ProcessOutcome:
    returncode: int | None
    output_seen: bool
    output_limit_exceeded: bool
    timed_out: bool
    runner_fault: bool
    launch_failed: bool
    terminated_by_observer: bool
    reaped: bool


@dataclass(frozen=True)
class _ExecutableView:
    device: int
    inode: int
    mode: int
    owner: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class _BuildResult:
    status: _BuildStatus
    executable_view: _ExecutableView | None


def _is_supported_linux_host() -> bool:
    if sys.platform != "linux":
        return False
    try:
        return os.uname().machine in _SUPPORTED_MACHINES
    except OSError:
        return False


def _same_file_view(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
    )


def _read_fd_bounded(descriptor: int, limit: int) -> bytes:
    retained = bytearray()
    while True:
        chunk = os.read(descriptor, min(16 * 1024, limit + 1 - len(retained)))
        if not chunk:
            return bytes(retained)
        retained.extend(chunk)
        if len(retained) > limit:
            raise ValueError("fixed native source exceeds its private bound")


def _load_fixed_source() -> bytes:
    repository_root = Path(__file__).resolve(strict=True).parents[1]
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptors: list[int] = []
    source_descriptor = -1
    try:
        current = os.open(repository_root, directory_flags)
        descriptors.append(current)
        for component in _SOURCE_PARTS[:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            descriptors.append(current)
        source_name = _SOURCE_PARTS[-1]
        path_before = os.stat(source_name, dir_fd=current, follow_symlinks=False)
        source_descriptor = os.open(source_name, source_flags, dir_fd=current)
        descriptor_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or descriptor_before.st_size <= 0
            or descriptor_before.st_size > _MAX_SOURCE_BYTES
            or not _same_file_view(path_before, descriptor_before)
        ):
            raise ValueError("fixed native source is not a stable bounded file")
        source = _read_fd_bounded(source_descriptor, _MAX_SOURCE_BYTES)
        descriptor_after = os.fstat(source_descriptor)
        path_after = os.stat(source_name, dir_fd=current, follow_symlinks=False)
        if (
            len(source) != descriptor_before.st_size
            or not _same_file_view(descriptor_before, descriptor_after)
            or not _same_file_view(descriptor_before, path_after)
            or hashlib.sha256(source).hexdigest() != _PROBE_SOURCE_SHA256
        ):
            raise ValueError("fixed native source identity or digest changed")
        return source
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _write_private_source_snapshot(directory: Path, source: bytes) -> Path:
    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    snapshot_descriptor = -1
    try:
        snapshot_descriptor = os.open(
            "probe.c",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_descriptor,
        )
        offset = 0
        while offset < len(source):
            written = os.write(snapshot_descriptor, source[offset:])
            if written <= 0:
                raise OSError("fixed source snapshot write made no progress")
            offset += written
        os.fsync(snapshot_descriptor)
        os.fchmod(snapshot_descriptor, 0o400)
        os.close(snapshot_descriptor)
        snapshot_descriptor = -1
        os.fsync(directory_descriptor)

        snapshot_descriptor = os.open(
            "probe.c",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_descriptor,
        )
        descriptor_view = os.fstat(snapshot_descriptor)
        path_view = os.stat(
            "probe.c", dir_fd=directory_descriptor, follow_symlinks=False
        )
        observed = _read_fd_bounded(snapshot_descriptor, _MAX_SOURCE_BYTES)
        descriptor_after = os.fstat(snapshot_descriptor)
        path_after = os.stat(
            "probe.c", dir_fd=directory_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(descriptor_view.st_mode)
            or not _same_file_view(descriptor_view, path_view)
            or not _same_file_view(descriptor_view, descriptor_after)
            or not _same_file_view(descriptor_view, path_after)
            or observed != source
            or hashlib.sha256(observed).hexdigest() != _PROBE_SOURCE_SHA256
        ):
            raise ValueError("private source snapshot changed")
        return directory / "probe.c"
    finally:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        os.close(directory_descriptor)


def _signal_process(process: subprocess.Popen[bytes], selected_signal: int) -> None:
    try:
        os.killpg(process.pid, selected_signal)
    except OSError:
        try:
            process.send_signal(selected_signal)
        except OSError:
            pass


def _terminate_and_reap(
    process: subprocess.Popen[bytes], cleanup_grace_seconds: float
) -> bool:
    if cleanup_grace_seconds > 0.0:
        _signal_process(process, signal.SIGTERM)
        # Do not reap a dead group leader during the grace interval. Its PID
        # pins the process-group identity while descendants finish cleanup.
        time.sleep(cleanup_grace_seconds)
    _signal_process(process, signal.SIGKILL)
    try:
        process.wait(timeout=_TERMINATION_TIMEOUT_SECONDS)
        return True
    except (OSError, subprocess.TimeoutExpired):
        _signal_process(process, signal.SIGKILL)
        try:
            process.wait(timeout=_TERMINATION_TIMEOUT_SECONDS)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return process.returncode is not None


def _run_fixed_process(
    command: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: float,
    cleanup_grace_seconds: float,
) -> _ProcessOutcome:
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return _ProcessOutcome(
            returncode=None,
            output_seen=False,
            output_limit_exceeded=False,
            timed_out=False,
            runner_fault=False,
            launch_failed=True,
            terminated_by_observer=False,
            reaped=True,
        )

    output_seen = False
    output_bytes = 0
    output_limit_exceeded = False
    timed_out = False
    runner_fault = False
    terminated_by_observer = False
    reaped = False
    selector: selectors.BaseSelector | None = None
    streams: tuple[IO[bytes], ...] = ()
    try:
        streams = tuple(
            stream for stream in (process.stdout, process.stderr) if stream is not None
        )
        if len(streams) != 2:
            raise RuntimeError("fixed process streams were not created")
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout_seconds
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)

        while selector.get_map() and not output_limit_exceeded:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                timed_out = True
                break
            ready = selector.select(min(_PROCESS_POLL_SECONDS, remaining))
            for key, _ in ready:
                try:
                    chunk = os.read(
                        key.fd,
                        min(
                            _STREAM_READ_BYTES,
                            _MAX_PROCESS_OUTPUT_BYTES + 1 - output_bytes,
                        ),
                    )
                except BlockingIOError:
                    continue
                if chunk:
                    output_seen = True
                    output_bytes = min(
                        _MAX_PROCESS_OUTPUT_BYTES + 1,
                        output_bytes + len(chunk),
                    )
                    if output_bytes > _MAX_PROCESS_OUTPUT_BYTES:
                        output_limit_exceeded = True
                        break
                else:
                    selector.unregister(key.fileobj)

        if not timed_out and not output_limit_exceeded:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                timed_out = True
            else:
                try:
                    process.wait(timeout=remaining)
                    reaped = True
                except subprocess.TimeoutExpired:
                    timed_out = True
    except Exception:
        runner_fault = True
    finally:
        force_group_cleanup = timed_out or output_limit_exceeded or runner_fault
        if force_group_cleanup:
            terminated_by_observer = True
            reaped = _terminate_and_reap(process, cleanup_grace_seconds)
        elif not reaped:
            try:
                process.wait(timeout=0.0)
                reaped = True
            except subprocess.TimeoutExpired:
                terminated_by_observer = True
                reaped = _terminate_and_reap(process, cleanup_grace_seconds)
            except OSError:
                terminated_by_observer = True
                reaped = _terminate_and_reap(process, cleanup_grace_seconds)
        if selector is not None:
            try:
                selector.close()
            except OSError:
                runner_fault = True
        for stream in streams:
            try:
                stream.close()
            except OSError:
                runner_fault = True

    return _ProcessOutcome(
        process.returncode if reaped else None,
        output_seen,
        output_limit_exceeded,
        timed_out,
        runner_fault,
        False,
        terminated_by_observer,
        reaped,
    )


def _executable_view(path: Path) -> _ExecutableView | None:
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.geteuid()
        or observed.st_nlink != 1
        or observed.st_size <= 0
        or observed.st_size > _MAX_EXECUTABLE_BYTES
        or observed.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
        or observed.st_mode & 0o111 == 0
    ):
        return None
    return _ExecutableView(
        device=observed.st_dev,
        inode=observed.st_ino,
        mode=observed.st_mode,
        owner=observed.st_uid,
        links=observed.st_nlink,
        size=observed.st_size,
        modified_ns=observed.st_mtime_ns,
        changed_ns=observed.st_ctime_ns,
    )


def _compile_snapshot(source: Path, executable: Path, temporary: Path) -> _BuildResult:
    outcome = _run_fixed_process(
        (_COMPILER, *_STRICT_C_FLAGS, os.fspath(source), "-o", os.fspath(executable)),
        environment={
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": os.fspath(temporary),
        },
        timeout_seconds=_COMPILE_TIMEOUT_SECONDS,
        cleanup_grace_seconds=0.0,
    )
    if (
        outcome.launch_failed
        or outcome.runner_fault
        or outcome.timed_out
        or outcome.terminated_by_observer
        or not outcome.reaped
        or outcome.output_seen
        or outcome.output_limit_exceeded
        or outcome.returncode != 0
    ):
        return _BuildResult(_BuildStatus.UNKNOWN, None)
    view = _executable_view(executable)
    if view is None:
        return _BuildResult(_BuildStatus.UNKNOWN, None)
    return _BuildResult(_BuildStatus.READY, view)


def _interpret_probe_outcome(outcome: _ProcessOutcome) -> _Observation:
    if outcome.returncode == int(_NativeExit.CLEANUP_UNCONFIRMED):
        return _Observation.CLEANUP_UNCONFIRMED
    if (
        outcome.timed_out
        or outcome.output_limit_exceeded
        or outcome.terminated_by_observer
        or not outcome.reaped
        or (outcome.returncode is not None and outcome.returncode < 0)
    ):
        return _Observation.CLEANUP_UNCONFIRMED
    if outcome.launch_failed or outcome.runner_fault or outcome.output_seen:
        return _Observation.UNKNOWN
    if outcome.returncode == int(_NativeExit.CASE_OBSERVED):
        return _Observation.CASE_OBSERVED
    if outcome.returncode == int(_NativeExit.UNAVAILABLE):
        return _Observation.UNAVAILABLE
    return _Observation.UNKNOWN


def _observe_linux_sandbox_case() -> _Observation:
    """Observe the fixed case without accepting caller-controlled inputs."""
    if not _is_supported_linux_host():
        return _Observation.UNAVAILABLE
    if not Path(_COMPILER).is_file():
        return _Observation.UNAVAILABLE
    try:
        source = _load_fixed_source()
        with tempfile.TemporaryDirectory(
            prefix="forge-linux-sandbox-probe-", dir="/tmp"
        ) as directory_name:
            directory = Path(directory_name)
            snapshot = _write_private_source_snapshot(directory, source)
            executable = directory / "probe"
            build = _compile_snapshot(snapshot, executable, directory)
            if (
                build.status is not _BuildStatus.READY
                or build.executable_view is None
                or _executable_view(executable) != build.executable_view
            ):
                return _Observation.UNKNOWN
            outcome = _run_fixed_process(
                (os.fspath(executable),),
                environment={},
                timeout_seconds=_PROBE_TIMEOUT_SECONDS,
                cleanup_grace_seconds=_CLEANUP_GRACE_SECONDS,
            )
            observed = _interpret_probe_outcome(outcome)
            if observed is _Observation.CLEANUP_UNCONFIRMED:
                return observed
            # These path views catch persistent drift around execution. They do
            # not turn this prototype into same-descriptor production identity.
            if _executable_view(executable) != build.executable_view:
                return _Observation.UNKNOWN
            return observed
    except (OSError, RuntimeError, ValueError):
        return _Observation.UNKNOWN
