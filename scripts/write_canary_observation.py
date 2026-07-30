#!/usr/bin/env python3
"""Write one bounded, diagnostic-only native runner observation.

This file is deliberately outside the v1 builder-record and provenance contracts.
It records allowlisted facts for the inactive qualification canary so a later
reviewed change can decide which stable inputs to freeze or conservatively verify.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence


SCHEMA = "forge.release-authority-canary-observation/v1"
PURPOSE = "inactive-canary-diagnostic-only"
TARGETS = {
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-musl",
}
SAFE_RUNNER_ENVIRONMENT = (
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
)
COMMAND_ENVIRONMENT = (
    "APPDATA",
    "CARGO_HOME",
    "COMSPEC",
    "DEVELOPER_DIR",
    "HOME",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SDKROOT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
)
PATH_REPLACEMENTS = {
    "APPDATA": "$APPDATA",
    "CARGO_HOME": "$CARGO_HOME",
    "GITHUB_WORKSPACE": "$GITHUB_WORKSPACE",
    "HOME": "$HOME",
    "LOCALAPPDATA": "$LOCALAPPDATA",
    "ProgramFiles": "$PROGRAMFILES",
    "ProgramFiles(x86)": "$PROGRAMFILES_X86",
    "RUNNER_TEMP": "$RUNNER_TEMP",
    "RUNNER_TOOL_CACHE": "$RUNNER_TOOL_CACHE",
    "RUSTUP_HOME": "$RUSTUP_HOME",
    "SYSTEMROOT": "$SYSTEMROOT",
    "TEMP": "$TEMP",
    "TMP": "$TMP",
    "TMPDIR": "$TMPDIR",
    "USERPROFILE": "$USERPROFILE",
    "WINDIR": "$WINDIR",
}
LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
SECRET_ASSIGNMENT = re.compile(
    r"(?im)(?P<prefix>\b(?:authorization|credentials?|passw(?:or)?d|secrets?|"
    r"tokens?|api[_-]?key|access[_-]?key|client[_-]?secret|github[_-]?token|"
    r"private[_-]?key)\b[ \t]*[:=][ \t]*)(?P<value>[^\n]*)"
)
URL_USERINFO = re.compile(r"(?i)\b(?P<scheme>https?://)[^/@\s]+@")

MAX_OUTPUT_BYTES = 256 * 1024
MAX_RETAINED_STREAM_BYTES = 4 * 1024
MAX_COMMAND_STREAM_BYTES = 64 * 1024
MAX_COMMAND_SECONDS = 15.0
MAX_SAFE_VALUE_CHARS = 256
MAX_PATH_CHARS = 1024
MAX_SCAN_ENTRIES = 4096
MAX_MANIFEST_ENTRIES = 512
MAX_SCAN_DEPTH = 5
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_CACHE_FILE_BYTES = 64 * 1024 * 1024
MAX_HASHED_BYTES = 768 * 1024 * 1024


class ObservationError(ValueError):
    """The requested observation is unsafe, unbounded, or cannot be created."""


@dataclass
class _StreamCapture:
    retained: bytearray
    total: int = 0
    exceeded: bool = False
    error: str | None = None


@dataclass
class HashBudget:
    """Shared upper bound for all bytes hashed by one observation."""

    remaining: int = MAX_HASHED_BYTES

    def digest_regular_file(self, path: Path, per_file_limit: int, label: str) -> tuple[int, str]:
        try:
            before = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ObservationError(f"cannot inspect {label}") from error
        if not stat.S_ISREG(before.st_mode):
            raise ObservationError(f"{label} is not a regular file")
        if before.st_size < 0 or before.st_size > per_file_limit:
            raise ObservationError(f"{label} exceeds its byte limit")
        if before.st_size > self.remaining:
            raise ObservationError("observation hashing exceeds its total byte limit")

        open_flags = os.O_RDONLY
        for optional_flag in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
            open_flags |= getattr(os, optional_flag, 0)

        descriptor: int | None = None
        try:
            descriptor = os.open(path, open_flags)
            stream = os.fdopen(descriptor, "rb")
            descriptor = None
            with stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode):
                    raise ObservationError(f"{label} is not a regular file")
                if _file_identity(before) != _file_identity(opened):
                    raise ObservationError(f"{label} changed before it was opened")

                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > before.st_size or total > per_file_limit:
                        raise ObservationError(f"{label} changed or exceeded its byte limit")
                    digest.update(chunk)
                opened_after = os.fstat(stream.fileno())
            after = path.stat(follow_symlinks=False)
        except ObservationError:
            raise
        except OSError as error:
            raise ObservationError(f"cannot hash {label}") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if (
            total != before.st_size
            or _file_identity(before) != _file_identity(opened_after)
            or _file_identity(before) != _file_identity(after)
        ):
            raise ObservationError(f"{label} changed while being hashed")
        self.remaining -= total
        return total, digest.hexdigest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_git_sha(value: str, label: str) -> str:
    if LOWER_GIT_SHA.fullmatch(value) is None:
        raise ObservationError(f"{label} must be a lowercase 40-character Git SHA")
    return value


def _safe_target(value: str) -> str:
    if value not in TARGETS:
        raise ObservationError("target is not in the five-target canary matrix")
    return value


def _safe_environment_value(value: str, label: str) -> str:
    if len(value) > MAX_SAFE_VALUE_CHARS or any(ord(character) < 32 for character in value):
        raise ObservationError(f"{label} is not a bounded printable value")
    return value


def _path_replacements(environment: Mapping[str, str]) -> list[tuple[str, str]]:
    replacements: list[tuple[str, str]] = []
    for key, replacement in PATH_REPLACEMENTS.items():
        value = environment.get(key)
        if value and len(value) <= MAX_PATH_CHARS:
            normalized = value.replace("\\", "/").rstrip("/")
            if normalized:
                replacements.append((normalized, replacement))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    return replacements


def _redact_text(data: bytes, replacements: Sequence[tuple[str, str]]) -> tuple[str, bool]:
    truncated = len(data) > MAX_RETAINED_STREAM_BYTES
    text = data[:MAX_RETAINED_STREAM_BYTES].decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\\", "/")
    for source, replacement in replacements:
        flags = re.IGNORECASE if os.name == "nt" else 0
        text = re.sub(re.escape(source), replacement, text, flags=flags)
    text = URL_USERINFO.sub(lambda match: f"{match.group('scheme')}<redacted>@", text)
    text = SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('prefix')}<redacted>", text
    )
    return text, truncated


def _command_environment(environment: Mapping[str, str]) -> dict[str, str]:
    result = {
        key: value
        for key in COMMAND_ENVIRONMENT
        if (value := environment.get(key)) is not None
    }
    result["LANG"] = "C"
    result["LC_ALL"] = "C"
    if os.name == "nt":
        result["NoDefaultCurrentDirectoryInExePath"] = "1"
    return result


def _normalized_case_path(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _is_within_path(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    normalized_path = _normalized_case_path(path)
    normalized_root = _normalized_case_path(root)
    try:
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _resolve_executable(
    executable: str, environment: Mapping[str, str]
) -> tuple[str | None, str | None]:
    if os.path.isabs(executable):
        return executable, None
    path_value = environment.get("PATH")
    resolved = shutil.which(executable, path=path_value)
    if resolved is None:
        return None, "not-found"
    if not os.path.isabs(resolved):
        return None, "refused-unsafe-search-result"

    safe_directories = {
        _normalized_case_path(entry)
        for entry in (path_value or "").split(os.pathsep)
        if entry and os.path.isabs(entry)
    }
    resolved_parent = _normalized_case_path(Path(resolved).parent)
    workspace = environment.get("GITHUB_WORKSPACE")
    if resolved_parent not in safe_directories or (
        workspace is not None and _is_within_path(resolved, workspace)
    ):
        return None, "refused-unsafe-search-result"
    return resolved, None


def _drain_stream(stream: BinaryIO, capture: _StreamCapture, limit_event: threading.Event) -> None:
    try:
        read = getattr(stream, "read1", stream.read)
        while True:
            chunk = read(4096)
            if not chunk:
                return
            capture.total += len(chunk)
            if len(capture.retained) < MAX_RETAINED_STREAM_BYTES:
                remaining = MAX_RETAINED_STREAM_BYTES - len(capture.retained)
                capture.retained.extend(chunk[:remaining])
            if capture.total > MAX_COMMAND_STREAM_BYTES:
                capture.exceeded = True
                limit_event.set()
                return
    except OSError as error:
        capture.error = error.__class__.__name__
        limit_event.set()


def _run_command(
    argv: Sequence[str],
    environment: Mapping[str, str],
    replacements: Sequence[tuple[str, str]],
    *,
    retained_stdout: list[bytes] | None = None,
) -> dict[str, Any]:
    if not argv or any("\0" in argument for argument in argv):
        raise ObservationError("internal observation command is invalid")
    executable = argv[0]
    resolved, resolution_error = _resolve_executable(executable, environment)
    displayed_argv = [_redact_text(item.encode(), replacements)[0] for item in argv]
    if resolved is None:
        return {"argv": displayed_argv, "status": resolution_error}

    stdout_capture = _StreamCapture(bytearray())
    stderr_capture = _StreamCapture(bytearray())
    limit_event = threading.Event()
    try:
        process = subprocess.Popen(
            [resolved, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_command_environment(environment),
        )
    except OSError as error:
        return {
            "argv": displayed_argv,
            "error": error.__class__.__name__,
            "status": "launch-error",
        }
    assert process.stdout is not None
    assert process.stderr is not None
    threads = [
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_capture, limit_event),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_capture, limit_event),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()

    status: str | None = None
    deadline = time.monotonic() + MAX_COMMAND_SECONDS
    while process.poll() is None:
        if limit_event.wait(timeout=0.02):
            status = "output-limit" if (
                stdout_capture.exceeded or stderr_capture.exceeded
            ) else "read-error"
            process.kill()
            break
        if time.monotonic() >= deadline:
            status = "timeout"
            process.kill()
            break
    try:
        exit_code = process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        process.kill()
        exit_code = process.wait(timeout=2.0)
        status = status or "timeout"
    for thread in threads:
        thread.join(timeout=2.0)
    if any(thread.is_alive() for thread in threads):
        status = "read-error"
    process.stdout.close()
    process.stderr.close()

    stdout, stdout_truncated = _redact_text(bytes(stdout_capture.retained), replacements)
    stderr, stderr_truncated = _redact_text(bytes(stderr_capture.retained), replacements)
    stdout_truncated = stdout_truncated or stdout_capture.total > len(stdout_capture.retained)
    stderr_truncated = stderr_truncated or stderr_capture.total > len(stderr_capture.retained)
    if retained_stdout is not None:
        retained_stdout.append(bytes(stdout_capture.retained))
    result: dict[str, Any] = {
        "argv": displayed_argv,
        "exit_code": exit_code,
        "status": status or ("ok" if exit_code == 0 else "nonzero"),
        "stderr": stderr,
        "stderr_total_bytes": stderr_capture.total,
        "stderr_truncated": stderr_truncated or stderr_capture.exceeded,
        "stdout": stdout,
        "stdout_total_bytes": stdout_capture.total,
        "stdout_truncated": stdout_truncated or stdout_capture.exceeded,
    }
    if stdout_capture.error is not None:
        result["stdout_error"] = stdout_capture.error
    if stderr_capture.error is not None:
        result["stderr_error"] = stderr_capture.error
    return result


def _run_path_command(
    argv: Sequence[str],
    environment: Mapping[str, str],
    replacements: Sequence[tuple[str, str]],
    *,
    require_absolute: bool = True,
) -> tuple[dict[str, Any], Path | None]:
    raw_stdout: list[bytes] = []
    command = _run_command(
        argv,
        environment,
        replacements,
        retained_stdout=raw_stdout,
    )
    if (
        command.get("status") != "ok"
        or command.get("stdout_truncated") is not False
        or len(raw_stdout) != 1
    ):
        return command, None
    try:
        text = raw_stdout[0].decode("utf-8", errors="strict")
    except UnicodeError:
        return command, None
    lines = text.strip().splitlines()
    if len(lines) != 1 or not lines[0] or "\0" in lines[0] or len(lines[0]) > MAX_PATH_CHARS:
        return command, None
    path = Path(lines[0])
    if require_absolute and not path.is_absolute():
        return command, None
    return command, path


def _normalized_path(path: Path, replacements: Sequence[tuple[str, str]]) -> str:
    rendered, truncated = _redact_text(os.fspath(path).encode(), replacements)
    if truncated or len(rendered) > MAX_PATH_CHARS or "\n" in rendered:
        raise ObservationError("observed path is not bounded")
    return rendered


def _file_summary(
    path: Path,
    budget: HashBudget,
    replacements: Sequence[tuple[str, str]],
    byte_limit: int,
    label: str,
    *,
    resolve: bool,
) -> dict[str, Any]:
    try:
        selected = path.resolve(strict=True) if resolve else path
        size, digest = budget.digest_regular_file(selected, byte_limit, label)
    except ObservationError as error:
        return {"reason": str(error), "status": "unavailable"}
    except OSError as error:
        return {"reason": error.__class__.__name__, "status": "unavailable"}
    return {
        "name": selected.name,
        "path": _normalized_path(selected, replacements),
        "sha256": digest,
        "size": size,
        "status": "observed",
    }


def _executable_summary(
    name: str,
    environment: Mapping[str, str],
    budget: HashBudget,
    replacements: Sequence[tuple[str, str]],
) -> dict[str, Any]:
    resolved, resolution_error = _resolve_executable(name, environment)
    if resolved is None:
        return {"status": resolution_error}
    return _file_summary(
        Path(resolved), budget, replacements, MAX_TOOL_BYTES, f"{name} executable", resolve=True
    )


def _safe_relative_name(path: Path) -> str:
    value = path.as_posix()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ObservationError("manifest contains a non-UTF-8 relative path") from error
    if (
        not value
        or len(encoded) > MAX_PATH_CHARS
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise ObservationError("manifest contains an unsafe relative path")
    return value


def _directory_manifest(
    root: Path,
    budget: HashBudget,
    *,
    suffix: str | None,
    per_file_limit: int,
    label: str,
) -> dict[str, Any]:
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except FileNotFoundError:
        return {"reason": f"{label} directory is absent", "status": "unavailable"}
    except OSError as error:
        return {"reason": error.__class__.__name__, "status": "unavailable"}
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ObservationError(f"{label} root is not a directory")

    stack = [(root, 0)]
    scanned = 0
    selected: list[tuple[str, Path]] = []
    while stack:
        directory, depth = stack.pop()
        if depth > MAX_SCAN_DEPTH:
            raise ObservationError(f"{label} exceeds its directory depth limit")
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    scanned += 1
                    if scanned > MAX_SCAN_ENTRIES:
                        raise ObservationError(f"{label} exceeds its scan entry limit")
                    entries.append(entry)
        except OSError as error:
            raise ObservationError(f"cannot scan {label}") from error
        for entry in sorted(entries, key=lambda item: item.name):
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    raise ObservationError(f"{label} contains a symbolic link")
                if entry.is_dir(follow_symlinks=False):
                    stack.append((path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ObservationError(f"{label} contains a non-regular entry")
            except OSError as error:
                raise ObservationError(f"cannot inspect {label} entry") from error
            if suffix is not None and not entry.name.endswith(suffix):
                continue
            relative = _safe_relative_name(path.relative_to(root))
            selected.append((relative, path))
            if len(selected) > MAX_MANIFEST_ENTRIES:
                raise ObservationError(f"{label} exceeds its manifest entry limit")

    manifest: list[dict[str, Any]] = []
    total_bytes = 0
    for relative, path in sorted(selected):
        size, digest = budget.digest_regular_file(path, per_file_limit, f"{label}/{relative}")
        total_bytes += size
        manifest.append({"name": relative, "sha256": digest, "size": size})
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return {
        "entries": manifest,
        "entry_count": len(manifest),
        "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
        "scanned_entry_count": scanned,
        "status": "observed",
        "total_bytes": total_bytes,
    }


def _runner_observation(environment: Mapping[str, str]) -> dict[str, Any]:
    values: dict[str, str | None] = {}
    for key in SAFE_RUNNER_ENVIRONMENT:
        value = environment.get(key)
        values[key] = None if value is None else _safe_environment_value(value, key)
    values["python_platform_machine"] = _safe_environment_value(platform.machine(), "machine")
    values["python_platform_system"] = _safe_environment_value(platform.system(), "system")
    values["python_platform_release"] = _safe_environment_value(platform.release(), "release")
    return values


def _tool_observations(
    target: str,
    environment: Mapping[str, str],
    budget: HashBudget,
    replacements: Sequence[tuple[str, str]],
) -> tuple[dict[str, Any], Path | None]:
    rustup_which_cargo, active_cargo = _run_path_command(
        ["rustup", "which", "cargo"], environment, replacements
    )
    rustup_which_rustc, active_rustc = _run_path_command(
        ["rustup", "which", "rustc"], environment, replacements
    )
    target_libdir_command, target_libdir = _run_path_command(
        ["rustc", "--print", "target-libdir", "--target", target],
        environment,
        replacements,
    )
    commands = {
        "cargo_verbose_version": _run_command(["cargo", "-Vv"], environment, replacements),
        "git_version": _run_command(["git", "--version"], environment, replacements),
        "rustc_verbose_version": _run_command(["rustc", "-vV"], environment, replacements),
        "rustup_active_toolchain": _run_command(
            ["rustup", "show", "active-toolchain"], environment, replacements
        ),
        "rustup_version": _run_command(["rustup", "-V"], environment, replacements),
        "rustup_which_cargo": rustup_which_cargo,
        "rustup_which_rustc": rustup_which_rustc,
        "target_libdir": target_libdir_command,
    }
    executables = {
        name: _executable_summary(name, environment, budget, replacements)
        for name in ("cargo", "git", "rustc", "rustup")
    }
    executables["python"] = _file_summary(
        Path(sys.executable),
        budget,
        replacements,
        MAX_TOOL_BYTES,
        "Python executable",
        resolve=True,
    )
    for name, path in (("cargo", active_cargo), ("rustc", active_rustc)):
        if path is not None:
            executables[f"active_{name}"] = _file_summary(
                Path(path),
                budget,
                replacements,
                MAX_TOOL_BYTES,
                f"active {name}",
                resolve=True,
            )
        else:
            executables[f"active_{name}"] = {
                "reason": "rustup did not return one complete path",
                "status": "unavailable",
            }
    python_version = {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
    }
    return {
        "commands": commands,
        "executables": executables,
        "python": python_version,
    }, target_libdir


def _platform_observation(
    system: str,
    binary: Path,
    environment: Mapping[str, str],
    budget: HashBudget,
    replacements: Sequence[tuple[str, str]],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    limitations: list[str] = []
    if system == "Linux":
        musl_ld_command, musl_ld_path = _run_path_command(
            ["musl-gcc", "-print-prog-name=ld"],
            environment,
            replacements,
            require_absolute=False,
        )
        if musl_ld_path is not None and not musl_ld_path.is_absolute():
            resolved_musl_ld, _ = _resolve_executable(
                os.fspath(musl_ld_path), environment
            )
            musl_ld_path = None if resolved_musl_ld is None else Path(resolved_musl_ld)
        commands = {
            "dpkg_packages": _run_command(
                [
                    "dpkg-query",
                    "-W",
                    "-f=${Package}\\t${Version}\\t${Architecture}\\n",
                    "binutils",
                    "gcc",
                    "musl",
                    "musl-dev",
                    "musl-tools",
                ],
                environment,
                replacements,
            ),
            "ld_version": _run_command(["ld", "--version"], environment, replacements),
            "musl_gcc_dumpmachine": _run_command(
                ["musl-gcc", "-dumpmachine"], environment, replacements
            ),
            "musl_gcc_linker": musl_ld_command,
            "musl_gcc_version": _run_command(
                ["musl-gcc", "--version"], environment, replacements
            ),
            "os_release": _run_command(
                ["uname", "-a"], environment, replacements
            ),
            "readelf_dynamic": _run_command(
                ["readelf", "-dW", os.fspath(binary)], environment, replacements
            ),
            "readelf_headers": _run_command(
                ["readelf", "-hW", os.fspath(binary)], environment, replacements
            ),
            "readelf_program_headers": _run_command(
                ["readelf", "-lW", os.fspath(binary)], environment, replacements
            ),
        }
        tools = {
            name: _executable_summary(name, environment, budget, replacements)
            for name in ("gcc", "ld", "musl-gcc", "readelf")
        }
        tools["musl_selected_ld"] = (
            _file_summary(
                musl_ld_path,
                budget,
                replacements,
                MAX_TOOL_BYTES,
                "musl-selected linker",
                resolve=True,
            )
            if musl_ld_path is not None
            else {"reason": "musl-gcc did not resolve one linker path", "status": "unavailable"}
        )
        runtime = {
            key: commands[key]
            for key in ("readelf_dynamic", "readelf_headers", "readelf_program_headers")
        }
        return {"commands": commands, "executables": tools}, runtime, limitations

    if system == "Darwin":
        sdk_path_command, sdk_path = _run_path_command(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"],
            environment,
            replacements,
        )
        xcrun_clang, clang_path = _run_path_command(
            ["xcrun", "--find", "clang"], environment, replacements
        )
        xcrun_ld, ld_path = _run_path_command(
            ["xcrun", "--find", "ld"], environment, replacements
        )
        commands = {
            "clang_version": _run_command(["clang", "--version"], environment, replacements),
            "ld_version_details": _run_command(
                ["ld", "-version_details"], environment, replacements
            ),
            "otool_libraries": _run_command(
                ["otool", "-L", os.fspath(binary)], environment, replacements
            ),
            "otool_load_commands": _run_command(
                ["otool", "-l", os.fspath(binary)], environment, replacements
            ),
            "sdk_build_version": _run_command(
                ["xcrun", "--sdk", "macosx", "--show-sdk-build-version"],
                environment,
                replacements,
            ),
            "sdk_path": sdk_path_command,
            "sdk_version": _run_command(
                ["xcrun", "--sdk", "macosx", "--show-sdk-version"],
                environment,
                replacements,
            ),
            "sw_vers": _run_command(["sw_vers"], environment, replacements),
            "xcode_version": _run_command(["xcodebuild", "-version"], environment, replacements),
            "xcrun_clang": xcrun_clang,
            "xcrun_ld": xcrun_ld,
        }
        tools = {
            name: _executable_summary(name, environment, budget, replacements)
            for name in ("clang", "ld", "otool", "xcodebuild", "xcrun")
        }
        if sdk_path is not None:
            tools["sdk_settings"] = _file_summary(
                sdk_path / "SDKSettings.json",
                budget,
                replacements,
                MAX_TOOL_BYTES,
                "macOS SDK settings",
                resolve=True,
            )
        else:
            tools["sdk_settings"] = {
                "reason": "xcrun did not return one complete SDK path",
                "status": "unavailable",
            }
        for name, path in (("selected_clang", clang_path), ("selected_ld", ld_path)):
            tools[name] = (
                _file_summary(
                    path,
                    budget,
                    replacements,
                    MAX_TOOL_BYTES,
                    name.replace("_", " "),
                    resolve=True,
                )
                if path is not None
                else {"reason": "xcrun did not return one complete path", "status": "unavailable"}
            )
        runtime = {
            "otool_libraries": commands["otool_libraries"],
            "otool_load_commands": commands["otool_load_commands"],
        }
        return {"commands": commands, "executables": tools}, runtime, limitations

    if system == "Windows":
        program_files_x86 = environment.get("ProgramFiles(x86)")
        vswhere = None if program_files_x86 is None else os.path.join(
            program_files_x86, "Microsoft Visual Studio", "Installer", "vswhere.exe"
        )
        windows_commands: dict[str, Any] = {
            "cmd_version": _run_command(["cmd.exe", "/d", "/c", "ver"], environment, replacements),
            "where_cl": _run_command(["where.exe", "cl.exe"], environment, replacements),
            "where_dumpbin": _run_command(
                ["where.exe", "dumpbin.exe"], environment, replacements
            ),
            "where_link": _run_command(["where.exe", "link.exe"], environment, replacements),
        }
        if vswhere is None:
            windows_commands["vswhere_installation_path"] = {"status": "not-found"}
            windows_commands["vswhere_installation_version"] = {"status": "not-found"}
        else:
            windows_commands["vswhere_installation_path"] = _run_command(
                [vswhere, "-latest", "-products", "*", "-property", "installationPath"],
                environment,
                replacements,
            )
            windows_commands["vswhere_installation_version"] = _run_command(
                [
                    vswhere,
                    "-latest",
                    "-products",
                    "*",
                    "-property",
                    "installationVersion",
                ],
                environment,
                replacements,
            )
        tools = {
            name: _executable_summary(name, environment, budget, replacements)
            for name in ("cmd.exe", "where.exe")
        }
        if vswhere is not None:
            tools["vswhere.exe"] = _file_summary(
                Path(vswhere),
                budget,
                replacements,
                MAX_TOOL_BYTES,
                "vswhere executable",
                resolve=True,
            )
        dumpbin = _run_command(
            ["dumpbin.exe", "/dependents", os.fspath(binary)], environment, replacements
        )
        runtime = {"dumpbin_dependents": dumpbin}
        limitations.append(
            "Windows compiler/linker discovery here observes only the outer workflow shell. "
            "Forge xtask resolves and projects its own bounded MSVC PATH/LIB/INCLUDE environment; "
            "that internal environment is unavailable to this authority-side canary script and is "
            "not claimed or reconstructed."
        )
        return {"commands": windows_commands, "executables": tools}, runtime, limitations

    limitations.append("platform-specific compiler, linker, SDK, and runtime probes are unavailable")
    return {"commands": {}, "executables": {}}, {}, limitations


def build_observation(
    *,
    target: str,
    source_commit: str,
    authority_commit: str,
    binary: Path,
    cargo_home: Path,
    environment: Mapping[str, str],
    system: str | None = None,
    budget: HashBudget | None = None,
) -> dict[str, Any]:
    target = _safe_target(target)
    source_commit = _safe_git_sha(source_commit, "source commit")
    authority_commit = _safe_git_sha(authority_commit, "authority commit")
    replacements = _path_replacements(environment)
    budget = budget or HashBudget()
    selected_system = platform.system() if system is None else system

    binary_summary = _file_summary(
        binary,
        budget,
        replacements,
        MAX_BINARY_BYTES,
        "staged binary",
        resolve=False,
    )
    if binary_summary.get("status") != "observed":
        raise ObservationError("staged binary could not be observed as a bounded regular file")
    tools, target_libdir_path = _tool_observations(
        target, environment, budget, replacements
    )
    if target_libdir_path is None:
        rustlib_manifest: dict[str, Any] = {
            "reason": "rustc did not return one complete target libdir",
            "status": "unavailable",
        }
    else:
        rustlib_manifest = _directory_manifest(
            target_libdir_path,
            budget,
            suffix=None,
            per_file_limit=MAX_TOOL_BYTES,
            label="target Rust library directory",
        )
    cargo_cache = _directory_manifest(
        cargo_home / "registry" / "cache",
        budget,
        suffix=".crate",
        per_file_limit=MAX_CACHE_FILE_BYTES,
        label="Cargo registry archive cache",
    )
    platform_observation, runtime, platform_limitations = _platform_observation(
        selected_system, binary, environment, budget, replacements
    )
    limitations = [
        "This observation is diagnostic canary evidence only; it is not a v1 builder record, "
        "provenance input, qualification result, approval, signature, or release authority.",
        "Cargo archive hashes describe the fresh cache contents but do not independently prove "
        "that unpacked dependency source trees remained unchanged during every compiler process.",
        *platform_limitations,
    ]
    return {
        "authority_commit": authority_commit,
        "binary": binary_summary,
        "cargo_registry_archive_cache": cargo_cache,
        "capture_limits": {
            "command_seconds": MAX_COMMAND_SECONDS,
            "command_stream_bytes": MAX_COMMAND_STREAM_BYTES,
            "hash_total_bytes": MAX_HASHED_BYTES,
            "manifest_entries": MAX_MANIFEST_ENTRIES,
            "output_bytes": MAX_OUTPUT_BYTES,
            "retained_stream_bytes": MAX_RETAINED_STREAM_BYTES,
            "scan_entries": MAX_SCAN_ENTRIES,
        },
        "limitations": limitations,
        "platform": platform_observation,
        "purpose": PURPOSE,
        "runner": _runner_observation(environment),
        "runtime": runtime,
        "schema": SCHEMA,
        "source_commit": source_commit,
        "target": target,
        "target_rustlib": rustlib_manifest,
        "tools": tools,
    }


def write_observation(output_directory: Path, target: str, observation: Mapping[str, Any]) -> Path:
    target = _safe_target(target)
    if not output_directory.is_absolute():
        raise ObservationError("observation output directory must be absolute")
    parent = output_directory.parent
    try:
        parent_metadata = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise ObservationError("cannot inspect observation output parent") from error
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise ObservationError("observation output parent is not a directory")
    try:
        output_directory.mkdir(mode=0o700)
    except OSError as error:
        raise ObservationError("cannot create fresh observation output directory") from error

    rendered = (
        json.dumps(observation, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    if len(rendered) > MAX_OUTPUT_BYTES:
        raise ObservationError("rendered observation exceeds its byte limit")
    output = output_directory / f"runner-observation-{target}.json"
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ObservationError("cannot create observation output") from error
    return output


def _parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority-commit", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    try:
        observation = build_observation(
            target=options.target,
            source_commit=options.source_commit,
            authority_commit=options.authority_commit,
            binary=options.binary,
            cargo_home=options.cargo_home,
            environment=os.environ,
        )
        output = write_observation(options.output_dir, options.target, observation)
    except ObservationError as error:
        print(f"canary runner observation failed: {error}", file=sys.stderr)
        return 1
    print(f"wrote {output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
