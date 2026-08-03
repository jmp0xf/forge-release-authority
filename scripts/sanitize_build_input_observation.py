#!/usr/bin/env python3
"""Consume one private Forge build-input observation into a safe canary summary.

The input is candidate-controlled and may contain private native paths. This
module returns only a closed vocabulary of reported properties and always
attempts to remove the raw namespace. Its output is diagnostic policy input,
never qualification evidence.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import ntpath
import os
import posixpath
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SOURCE_SCHEMA = "forge.release-build-input-observation/v1"
SUMMARY_SCHEMA = "forge.release-authority-candidate-build-input-summary/v1"
SOURCE_PURPOSE = "diagnostic-only-not-release-evidence"
SOURCE_PHASE = "after-environment-preparation-before-cargo-release-build"
SUMMARY_TRUST = "candidate-controlled-self-report"
SUMMARY_EVIDENCE_STATUS = "excluded-from-release-evidence"
RAW_DIRECTORY_NAME = "forge-private-build-input"
RAW_FILE_PREFIX = "release-build-input-observation-"
MAX_RAW_BYTES = 512 * 1024
MAX_NATIVE_BYTES = 65_532
MAX_PATH_ENTRIES = 256
TARGETS = {
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-musl",
}
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
WINDOWS_DRIVE_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/].*\Z")
EXPECTED_ARGUMENTS_BEFORE_TARGET_DIRECTORY = (
    "build",
    "--release",
    "--locked",
    "--offline",
    "-p",
    "forge-cli",
    "--bin",
    "forge",
    "--message-format=json-render-diagnostics",
    "--target",
)
WINDOWS_ROOT_CLASSES = {
    "cargo-home",
    "git",
    "other-absolute",
    "program-data",
    "program-files",
    "runner-temp",
    "runner-tool-cache",
    "runner-tools",
    "rustup-home",
    "source-checkout",
    "system",
    "user-profile",
    "visual-studio",
    "windows-sdk",
    "workspace",
}


class SanitizationError(ValueError):
    """A private observation is unsafe, malformed, inconsistent, or unbounded."""


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare path and descriptor views without Windows-only projections."""
    if (
        left.st_dev == 0
        or left.st_ino == 0
        or right.st_dev == 0
        or right.st_ino == 0
    ):
        return False
    return (
        os.path.samestat(left, right)
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
    )


def _same_directory_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev != 0
        and left.st_ino != 0
        and right.st_dev != 0
        and right.st_ino != 0
        and os.path.samestat(left, right)
        and stat.S_ISDIR(left.st_mode)
        and stat.S_ISDIR(right.st_mode)
        and not _is_reparse_point(left)
        and not _is_reparse_point(right)
    )


def _read_bounded_stable_regular_file(path: Path) -> bytes:
    try:
        before = path.stat(follow_symlinks=False)
    except OSError as error:
        raise SanitizationError("private observation cannot be inspected") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or _is_reparse_point(before)
        or before.st_size <= 0
        or before.st_size > MAX_RAW_BYTES
    ):
        raise SanitizationError("private observation is not one bounded regular file")

    flags = os.O_RDONLY
    for optional_flag in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, optional_flag, 0)

    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_point(opened)
                or opened.st_size <= 0
                or opened.st_size > MAX_RAW_BYTES
                or not _same_file_snapshot(before, opened)
            ):
                raise SanitizationError("private observation changed before it was opened")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > opened.st_size or total > MAX_RAW_BYTES:
                    raise SanitizationError("private observation changed while it was read")
                chunks.append(chunk)
            opened_after = os.fstat(stream.fileno())
        after = path.stat(follow_symlinks=False)
    except SanitizationError:
        raise
    except OSError as error:
        raise SanitizationError("private observation cannot be read") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if (
        total != opened.st_size
        or _file_identity(before) != _file_identity(after)
        or _file_identity(opened) != _file_identity(opened_after)
        or not _same_file_snapshot(after, opened_after)
    ):
        raise SanitizationError("private observation changed while it was read")
    return b"".join(chunks)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SanitizationError("private observation contains a duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise SanitizationError("private observation contains a non-finite JSON number")


def _reject_json_number(_value: str) -> None:
    raise SanitizationError("private observation contains an unexpected JSON number")


def _parse_document(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_reject_json_number,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_constant,
        )
    except SanitizationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SanitizationError("private observation is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise SanitizationError("private observation root is not an object")
    return value


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SanitizationError(f"{label} has an unexpected structure")
    return value


def _require_string(value: Any, expected: str, label: str) -> str:
    if not isinstance(value, str) or value != expected:
        raise SanitizationError(f"{label} is unexpected")
    return value


def _decode_canonical_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) > 87_376:
        raise SanitizationError(f"{label} is not bounded canonical Base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SanitizationError(f"{label} is not bounded canonical Base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SanitizationError(f"{label} is not bounded canonical Base64")
    if not decoded or len(decoded) > MAX_NATIVE_BYTES:
        raise SanitizationError(f"{label} decoded size is outside its bound")
    return decoded


def _decode_unix_native(value: Any, label: str) -> bytes:
    item = _require_exact_keys(value, {"encoding", "raw_base64"}, label)
    _require_string(item["encoding"], "unix-bytes", f"{label} encoding")
    decoded = _decode_canonical_base64(item["raw_base64"], label)
    if b"\0" in decoded or any(byte < 32 or byte == 127 for byte in decoded):
        raise SanitizationError(f"{label} contains a forbidden native byte")
    return decoded


def _decode_windows_native(value: Any, expected_encoding: str, label: str) -> str:
    item = _require_exact_keys(value, {"encoding", "raw_base64"}, label)
    _require_string(item["encoding"], expected_encoding, f"{label} encoding")
    decoded = _decode_canonical_base64(item["raw_base64"], label)
    if len(decoded) % 2 != 0:
        raise SanitizationError(f"{label} has an invalid Windows-native byte length")
    if any(decoded[index : index + 2] == b"\0\0" for index in range(0, len(decoded), 2)):
        raise SanitizationError(f"{label} contains a NUL code unit")
    try:
        text = decoded.decode("utf-16-le", errors="strict")
    except UnicodeError as error:
        raise SanitizationError(f"{label} is not strict UTF-16LE") from error
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise SanitizationError(f"{label} contains a forbidden native character")
    return text


def _native_value(value: Any, target: str, label: str) -> bytes | str:
    if target == WINDOWS_TARGET:
        return _decode_windows_native(value, "windows-wide", label)
    return _decode_unix_native(value, label)


def _native_literal(value: str, target: str) -> bytes | str:
    return value if target == WINDOWS_TARGET else value.encode("ascii")


def _native_path(value: str, target: str) -> bytes | str:
    return value if target == WINDOWS_TARGET else os.fsencode(value)


def _normalized_native_path(value: bytes | str, target: str) -> bytes | str:
    if target == WINDOWS_TARGET:
        assert isinstance(value, str)
        return ntpath.normcase(ntpath.normpath(value))
    assert isinstance(value, bytes)
    return posixpath.normpath(value)


def _is_absolute_native_path(value: bytes | str, target: str) -> bool:
    if target == WINDOWS_TARGET:
        assert isinstance(value, str)
        return WINDOWS_DRIVE_ABSOLUTE.fullmatch(value) is not None
    assert isinstance(value, bytes)
    return posixpath.isabs(value)


def _native_basename(value: bytes | str, target: str) -> bytes | str:
    if target == WINDOWS_TARGET:
        assert isinstance(value, str)
        return ntpath.basename(ntpath.normpath(value))
    assert isinstance(value, bytes)
    return posixpath.basename(posixpath.normpath(value))


def _is_within_native_path(candidate: bytes | str, root: bytes | str, target: str) -> bool:
    candidate = _normalized_native_path(candidate, target)
    root = _normalized_native_path(root, target)
    path_module = ntpath if target == WINDOWS_TARGET else posixpath
    try:
        return path_module.commonpath((candidate, root)) == root
    except (TypeError, ValueError):
        return False


def _validate_source_identity(value: Any, source_commit: str) -> None:
    identity = _require_exact_keys(value, {"object_format", "oid"}, "source identity")
    _require_string(identity["object_format"], "sha1", "source object format")
    _require_string(identity["oid"], source_commit, "source object ID")


def _validate_cargo_command(
    value: Any,
    *,
    target: str,
    expected_cargo: str,
    source_root: str,
    runner_temp: str,
    build_temp: str,
    stage_directory: str,
    cargo_home: str,
    raw_directory: str,
) -> dict[str, Any]:
    command = _require_exact_keys(
        value,
        {"program", "arguments", "working_directory"},
        "reported Cargo command",
    )
    program = _native_value(command["program"], target, "reported Cargo program")
    if program != _native_path(expected_cargo, target):
        raise SanitizationError("reported Cargo program differs from the authority selection")

    arguments_raw = command["arguments"]
    if not isinstance(arguments_raw, list) or len(arguments_raw) != 13:
        raise SanitizationError("reported Cargo argument count is unexpected")
    arguments = [
        _native_value(argument, target, "reported Cargo argument")
        for argument in arguments_raw
    ]
    expected = [
        _native_literal(argument, target)
        for argument in (
            *EXPECTED_ARGUMENTS_BEFORE_TARGET_DIRECTORY,
            target,
            "--target-dir",
        )
    ]
    if arguments[:-1] != expected:
        raise SanitizationError("reported Cargo arguments differ from the frozen profile")

    target_directory = arguments[-1]
    if not _is_absolute_native_path(target_directory, target):
        raise SanitizationError("reported Cargo target directory is not absolute")
    roots = (source_root, stage_directory, cargo_home, raw_directory)
    native_build_temp = _native_path(build_temp, target)
    if (
        not _is_absolute_native_path(native_build_temp, target)
        or not _is_within_native_path(
            native_build_temp, _native_path(runner_temp, target), target
        )
        or any(
            _is_within_native_path(native_build_temp, _native_path(root, target), target)
            or _is_within_native_path(
                _native_path(root, target), native_build_temp, target
            )
            for root in roots
        )
    ):
        raise SanitizationError("authority build temp root is not isolated")
    if any(
        _is_within_native_path(target_directory, _native_path(root, target), target)
        or _is_within_native_path(_native_path(root, target), target_directory, target)
        for root in roots
    ):
        raise SanitizationError("reported Cargo target directory is not disjoint")

    working_directory = _native_value(
        command["working_directory"], target, "reported Cargo working directory"
    )
    if (
        not _is_absolute_native_path(working_directory, target)
        or _native_basename(working_directory, target)
        != _native_literal("source", target)
        or not _is_within_native_path(
            working_directory, native_build_temp, target
        )
        or any(
            _is_within_native_path(
                working_directory, _native_path(root, target), target
            )
            or _is_within_native_path(
                _native_path(root, target), working_directory, target
            )
            for root in roots
        )
        or _is_within_native_path(working_directory, target_directory, target)
        or _is_within_native_path(target_directory, working_directory, target)
    ):
        raise SanitizationError(
            "reported Cargo working directory is not one isolated source checkout"
        )
    if not _is_within_native_path(
        target_directory, native_build_temp, target
    ):
        raise SanitizationError(
            "reported Cargo target directory is outside the authority build temp root"
        )
    return {
        "argument_count": 13,
        "native_encoding": "windows-wide" if target == WINDOWS_TARGET else "unix-bytes",
        "profile": "forge-release-cargo-v1",
        "program_profile": "matches-authority-selected-cargo",
        "target_directory_profile": "absolute-under-authority-build-temp-disjoint",
        "working_directory_profile": "absolute-under-authority-build-temp-isolated-source",
    }


def _windows_path_key(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value))


def _windows_path_is_within(candidate: str, root: str) -> bool:
    if not candidate or not root:
        return False
    try:
        return ntpath.commonpath(
            (_windows_path_key(candidate), _windows_path_key(root))
        ) == _windows_path_key(root)
    except ValueError:
        return False


def _classify_windows_path(
    value: str,
    *,
    environment: Mapping[str, str],
    source_root: str,
    runner_temp: str,
    cargo_home: str,
) -> str:
    if WINDOWS_DRIVE_ABSOLUTE.fullmatch(value) is None:
        raise SanitizationError("reported Windows environment contains a relative path")

    ordered_roots = (
        (source_root, "source-checkout"),
        (cargo_home, "cargo-home"),
        (environment.get("RUSTUP_HOME", ""), "rustup-home"),
        (environment.get("RUNNER_TOOL_CACHE", ""), "runner-tool-cache"),
        (runner_temp, "runner-temp"),
        (environment.get("GITHUB_WORKSPACE", ""), "workspace"),
        (environment.get("SYSTEMROOT", "") or environment.get("WINDIR", ""), "system"),
        (environment.get("USERPROFILE", ""), "user-profile"),
        (environment.get("ProgramData", ""), "program-data"),
    )
    for root, root_class in ordered_roots:
        if _windows_path_is_within(value, root):
            return root_class

    for key in ("ProgramFiles(x86)", "ProgramFiles"):
        root = environment.get(key, "")
        if _windows_path_is_within(value, root):
            relative = ntpath.relpath(_windows_path_key(value), _windows_path_key(root))
            if relative.startswith("microsoft visual studio\\"):
                return "visual-studio"
            if relative.startswith("windows kits\\"):
                return "windows-sdk"
            if relative.startswith("git\\"):
                return "git"
            return "program-files"

    folded = _windows_path_key(value).replace("/", "\\")
    drive, tail = ntpath.splitdrive(folded)
    first = next((part for part in tail.split("\\") if part), "")
    if first == "hostedtoolcache":
        return "runner-tool-cache"
    if first == "tools":
        return "runner-tools"
    if first == "programdata":
        return "program-data"
    if first == "windows":
        return "system"
    if drive and first in {"program files", "program files (x86)"}:
        return "program-files"
    return "other-absolute"


def _summarize_windows_path_list(
    value: str,
    *,
    environment: Mapping[str, str],
    source_root: str,
    runner_temp: str,
    cargo_home: str,
) -> dict[str, Any]:
    entries = value.split(";")
    if not entries or len(entries) > MAX_PATH_ENTRIES or any(not entry for entry in entries):
        raise SanitizationError("reported Windows environment path-list shape is unexpected")
    classes = [
        _classify_windows_path(
            entry,
            environment=environment,
            source_root=source_root,
            runner_temp=runner_temp,
            cargo_home=cargo_home,
        )
        for entry in entries
    ]
    if any(root_class not in WINDOWS_ROOT_CLASSES for root_class in classes):
        raise SanitizationError("reported Windows environment path class is unexpected")
    return {"entry_count": len(entries), "root_classes": classes}


def _validate_windows_environment(
    value: Any,
    *,
    target: str,
    environment: Mapping[str, str],
    source_root: str,
    runner_temp: str,
    cargo_home: str,
) -> dict[str, Any]:
    if target != WINDOWS_TARGET:
        status = _require_exact_keys(value, {"status"}, "reported MSVC environment")
        _require_string(status["status"], "not-applicable", "reported MSVC status")
        return {"status": "reported-not-applicable"}

    observed = _require_exact_keys(
        value,
        {"status", "path", "lib", "include"},
        "reported MSVC environment",
    )
    _require_string(observed["status"], "observed", "reported MSVC status")
    result: dict[str, Any] = {"status": "reported-observed"}
    for name in ("path", "lib", "include"):
        decoded = _decode_windows_native(
            observed[name], "windows-utf16le-base64", f"reported MSVC {name}"
        )
        result[name] = _summarize_windows_path_list(
            decoded,
            environment=environment,
            source_root=source_root,
            runner_temp=runner_temp,
            cargo_home=cargo_home,
        )
    return result


def sanitize_document(
    document: Mapping[str, Any],
    *,
    target: str,
    source_commit: str,
    expected_cargo: str,
    source_root: str,
    runner_temp: str,
    build_temp: str,
    stage_directory: str,
    cargo_home: str,
    raw_directory: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    if target not in TARGETS:
        raise SanitizationError("target is outside the five-target canary matrix")
    if LOWER_GIT_SHA.fullmatch(source_commit) is None:
        raise SanitizationError("source commit is not a full lowercase Git SHA")
    root = _require_exact_keys(
        document,
        {
            "schema",
            "purpose",
            "phase",
            "source_commit",
            "target",
            "cargo_command",
            "windows_msvc_environment",
        },
        "private observation",
    )
    _require_string(root["schema"], SOURCE_SCHEMA, "private observation schema")
    _require_string(root["purpose"], SOURCE_PURPOSE, "private observation purpose")
    _require_string(root["phase"], SOURCE_PHASE, "private observation phase")
    _require_string(root["target"], target, "private observation target")
    _validate_source_identity(root["source_commit"], source_commit)
    cargo = _validate_cargo_command(
        root["cargo_command"],
        target=target,
        expected_cargo=expected_cargo,
        source_root=source_root,
        runner_temp=runner_temp,
        build_temp=build_temp,
        stage_directory=stage_directory,
        cargo_home=cargo_home,
        raw_directory=raw_directory,
    )
    windows_environment = _validate_windows_environment(
        root["windows_msvc_environment"],
        target=target,
        environment=environment,
        source_root=source_root,
        runner_temp=runner_temp,
        cargo_home=cargo_home,
    )
    return {
        "evidence_status": SUMMARY_EVIDENCE_STATUS,
        "reported_cargo_command": cargo,
        "reported_phase": SOURCE_PHASE,
        "reported_windows_msvc_environment": windows_environment,
        "schema": SUMMARY_SCHEMA,
        "source_contract": SOURCE_SCHEMA,
        "trust": SUMMARY_TRUST,
    }


def _expected_raw_directory(input_directory: Path, runner_temp: Path) -> Path:
    if not input_directory.is_absolute() or not runner_temp.is_absolute():
        raise SanitizationError("private observation namespace must be absolute")
    expected = Path(os.path.abspath(runner_temp / RAW_DIRECTORY_NAME))
    actual = Path(os.path.abspath(input_directory))
    if os.path.normcase(os.fspath(actual)) != os.path.normcase(os.fspath(expected)):
        raise SanitizationError("private observation namespace is outside the fixed runner location")
    return actual


def cleanup_raw_namespace(input_directory: Path, runner_temp: Path, target: str) -> None:
    if target not in TARGETS:
        raise SanitizationError("target is outside the five-target canary matrix")
    directory = _expected_raw_directory(input_directory, runner_temp)
    expected_name = f"{RAW_FILE_PREFIX}{target}.json"
    try:
        metadata = directory.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise SanitizationError("private observation namespace cannot be inspected") from error
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_point(metadata):
        raise SanitizationError("private observation namespace is not a regular directory")
    if os.name != "nt":
        _cleanup_raw_namespace_posix(directory, expected_name, metadata)
        return
    _cleanup_raw_namespace_windows(directory, expected_name, metadata)


def _cleanup_raw_namespace_posix(
    directory: Path, expected_name: str, metadata: os.stat_result
) -> None:
    flags = os.O_RDONLY
    for optional_flag in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW"):
        flags |= getattr(os, optional_flag, 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(directory, flags)
        opened = os.fstat(descriptor)
        if not _same_directory_object(metadata, opened):
            raise SanitizationError("private observation namespace changed before cleanup")
        try:
            expected_metadata = os.stat(
                expected_name, dir_fd=descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            expected_metadata = None
        except OSError as error:
            raise SanitizationError(
                "private observation entry cannot be inspected"
            ) from error
        if expected_metadata is not None:
            if stat.S_ISDIR(expected_metadata.st_mode):
                raise SanitizationError("private observation entry is a directory")
            try:
                os.unlink(expected_name, dir_fd=descriptor)
            except OSError as error:
                raise SanitizationError(
                    "private observation entry cannot be removed"
                ) from error

        entry_count = 0
        try:
            with os.scandir(descriptor) as iterator:
                for _entry in iterator:
                    entry_count += 1
                    if entry_count > 4:
                        break
        except OSError as error:
            raise SanitizationError(
                "private observation namespace cannot be scanned"
            ) from error
        if entry_count > 4:
            raise SanitizationError(
                "private observation namespace exceeds its entry bound"
            )
        if entry_count:
            raise SanitizationError(
                "private observation namespace contains an unexpected entry"
            )
        opened_after = os.fstat(descriptor)
        if not _same_directory_object(opened, opened_after):
            raise SanitizationError("private observation namespace changed during cleanup")
    except SanitizationError:
        raise
    except OSError as error:
        raise SanitizationError("private observation namespace cannot be cleaned") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        final = directory.stat(follow_symlinks=False)
        if not _same_directory_object(metadata, final):
            raise SanitizationError("private observation namespace changed during cleanup")
        os.rmdir(directory)
    except SanitizationError:
        raise
    except OSError as error:
        raise SanitizationError("private observation namespace cannot be removed") from error


def _cleanup_raw_namespace_windows(
    directory: Path, expected_name: str, metadata: os.stat_result
) -> None:
    expected_path = directory / expected_name
    try:
        expected_metadata = expected_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        expected_metadata = None
    except OSError as error:
        raise SanitizationError("private observation entry cannot be inspected") from error
    if expected_metadata is not None:
        try:
            if stat.S_ISDIR(expected_metadata.st_mode):
                raise SanitizationError("private observation entry is a directory")
            before_unlink = directory.stat(follow_symlinks=False)
            if not _same_directory_object(metadata, before_unlink):
                raise SanitizationError(
                    "private observation namespace changed before cleanup"
                )
            os.unlink(expected_path)
            after_unlink = directory.stat(follow_symlinks=False)
            if not _same_directory_object(metadata, after_unlink):
                raise SanitizationError(
                    "private observation namespace changed during cleanup"
                )
        except SanitizationError:
            raise
        except OSError as error:
            raise SanitizationError("private observation entry cannot be removed") from error

    entries: list[os.DirEntry[str]] = []
    overflow = False
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries.append(entry)
                if len(entries) > 4:
                    overflow = True
                    break
    except OSError as error:
        raise SanitizationError("private observation namespace cannot be scanned") from error
    if overflow:
        raise SanitizationError("private observation namespace exceeds its entry bound")
    if entries:
        raise SanitizationError("private observation namespace contains an unexpected entry")
    try:
        final = directory.stat(follow_symlinks=False)
        if not _same_directory_object(metadata, final):
            raise SanitizationError("private observation namespace changed during cleanup")
        os.rmdir(directory)
    except SanitizationError:
        raise
    except OSError as error:
        raise SanitizationError("private observation namespace cannot be removed") from error


def consume_build_input_observation(
    *,
    input_directory: Path,
    target: str,
    source_commit: str,
    expected_cargo: str,
    source_root: str,
    runner_temp: str,
    build_temp: str,
    stage_directory: str,
    cargo_home: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    if target not in TARGETS:
        raise SanitizationError("target is outside the five-target canary matrix")
    directory = _expected_raw_directory(input_directory, Path(runner_temp))
    raw_path = directory / f"{RAW_FILE_PREFIX}{target}.json"
    try:
        raw = _read_bounded_stable_regular_file(raw_path)
        document = _parse_document(raw)
        return sanitize_document(
            document,
            target=target,
            source_commit=source_commit,
            expected_cargo=expected_cargo,
            source_root=source_root,
            runner_temp=runner_temp,
            build_temp=build_temp,
            stage_directory=stage_directory,
            cargo_home=cargo_home,
            raw_directory=os.fspath(directory),
            environment=environment,
        )
    finally:
        cleanup_raw_namespace(directory, Path(runner_temp), target)


def _parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup-only", action="store_true", required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--runner-temp", type=Path, required=True)
    parser.add_argument("--target", required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    try:
        cleanup_raw_namespace(options.input_dir, options.runner_temp, options.target)
    except SanitizationError as error:
        print(f"private build-input cleanup failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
