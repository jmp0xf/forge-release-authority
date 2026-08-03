#!/usr/bin/env python3
"""Independently qualify the fixed Forge rc.2 release asset set.

This verifier is intentionally Python-standard-library-only and never imports or
executes Forge.  It accepts only the checked-in authority policy, finalized
release files, and build records.  The production CLI requires independent
binary-structure checking.  On success it can write a deterministic SLSA
provenance v1 *predicate*.  Signing and publication are deliberately out of
scope.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import sys
import threading
import tomllib
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Iterator,
    Mapping,
    NoReturn,
    Sequence,
    SupportsIndex,
    cast,
)
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


POLICY_SCHEMA = "forge.release-authority-policy/v1"
BUILDER_RECORD_SCHEMA = "forge.release-authority-builder-record/v1"
MANIFEST_SCHEMA = "forge.release-manifest/v2"
SBOM_GRAPH_SCHEMA = "forge.release-sbom-graph/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
SOURCE_OWNER = "jmp0xf"
SOURCE_OWNER_ID = 2247932
SOURCE_REPOSITORY = "forge"
SOURCE_REPOSITORY_ID = 1312750430
AUTHORITY_OWNER = "jmp0xf"
AUTHORITY_OWNER_ID = 2247932
AUTHORITY_REPOSITORY = "forge-release-authority"
AUTHORITY_REPOSITORY_ID = 1317240187
AUTHORITY_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
AUTHORITY_OIDC_SUBJECT_PREFIX = "repo:jmp0xf@2247932/forge-release-authority@1317240187"
AUTHORITY_ENVIRONMENT = "forge-release"
TARGET_CONTRACTS = {
    "x86_64-unknown-linux-musl": {
        "runnerLabel": "ubuntu-24.04",
        "binaryFormat": "elf64-x86_64-static",
        "binary": "forge-0.1.0-rc.2-x86_64-unknown-linux-musl",
        "sbom": "forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json",
        "builderRecord": "builder-record-x86_64-unknown-linux-musl.json",
    },
    "aarch64-unknown-linux-musl": {
        "runnerLabel": "ubuntu-24.04-arm",
        "binaryFormat": "elf64-aarch64-static",
        "binary": "forge-0.1.0-rc.2-aarch64-unknown-linux-musl",
        "sbom": "forge-0.1.0-rc.2-aarch64-unknown-linux-musl.cdx.json",
        "builderRecord": "builder-record-aarch64-unknown-linux-musl.json",
    },
    "x86_64-apple-darwin": {
        "runnerLabel": "macos-15-intel",
        "binaryFormat": "macho64-x86_64",
        "binary": "forge-0.1.0-rc.2-x86_64-apple-darwin",
        "sbom": "forge-0.1.0-rc.2-x86_64-apple-darwin.cdx.json",
        "builderRecord": "builder-record-x86_64-apple-darwin.json",
    },
    "aarch64-apple-darwin": {
        "runnerLabel": "macos-15",
        "binaryFormat": "macho64-aarch64",
        "binary": "forge-0.1.0-rc.2-aarch64-apple-darwin",
        "sbom": "forge-0.1.0-rc.2-aarch64-apple-darwin.cdx.json",
        "builderRecord": "builder-record-aarch64-apple-darwin.json",
    },
    "x86_64-pc-windows-msvc": {
        "runnerLabel": "windows-2025",
        "binaryFormat": "pe64-x86_64",
        "binary": "forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe",
        "sbom": "forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe.cdx.json",
        "builderRecord": "builder-record-x86_64-pc-windows-msvc.json",
    },
}
AUTHORITY_WORKFLOW_REF = (
    "jmp0xf/forge-release-authority/.github/workflows/qualify.yml@refs/heads/main"
)
GITHUB_API_ROOT = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_API_TOKEN_ENV = "FORGE_AUTHORITY_GITHUB_TOKEN"
GITHUB_API_TIMEOUT_SECONDS = 30
AUTHORITY_VERIFIER_PATH = Path(__file__).resolve()
AUTHORITY_POLICY_PATH = (
    AUTHORITY_VERIFIER_PATH.parents[1] / "contracts" / "release-policy.json"
)
BUILD_TYPE_URI = (
    "https://github.com/jmp0xf/forge-release-authority/"
    "blob/main/docs/build-types/qualify-v1.md"
)
BUILDER_ID_URI = (
    "https://github.com/jmp0xf/forge-release-authority/"
    "blob/main/docs/builders/github-actions-protected-v1.md"
)
MANIFEST_NAME = "release-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
NOTICE_NAME = "THIRD-PARTY-LICENSES.txt"
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SPDX_EXPRESSION = re.compile(r"[A-Za-z0-9.+() -]+\Z")
MAX_AUTHORITY_POLICY_BYTES = 1024 * 1024
MAX_AUTHORITY_VERIFIER_BYTES = 4 * 1024 * 1024
MAX_GITHUB_METADATA_BYTES = 4 * 1024 * 1024
MAX_GITHUB_TREE_ENTRIES = 4096
MAX_SBOM_COMPONENTS = 512
MAX_SBOM_DEPENDENCY_EDGES = 4_096
MAX_ELF_PROGRAM_HEADERS = 128
MAX_ELF_DYNAMIC_TABLE_BYTES = 1024 * 1024
MAX_MACHO_LOAD_COMMANDS = 256
MAX_MACHO_LOAD_COMMAND_BYTES = 1024 * 1024
MAX_PE_SECTIONS = 96
MAX_JSON_INTEGER_CHARACTERS = 64
MAX_DIRECTORY_ANCESTORS = 1024

StatIdentity = tuple[int, int, int, int, int, int]
ObjectIdentity = tuple[int, int, int]


class VerificationError(ValueError):
    """An input did not satisfy the frozen qualification contract."""


_EXACT_IO_CONSTRUCTION_TOKEN = object()
_EXACT_IO_LIVE = "live"
_EXACT_IO_CLOSING = "closing"
_EXACT_IO_CLOSED = "closed"


class _ExactIoCloseAttempt:
    """Whether fd cleanup crossed the point after which retry is unsafe."""

    __slots__ = ("started",)

    def __init__(self) -> None:
        self.started = False


class _ExactIoLifetime:
    """Owner-bound state granting at most one thread permission to close fds."""

    __slots__ = ("_active_depth", "_active_thread", "_lock", "_owner", "_state")

    def __init__(self, construction_token: object) -> None:
        if construction_token is not _EXACT_IO_CONSTRUCTION_TOKEN:
            raise TypeError("exact I/O lifetimes are backend-created only")
        self._active_depth = 0
        self._active_thread: int | None = None
        self._lock = threading.RLock()
        self._owner: object | None = None
        self._state = _EXACT_IO_LIVE

    def bind(self, owner: object, construction_token: object) -> None:
        """Bind this lifetime exactly once to its backend-created resource."""
        if construction_token is not _EXACT_IO_CONSTRUCTION_TOKEN:
            raise TypeError("exact I/O lifetimes are backend-created only")
        with self._lock:
            if self._owner is not None:
                raise TypeError("exact I/O lifetime already has an owner")
            self._owner = owner

    def owns(self, owner: object) -> bool:
        with self._lock:
            return self._owner is owner

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._state != _EXACT_IO_LIVE

    @contextmanager
    def operation(self, owner: object, label: str) -> Iterator[None]:
        """Exclude close while one owner-validated fd operation is in progress."""
        with self._lock:
            if self._owner is not owner:
                raise VerificationError(f"{label} has invalid resource ownership")
            if self._state != _EXACT_IO_LIVE:
                raise VerificationError(f"{label} is already closed")
            current_thread = threading.get_ident()
            if self._active_depth == 0:
                self._active_thread = current_thread
            elif self._active_thread != current_thread:
                raise VerificationError(f"{label} has inconsistent operation ownership")
            self._active_depth += 1
            try:
                yield
            finally:
                self._active_depth -= 1
                if self._active_depth == 0:
                    self._active_thread = None

    def close_with(
        self,
        owner: object,
        label: str,
        cleanup: Callable[[_ExactIoCloseAttempt], None],
    ) -> bool:
        """Grant one close attempt and classify interruption by cleanup progress.

        An interruption before cleanup starts restores LIVE because no fd was
        attempted. After cleanup starts, any interruption permanently leaves the
        resource CLOSED: later fds might remain open, so the Authority must discard
        the process rather than retry and risk closing reused fd numbers.
        """
        with self._lock:
            if self._owner is not owner:
                raise VerificationError(f"{label} has invalid resource ownership")
            if self._active_depth > 0 and self._active_thread == threading.get_ident():
                raise VerificationError(
                    f"{label} cannot close during an active operation"
                )
            if self._state == _EXACT_IO_CLOSED:
                return False
            if self._state == _EXACT_IO_CLOSING:
                raise VerificationError(f"{label} close is already in progress")
            attempt = _ExactIoCloseAttempt()
            try:
                self._state = _EXACT_IO_CLOSING
                cleanup(attempt)
                self._state = _EXACT_IO_CLOSED
            except BaseException:
                self._state = _EXACT_IO_CLOSED if attempt.started else _EXACT_IO_LIVE
                raise
            return True


class _OpaqueExactIoResource:
    """Read-only, non-constructible handle for live fd ownership."""

    __slots__ = ()
    _resource_kind = "exact I/O resource"

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise TypeError(f"opaque {self._resource_kind} cannot be constructed directly")

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise TypeError(f"opaque {self._resource_kind} is read-only")

    def __delattr__(self, _name: str) -> NoReturn:
        raise TypeError(f"opaque {self._resource_kind} is read-only")

    def _reject_copy_or_serialization(self) -> NoReturn:
        raise TypeError(f"opaque {self._resource_kind} cannot be copied or serialized")

    def __copy__(self) -> NoReturn:
        self._reject_copy_or_serialization()

    def __deepcopy__(self, _memo: dict[int, Any]) -> NoReturn:
        self._reject_copy_or_serialization()

    def __reduce__(self) -> NoReturn:
        self._reject_copy_or_serialization()

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        self._reject_copy_or_serialization()

    def __replace__(self, /, **_changes: Any) -> NoReturn:
        self._reject_copy_or_serialization()


@dataclass(frozen=True)
class _PinnedDirectory:
    """A directory whose actual inode is held independently of later path changes."""

    requested_path: Path
    resolved_path: Path
    directory_fd: int
    directory_identity: ObjectIdentity
    label: str


@dataclass(frozen=True)
class _PinnedOutput:
    """One create-only output addressed relative to a held parent directory."""

    requested_directory: Path
    directory: Path
    directory_fd: int
    directory_identity: ObjectIdentity
    name: str
    path: Path


@dataclass(frozen=True)
class _CreatedOutput:
    """A create-only output kept open until the complete output set is verified."""

    output: _PinnedOutput
    file_fd: int
    identity: StatIdentity
    expected_length: int
    expected_sha256: str
    expected_mode: int | None
    require_single_link: bool


class ExactInput(_OpaqueExactIoResource):
    """An immutable exact-directory snapshot backed by a held directory fd."""

    __slots__ = (
        "files",
        "resolved_path",
        "_directory",
        "_limits_by_name",
        "_total_limit",
        "_label",
        "_directory_identity",
        "_entry_identities",
        "_path_component_identities",
        "_content_sha256",
        "_lifetime",
    )
    _resource_kind = "input"

    files: Mapping[str, bytes]
    resolved_path: Path
    _directory: _PinnedDirectory
    _limits_by_name: Mapping[str, int]
    _total_limit: int
    _label: str
    _directory_identity: StatIdentity
    _entry_identities: Mapping[str, StatIdentity]
    _path_component_identities: tuple[tuple[str, str, ObjectIdentity], ...]
    _content_sha256: Mapping[str, str]
    _lifetime: _ExactIoLifetime

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("opaque ExactInput cannot be subclassed")

    @property
    def _closed(self) -> bool:
        return _require_exact_input_owner(self).closed

    def revalidate(self, rehash: bool = True) -> None:
        """Reject any path, identity, exact-set, or optional content drift."""
        _revalidate_exact_input(self, rehash=rehash)


class ExactOutput(_OpaqueExactIoResource):
    """Pinned exact outputs for consumption by the next Authority phase.

    The sandbox backend must keep every external writer terminated while this
    object is alive. POSIX file descriptors detect name and identity drift but
    cannot by themselves exclude a concurrent process with the same uid.
    """

    __slots__ = (
        "resolved_path",
        "names",
        "_directory",
        "_created_outputs",
        "_path_component_identities",
        "_maximum_file_count",
        "_maximum_file_bytes",
        "_maximum_total_bytes",
        "_label",
        "_lifetime",
    )
    _resource_kind = "output"

    resolved_path: Path
    names: tuple[str, ...]
    _directory: _PinnedDirectory
    _created_outputs: tuple[_CreatedOutput, ...]
    _path_component_identities: tuple[tuple[str, str, ObjectIdentity], ...]
    _maximum_file_count: int
    _maximum_file_bytes: int
    _maximum_total_bytes: int
    _label: str
    _lifetime: _ExactIoLifetime

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("opaque ExactOutput cannot be subclassed")

    @property
    def _closed(self) -> bool:
        return _require_exact_output_owner(self).closed

    def revalidate(self) -> None:
        """Recheck held fds, visible names, identities, bytes, and budgets."""
        if self._closed:
            raise VerificationError(f"{self._label} output is already closed")
        _revalidate_exact_output(self)

    def close(self) -> None:
        """Release held output fds without deleting any visible filesystem name."""
        lifetime = _require_exact_output_owner(self)

        def cleanup(attempt: _ExactIoCloseAttempt) -> None:
            _close_exact_io_fds_once(attempt, self._created_outputs, self._directory)

        lifetime.close_with(self, f"{self._label} output", cleanup)

    def __enter__(self) -> ExactOutput:
        lifetime = _require_exact_output_owner(self)
        with lifetime.operation(self, f"{self._label} output"):
            pass
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: Any,
    ) -> None:
        try:
            if exception_type is None:
                self.revalidate()
        finally:
            self.close()


def _require_exact_io_owner(
    resource: object, expected_type: type[object], kind: str
) -> _ExactIoLifetime:
    """Reject subclasses, hand-built objects, and detached lifetime tokens."""
    if type(resource) is not expected_type:
        raise VerificationError(f"exact {kind} must have its exact backend type")
    try:
        lifetime = object.__getattribute__(resource, "_lifetime")
    except AttributeError as error:
        raise VerificationError(
            f"exact {kind} has invalid resource ownership"
        ) from error
    if type(lifetime) is not _ExactIoLifetime or not lifetime.owns(resource):
        raise VerificationError(f"exact {kind} has invalid resource ownership")
    return lifetime


def _require_exact_input_owner(resource: object) -> _ExactIoLifetime:
    return _require_exact_io_owner(resource, ExactInput, "input")


def _require_exact_output_owner(resource: object) -> _ExactIoLifetime:
    return _require_exact_io_owner(resource, ExactOutput, "output")


def _new_exact_input(
    *,
    files: Mapping[str, bytes],
    resolved_path: Path,
    directory: _PinnedDirectory,
    limits_by_name: Mapping[str, int],
    total_limit: int,
    label: str,
    directory_identity: StatIdentity,
    entry_identities: Mapping[str, StatIdentity],
    path_component_identities: tuple[tuple[str, str, ObjectIdentity], ...],
    content_sha256: Mapping[str, str],
) -> ExactInput:
    result = object.__new__(ExactInput)
    lifetime = _ExactIoLifetime(_EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "files", files)
    object.__setattr__(result, "resolved_path", resolved_path)
    object.__setattr__(result, "_directory", directory)
    object.__setattr__(result, "_limits_by_name", limits_by_name)
    object.__setattr__(result, "_total_limit", total_limit)
    object.__setattr__(result, "_label", label)
    object.__setattr__(result, "_directory_identity", directory_identity)
    object.__setattr__(result, "_entry_identities", entry_identities)
    object.__setattr__(result, "_path_component_identities", path_component_identities)
    object.__setattr__(result, "_content_sha256", content_sha256)
    lifetime.bind(result, _EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_lifetime", lifetime)
    return result


def _new_exact_output(
    *,
    resolved_path: Path,
    names: tuple[str, ...],
    directory: _PinnedDirectory,
    created_outputs: tuple[_CreatedOutput, ...],
    path_component_identities: tuple[tuple[str, str, ObjectIdentity], ...],
    maximum_file_count: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
    label: str,
) -> ExactOutput:
    result = object.__new__(ExactOutput)
    lifetime = _ExactIoLifetime(_EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "resolved_path", resolved_path)
    object.__setattr__(result, "names", names)
    object.__setattr__(result, "_directory", directory)
    object.__setattr__(result, "_created_outputs", created_outputs)
    object.__setattr__(result, "_path_component_identities", path_component_identities)
    object.__setattr__(result, "_maximum_file_count", maximum_file_count)
    object.__setattr__(result, "_maximum_file_bytes", maximum_file_bytes)
    object.__setattr__(result, "_maximum_total_bytes", maximum_total_bytes)
    object.__setattr__(result, "_label", label)
    lifetime.bind(result, _EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_lifetime", lifetime)
    return result


@dataclass(frozen=True)
class _ResolvedMaterials:
    """Bytes resolved by the authority from immutable GitHub repository identities."""

    cargo_lock: bytes
    source_license_notices: bytes
    authority_policy: bytes
    authority_verifier: bytes


class _RejectRedirects(HTTPRedirectHandler):
    """Never send an authority request, including its token, through a redirect."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def _require_secure_posix_fs_capabilities() -> None:
    """Fail closed unless every filesystem primitive used for qualification exists."""
    missing: list[str] = []
    if os.name != "posix":
        missing.append("POSIX")
    for name in ("O_DIRECTORY", "O_NOFOLLOW"):
        value = getattr(os, name, None)
        if not isinstance(value, int) or value == 0:
            missing.append(name)
    supports_dir_fd = getattr(os, "supports_dir_fd", ())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", ())
    supports_fd = getattr(os, "supports_fd", ())
    if os.open not in supports_dir_fd:
        missing.append("open(dir_fd)")
    if os.stat not in supports_dir_fd:
        missing.append("stat(dir_fd)")
    if os.stat not in supports_follow_symlinks:
        missing.append("stat(follow_symlinks=False)")
    if os.scandir not in supports_fd:
        missing.append("scandir(fd)")
    if not callable(getattr(os, "geteuid", None)):
        missing.append("geteuid")
    if missing:
        raise VerificationError(
            "required secure POSIX filesystem capabilities unavailable: "
            + ", ".join(missing)
        )


def _require_exact_io_capabilities() -> None:
    """Fail closed unless the exact-I/O wrappers can enforce their contract."""
    _require_secure_posix_fs_capabilities()
    missing: list[str] = []
    if not isinstance(getattr(os, "O_EXCL", None), int) or os.O_EXCL == 0:
        missing.append("O_EXCL")
    for name in ("fchmod", "fsync"):
        if not callable(getattr(os, name, None)):
            missing.append(name)
    if missing:
        raise VerificationError(
            "required exact-I/O POSIX capabilities unavailable: "
            + ", ".join(missing)
        )


def _stat_identity(value: os.stat_result) -> StatIdentity:
    """Return the stable metadata that must not change while an input is read."""
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _object_identity(value: os.stat_result) -> ObjectIdentity:
    """Identify an object while allowing intentional directory-content changes."""
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _fstat(file_fd: int, label: str) -> os.stat_result:
    try:
        return os.fstat(file_fd)
    except OSError as error:
        raise VerificationError(f"cannot inspect {label}: {error}") from error


def _close_fd(file_fd: int) -> None:
    """Release one owned fd once; close errors have platform-dependent state."""
    try:
        os.close(file_fd)
    except OSError:
        pass


def _close_exact_io_fds_once(
    attempt: _ExactIoCloseAttempt,
    created_outputs: Sequence[_CreatedOutput],
    directory: _PinnedDirectory,
) -> None:
    attempt.started = True
    # Repeated asynchronous interruption after this boundary can strand later fds.
    # Never retry in-process: the Authority must fail closed and discard the process.
    first_error: BaseException | None = None
    for created in created_outputs:
        try:
            _close_fd(created.file_fd)
        except BaseException as error:
            if first_error is None:
                first_error = error
    try:
        _close_pinned_directory(directory)
    except BaseException as error:
        if first_error is None:
            first_error = error
    if first_error is not None:
        raise first_error


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_resolved_directory(resolved_path: Path, label: str) -> int:
    """Open every component of an absolute resolved path without following links."""
    if not resolved_path.is_absolute():
        raise VerificationError(f"{label} resolved path must be absolute")
    flags = _directory_open_flags()
    try:
        current_fd = os.open(resolved_path.anchor, flags)
    except OSError as error:
        raise VerificationError(f"cannot securely open {label}: {error}") from error
    try:
        for component in resolved_path.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as error:
                raise VerificationError(
                    f"cannot securely traverse {label}: {error}"
                ) from error
            previous_fd = current_fd
            current_fd = next_fd
            try:
                os.close(previous_fd)
            except OSError as error:
                raise VerificationError(
                    f"cannot release a traversed component of {label}: {error}"
                ) from error
        return current_fd
    except BaseException:
        _close_fd(current_fd)
        raise


def _pin_directory(path: Path, label: str) -> _PinnedDirectory:
    """Resolve a path for diagnostics, then bind all work to its opened inode."""
    _require_secure_posix_fs_capabilities()
    requested_path = Path(os.path.abspath(path))
    try:
        requested_visible = requested_path.lstat()
        resolved_path = requested_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise VerificationError(f"cannot inspect {label} {path}: {error}") from error
    if stat.S_ISLNK(requested_visible.st_mode) or not stat.S_ISDIR(
        requested_visible.st_mode
    ):
        raise VerificationError(f"{label} must be a non-symlink directory")

    directory_fd = _open_resolved_directory(resolved_path, label)
    try:
        opened = _fstat(directory_fd, label)
        if not stat.S_ISDIR(opened.st_mode) or _stat_identity(opened) != _stat_identity(
            requested_visible
        ):
            raise VerificationError(f"{label} changed before it was opened")
        try:
            visible_resolved_path = requested_path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise VerificationError(f"cannot re-inspect {label}: {error}") from error
        if visible_resolved_path != resolved_path:
            raise VerificationError(f"{label} path changed while it was opened")
        return _PinnedDirectory(
            requested_path=requested_path,
            resolved_path=resolved_path,
            directory_fd=directory_fd,
            directory_identity=_object_identity(opened),
            label=label,
        )
    except BaseException:
        os.close(directory_fd)
        raise


def _close_pinned_directory(directory: _PinnedDirectory) -> None:
    _close_fd(directory.directory_fd)


def _require_pinned_directory_path_stable(directory: _PinnedDirectory) -> None:
    """Require the diagnostic path to reopen to the inode already being used."""
    reopened = _pin_directory(directory.requested_path, directory.label)
    try:
        opened = _fstat(directory.directory_fd, directory.label)
        if (
            _object_identity(opened) != directory.directory_identity
            or reopened.directory_identity != directory.directory_identity
            or reopened.resolved_path != directory.resolved_path
        ):
            raise VerificationError(
                f"{directory.label} path changed during verification"
            )
    finally:
        _close_pinned_directory(reopened)


def _path_component_identities(
    requested_path: Path, resolved_path: Path, label: str
) -> tuple[tuple[str, str, ObjectIdentity], ...]:
    """Snapshot requested and canonical path components without hiding aliases."""

    def snapshot(kind: str, absolute_path: Path) -> list[tuple[str, str, ObjectIdentity]]:
        if not absolute_path.is_absolute():
            raise VerificationError(f"{label} {kind} path must be absolute")
        current = Path(absolute_path.anchor)
        result: list[tuple[str, str, ObjectIdentity]] = []
        for component in (None, *absolute_path.parts[1:]):
            if component is not None:
                current /= component
            try:
                visible = current.lstat()
            except OSError as error:
                raise VerificationError(
                    f"cannot inspect {label} {kind} path component {current}: {error}"
                ) from error
            result.append((kind, str(current), _object_identity(visible)))
        return result

    return tuple(
        snapshot("requested", requested_path) + snapshot("resolved", resolved_path)
    )


def _directory_is_same_or_descendant(
    directory_fd: int, possible_ancestor: ObjectIdentity
) -> bool:
    """Walk parent inodes from a held fd; never infer ancestry from path strings."""
    try:
        current_fd = os.dup(directory_fd)
    except OSError as error:
        raise VerificationError(
            f"cannot inspect qualification directory ancestry: {error}"
        ) from error
    try:
        for _depth in range(MAX_DIRECTORY_ANCESTORS):
            try:
                current_identity = _object_identity(
                    _fstat(current_fd, "qualification directory ancestry")
                )
            except OSError as error:
                raise VerificationError(
                    f"cannot inspect qualification directory ancestry: {error}"
                ) from error
            if current_identity == possible_ancestor:
                return True
            parent_fd: int | None = None
            try:
                parent_fd = os.open("..", _directory_open_flags(), dir_fd=current_fd)
                parent_identity = _object_identity(
                    _fstat(parent_fd, "qualification directory ancestry")
                )
            except VerificationError:
                if parent_fd is not None:
                    _close_fd(parent_fd)
                raise
            except OSError as error:
                if parent_fd is not None:
                    _close_fd(parent_fd)
                raise VerificationError(
                    f"cannot inspect qualification directory ancestry: {error}"
                ) from error
            if parent_identity == current_identity:
                _close_fd(parent_fd)
                return False
            previous_fd = current_fd
            current_fd = parent_fd
            try:
                os.close(previous_fd)
            except OSError as error:
                raise VerificationError(
                    f"cannot release qualification directory ancestry: {error}"
                ) from error
    finally:
        _close_fd(current_fd)
    raise VerificationError(
        f"qualification directory ancestry exceeds {MAX_DIRECTORY_ANCESTORS} levels"
    )


def _bounded_directory_names(
    directory_fd: int, maximum_count: int, label: str
) -> list[str]:
    """Enumerate no more than the exact contract can accept."""
    names: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if len(names) >= maximum_count:
                    raise VerificationError(
                        f"{label} contains more than {maximum_count} entries"
                    )
                names.append(entry.name)
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot enumerate {label}: {error}") from error
    return sorted(names)


def _duplicate_rejecting_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise VerificationError(f"JSON contains forbidden non-finite number {value!r}")


def _load_json_bytes(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} is not UTF-8: {error}") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
            parse_int=_parse_bounded_json_integer,
        )
    except VerificationError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise VerificationError(f"{label} is not valid JSON: {error}") from error


def _parse_bounded_json_integer(value: str) -> int:
    """Parse an integer only after bounding conversion work across Python versions."""
    if len(value) > MAX_JSON_INTEGER_CHARACTERS:
        raise VerificationError(
            "JSON integer exceeds the 64-character qualification limit"
        )
    return int(value, 10)


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{path} must be an object")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{path} must be an array")
    return value


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise VerificationError(f"{path} must be a string")
    return value


def _require_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise VerificationError(f"{path} must be an integer")
    return cast(int, value)


def _require_keys(value: Mapping[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise VerificationError(
            f"{path} fields differ from the contract; missing={missing}, extra={extra}"
        )


def _require_value(actual: Any, expected: Any, path: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise VerificationError(f"{path} must be {expected!r}, got {actual!r}")


def _require_sha256(value: Any, path: str) -> str:
    digest = _require_string(value, path)
    if LOWER_SHA256.fullmatch(digest) is None:
        raise VerificationError(f"{path} must be 64 lowercase hexadecimal characters")
    return digest


def _require_git_sha(value: str, path: str) -> str:
    if LOWER_GIT_SHA.fullmatch(value) is None:
        raise VerificationError(f"{path} must be a 40-character lowercase Git SHA")
    return value


def _require_safe_basename(value: Any, path: str) -> str:
    name = _require_string(value, path)
    if not name or name in {".", ".."} or Path(name).name != name:
        raise VerificationError(f"{path} must be a non-empty portable basename")
    if "/" in name or "\\" in name or "\x00" in name:
        raise VerificationError(f"{path} must not contain a path separator or NUL")
    return name


def _require_unique_casefold(names: Sequence[str], path: str) -> None:
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for name in names:
        if name in exact:
            raise VerificationError(f"{path} contains duplicate name {name!r}")
        exact.add(name)
        key = name.casefold()
        previous = folded.get(key)
        if previous is not None:
            raise VerificationError(
                f"{path} contains case-fold collision {previous!r} and {name!r}"
            )
        folded[key] = name


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _github_api_get(path: str, limit: int, label: str) -> Any:
    """Read one bounded JSON response from the fixed GitHub API origin."""
    if not path.startswith("/repositories/") or "\r" in path or "\n" in path:
        raise VerificationError(f"invalid GitHub API path for {label}")
    if limit <= 0:
        raise VerificationError(f"invalid GitHub API response limit for {label}")
    token = os.environ.get(GITHUB_API_TOKEN_ENV)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "forge-release-authority/v1",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token is not None:
        if (
            not token
            or len(token) > 4096
            or not token.isascii()
            or "\r" in token
            or "\n" in token
        ):
            raise VerificationError(
                f"{GITHUB_API_TOKEN_ENV} is not a bounded ASCII token"
            )
        headers["Authorization"] = f"Bearer {token}"
    url = GITHUB_API_ROOT + path
    request = Request(url, headers=headers, method="GET")
    try:
        with build_opener(_RejectRedirects()).open(
            request, timeout=GITHUB_API_TIMEOUT_SECONDS
        ) as response:
            if response.getcode() != 200 or response.geturl() != url:
                raise VerificationError(
                    f"GitHub API returned an unexpected response for {label}"
                )
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise VerificationError(
                    f"GitHub API returned non-JSON content for {label}"
                )
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                if (
                    len(content_length) > 20
                    or DECIMAL.fullmatch(content_length) is None
                    or int(content_length) > limit
                ):
                    raise VerificationError(
                        f"GitHub API response for {label} exceeds {limit} bytes"
                    )
            data = response.read(limit + 1)
    except VerificationError:
        raise
    except HTTPError as error:
        raise VerificationError(
            f"GitHub API request for {label} failed with HTTP {error.code}"
        ) from error
    except (OSError, TimeoutError, URLError) as error:
        raise VerificationError(f"GitHub API request for {label} failed") from error
    if len(data) > limit:
        raise VerificationError(
            f"GitHub API response for {label} exceeds {limit} bytes"
        )
    return _load_json_bytes(data, f"GitHub API {label}")


def _require_github_repository(
    identity: Mapping[str, Any], api_get: Callable[[str, int, str], Any]
) -> str:
    """Resolve and validate one immutable repository identity and protected main."""
    repository_id = _require_integer(identity["repositoryId"], "repository ID")
    owner_id = _require_integer(identity["ownerId"], "repository owner ID")
    owner = _require_string(identity["owner"], "repository owner")
    repository = _require_string(identity["repository"], "repository name")
    prefix = f"/repositories/{repository_id}"
    metadata = _require_object(
        api_get(prefix, MAX_GITHUB_METADATA_BYTES, f"repository {repository_id}"),
        f"GitHub repository {repository_id}",
    )
    _require_value(metadata.get("id"), repository_id, "GitHub repository.id")
    _require_value(metadata.get("name"), repository, "GitHub repository.name")
    _require_value(
        metadata.get("full_name"),
        f"{owner}/{repository}",
        "GitHub repository.full_name",
    )
    remote_owner = _require_object(metadata.get("owner"), "GitHub repository.owner")
    _require_value(remote_owner.get("id"), owner_id, "GitHub repository.owner.id")
    _require_value(remote_owner.get("login"), owner, "GitHub repository.owner.login")
    _require_value(metadata.get("visibility"), "public", "GitHub repository.visibility")
    _require_value(metadata.get("private"), False, "GitHub repository.private")
    _require_value(metadata.get("default_branch"), "main", "GitHub default branch")

    branch = _require_object(
        api_get(
            prefix + "/branches/main",
            MAX_GITHUB_METADATA_BYTES,
            f"repository {repository_id} protected main",
        ),
        "GitHub main branch",
    )
    _require_value(branch.get("name"), "main", "GitHub branch.name")
    _require_value(branch.get("protected"), True, "GitHub branch.protected")
    branch_commit = _require_object(branch.get("commit"), "GitHub branch.commit")
    return _require_git_sha(
        _require_string(branch_commit.get("sha"), "GitHub branch.commit.sha"),
        "GitHub branch.commit.sha",
    )


def _git_blob_sha(data: bytes) -> str:
    """Reproduce the SHA-1 object identity used by this 40-hex Git repository."""
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _resolve_repository_files(
    identity: Mapping[str, Any],
    commit: str,
    paths: Mapping[str, int],
    api_get: Callable[[str, int, str], Any] = _github_api_get,
) -> dict[str, bytes]:
    """Resolve regular blobs through repository -> commit -> tree -> blob APIs."""
    commit = _require_git_sha(commit, "repository commit")
    repository_id = _require_integer(identity["repositoryId"], "repository ID")
    main_commit = _require_github_repository(identity, api_get)
    if commit != main_commit:
        raise VerificationError(
            f"repository {repository_id} commit is not the protected main HEAD"
        )
    prefix = f"/repositories/{repository_id}"
    commit_document = _require_object(
        api_get(
            f"{prefix}/git/commits/{commit}",
            MAX_GITHUB_METADATA_BYTES,
            f"repository {repository_id} commit",
        ),
        "GitHub Git commit",
    )
    _require_value(commit_document.get("sha"), commit, "GitHub Git commit.sha")
    root_tree = _require_object(commit_document.get("tree"), "GitHub Git commit.tree")
    root_tree_sha = _require_git_sha(
        _require_string(root_tree.get("sha"), "GitHub Git commit.tree.sha"),
        "GitHub Git commit.tree.sha",
    )

    tree_cache: dict[str, dict[str, dict[str, Any]]] = {}

    def tree_entries(tree_sha: str) -> dict[str, dict[str, Any]]:
        cached = tree_cache.get(tree_sha)
        if cached is not None:
            return cached
        document = _require_object(
            api_get(
                f"{prefix}/git/trees/{tree_sha}",
                MAX_GITHUB_METADATA_BYTES,
                f"repository {repository_id} tree {tree_sha}",
            ),
            "GitHub Git tree",
        )
        _require_value(document.get("sha"), tree_sha, "GitHub Git tree.sha")
        _require_value(document.get("truncated"), False, "GitHub Git tree.truncated")
        raw_entries = _require_list(document.get("tree"), "GitHub Git tree.tree")
        if len(raw_entries) > MAX_GITHUB_TREE_ENTRIES:
            raise VerificationError(
                f"GitHub Git tree exceeds {MAX_GITHUB_TREE_ENTRIES} entries"
            )
        entries: dict[str, dict[str, Any]] = {}
        for index, raw_entry in enumerate(raw_entries):
            entry = _require_object(raw_entry, f"GitHub Git tree.tree[{index}]")
            path = _require_string(
                entry.get("path"), f"GitHub Git tree.tree[{index}].path"
            )
            if path in entries:
                raise VerificationError(f"GitHub Git tree repeats path {path!r}")
            entries[path] = entry
        tree_cache[tree_sha] = entries
        return entries

    resolved: dict[str, bytes] = {}
    for path, limit in paths.items():
        components = path.split("/")
        if (
            not components
            or any(component in {"", ".", ".."} for component in components)
            or any("\\" in component or "\x00" in component for component in components)
        ):
            raise VerificationError(f"invalid trusted repository path {path!r}")
        tree_sha = root_tree_sha
        final_entry: dict[str, Any] | None = None
        for index, component in enumerate(components):
            entry = tree_entries(tree_sha).get(component)
            if entry is None:
                raise VerificationError(f"trusted repository path {path!r} is absent")
            is_final = index == len(components) - 1
            if is_final:
                final_entry = entry
                break
            _require_value(
                entry.get("type"), "tree", f"trusted repository path {path!r} type"
            )
            _require_value(
                entry.get("mode"), "040000", f"trusted repository path {path!r} mode"
            )
            tree_sha = _require_git_sha(
                _require_string(
                    entry.get("sha"), f"trusted repository path {path!r} tree SHA"
                ),
                f"trusted repository path {path!r} tree SHA",
            )
        if final_entry is None:
            raise VerificationError(f"trusted repository path {path!r} is absent")
        _require_value(
            final_entry.get("type"), "blob", f"trusted repository path {path!r} type"
        )
        _require_value(
            final_entry.get("mode"), "100644", f"trusted repository path {path!r} mode"
        )
        blob_sha = _require_git_sha(
            _require_string(
                final_entry.get("sha"), f"trusted repository path {path!r} blob SHA"
            ),
            f"trusted repository path {path!r} blob SHA",
        )
        blob_document = _require_object(
            api_get(
                f"{prefix}/git/blobs/{blob_sha}",
                max(MAX_GITHUB_METADATA_BYTES, 2 * limit + 65536),
                f"repository {repository_id} blob {path}",
            ),
            "GitHub Git blob",
        )
        _require_value(blob_document.get("sha"), blob_sha, "GitHub Git blob.sha")
        _require_value(
            blob_document.get("encoding"), "base64", "GitHub Git blob.encoding"
        )
        size = _require_integer(blob_document.get("size"), "GitHub Git blob.size")
        if size < 0 or size > limit:
            raise VerificationError(
                f"trusted repository path {path!r} exceeds {limit} bytes"
            )
        encoded = _require_string(
            blob_document.get("content"), "GitHub Git blob.content"
        )
        try:
            data = base64.b64decode("".join(encoded.splitlines()), validate=True)
        except (ValueError, binascii.Error) as error:
            raise VerificationError(
                f"trusted repository path {path!r} has invalid base64"
            ) from error
        if len(data) != size:
            raise VerificationError(
                f"trusted repository path {path!r} size is inconsistent"
            )
        if _git_blob_sha(data) != blob_sha:
            raise VerificationError(
                f"trusted repository path {path!r} blob SHA is inconsistent"
            )
        resolved[path] = data
    return resolved


def _resolve_github_materials(
    policy: Mapping[str, Any], forge_commit: str, authority_commit: str
) -> _ResolvedMaterials:
    """Resolve every source/authority byte that the predicate attributes to Git."""
    source = _resolve_repository_files(
        policy["source"],
        forge_commit,
        {
            "Cargo.lock": policy["limits"]["cargoLockBytes"],
            "THIRD-PARTY-LICENSES.txt": policy["limits"]["noticeBytes"],
        },
    )
    authority = _resolve_repository_files(
        policy["authority"],
        authority_commit,
        {
            "contracts/release-policy.json": MAX_AUTHORITY_POLICY_BYTES,
            "scripts/verify_release.py": MAX_AUTHORITY_VERIFIER_BYTES,
        },
    )
    return _ResolvedMaterials(
        cargo_lock=source["Cargo.lock"],
        source_license_notices=source["THIRD-PARTY-LICENSES.txt"],
        authority_policy=authority["contracts/release-policy.json"],
        authority_verifier=authority["scripts/verify_release.py"],
    )


def _authority_commit_from_actions_environment(
    environment: Mapping[str, str],
) -> str:
    """Derive the authority commit only from a protected main workflow context."""
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_NAME": "main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_REF_TYPE": "branch",
        "GITHUB_REPOSITORY": f"{AUTHORITY_OWNER}/{AUTHORITY_REPOSITORY}",
        "GITHUB_REPOSITORY_ID": str(AUTHORITY_REPOSITORY_ID),
        "GITHUB_REPOSITORY_OWNER": AUTHORITY_OWNER,
        "GITHUB_REPOSITORY_OWNER_ID": str(AUTHORITY_OWNER_ID),
        "GITHUB_WORKFLOW_REF": AUTHORITY_WORKFLOW_REF,
    }
    for name, value in expected.items():
        _require_value(environment.get(name), value, f"Actions context {name}")
    authority_commit = _require_git_sha(
        environment.get("GITHUB_SHA", ""), "Actions context GITHUB_SHA"
    )
    workflow_commit = _require_git_sha(
        environment.get("GITHUB_WORKFLOW_SHA", ""),
        "Actions context GITHUB_WORKFLOW_SHA",
    )
    if authority_commit != workflow_commit:
        raise VerificationError(
            "Actions workflow commit differs from the protected authority commit"
        )
    return authority_commit


def _read_bounded_regular_path(path: Path, limit: int, label: str) -> bytes:
    name = _require_safe_basename(path.name, f"{label} name")
    parent = _pin_directory(path.parent, f"{label} parent directory")
    try:
        data, _identity = _read_regular_file_at(
            parent.directory_fd, name, limit, limit, label
        )
        _require_pinned_directory_path_stable(parent)
        return data
    finally:
        _close_pinned_directory(parent)


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    data = _read_bounded_regular_path(
        path, MAX_AUTHORITY_POLICY_BYTES, "authority policy"
    )
    policy = _require_object(_load_json_bytes(data, "authority policy"), "policy")
    _validate_policy(policy)
    return policy, _sha256(data)


def _validate_policy(policy: dict[str, Any]) -> None:
    _require_keys(
        policy,
        {
            "schema",
            "source",
            "authority",
            "release",
            "toolchain",
            "projectLicenseExpression",
            "targets",
            "builderRecords",
            "provenance",
            "limits",
        },
        "policy",
    )
    _require_value(policy["schema"], POLICY_SCHEMA, "policy.schema")

    source = _require_object(policy["source"], "policy.source")
    _require_keys(
        source, {"owner", "repository", "ownerId", "repositoryId"}, "policy.source"
    )
    for key in ("owner", "repository"):
        if not _require_string(source[key], f"policy.source.{key}"):
            raise VerificationError(f"policy.source.{key} must not be empty")
    for key in ("ownerId", "repositoryId"):
        if _require_integer(source[key], f"policy.source.{key}") <= 0:
            raise VerificationError(f"policy.source.{key} must be positive")
    for key, expected in {
        "owner": SOURCE_OWNER,
        "ownerId": SOURCE_OWNER_ID,
        "repository": SOURCE_REPOSITORY,
        "repositoryId": SOURCE_REPOSITORY_ID,
    }.items():
        _require_value(source[key], expected, f"policy.source.{key}")

    authority = _require_object(policy["authority"], "policy.authority")
    _require_keys(
        authority,
        {
            "owner",
            "repository",
            "ownerId",
            "repositoryId",
            "oidcIssuer",
            "oidcSubjectPrefix",
            "environment",
        },
        "policy.authority",
    )
    for key in (
        "owner",
        "repository",
        "oidcIssuer",
        "oidcSubjectPrefix",
        "environment",
    ):
        if not _require_string(authority[key], f"policy.authority.{key}"):
            raise VerificationError(f"policy.authority.{key} must not be empty")
    for key in ("ownerId", "repositoryId"):
        if _require_integer(authority[key], f"policy.authority.{key}") <= 0:
            raise VerificationError(f"policy.authority.{key} must be positive")
    for key, expected in {
        "owner": AUTHORITY_OWNER,
        "ownerId": AUTHORITY_OWNER_ID,
        "repository": AUTHORITY_REPOSITORY,
        "repositoryId": AUTHORITY_REPOSITORY_ID,
        "oidcIssuer": AUTHORITY_OIDC_ISSUER,
        "oidcSubjectPrefix": AUTHORITY_OIDC_SUBJECT_PREFIX,
        "environment": AUTHORITY_ENVIRONMENT,
    }.items():
        _require_value(authority[key], expected, f"policy.authority.{key}")

    release = _require_object(policy["release"], "policy.release")
    _require_keys(
        release,
        {
            "version",
            "tag",
            "manifestSchema",
            "artifactCount",
            "subjectCount",
            "checksumLineCount",
            "binaryStructureCheckRequired",
            "notice",
            "assets",
        },
        "policy.release",
    )
    version = _require_string(release["version"], "policy.release.version")
    _require_value(version, "0.1.0-rc.2", "policy.release.version")
    _require_value(release["tag"], f"v{version}", "policy.release.tag")
    _require_value(
        release["manifestSchema"], MANIFEST_SCHEMA, "policy.release.manifestSchema"
    )
    _require_value(release["artifactCount"], 11, "policy.release.artifactCount")
    _require_value(release["subjectCount"], 13, "policy.release.subjectCount")
    _require_value(release["checksumLineCount"], 12, "policy.release.checksumLineCount")
    _require_value(
        release["binaryStructureCheckRequired"],
        True,
        "policy.release.binaryStructureCheckRequired",
    )
    notice = _require_object(release["notice"], "policy.release.notice")
    _require_keys(notice, {"name", "target"}, "policy.release.notice")
    notice_name = _require_safe_basename(notice["name"], "policy.release.notice.name")
    _require_value(notice_name, NOTICE_NAME, "policy.release.notice.name")
    _require_value(notice["target"], "all", "policy.release.notice.target")

    toolchain = _require_object(policy["toolchain"], "policy.toolchain")
    _require_keys(toolchain, {"rust"}, "policy.toolchain")
    _require_value(toolchain["rust"], "1.96.0", "policy.toolchain.rust")
    expression = _require_string(
        policy["projectLicenseExpression"], "policy.projectLicenseExpression"
    )
    if not expression or SPDX_EXPRESSION.fullmatch(expression) is None:
        raise VerificationError(
            "policy.projectLicenseExpression is not a bounded SPDX expression"
        )

    targets = _require_list(policy["targets"], "policy.targets")
    if len(targets) != 5:
        raise VerificationError("policy.targets must contain exactly five entries")
    target_names: list[str] = []
    binaries: list[str] = []
    sboms: list[str] = []
    records: list[str] = []
    for index, raw_target in enumerate(targets):
        path = f"policy.targets[{index}]"
        target = _require_object(raw_target, path)
        _require_keys(
            target,
            {
                "triple",
                "runnerLabel",
                "binaryFormat",
                "binary",
                "sbom",
                "sbomGraph",
                "builderRecord",
            },
            path,
        )
        triple = _require_string(target["triple"], f"{path}.triple")
        target_names.append(triple)
        expected_target = TARGET_CONTRACTS.get(triple)
        if expected_target is None:
            raise VerificationError(f"{path}.triple is not a frozen v1 target")
        runner_label = _require_string(target["runnerLabel"], f"{path}.runnerLabel")
        _require_value(
            runner_label, expected_target["runnerLabel"], f"{path}.runnerLabel"
        )
        binary_format = _require_string(target["binaryFormat"], f"{path}.binaryFormat")
        _require_value(
            binary_format, expected_target["binaryFormat"], f"{path}.binaryFormat"
        )
        binary = _require_safe_basename(target["binary"], f"{path}.binary")
        _require_value(binary, expected_target["binary"], f"{path}.binary")
        sbom = _require_safe_basename(target["sbom"], f"{path}.sbom")
        _require_value(sbom, expected_target["sbom"], f"{path}.sbom")
        if sbom != f"{binary}.cdx.json":
            raise VerificationError(
                f"{path}.sbom must be the binary basename plus .cdx.json"
            )
        sbom_graph = _require_object(target["sbomGraph"], f"{path}.sbomGraph")
        _require_keys(
            sbom_graph,
            {"componentCount", "dependencyEdgeCount", "canonicalSha256"},
            f"{path}.sbomGraph",
        )
        component_count = _require_integer(
            sbom_graph["componentCount"], f"{path}.sbomGraph.componentCount"
        )
        if component_count <= 0 or component_count > MAX_SBOM_COMPONENTS:
            raise VerificationError(
                f"{path}.sbomGraph.componentCount is outside the accepted range"
            )
        dependency_edge_count = _require_integer(
            sbom_graph["dependencyEdgeCount"],
            f"{path}.sbomGraph.dependencyEdgeCount",
        )
        if (
            dependency_edge_count <= 0
            or dependency_edge_count > MAX_SBOM_DEPENDENCY_EDGES
        ):
            raise VerificationError(
                f"{path}.sbomGraph.dependencyEdgeCount is outside the accepted range"
            )
        _require_sha256(
            sbom_graph["canonicalSha256"], f"{path}.sbomGraph.canonicalSha256"
        )
        binaries.append(binary)
        sboms.append(sbom)
        builder_record = _require_safe_basename(
            target["builderRecord"], f"{path}.builderRecord"
        )
        _require_value(
            builder_record, expected_target["builderRecord"], f"{path}.builderRecord"
        )
        records.append(builder_record)
    _require_unique_casefold(target_names, "policy target triples")
    if set(target_names) != set(TARGET_CONTRACTS):
        raise VerificationError("policy targets must be the frozen v1 target set")
    _require_unique_casefold(binaries + sboms, "policy target assets")
    _require_unique_casefold(records, "policy builder records")

    assets_raw = _require_list(release["assets"], "policy.release.assets")
    assets = [
        _require_safe_basename(value, f"policy.release.assets[{index}]")
        for index, value in enumerate(assets_raw)
    ]
    _require_unique_casefold(assets, "policy.release.assets")
    expected_assets = sorted(
        binaries + sboms + [notice_name, MANIFEST_NAME, CHECKSUMS_NAME]
    )
    if assets != expected_assets:
        raise VerificationError(
            "policy.release.assets must be the sorted exact 13-file set"
        )

    records_policy = _require_object(policy["builderRecords"], "policy.builderRecords")
    _require_keys(records_policy, {"schema", "count"}, "policy.builderRecords")
    _require_value(
        records_policy["schema"], BUILDER_RECORD_SCHEMA, "policy.builderRecords.schema"
    )
    _require_value(records_policy["count"], 5, "policy.builderRecords.count")

    provenance = _require_object(policy["provenance"], "policy.provenance")
    _require_keys(
        provenance, {"predicateType", "buildType", "builderId"}, "policy.provenance"
    )
    _require_value(
        provenance["predicateType"],
        SLSA_PROVENANCE_V1,
        "policy.provenance.predicateType",
    )
    _require_value(
        provenance["buildType"], BUILD_TYPE_URI, "policy.provenance.buildType"
    )
    _require_value(
        provenance["builderId"], BUILDER_ID_URI, "policy.provenance.builderId"
    )

    limits = _require_object(policy["limits"], "policy.limits")
    expected_limits = {
        "binaryBytes",
        "cargoLockBytes",
        "sbomBytes",
        "noticeBytes",
        "manifestBytes",
        "checksumsBytes",
        "builderRecordBytes",
        "totalAssetBytes",
        "totalBuilderRecordBytes",
    }
    _require_keys(limits, expected_limits, "policy.limits")
    validated_limits: dict[str, int] = {}
    for key in expected_limits:
        limit_value = _require_integer(limits[key], f"policy.limits.{key}")
        if limit_value <= 0 or limit_value > 4 * 1024 * 1024 * 1024:
            raise VerificationError(
                f"policy.limits.{key} is outside the accepted range"
            )
        validated_limits[key] = limit_value
    maximum_asset_total = (
        5 * validated_limits["binaryBytes"]
        + 5 * validated_limits["sbomBytes"]
        + validated_limits["noticeBytes"]
        + validated_limits["manifestBytes"]
        + validated_limits["checksumsBytes"]
    )
    if validated_limits["totalAssetBytes"] > maximum_asset_total:
        raise VerificationError(
            "policy.limits.totalAssetBytes exceeds the sum of all per-file limits"
        )
    if (
        validated_limits["totalBuilderRecordBytes"]
        > 5 * validated_limits["builderRecordBytes"]
    ):
        raise VerificationError(
            "policy.limits.totalBuilderRecordBytes exceeds the five-record limit"
        )


def _read_exact_directory(
    directory: Path,
    expected_names: Sequence[str],
    size_limit: Callable[[str], int],
    total_limit: int,
    label: str,
) -> dict[str, bytes]:
    pinned = _pin_directory(directory, f"{label} directory")
    try:
        return _read_exact_pinned_directory(
            pinned, expected_names, size_limit, total_limit, label
        )
    finally:
        _close_pinned_directory(pinned)


def _read_exact_pinned_directory(
    directory: _PinnedDirectory,
    expected_names: Sequence[str],
    size_limit: Callable[[str], int],
    total_limit: int,
    label: str,
) -> dict[str, bytes]:
    files, _directory_identity, _entry_identities = (
        _read_exact_pinned_directory_snapshot(
            directory, expected_names, size_limit, total_limit, label
        )
    )
    return files


def _read_exact_pinned_directory_snapshot(
    directory: _PinnedDirectory,
    expected_names: Sequence[str],
    size_limit: Callable[[str], int],
    total_limit: int,
    label: str,
    *,
    require_single_link: bool = False,
) -> tuple[dict[str, bytes], StatIdentity, Mapping[str, StatIdentity]]:
    """Read one exact directory snapshot through its already-held inode."""
    if total_limit <= 0:
        raise VerificationError(f"{label} total byte limit must be positive")
    directory_before = _fstat(directory.directory_fd, f"{label} directory")
    if (
        not stat.S_ISDIR(directory_before.st_mode)
        or _object_identity(directory_before) != directory.directory_identity
    ):
        raise VerificationError(f"{label} directory changed before it was read")
    expected = sorted(expected_names)
    names = _bounded_directory_names(directory.directory_fd, len(expected), label)
    _require_unique_casefold(names, f"{label} directory")
    if names != expected:
        raise VerificationError(
            f"{label} file set differs from policy; missing={sorted(set(expected) - set(names))}, "
            f"extra={sorted(set(names) - set(expected))}"
        )
    result: dict[str, bytes] = {}
    entry_identities: dict[str, StatIdentity] = {}
    total = 0
    for name in expected:
        if require_single_link:
            try:
                visible_before = os.stat(
                    name, dir_fd=directory.directory_fd, follow_symlinks=False
                )
            except OSError as error:
                raise VerificationError(
                    f"cannot inspect {label}/{name}: {error}"
                ) from error
            if visible_before.st_nlink != 1:
                raise VerificationError(f"{label}/{name} must not be hard-linked")
        data, identity = _read_regular_file_at(
            directory.directory_fd,
            name,
            size_limit(name),
            total_limit - total,
            f"{label}/{name}",
        )
        total += len(data)
        if total > total_limit:
            raise VerificationError(
                f"{label} exceeds its {total_limit}-byte total policy limit"
            )
        result[name] = data
        entry_identities[name] = identity
    if (
        _bounded_directory_names(directory.directory_fd, len(expected), label)
        != expected
    ):
        raise VerificationError(f"{label} directory changed during verification")
    for name in expected:
        try:
            visible_final = os.stat(
                name, dir_fd=directory.directory_fd, follow_symlinks=False
            )
        except OSError as error:
            raise VerificationError(
                f"cannot re-inspect {label}/{name}: {error}"
            ) from error
        if (
            _stat_identity(visible_final) != entry_identities[name]
            or (require_single_link and visible_final.st_nlink != 1)
        ):
            raise VerificationError(f"{label}/{name} changed after it was read")
    directory_after = _fstat(directory.directory_fd, f"{label} directory")
    if _stat_identity(directory_before) != _stat_identity(directory_after):
        raise VerificationError(f"{label} directory changed during verification")
    _require_pinned_directory_path_stable(directory)
    return (
        result,
        _stat_identity(directory_after),
        MappingProxyType(entry_identities),
    )


def _normalize_exact_file_limits(
    limits_by_name: Mapping[str, int], total_limit: int, label: str
) -> Mapping[str, int]:
    if isinstance(total_limit, bool) or not isinstance(total_limit, int):
        raise VerificationError(f"{label} total byte limit must be an integer")
    if total_limit <= 0:
        raise VerificationError(f"{label} total byte limit must be positive")
    normalized: dict[str, int] = {}
    for candidate_name, candidate_limit in limits_by_name.items():
        name = _require_safe_basename(candidate_name, f"{label} input name")
        if isinstance(candidate_limit, bool) or not isinstance(candidate_limit, int):
            raise VerificationError(f"{label}/{name} byte limit must be an integer")
        if candidate_limit <= 0:
            raise VerificationError(f"{label}/{name} byte limit must be positive")
        normalized[name] = candidate_limit
    _require_unique_casefold(list(normalized), f"{label} input names")
    return MappingProxyType(normalized)


def _inspect_exact_pinned_directory(
    directory: _PinnedDirectory,
    limits_by_name: Mapping[str, int],
    total_limit: int,
    label: str,
) -> tuple[StatIdentity, Mapping[str, StatIdentity]]:
    """Capture exact entry identities without opening untrusted path strings."""
    directory_before = _fstat(directory.directory_fd, f"{label} directory")
    if (
        not stat.S_ISDIR(directory_before.st_mode)
        or _object_identity(directory_before) != directory.directory_identity
    ):
        raise VerificationError(f"{label} directory changed before inspection")
    expected = sorted(limits_by_name)
    names = _bounded_directory_names(directory.directory_fd, len(expected), label)
    _require_unique_casefold(names, f"{label} directory")
    if names != expected:
        raise VerificationError(
            f"{label} file set differs from contract; "
            f"missing={sorted(set(expected) - set(names))}, "
            f"extra={sorted(set(names) - set(expected))}"
        )
    identities: dict[str, StatIdentity] = {}
    total = 0
    for name in expected:
        try:
            visible = os.stat(name, dir_fd=directory.directory_fd, follow_symlinks=False)
        except OSError as error:
            raise VerificationError(f"cannot inspect {label}/{name}: {error}") from error
        if not stat.S_ISREG(visible.st_mode) or stat.S_ISLNK(visible.st_mode):
            raise VerificationError(f"{label}/{name} must be a non-symlink regular file")
        if visible.st_nlink != 1:
            raise VerificationError(f"{label}/{name} must not be hard-linked")
        if visible.st_size <= 0:
            raise VerificationError(f"{label}/{name} must not be empty")
        limit = limits_by_name[name]
        if visible.st_size > limit:
            raise VerificationError(f"{label}/{name} exceeds its {limit}-byte limit")
        total += visible.st_size
        if total > total_limit:
            raise VerificationError(f"{label} exceeds its total byte limit")
        identities[name] = _stat_identity(visible)
    if _bounded_directory_names(directory.directory_fd, len(expected), label) != expected:
        raise VerificationError(f"{label} directory changed during inspection")
    directory_after = _fstat(directory.directory_fd, f"{label} directory")
    if _stat_identity(directory_before) != _stat_identity(directory_after):
        raise VerificationError(f"{label} directory changed during inspection")
    _require_pinned_directory_path_stable(directory)
    return _stat_identity(directory_after), MappingProxyType(identities)


def _revalidate_exact_input(snapshot: ExactInput, *, rehash: bool) -> None:
    lifetime = _require_exact_input_owner(snapshot)
    with lifetime.operation(snapshot, f"{snapshot._label} input"):
        _revalidate_exact_input_open(snapshot, rehash=rehash)


def _revalidate_exact_input_open(snapshot: ExactInput, *, rehash: bool) -> None:
    if not isinstance(rehash, bool):
        raise VerificationError(f"{snapshot._label} rehash must be a boolean")
    components_before = _path_component_identities(
        snapshot._directory.requested_path,
        snapshot._directory.resolved_path,
        snapshot._label,
    )
    if components_before != snapshot._path_component_identities:
        raise VerificationError(f"{snapshot._label} path or ancestor identity changed")
    if rehash:
        files, directory_identity, entry_identities = (
            _read_exact_pinned_directory_snapshot(
                snapshot._directory,
                sorted(snapshot._limits_by_name),
                snapshot._limits_by_name.__getitem__,
                snapshot._total_limit,
                snapshot._label,
                require_single_link=True,
            )
        )
        content_sha256 = {name: _sha256(data) for name, data in files.items()}
        if content_sha256 != dict(snapshot._content_sha256):
            raise VerificationError(f"{snapshot._label} file content changed")
    else:
        directory_identity, entry_identities = _inspect_exact_pinned_directory(
            snapshot._directory,
            snapshot._limits_by_name,
            snapshot._total_limit,
            snapshot._label,
        )
    if directory_identity != snapshot._directory_identity:
        raise VerificationError(f"{snapshot._label} directory identity changed")
    if dict(entry_identities) != dict(snapshot._entry_identities):
        raise VerificationError(f"{snapshot._label} file identity changed")
    components_after = _path_component_identities(
        snapshot._directory.requested_path,
        snapshot._directory.resolved_path,
        snapshot._label,
    )
    if components_after != snapshot._path_component_identities:
        raise VerificationError(f"{snapshot._label} path or ancestor identity changed")


@contextmanager
def open_exact_input(
    directory: Path,
    limits_by_name: Mapping[str, int],
    total_limit: int,
    label: str,
) -> Iterator[ExactInput]:
    """Open one bounded exact input set and hold its directory until context exit."""
    _require_exact_io_capabilities()
    limits = _normalize_exact_file_limits(limits_by_name, total_limit, label)
    pinned = _pin_directory(directory, f"{label} directory")
    snapshot: ExactInput | None = None
    try:
        components_before = _path_component_identities(
            pinned.requested_path, pinned.resolved_path, label
        )
        files, directory_identity, entry_identities = (
            _read_exact_pinned_directory_snapshot(
                pinned,
                sorted(limits),
                limits.__getitem__,
                total_limit,
                label,
                require_single_link=True,
            )
        )
        components_after = _path_component_identities(
            pinned.requested_path, pinned.resolved_path, label
        )
        if components_before != components_after:
            raise VerificationError(f"{label} path or ancestor changed while opening")
        snapshot = _new_exact_input(
            files=MappingProxyType(files),
            resolved_path=pinned.resolved_path,
            directory=pinned,
            limits_by_name=limits,
            total_limit=total_limit,
            label=label,
            directory_identity=directory_identity,
            entry_identities=entry_identities,
            path_component_identities=components_after,
            content_sha256=MappingProxyType(
                {name: _sha256(data) for name, data in files.items()}
            ),
        )
        try:
            yield snapshot
        except BaseException:
            raise
        else:
            snapshot.revalidate()
    finally:
        if snapshot is None:
            _close_exact_io_fds_once(_ExactIoCloseAttempt(), (), pinned)
        else:
            lifetime = _require_exact_input_owner(snapshot)

            def cleanup(attempt: _ExactIoCloseAttempt) -> None:
                _close_exact_io_fds_once(attempt, (), pinned)

            lifetime.close_with(snapshot, f"{label} input", cleanup)


def _read_regular_file_at(
    directory_fd: int,
    name: str,
    limit: int,
    remaining_total: int,
    label: str,
) -> tuple[bytes, StatIdentity]:
    _require_secure_posix_fs_capabilities()
    try:
        visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise VerificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(visible.st_mode) or stat.S_ISLNK(visible.st_mode):
        raise VerificationError(f"{label} must be a non-symlink regular file")
    if visible.st_size <= 0:
        raise VerificationError(f"{label} must not be empty")
    if visible.st_size > limit:
        raise VerificationError(f"{label} exceeds its {limit}-byte policy limit")
    if visible.st_size > remaining_total:
        raise VerificationError(f"{label} exceeds the remaining directory total limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | os.O_NOFOLLOW
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise VerificationError(f"cannot securely open {label}: {error}") from error
    try:
        before = _fstat(file_fd, label)
        if not stat.S_ISREG(before.st_mode) or _stat_identity(
            visible
        ) != _stat_identity(before):
            raise VerificationError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        read_limit = min(limit, remaining_total)
        while True:
            chunk = os.read(file_fd, min(1024 * 1024, read_limit - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > read_limit:
                if remaining_total < limit:
                    raise VerificationError(
                        f"{label} exceeds the remaining directory total limit"
                    )
                raise VerificationError(
                    f"{label} exceeds its {limit}-byte policy limit"
                )
        after = _fstat(file_fd, label)
        try:
            visible_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise VerificationError(f"cannot re-inspect {label}: {error}") from error
    finally:
        os.close(file_fd)
    identity = _stat_identity(before)
    if (
        identity != _stat_identity(after)
        or identity != _stat_identity(visible_after)
        or total != before.st_size
    ):
        raise VerificationError(f"{label} changed while it was read")
    return b"".join(chunks), identity


def _asset_limit(
    policy: Mapping[str, Any], target_by_asset: Mapping[str, Any], name: str
) -> int:
    limits = _require_object(policy["limits"], "policy.limits")
    if name in target_by_asset:
        key = "sbomBytes" if name.endswith(".cdx.json") else "binaryBytes"
    elif name == policy["release"]["notice"]["name"]:
        key = "noticeBytes"
    elif name == MANIFEST_NAME:
        key = "manifestBytes"
    elif name == CHECKSUMS_NAME:
        key = "checksumsBytes"
    else:
        raise VerificationError(f"policy has no size class for asset {name!r}")
    return _require_integer(limits[key], f"policy.limits.{key}")


def _target_maps(policy: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_triple: dict[str, Any] = {}
    by_asset: dict[str, Any] = {}
    for target in policy["targets"]:
        by_triple[target["triple"]] = target
        by_asset[target["binary"]] = target
        by_asset[target["sbom"]] = target
    return by_triple, by_asset


def _validate_manifest(
    policy: Mapping[str, Any], assets: Mapping[str, bytes]
) -> dict[str, Any]:
    manifest = _require_object(
        _load_json_bytes(assets[MANIFEST_NAME], MANIFEST_NAME), "manifest"
    )
    _require_keys(
        manifest,
        {"schema", "release", "artifacts", "provenance", "rollback"},
        "manifest",
    )
    _require_value(
        manifest["schema"], policy["release"]["manifestSchema"], "manifest.schema"
    )

    release = _require_object(manifest["release"], "manifest.release")
    _require_keys(
        release, {"version", "channel", "distribution", "status"}, "manifest.release"
    )
    _require_value(
        release["version"], policy["release"]["version"], "manifest.release.version"
    )
    _require_value(release["channel"], "release-candidate", "manifest.release.channel")
    _require_value(
        release["distribution"], "github-release", "manifest.release.distribution"
    )
    _require_value(
        release["status"], "local-review-candidate", "manifest.release.status"
    )

    _, target_by_asset = _target_maps(policy)
    expected_artifacts: dict[str, tuple[str, str]] = {}
    for target in policy["targets"]:
        expected_artifacts[target["binary"]] = ("binary", target["triple"])
        expected_artifacts[target["sbom"]] = ("cyclonedx-sbom", target["triple"])
    notice = policy["release"]["notice"]
    expected_artifacts[notice["name"]] = ("license-notices", notice["target"])

    artifacts = _require_list(manifest["artifacts"], "manifest.artifacts")
    if len(artifacts) != policy["release"]["artifactCount"]:
        raise VerificationError(
            "manifest.artifacts does not contain exactly 11 entries"
        )
    artifact_names: list[str] = []
    for index, raw_artifact in enumerate(artifacts):
        path = f"manifest.artifacts[{index}]"
        artifact = _require_object(raw_artifact, path)
        _require_keys(artifact, {"name", "kind", "target", "length", "sha256"}, path)
        name = _require_safe_basename(artifact["name"], f"{path}.name")
        artifact_names.append(name)
        expected_kind_target = expected_artifacts.get(name)
        if expected_kind_target is None:
            raise VerificationError(f"{path}.name is not an allowed artifact")
        expected_kind, expected_target = expected_kind_target
        _require_value(artifact["kind"], expected_kind, f"{path}.kind")
        _require_value(artifact["target"], expected_target, f"{path}.target")
        actual_bytes = assets[name]
        _require_value(artifact["length"], len(actual_bytes), f"{path}.length")
        _require_value(artifact["sha256"], _sha256(actual_bytes), f"{path}.sha256")
    _require_unique_casefold(artifact_names, "manifest.artifacts")
    if artifact_names != sorted(expected_artifacts):
        raise VerificationError(
            "manifest.artifacts must be the sorted exact 11-artifact set"
        )

    provenance = _require_object(manifest["provenance"], "manifest.provenance")
    _require_keys(
        provenance,
        {
            "status",
            "predicate_type",
            "signing",
            "authority_status",
            "subject_set",
            "subjects",
        },
        "manifest.provenance",
    )
    expected_provenance = {
        "status": "required-external",
        "predicate_type": SLSA_PROVENANCE_V1,
        "signing": "sigstore-keyless-oidc",
        "authority_status": "unassigned-external",
        "subject_set": "exact-finalized-local-assets",
    }
    for key, expected in expected_provenance.items():
        _require_value(provenance[key], expected, f"manifest.provenance.{key}")
    subjects = _require_list(provenance["subjects"], "manifest.provenance.subjects")
    for index, subject in enumerate(subjects):
        _require_safe_basename(subject, f"manifest.provenance.subjects[{index}]")
    _require_unique_casefold(subjects, "manifest.provenance.subjects")
    if subjects != policy["release"]["assets"]:
        raise VerificationError(
            "manifest.provenance.subjects must be the sorted exact 13-file set"
        )

    rollback = _require_object(manifest["rollback"], "manifest.rollback")
    _require_keys(
        rollback,
        {"retain_published_releases", "previous_release", "status"},
        "manifest.rollback",
    )
    _require_value(
        rollback["retain_published_releases"],
        2,
        "manifest.rollback.retain_published_releases",
    )
    _require_value(
        rollback["previous_release"], None, "manifest.rollback.previous_release"
    )
    _require_value(
        rollback["status"], "first-candidate-no-n-minus-one", "manifest.rollback.status"
    )

    # Ensure every target asset used above is policy-mapped; this catches policy/code drift.
    if set(target_by_asset) != set(expected_artifacts) - {notice["name"]}:
        raise VerificationError("internal target-to-artifact mapping is inconsistent")
    return manifest


def _validate_checksums(policy: Mapping[str, Any], assets: Mapping[str, bytes]) -> None:
    data = assets[CHECKSUMS_NAME]
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("SHA256SUMS must be ASCII") from error
    if not text.endswith("\n") or "\r" in text:
        raise VerificationError("SHA256SUMS must use LF lines and end with one newline")
    lines = text[:-1].split("\n")
    if len(lines) != policy["release"]["checksumLineCount"]:
        raise VerificationError("SHA256SUMS must contain exactly 12 lines")
    expected_names = sorted(
        name for name in policy["release"]["assets"] if name != CHECKSUMS_NAME
    )
    actual_names: list[str] = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\x00]+)", line)
        if match is None:
            raise VerificationError(f"SHA256SUMS line {index + 1} is not canonical")
        digest, name = match.groups()
        _require_safe_basename(name, f"SHA256SUMS line {index + 1} name")
        actual_names.append(name)
        if name not in assets or name == CHECKSUMS_NAME:
            raise VerificationError(f"SHA256SUMS names unexpected asset {name!r}")
        if digest != _sha256(assets[name]):
            raise VerificationError(f"SHA256SUMS digest mismatch for {name}")
    _require_unique_casefold(actual_names, "SHA256SUMS")
    if actual_names != expected_names:
        raise VerificationError("SHA256SUMS names must be the sorted exact 12-file set")


def _validate_license_choice(value: Any, path: str, expected: str | None = None) -> str:
    choices = _require_list(value, path)
    if len(choices) != 1:
        raise VerificationError(f"{path} must contain exactly one expression")
    choice = _require_object(choices[0], f"{path}[0]")
    _require_keys(choice, {"expression"}, f"{path}[0]")
    expression = _require_string(choice["expression"], f"{path}[0].expression")
    if (
        not expression
        or len(expression) > 1024
        or SPDX_EXPRESSION.fullmatch(expression) is None
    ):
        raise VerificationError(
            f"{path}[0].expression is not a bounded SPDX expression"
        )
    if expected is not None:
        _require_value(expression, expected, f"{path}[0].expression")
    return expression


def _validate_hashes(value: Any, path: str, expected: str | None = None) -> str:
    hashes = _require_list(value, path)
    if len(hashes) != 1:
        raise VerificationError(f"{path} must contain exactly one SHA-256 hash")
    item = _require_object(hashes[0], f"{path}[0]")
    _require_keys(item, {"alg", "content"}, f"{path}[0]")
    _require_value(item["alg"], "SHA-256", f"{path}[0].alg")
    digest = _require_sha256(item["content"], f"{path}[0].content")
    if expected is not None and digest != expected:
        raise VerificationError(f"{path}[0].content does not match the binary")
    return digest


def _parse_trusted_cargo_lock(data: bytes) -> dict[tuple[str, str, str], str | None]:
    try:
        lock = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(
            f"trusted Cargo.lock is not valid UTF-8 TOML: {error}"
        ) from error
    if set(lock) != {"version", "package"} or lock.get("version") != 4:
        raise VerificationError(
            "trusted Cargo.lock must have only format-4 package data"
        )
    packages = _require_list(lock["package"], "trusted Cargo.lock.package")
    identities: dict[tuple[str, str, str], str | None] = {}
    for index, raw_package in enumerate(packages):
        path = f"trusted Cargo.lock.package[{index}]"
        package = _require_object(raw_package, path)
        if not {"name", "version"}.issubset(package) or not set(package).issubset(
            {"name", "version", "source", "checksum", "dependencies"}
        ):
            raise VerificationError(f"{path} has unknown or missing fields")
        name = _require_string(package["name"], f"{path}.name")
        version = _require_string(package["version"], f"{path}.version")
        source = ""
        if "source" in package:
            source = _require_string(package["source"], f"{path}.source")
        checksum = None
        if "checksum" in package:
            checksum = _require_sha256(package["checksum"], f"{path}.checksum")
        if bool(source) != bool(checksum):
            raise VerificationError(
                f"{path} must bind registry source and checksum together"
            )
        if "dependencies" in package:
            dependencies = _require_list(
                package["dependencies"], f"{path}.dependencies"
            )
            if not all(isinstance(dependency, str) for dependency in dependencies):
                raise VerificationError(
                    f"{path}.dependencies must contain only strings"
                )
        identity = (name, version, source)
        if identity in identities:
            raise VerificationError(
                f"trusted Cargo.lock repeats package identity {identity!r}"
            )
        identities[identity] = checksum
    if not identities:
        raise VerificationError("trusted Cargo.lock has no packages")
    return identities


def _sbom_graph_node(
    bom_ref: str,
    component_type: str,
    name: str,
    version: str,
    source: str,
    checksum: str | None,
    license_expression: str,
) -> dict[str, Any]:
    """Project one CycloneDX component onto its stable release identity."""
    return {
        "bomRef": bom_ref,
        "type": component_type,
        "name": name,
        "version": version,
        "source": source,
        "checksum": checksum,
        "licenseExpression": license_expression,
    }


def _sbom_graph_sort_key(component: dict[str, Any]) -> tuple[str, ...]:
    checksum = component["checksum"]
    return (
        component["type"],
        component["name"],
        component["version"],
        component["source"],
        "" if checksum is None else checksum,
        component["licenseExpression"],
        component["bomRef"],
    )


def _canonical_sbom_graph_contract(
    root_ref: str,
    components_by_ref: Mapping[str, dict[str, Any]],
    graph: Mapping[str, list[str]],
) -> tuple[int, int, str]:
    """Hash bom-ref bindings and the semantic identities and edges they denote."""
    root = components_by_ref[root_ref]
    components = sorted(
        (
            component
            for reference, component in components_by_ref.items()
            if reference != root_ref
        ),
        key=_sbom_graph_sort_key,
    )
    dependencies = []
    for reference in sorted(
        components_by_ref,
        key=lambda item: _sbom_graph_sort_key(components_by_ref[item]),
    ):
        dependent_components: list[dict[str, Any]] = [
            components_by_ref[dependency] for dependency in graph[reference]
        ]
        dependent_components.sort(key=_sbom_graph_sort_key)
        dependencies.append(
            {
                "component": components_by_ref[reference],
                "dependsOn": dependent_components,
            }
        )
    projection = {
        "schema": SBOM_GRAPH_SCHEMA,
        "root": root,
        "components": components,
        "dependencies": dependencies,
    }
    dependency_edge_count = sum(len(dependencies) for dependencies in graph.values())
    return (
        len(components_by_ref),
        dependency_edge_count,
        _sha256(_canonical_json(projection)),
    )


def _validate_sbom(
    policy: Mapping[str, Any],
    target: Mapping[str, Any],
    data: bytes,
    binary: bytes,
    forge_commit: str,
    lock_packages: Mapping[tuple[str, str, str], str | None],
) -> str:
    label = target["sbom"]
    bom = _require_object(_load_json_bytes(data, label), f"SBOM {label}")
    _require_keys(
        bom,
        {
            "bomFormat",
            "specVersion",
            "version",
            "metadata",
            "components",
            "dependencies",
        },
        f"SBOM {label}",
    )
    _require_value(bom["bomFormat"], "CycloneDX", f"SBOM {label}.bomFormat")
    _require_value(bom["specVersion"], "1.6", f"SBOM {label}.specVersion")
    _require_value(bom["version"], 1, f"SBOM {label}.version")

    root_ref = f"pkg:cargo/forge@{policy['release']['version']}"
    metadata = _require_object(bom["metadata"], f"SBOM {label}.metadata")
    _require_keys(metadata, {"component"}, f"SBOM {label}.metadata")
    component = _require_object(
        metadata["component"], f"SBOM {label}.metadata.component"
    )
    _require_keys(
        component,
        {"type", "bom-ref", "name", "version", "licenses", "hashes", "properties"},
        f"SBOM {label}.metadata.component",
    )
    prefix = f"SBOM {label}.metadata.component"
    _require_value(component["type"], "application", f"{prefix}.type")
    _require_value(component["bom-ref"], root_ref, f"{prefix}.bom-ref")
    _require_value(component["name"], "forge", f"{prefix}.name")
    _require_value(
        component["version"], policy["release"]["version"], f"{prefix}.version"
    )
    root_license_expression = _validate_license_choice(
        component["licenses"], f"{prefix}.licenses", policy["projectLicenseExpression"]
    )
    binary_digest = _sha256(binary)
    _validate_hashes(component["hashes"], f"{prefix}.hashes", binary_digest)
    properties = _require_list(component["properties"], f"{prefix}.properties")
    if len(properties) != 5:
        raise VerificationError(
            f"{prefix}.properties must contain exactly five bindings"
        )
    property_values: dict[str, str] = {}
    for index, raw_property in enumerate(properties):
        item_path = f"{prefix}.properties[{index}]"
        item = _require_object(raw_property, item_path)
        _require_keys(item, {"name", "value"}, item_path)
        name = _require_string(item["name"], f"{item_path}.name")
        value = _require_string(item["value"], f"{item_path}.value")
        if name in property_values:
            raise VerificationError(f"{prefix}.properties repeats {name!r}")
        property_values[name] = value
    expected_property_names = {
        "forge:target-triple",
        "forge:cargo-lock-sha256",
        "forge:source-commit",
        "forge:binary-sha256",
        "forge:binary-length",
    }
    if set(property_values) != expected_property_names:
        raise VerificationError(
            f"{prefix}.properties has an unknown or missing semantic binding"
        )
    _require_value(
        property_values["forge:target-triple"], target["triple"], f"{prefix}.target"
    )
    lock_digest = _require_sha256(
        property_values["forge:cargo-lock-sha256"], f"{prefix}.cargo-lock-sha256"
    )
    _require_value(
        property_values["forge:source-commit"], forge_commit, f"{prefix}.source-commit"
    )
    _require_value(
        property_values["forge:binary-sha256"], binary_digest, f"{prefix}.binary-sha256"
    )
    binary_length = property_values["forge:binary-length"]
    if DECIMAL.fullmatch(binary_length) is None or int(binary_length) != len(binary):
        raise VerificationError(f"{prefix}.binary-length does not match the binary")

    graph_contract = target["sbomGraph"]
    components = _require_list(bom["components"], f"SBOM {label}.components")
    if len(components) + 1 != graph_contract["componentCount"]:
        raise VerificationError(
            f"SBOM {label} has {len(components) + 1} semantic components; "
            f"policy requires {graph_contract['componentCount']}"
        )
    references = {root_ref}
    components_by_ref = {
        root_ref: _sbom_graph_node(
            root_ref,
            "application",
            "forge",
            policy["release"]["version"],
            "workspace",
            None,
            root_license_expression,
        )
    }
    package_identities: set[tuple[str, str, str]] = set()
    ordering: list[tuple[str, str, str]] = []
    for index, raw_component in enumerate(components):
        item_path = f"SBOM {label}.components[{index}]"
        item = _require_object(raw_component, item_path)
        allowed = {
            "type",
            "bom-ref",
            "name",
            "version",
            "licenses",
            "hashes",
            "properties",
        }
        required = {"type", "bom-ref", "name", "version", "licenses"}
        if not required.issubset(item) or not set(item).issubset(allowed):
            raise VerificationError(f"{item_path} has unknown or missing fields")
        _require_value(item["type"], "library", f"{item_path}.type")
        reference = _require_string(item["bom-ref"], f"{item_path}.bom-ref")
        if re.fullmatch(r"urn:forge:cargo:blake3:[0-9a-f]{64}", reference) is None:
            raise VerificationError(
                f"{item_path}.bom-ref is not a Forge package reference"
            )
        if reference in references:
            raise VerificationError(f"{item_path}.bom-ref is duplicated")
        references.add(reference)
        name = _require_string(item["name"], f"{item_path}.name")
        version = _require_string(item["version"], f"{item_path}.version")
        if not name or not version:
            raise VerificationError(f"{item_path} name and version must not be empty")
        license_expression = _validate_license_choice(
            item["licenses"], f"{item_path}.licenses"
        )
        component_checksum = None
        if "hashes" in item:
            component_checksum = _validate_hashes(item["hashes"], f"{item_path}.hashes")
        source = ""
        if "properties" in item:
            values = _require_list(item["properties"], f"{item_path}.properties")
            if len(values) != 1:
                raise VerificationError(
                    f"{item_path}.properties must contain one cargo source"
                )
            prop = _require_object(values[0], f"{item_path}.properties[0]")
            _require_keys(prop, {"name", "value"}, f"{item_path}.properties[0]")
            _require_value(
                prop["name"], "forge:cargo-source", f"{item_path}.properties[0].name"
            )
            source = _require_string(prop["value"], f"{item_path}.properties[0].value")
            if not source:
                raise VerificationError(
                    f"{item_path}.properties[0].value must not be empty"
                )
        identity = (name, version, source)
        if identity in package_identities:
            raise VerificationError(
                f"{item_path} repeats semantic package identity {identity!r}"
            )
        package_identities.add(identity)
        if identity not in lock_packages:
            raise VerificationError(
                f"{item_path} is absent from the trusted source-commit Cargo.lock"
            )
        if component_checksum != lock_packages[identity]:
            raise VerificationError(
                f"{item_path}.hashes does not match the trusted source-commit Cargo.lock"
            )
        components_by_ref[reference] = _sbom_graph_node(
            reference,
            "library",
            name,
            version,
            source or "workspace",
            component_checksum,
            license_expression,
        )
        ordering.append((name, version, source))
    if ordering != sorted(ordering):
        raise VerificationError(
            f"SBOM {label}.components is not in canonical package order"
        )

    dependencies = _require_list(bom["dependencies"], f"SBOM {label}.dependencies")
    if len(dependencies) != len(references):
        raise VerificationError(
            f"SBOM {label}.dependencies must describe every component exactly once"
        )
    graph: dict[str, list[str]] = {}
    dependency_order: list[str] = []
    running_edge_count = 0
    for index, raw_dependency in enumerate(dependencies):
        item_path = f"SBOM {label}.dependencies[{index}]"
        item = _require_object(raw_dependency, item_path)
        _require_keys(item, {"ref", "dependsOn"}, item_path)
        reference = _require_string(item["ref"], f"{item_path}.ref")
        depends_on = _require_list(item["dependsOn"], f"{item_path}.dependsOn")
        running_edge_count += len(depends_on)
        if running_edge_count > MAX_SBOM_DEPENDENCY_EDGES:
            raise VerificationError(
                f"SBOM {label} exceeds the {MAX_SBOM_DEPENDENCY_EDGES}-edge complexity limit"
            )
        if running_edge_count > graph_contract["dependencyEdgeCount"]:
            raise VerificationError(
                f"SBOM {label} has more dependency edges than policy permits"
            )
        for edge_index, edge in enumerate(depends_on):
            _require_string(edge, f"{item_path}.dependsOn[{edge_index}]")
        if depends_on != sorted(set(depends_on)):
            raise VerificationError(f"{item_path}.dependsOn must be sorted and unique")
        if reference in graph:
            raise VerificationError(f"{item_path}.ref is duplicated")
        graph[reference] = depends_on
        dependency_order.append(reference)
    if dependency_order != sorted(references) or set(graph) != references:
        raise VerificationError(
            f"SBOM {label}.dependencies is not the sorted exact reference set"
        )
    if running_edge_count != graph_contract["dependencyEdgeCount"]:
        raise VerificationError(
            f"SBOM {label} has {running_edge_count} dependency edges; "
            f"policy requires {graph_contract['dependencyEdgeCount']}"
        )
    for reference, edges in graph.items():
        unknown = set(edges) - references
        if unknown:
            raise VerificationError(
                f"SBOM {label} dependency {reference!r} names unknown refs"
            )
    reachable: set[str] = set()
    pending = [root_ref]
    while pending:
        reference = pending.pop()
        if reference in reachable:
            continue
        reachable.add(reference)
        pending.extend(graph[reference])
    if reachable != references:
        raise VerificationError(
            f"SBOM {label} contains components unreachable from Forge"
        )
    component_count = len(components_by_ref)
    if component_count != graph_contract["componentCount"]:
        raise VerificationError(
            f"SBOM {label} has {component_count} semantic components; "
            f"policy requires {graph_contract['componentCount']}"
        )
    _, _, canonical_graph_sha256 = _canonical_sbom_graph_contract(
        root_ref, components_by_ref, graph
    )
    if canonical_graph_sha256 != graph_contract["canonicalSha256"]:
        raise VerificationError(
            f"SBOM {label} canonical bom-ref and semantic graph SHA-256 differs from policy"
        )
    return lock_digest


def _validate_binary_structure(target: Mapping[str, Any], data: bytes) -> None:
    binary_format = target["binaryFormat"]
    if binary_format.startswith("elf64-"):
        _validate_elf(target, data)
    elif binary_format.startswith("macho64-"):
        _validate_macho(target, data)
    elif binary_format == "pe64-x86_64":
        _validate_pe(target, data)
    else:
        raise VerificationError(
            f"unsupported binary structure policy {binary_format!r}"
        )


def _validate_elf(target: Mapping[str, Any], data: bytes) -> None:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise VerificationError(f"{target['binary']} is not little-endian ELF64")
    file_type = struct.unpack_from("<H", data, 16)[0]
    machine = struct.unpack_from("<H", data, 18)[0]
    version = struct.unpack_from("<I", data, 20)[0]
    expected_machine = 62 if target["binaryFormat"] == "elf64-x86_64-static" else 183
    if file_type not in {2, 3}:  # ET_EXEC or ET_DYN (static PIE)
        raise VerificationError(f"{target['binary']} is not an ELF executable or PIE")
    if machine != expected_machine:
        raise VerificationError(
            f"{target['binary']} ELF machine does not match its target"
        )
    if version != 1 or struct.unpack_from("<H", data, 52)[0] != 64:
        raise VerificationError(f"{target['binary']} has an invalid ELF64 header")
    entrypoint = struct.unpack_from("<Q", data, 24)[0]
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    entry_size = struct.unpack_from("<H", data, 54)[0]
    entry_count = struct.unpack_from("<H", data, 56)[0]
    if entry_count > MAX_ELF_PROGRAM_HEADERS:
        raise VerificationError(
            f"{target['binary']} exceeds the {MAX_ELF_PROGRAM_HEADERS}-header ELF complexity limit"
        )
    if (
        entrypoint == 0
        or program_offset < 64
        or entry_size != 56
        or entry_count == 0
        or program_offset + entry_size * entry_count > len(data)
    ):
        raise VerificationError(
            f"{target['binary']} has an invalid ELF program-header table"
        )
    executable_load = False
    executable_entrypoint = False
    dynamic_ranges: list[tuple[int, int]] = []
    dynamic_bytes_total = 0
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        program_type, flags = struct.unpack_from("<II", data, offset)
        file_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        virtual_address = struct.unpack_from("<Q", data, offset + 16)[0]
        file_size = struct.unpack_from("<Q", data, offset + 32)[0]
        memory_size = struct.unpack_from("<Q", data, offset + 40)[0]
        alignment = struct.unpack_from("<Q", data, offset + 48)[0]
        if program_type == 3:  # PT_INTERP
            raise VerificationError(
                f"{target['binary']} is dynamically interpreted, not static"
            )
        if program_type == 1:  # PT_LOAD
            if (
                memory_size < file_size
                or file_offset + file_size > len(data)
                or (
                    alignment > 1
                    and (
                        alignment & (alignment - 1) != 0
                        or file_offset % alignment != virtual_address % alignment
                    )
                )
            ):
                raise VerificationError(
                    f"{target['binary']} has an invalid ELF load segment"
                )
            if flags & 0x1 and file_size > 0:  # PF_X
                executable_load = True
                entry_delta = entrypoint - virtual_address
                if (
                    virtual_address <= entrypoint
                    and 0 <= entry_delta < file_size
                    and file_offset + entry_delta < len(data)
                ):
                    executable_entrypoint = True
        if program_type == 2:  # PT_DYNAMIC
            if (
                file_size == 0
                or file_size % 16 != 0
                or file_offset + file_size > len(data)
            ):
                raise VerificationError(
                    f"{target['binary']} has an invalid ELF dynamic table"
                )
            dynamic_end = file_offset + file_size
            if any(
                file_offset < previous_end and previous_start < dynamic_end
                for previous_start, previous_end in dynamic_ranges
            ):
                raise VerificationError(
                    f"{target['binary']} has overlapping ELF dynamic tables"
                )
            dynamic_bytes_total += file_size
            if dynamic_bytes_total > MAX_ELF_DYNAMIC_TABLE_BYTES:
                raise VerificationError(
                    f"{target['binary']} exceeds the ELF dynamic-table complexity limit"
                )
            dynamic_ranges.append((file_offset, dynamic_end))
    if not executable_load:
        raise VerificationError(
            f"{target['binary']} has no file-backed executable ELF load segment"
        )
    if not executable_entrypoint:
        raise VerificationError(
            f"{target['binary']} entry point is outside executable ELF load segments"
        )
    for dynamic_offset, dynamic_end in dynamic_ranges:
        terminated = False
        for offset in range(dynamic_offset, dynamic_end, 16):
            tag = struct.unpack_from("<q", data, offset)[0]
            if tag == 0:  # DT_NULL
                terminated = True
                break
            if tag == 1:  # DT_NEEDED
                raise VerificationError(
                    f"{target['binary']} declares a dynamic DT_NEEDED dependency"
                )
        if not terminated:
            raise VerificationError(
                f"{target['binary']} has an unterminated ELF dynamic table"
            )


def _validate_macho(target: Mapping[str, Any], data: bytes) -> None:
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        raise VerificationError(f"{target['binary']} is not little-endian Mach-O 64")
    cpu_type = struct.unpack_from("<I", data, 4)[0]
    expected = 0x01000007 if target["binaryFormat"] == "macho64-x86_64" else 0x0100000C
    if cpu_type != expected:
        raise VerificationError(
            f"{target['binary']} Mach-O CPU type does not match its target"
        )
    file_type, command_count, command_bytes = struct.unpack_from("<III", data, 12)
    if file_type != 2:  # MH_EXECUTE
        raise VerificationError(f"{target['binary']} is not a Mach-O executable")
    if (
        command_count > MAX_MACHO_LOAD_COMMANDS
        or command_bytes > MAX_MACHO_LOAD_COMMAND_BYTES
    ):
        raise VerificationError(
            f"{target['binary']} exceeds the Mach-O load-command complexity limit"
        )
    commands_end = 32 + command_bytes
    if (
        command_count == 0
        or command_bytes < command_count * 8
        or commands_end > len(data)
    ):
        raise VerificationError(
            f"{target['binary']} has an invalid Mach-O load-command table"
        )
    offset = 32
    executable_segments: list[tuple[int, int]] = []
    entry_offsets: list[int] = []
    for _index in range(command_count):
        if offset + 8 > commands_end:
            raise VerificationError(
                f"{target['binary']} has a truncated Mach-O load command"
            )
        command, command_size = struct.unpack_from("<II", data, offset)
        if (
            command_size < 8
            or command_size % 8 != 0
            or offset + command_size > commands_end
        ):
            raise VerificationError(
                f"{target['binary']} has an invalid Mach-O load command"
            )
        if command == 0x19:  # LC_SEGMENT_64
            if command_size < 72:
                raise VerificationError(
                    f"{target['binary']} has a truncated LC_SEGMENT_64"
                )
            virtual_size = struct.unpack_from("<Q", data, offset + 32)[0]
            file_offset, file_size = struct.unpack_from("<QQ", data, offset + 40)
            maximum_protection = struct.unpack_from("<i", data, offset + 56)[0]
            initial_protection = struct.unpack_from("<i", data, offset + 60)[0]
            section_count = struct.unpack_from("<I", data, offset + 64)[0]
            if command_size != 72 + section_count * 80:
                raise VerificationError(
                    f"{target['binary']} has a malformed LC_SEGMENT_64"
                )
            if virtual_size < file_size or file_offset + file_size > len(data):
                raise VerificationError(
                    f"{target['binary']} has an out-of-bounds Mach-O segment"
                )
            if initial_protection & 0x4 and file_size > 0:  # VM_PROT_EXECUTE
                if maximum_protection & 0x4 == 0:
                    raise VerificationError(
                        f"{target['binary']} has an executable Mach-O segment "
                        "forbidden by its maximum protection"
                    )
                executable_segments.append((file_offset, file_offset + file_size))
        elif command == 0x80000028:  # LC_MAIN
            if command_size != 24:
                raise VerificationError(f"{target['binary']} has a malformed LC_MAIN")
            entry_offsets.append(struct.unpack_from("<Q", data, offset + 8)[0])
        offset += command_size
    if offset != commands_end:
        raise VerificationError(
            f"{target['binary']} does not fully consume its Mach-O commands"
        )
    if not executable_segments:
        raise VerificationError(
            f"{target['binary']} has no file-backed executable Mach-O segment"
        )
    if (
        len(entry_offsets) != 1
        or entry_offsets[0] < commands_end
        or not any(
            start <= entry_offsets[0] < end for start, end in executable_segments
        )
    ):
        raise VerificationError(
            f"{target['binary']} has no unique file-backed executable LC_MAIN entry point"
        )


def _validate_pe(target: Mapping[str, Any], data: bytes) -> None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise VerificationError(f"{target['binary']} is not a PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if (
        pe_offset < 0x40
        or pe_offset + 24 > len(data)
        or data[pe_offset : pe_offset + 4] != b"PE\x00\x00"
    ):
        raise VerificationError(f"{target['binary']} has an invalid PE header")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
    if section_count > MAX_PE_SECTIONS:
        raise VerificationError(
            f"{target['binary']} exceeds the {MAX_PE_SECTIONS}-section PE limit"
        )
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if (
        machine != 0x8664
        or section_count == 0
        or optional_size < 112
        or optional_end > len(data)
        or characteristics & 0x0002 == 0  # IMAGE_FILE_EXECUTABLE_IMAGE
        or characteristics & 0x2000 != 0  # IMAGE_FILE_DLL
    ):
        raise VerificationError(
            f"{target['binary']} has an invalid executable PE32+ header"
        )
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0]
    if optional_magic != 0x20B:
        raise VerificationError(f"{target['binary']} is not x86_64 PE32+")
    entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
    size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    if entry_rva == 0 or size_of_image == 0 or entry_rva >= size_of_image:
        raise VerificationError(f"{target['binary']} has no PE entry point")
    section_table_end = optional_end + section_count * 40
    if (
        section_table_end > len(data)
        or size_of_headers < section_table_end
        or size_of_headers > len(data)
    ):
        raise VerificationError(
            f"{target['binary']} has an out-of-bounds PE section table"
        )
    executable_code_section = False
    file_backed_entrypoint = False
    for index in range(section_count):
        offset = optional_end + index * 40
        virtual_size, virtual_address = struct.unpack_from("<II", data, offset + 8)
        raw_size, raw_offset = struct.unpack_from("<II", data, offset + 16)
        section_characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if raw_size > 0 and (
            raw_offset < size_of_headers or raw_offset + raw_size > len(data)
        ):
            raise VerificationError(
                f"{target['binary']} has an out-of-bounds PE section"
            )
        if (
            raw_size > 0
            and section_characteristics & 0x00000020  # IMAGE_SCN_CNT_CODE
            and section_characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
        ):
            executable_code_section = True
            relative_entry = entry_rva - virtual_address
            if (
                virtual_address
                <= entry_rva
                < virtual_address + max(virtual_size, raw_size)
                and 0 <= relative_entry < raw_size
                and raw_offset + relative_entry < len(data)
            ):
                file_backed_entrypoint = True
    if not executable_code_section:
        raise VerificationError(
            f"{target['binary']} has no file-backed executable PE code section"
        )
    if not file_backed_entrypoint:
        raise VerificationError(
            f"{target['binary']} PE entry point is outside file-backed executable code"
        )


def _validate_builder_records(
    policy: Mapping[str, Any],
    records: Mapping[str, bytes],
    assets: Mapping[str, bytes],
    forge_commit: str,
    authority_commit: str,
) -> None:
    source = policy["source"]
    authority = policy["authority"]
    for target in policy["targets"]:
        record_name = target["builderRecord"]
        record = _require_object(
            _load_json_bytes(records[record_name], record_name),
            f"builder record {record_name}",
        )
        _require_keys(
            record,
            {
                "schema",
                "target",
                "runner_label",
                "rust_version",
                "source",
                "authority",
                "binary",
                "sbom",
            },
            f"builder record {record_name}",
        )
        prefix = f"builder record {record_name}"
        _require_value(
            record["schema"], policy["builderRecords"]["schema"], f"{prefix}.schema"
        )
        _require_value(record["target"], target["triple"], f"{prefix}.target")
        _require_value(
            record["runner_label"], target["runnerLabel"], f"{prefix}.runner_label"
        )
        _require_value(
            record["rust_version"],
            policy["toolchain"]["rust"],
            f"{prefix}.rust_version",
        )
        _validate_repository_binding(
            record["source"], source, forge_commit, f"{prefix}.source"
        )
        _validate_repository_binding(
            record["authority"], authority, authority_commit, f"{prefix}.authority"
        )
        _validate_asset_descriptor(
            record["binary"],
            target["binary"],
            assets[target["binary"]],
            f"{prefix}.binary",
        )
        _validate_asset_descriptor(
            record["sbom"], target["sbom"], assets[target["sbom"]], f"{prefix}.sbom"
        )


def _validate_repository_binding(
    value: Any, policy_identity: Mapping[str, Any], commit: str, path: str
) -> None:
    binding = _require_object(value, path)
    _require_keys(binding, {"owner_id", "repository_id", "commit"}, path)
    _require_value(binding["owner_id"], policy_identity["ownerId"], f"{path}.owner_id")
    _require_value(
        binding["repository_id"],
        policy_identity["repositoryId"],
        f"{path}.repository_id",
    )
    _require_value(binding["commit"], commit, f"{path}.commit")


def _validate_asset_descriptor(value: Any, name: str, data: bytes, path: str) -> None:
    descriptor = _require_object(value, path)
    _require_keys(descriptor, {"name", "length", "sha256"}, path)
    _require_value(descriptor["name"], name, f"{path}.name")
    _require_value(descriptor["length"], len(data), f"{path}.length")
    _require_value(descriptor["sha256"], _sha256(data), f"{path}.sha256")


def build_predicate(
    policy: Mapping[str, Any],
    policy_digest: str,
    cargo_lock: bytes,
    source_license_notices: bytes,
    records: Mapping[str, bytes],
    forge_commit: str,
    authority_commit: str,
) -> dict[str, Any]:
    source = policy["source"]
    authority = policy["authority"]
    byproducts = [
        {"name": name, "digest": {"sha256": _sha256(records[name])}}
        for name in sorted(records)
    ]
    return {
        "buildDefinition": {
            "buildType": policy["provenance"]["buildType"],
            "externalParameters": {"sourceCommit": forge_commit},
            "internalParameters": {
                "authority": {
                    "environment": authority["environment"],
                    "oidcIssuer": authority["oidcIssuer"],
                    "oidcSubjectPrefix": authority["oidcSubjectPrefix"],
                    "ownerId": authority["ownerId"],
                    "repositoryId": authority["repositoryId"],
                },
                "authorityCommit": authority_commit,
                "policySha256": policy_digest,
                "release": {
                    "subjectNames": policy["release"]["assets"],
                    "tag": policy["release"]["tag"],
                    "targets": [target["triple"] for target in policy["targets"]],
                    "version": policy["release"]["version"],
                },
            },
            "resolvedDependencies": [
                {
                    "uri": (
                        f"git+https://github.com/{source['owner']}/"
                        f"{source['repository']}.git@{forge_commit}"
                    ),
                    "digest": {"gitCommit": forge_commit},
                },
                {
                    "uri": (
                        f"git+https://github.com/{authority['owner']}/"
                        f"{authority['repository']}.git@{authority_commit}"
                    ),
                    "digest": {"gitCommit": authority_commit},
                },
                {
                    "name": "Cargo.lock",
                    "uri": (
                        f"https://github.com/{source['owner']}/{source['repository']}"
                        f"/blob/{forge_commit}/Cargo.lock"
                    ),
                    "digest": {"sha256": _sha256(cargo_lock)},
                },
                {
                    "name": "THIRD-PARTY-LICENSES.txt",
                    "uri": (
                        f"https://github.com/{source['owner']}/{source['repository']}"
                        f"/blob/{forge_commit}/THIRD-PARTY-LICENSES.txt"
                    ),
                    "digest": {"sha256": _sha256(source_license_notices)},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": policy["provenance"]["builderId"]},
            # SLSA permits invocation timestamps and IDs here. Omitting them keeps this predicate
            # deterministic without reusing one invocation ID across qualification retries.
            "metadata": {},
            "byproducts": byproducts,
        },
    }


def _render_subject_checksums(
    policy: Mapping[str, Any], assets: Mapping[str, bytes]
) -> bytes:
    return "".join(
        f"{_sha256(assets[name])}  {name}\n" for name in policy["release"]["assets"]
    ).encode("ascii")


def _verify_release_with_pinned_directories(
    policy_path: Path,
    assets_directory: _PinnedDirectory,
    builder_records_directory: _PinnedDirectory,
    forge_commit: str,
    authority_commit: str,
    resolved_materials: _ResolvedMaterials,
) -> tuple[dict[str, Any], bytes]:
    """Verify every qualification gate and derive predicate plus subject hashes."""
    forge_commit = _require_git_sha(forge_commit, "forge commit")
    authority_commit = _require_git_sha(authority_commit, "authority commit")
    policy, policy_digest = load_policy(policy_path)
    if _sha256(resolved_materials.authority_policy) != policy_digest:
        raise VerificationError(
            "authority policy differs from the protected authority commit"
        )
    local_verifier = _read_bounded_regular_path(
        AUTHORITY_VERIFIER_PATH,
        MAX_AUTHORITY_VERIFIER_BYTES,
        "authority verifier",
    )
    if resolved_materials.authority_verifier != local_verifier:
        raise VerificationError(
            "authority verifier differs from the protected authority commit"
        )
    cargo_lock = resolved_materials.cargo_lock
    if len(cargo_lock) > policy["limits"]["cargoLockBytes"]:
        raise VerificationError("trusted Cargo.lock exceeds the policy limit")
    lock_packages = _parse_trusted_cargo_lock(cargo_lock)
    source_license_notices = resolved_materials.source_license_notices
    if len(source_license_notices) > policy["limits"]["noticeBytes"]:
        raise VerificationError(
            "trusted source license notices exceed the policy limit"
        )
    _, target_by_asset = _target_maps(policy)
    assets = _read_exact_pinned_directory(
        assets_directory,
        policy["release"]["assets"],
        lambda name: _asset_limit(policy, target_by_asset, name),
        policy["limits"]["totalAssetBytes"],
        "release assets",
    )
    record_names = [target["builderRecord"] for target in policy["targets"]]
    records = _read_exact_pinned_directory(
        builder_records_directory,
        record_names,
        lambda _name: policy["limits"]["builderRecordBytes"],
        policy["limits"]["totalBuilderRecordBytes"],
        "builder records",
    )

    notice_name = policy["release"]["notice"]["name"]
    if assets[notice_name] != source_license_notices:
        raise VerificationError(
            "release license notices differ from the trusted source-commit bytes"
        )

    _validate_manifest(policy, assets)
    _validate_checksums(policy, assets)
    lock_digests: set[str] = set()
    for target in policy["targets"]:
        binary = assets[target["binary"]]
        lock_digests.add(
            _validate_sbom(
                policy,
                target,
                assets[target["sbom"]],
                binary,
                forge_commit,
                lock_packages,
            )
        )
        _validate_binary_structure(target, binary)
    if len(lock_digests) != 1:
        raise VerificationError("the five SBOMs do not bind one Cargo.lock digest")
    if lock_digests != {_sha256(cargo_lock)}:
        raise VerificationError(
            "the five SBOMs do not bind the trusted source-commit Cargo.lock"
        )
    _validate_builder_records(policy, records, assets, forge_commit, authority_commit)
    return (
        build_predicate(
            policy,
            policy_digest,
            cargo_lock,
            source_license_notices,
            records,
            forge_commit,
            authority_commit,
        ),
        _render_subject_checksums(policy, assets),
    )


def _verify_release_with_subjects(
    policy_path: Path,
    assets_directory: Path,
    builder_records_directory: Path,
    forge_commit: str,
    authority_commit: str,
    resolved_materials: _ResolvedMaterials,
) -> tuple[dict[str, Any], bytes]:
    """Verify through directory inodes pinned for the complete read operation."""
    assets = _pin_directory(assets_directory, "release assets directory")
    try:
        records = _pin_directory(builder_records_directory, "builder records directory")
        try:
            return _verify_release_with_pinned_directories(
                policy_path,
                assets,
                records,
                forge_commit,
                authority_commit,
                resolved_materials,
            )
        finally:
            _close_pinned_directory(records)
    finally:
        _close_pinned_directory(assets)


def verify_release(
    policy_path: Path,
    assets_directory: Path,
    builder_records_directory: Path,
    forge_commit: str,
    authority_commit: str,
) -> dict[str, Any]:
    """Verify every qualification gate without publishing any external state."""
    policy, _policy_digest = load_policy(policy_path)
    resolved_materials = _resolve_github_materials(
        policy, forge_commit, authority_commit
    )
    predicate, _subject_checksums = _verify_release_with_subjects(
        policy_path,
        assets_directory,
        builder_records_directory,
        forge_commit,
        authority_commit,
        resolved_materials,
    )
    return predicate


def _pin_output(
    output: Path, input_directories: Sequence[_PinnedDirectory]
) -> _PinnedOutput:
    """Hold an actual output-parent inode outside every verified input inode."""
    name = _require_safe_basename(output.name, "qualification output name")
    pinned = _pin_directory(output.parent, "qualification output parent")
    try:
        if any(
            _directory_is_same_or_descendant(
                pinned.directory_fd, input_directory.directory_identity
            )
            for input_directory in input_directories
        ):
            raise VerificationError(
                "qualification outputs must be outside the verified input directories"
            )
        return _PinnedOutput(
            requested_directory=pinned.requested_path,
            directory=pinned.resolved_path,
            directory_fd=pinned.directory_fd,
            directory_identity=pinned.directory_identity,
            name=name,
            path=pinned.requested_path / name,
        )
    except BaseException:
        _close_pinned_directory(pinned)
        raise


def _require_pinned_output_parents_stable(
    outputs: Sequence[_PinnedOutput], input_directories: Sequence[_PinnedDirectory]
) -> None:
    """Recheck held parents, visible paths, and actual inode ancestry."""
    for output in outputs:
        pinned = _PinnedDirectory(
            requested_path=output.requested_directory,
            resolved_path=output.directory,
            directory_fd=output.directory_fd,
            directory_identity=output.directory_identity,
            label="qualification output parent",
        )
        _require_pinned_directory_path_stable(pinned)
        if any(
            _directory_is_same_or_descendant(
                output.directory_fd, input_directory.directory_identity
            )
            for input_directory in input_directories
        ):
            raise VerificationError(
                "qualification output directory moved inside a verified input directory"
            )


def _require_outputs_absent(outputs: Sequence[_PinnedOutput]) -> None:
    for output in outputs:
        try:
            os.stat(
                output.name,
                dir_fd=output.directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise VerificationError(
                f"cannot inspect qualification output {output.path}: {error}"
            ) from error
        raise VerificationError(
            f"refusing to overwrite existing qualification output {output.path}"
        )


def _require_fresh_private_output_directories(
    outputs: Sequence[_PinnedOutput],
) -> None:
    """Enforce the workflow boundary that excludes unrelated filesystem writers."""
    seen: set[ObjectIdentity] = set()
    for output in outputs:
        if output.directory_identity in seen:
            continue
        seen.add(output.directory_identity)
        metadata = _fstat(
            output.directory_fd, f"qualification output directory {output.directory}"
        )
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise VerificationError(
                "qualification output directories must be owned by the current user "
                "with mode 0700"
            )
        _bounded_directory_names(
            output.directory_fd, 0, "qualification output directory"
        )


def _write_create_only(
    output: _PinnedOutput,
    data: bytes,
    *,
    mode: int | None = None,
    require_single_link: bool = False,
    retain_partial_on_failure: bool = False,
) -> _CreatedOutput:
    """Create one output and keep its inode open for the final set-wide check."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        file_fd = os.open(
            output.name,
            flags,
            0o644,
            dir_fd=output.directory_fd,
        )
    except OSError as error:
        raise VerificationError(
            f"refusing to overwrite qualification output {output.path}: {error}"
        ) from error
    try:
        if mode is not None:
            os.fchmod(file_fd, mode)
        opened = _fstat(file_fd, f"qualification output {output.path}")
        if (
            not stat.S_ISREG(opened.st_mode)
            or (mode is not None and stat.S_IMODE(opened.st_mode) != mode)
            or (require_single_link and opened.st_nlink != 1)
        ):
            raise VerificationError(
                f"qualification output {output.path} is not a private regular file"
            )
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise VerificationError(
                    f"short write while creating qualification output {output.path}"
                )
            view = view[written:]
        os.fsync(file_fd)
        after = _fstat(file_fd, f"qualification output {output.path}")
        visible_after = os.stat(
            output.name,
            dir_fd=output.directory_fd,
            follow_symlinks=False,
        )
        identity = _stat_identity(after)
        if (
            not stat.S_ISREG(after.st_mode)
            or (mode is not None and stat.S_IMODE(after.st_mode) != mode)
            or (require_single_link and after.st_nlink != 1)
            or (require_single_link and visible_after.st_nlink != 1)
            or _object_identity(opened) != _object_identity(after)
            or identity != _stat_identity(visible_after)
            or after.st_size != len(data)
        ):
            raise VerificationError(
                f"qualification output {output.path} changed while it was written"
            )
        return _CreatedOutput(
            output=output,
            file_fd=file_fd,
            identity=identity,
            expected_length=len(data),
            expected_sha256=_sha256(data),
            expected_mode=mode,
            require_single_link=require_single_link,
        )
    except VerificationError as error:
        _close_fd(file_fd)
        if retain_partial_on_failure:
            raise VerificationError(
                f"{error}; partial output retained for fail-closed quarantine"
            ) from error
        raise
    except OSError as error:
        _close_fd(file_fd)
        retained = (
            "; partial output retained for fail-closed quarantine"
            if retain_partial_on_failure
            else ""
        )
        raise VerificationError(
            f"cannot securely create qualification output {output.path}: "
            f"{error}{retained}"
        ) from error
    except BaseException:
        _close_fd(file_fd)
        raise


def _require_created_outputs_stable(outputs: Sequence[_CreatedOutput]) -> None:
    """Verify both created names still expose the exact bytes written by this run."""
    for created in outputs:
        output = created.output
        try:
            opened = _fstat(created.file_fd, f"qualification output {output.path}")
            visible = os.stat(
                output.name,
                dir_fd=output.directory_fd,
                follow_symlinks=False,
            )
            if (
                _stat_identity(opened) != created.identity
                or _stat_identity(visible) != created.identity
                or (created.require_single_link and opened.st_nlink != 1)
                or (created.require_single_link and visible.st_nlink != 1)
                or (
                    created.expected_mode is not None
                    and stat.S_IMODE(opened.st_mode) != created.expected_mode
                )
                or (
                    created.expected_mode is not None
                    and stat.S_IMODE(visible.st_mode) != created.expected_mode
                )
                or opened.st_size != created.expected_length
            ):
                raise VerificationError(
                    f"qualification output {output.path} changed before completion"
                )
            os.lseek(created.file_fd, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = created.expected_length
            while remaining > 0:
                chunk = os.read(created.file_fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            trailing = os.read(created.file_fd, 1)
            final = _fstat(created.file_fd, f"qualification output {output.path}")
        except OSError as error:
            raise VerificationError(
                f"cannot re-inspect qualification output {output.path}: {error}"
            ) from error
        if (
            _stat_identity(opened) != created.identity
            or _stat_identity(final) != created.identity
            or _stat_identity(visible) != created.identity
            or (created.require_single_link and final.st_nlink != 1)
            or (
                created.expected_mode is not None
                and stat.S_IMODE(final.st_mode) != created.expected_mode
            )
            or remaining != 0
            or trailing
            or _sha256(b"".join(chunks)) != created.expected_sha256
        ):
            raise VerificationError(
                f"qualification output {output.path} changed before completion"
            )


def _normalize_exact_output_files(
    files: Mapping[str, bytes],
    label: str,
    *,
    maximum_file_count: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
) -> Mapping[str, bytes]:
    for name, value in (
        ("maximum file count", maximum_file_count),
        ("maximum file bytes", maximum_file_bytes),
        ("maximum total bytes", maximum_total_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise VerificationError(f"{label} {name} must be a positive integer")
    if len(files) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file output limit"
        )
    normalized: dict[str, bytes] = {}
    total = 0
    for index, (candidate_name, data) in enumerate(files.items()):
        if index >= maximum_file_count:
            raise VerificationError(
                f"{label} exceeds the {maximum_file_count}-file output limit"
            )
        name = _require_safe_basename(candidate_name, f"{label} output name")
        if not isinstance(data, bytes):
            raise VerificationError(f"{label}/{name} output must be bytes")
        if len(data) > maximum_file_bytes:
            raise VerificationError(
                f"{label}/{name} exceeds the {maximum_file_bytes}-byte output limit"
            )
        total += len(data)
        if total > maximum_total_bytes:
            raise VerificationError(
                f"{label} exceeds the {maximum_total_bytes}-byte total output limit"
            )
        normalized[name] = data
    _require_unique_casefold(list(normalized), f"{label} output names")
    if len(normalized) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file output limit"
        )
    return MappingProxyType(normalized)


def _require_fresh_private_pinned_directory(
    directory: _PinnedDirectory, label: str
) -> None:
    metadata = _fstat(directory.directory_fd, f"{label} directory")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or _object_identity(metadata) != directory.directory_identity
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerificationError(
            f"{label} directory must be owned by the current user with mode 0700"
        )
    _bounded_directory_names(directory.directory_fd, 0, f"{label} directory")
    _require_pinned_directory_path_stable(directory)


def _require_exact_created_output_directory(
    directory: _PinnedDirectory,
    created_outputs: Sequence[_CreatedOutput],
    expected_names: Sequence[str],
    label: str,
    *,
    maximum_file_count: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
) -> None:
    directory_before = _fstat(directory.directory_fd, f"{label} directory")
    if (
        not stat.S_ISDIR(directory_before.st_mode)
        or _object_identity(directory_before) != directory.directory_identity
        or directory_before.st_uid != os.geteuid()
        or stat.S_IMODE(directory_before.st_mode) != 0o700
    ):
        raise VerificationError(
            f"{label} directory must remain owned by the current user with mode 0700"
        )
    expected = sorted(expected_names)
    if len(expected) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file output limit"
        )
    names = _bounded_directory_names(
        directory.directory_fd, maximum_file_count, label
    )
    _require_unique_casefold(names, f"{label} directory")
    if names != expected:
        raise VerificationError(
            f"{label} output set differs from contract; "
            f"missing={sorted(set(expected) - set(names))}, "
            f"extra={sorted(set(names) - set(expected))}"
        )
    by_name = {created.output.name: created for created in created_outputs}
    total = 0
    for name in expected:
        created = by_name[name]
        try:
            visible = os.stat(name, dir_fd=directory.directory_fd, follow_symlinks=False)
        except OSError as error:
            raise VerificationError(f"cannot inspect {label}/{name}: {error}") from error
        if visible.st_size > maximum_file_bytes:
            raise VerificationError(
                f"{label}/{name} exceeds the {maximum_file_bytes}-byte output limit"
            )
        total += visible.st_size
        if total > maximum_total_bytes:
            raise VerificationError(
                f"{label} exceeds the {maximum_total_bytes}-byte total output limit"
            )
        if (
            not stat.S_ISREG(visible.st_mode)
            or stat.S_ISLNK(visible.st_mode)
            or stat.S_IMODE(visible.st_mode) != 0o600
            or visible.st_nlink != 1
            or _stat_identity(visible) != created.identity
        ):
            raise VerificationError(f"{label}/{name} changed before completion")
    directory_after = _fstat(directory.directory_fd, f"{label} directory")
    if _stat_identity(directory_before) != _stat_identity(directory_after):
        raise VerificationError(f"{label} directory changed during final inspection")
    _require_pinned_directory_path_stable(directory)


def _revalidate_exact_output(output: ExactOutput) -> None:
    """Close one output-side consistency sweep over every held identity."""
    lifetime = _require_exact_output_owner(output)
    with lifetime.operation(output, f"{output._label} output"):
        _revalidate_exact_output_open(output)


def _revalidate_exact_output_open(output: ExactOutput) -> None:
    _require_exact_io_capabilities()
    components_before = _path_component_identities(
        output._directory.requested_path,
        output._directory.resolved_path,
        output._label,
    )
    if components_before != output._path_component_identities:
        raise VerificationError(f"{output._label} path or ancestor identity changed")
    _require_exact_created_output_directory(
        output._directory,
        output._created_outputs,
        output.names,
        output._label,
        maximum_file_count=output._maximum_file_count,
        maximum_file_bytes=output._maximum_file_bytes,
        maximum_total_bytes=output._maximum_total_bytes,
    )
    _require_created_outputs_stable(output._created_outputs)
    components_after = _path_component_identities(
        output._directory.requested_path,
        output._directory.resolved_path,
        output._label,
    )
    if components_after != output._path_component_identities:
        raise VerificationError(f"{output._label} path or ancestor identity changed")
    _require_exact_created_output_directory(
        output._directory,
        output._created_outputs,
        output.names,
        output._label,
        maximum_file_count=output._maximum_file_count,
        maximum_file_bytes=output._maximum_file_bytes,
        maximum_total_bytes=output._maximum_total_bytes,
    )


def create_exact_output(
    directory: Path,
    files: Mapping[str, bytes],
    disjoint_from: Sequence[ExactInput],
    label: str,
    *,
    maximum_file_count: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
) -> ExactOutput:
    """Create and pin a budgeted exact output set after all writers terminate.

    The caller and sandbox backend must prevent same-uid concurrent writers and
    enforce an OS storage quota. This function provides bounded in-process writes
    and detects drift; it does not claim those external isolation properties.
    """
    _require_exact_io_capabilities()
    normalized = _normalize_exact_output_files(
        files,
        label,
        maximum_file_count=maximum_file_count,
        maximum_file_bytes=maximum_file_bytes,
        maximum_total_bytes=maximum_total_bytes,
    )
    inputs = tuple(disjoint_from)
    if any(type(snapshot) is not ExactInput for snapshot in inputs):
        raise VerificationError(f"{label} disjoint inputs must be ExactInput values")
    for snapshot in inputs:
        _require_exact_input_owner(snapshot)
        snapshot.revalidate()

    pinned = _pin_directory(directory, f"{label} directory")
    created: list[_CreatedOutput] = []
    result: ExactOutput | None = None
    succeeded = False
    try:
        components_before = _path_component_identities(
            pinned.requested_path, pinned.resolved_path, label
        )
        if any(
            _directory_is_same_or_descendant(
                pinned.directory_fd, snapshot._directory.directory_identity
            )
            for snapshot in inputs
        ):
            raise VerificationError(
                f"{label} output directory must be disjoint from exact inputs"
            )
        _require_fresh_private_pinned_directory(pinned, label)
        outputs = [
            _PinnedOutput(
                requested_directory=pinned.requested_path,
                directory=pinned.resolved_path,
                directory_fd=pinned.directory_fd,
                directory_identity=pinned.directory_identity,
                name=name,
                path=pinned.requested_path / name,
            )
            for name in sorted(normalized)
        ]
        _require_outputs_absent(outputs)
        for output in outputs:
            created_output = _write_create_only(
                output,
                normalized[output.name],
                mode=0o600,
                require_single_link=True,
                retain_partial_on_failure=True,
            )
            try:
                created.append(created_output)
            except BaseException:
                _close_fd(created_output.file_fd)
                raise
        try:
            os.fsync(pinned.directory_fd)
        except OSError as error:
            raise VerificationError(f"cannot sync {label} directory: {error}") from error
        _require_created_outputs_stable(created)
        _require_exact_created_output_directory(
            pinned,
            created,
            sorted(normalized),
            label,
            maximum_file_count=maximum_file_count,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_bytes=maximum_total_bytes,
        )
        components_after = _path_component_identities(
            pinned.requested_path, pinned.resolved_path, label
        )
        if components_after != components_before:
            raise VerificationError(f"{label} path or ancestor changed while writing")
        for snapshot in inputs:
            snapshot.revalidate()
        result = _new_exact_output(
            resolved_path=pinned.resolved_path,
            names=tuple(sorted(normalized)),
            directory=pinned,
            created_outputs=tuple(created),
            path_component_identities=components_before,
            maximum_file_count=maximum_file_count,
            maximum_file_bytes=maximum_file_bytes,
            maximum_total_bytes=maximum_total_bytes,
            label=label,
        )
        result.revalidate()
        succeeded = True
        return result
    except VerificationError as error:
        if created and "retained for fail-closed quarantine" not in str(error):
            raise VerificationError(
                f"{error}; output residual retained for fail-closed quarantine"
            ) from error
        raise
    finally:
        if not succeeded:
            if result is None:
                _close_exact_io_fds_once(_ExactIoCloseAttempt(), created, pinned)
            else:
                lifetime = _require_exact_output_owner(result)

                def cleanup(attempt: _ExactIoCloseAttempt) -> None:
                    _close_exact_io_fds_once(attempt, created, pinned)

                lifetime.close_with(result, f"{label} output", cleanup)


def _parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--builder-records", type=Path, required=True)
    parser.add_argument("--forge-commit", required=True)
    parser.add_argument("--predicate-out", type=Path, required=True)
    parser.add_argument("--subject-checksums-out", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    pinned_inputs: list[_PinnedDirectory] = []
    pinned_outputs: list[_PinnedOutput] = []
    created_outputs: list[_CreatedOutput] = []
    try:
        _require_secure_posix_fs_capabilities()
        authority_commit = _authority_commit_from_actions_environment(os.environ)
        policy_path = AUTHORITY_POLICY_PATH
        policy, _policy_digest = load_policy(policy_path)
        resolved_materials = _resolve_github_materials(
            policy, options.forge_commit, authority_commit
        )
        assets_directory = _pin_directory(options.assets, "release assets directory")
        pinned_inputs.append(assets_directory)
        builder_records_directory = _pin_directory(
            options.builder_records, "builder records directory"
        )
        pinned_inputs.append(builder_records_directory)
        predicate_output = _pin_output(options.predicate_out, pinned_inputs)
        pinned_outputs.append(predicate_output)
        subject_checksums_output = _pin_output(
            options.subject_checksums_out, pinned_inputs
        )
        pinned_outputs.append(subject_checksums_output)
        if (
            predicate_output.directory_identity
            == subject_checksums_output.directory_identity
        ):
            _require_unique_casefold(
                [predicate_output.name, subject_checksums_output.name],
                "qualification output names",
            )
        _require_outputs_absent(pinned_outputs)
        _require_fresh_private_output_directories(pinned_outputs)
        predicate, subject_checksums = _verify_release_with_pinned_directories(
            policy_path,
            assets_directory,
            builder_records_directory,
            options.forge_commit,
            authority_commit,
            resolved_materials,
        )
        rendered = _canonical_json(predicate)
        _require_pinned_output_parents_stable(pinned_outputs, pinned_inputs)
        created_outputs.append(
            _write_create_only(subject_checksums_output, subject_checksums)
        )
        _require_pinned_output_parents_stable(pinned_outputs, pinned_inputs)
        created_outputs.append(_write_create_only(predicate_output, rendered))
        _require_pinned_output_parents_stable(pinned_outputs, pinned_inputs)
        _require_created_outputs_stable(created_outputs)
    except VerificationError as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1
    finally:
        for created in created_outputs:
            try:
                os.close(created.file_fd)
            except OSError:
                pass
        for output in pinned_outputs:
            try:
                os.close(output.directory_fd)
            except OSError:
                pass
        for input_directory in pinned_inputs:
            _close_pinned_directory(input_directory)
    print(
        json.dumps(
            {
                "authorityCommit": authority_commit,
                "forgeCommit": options.forge_commit,
                "predicate": str(options.predicate_out),
                "subjectChecksums": str(options.subject_checksums_out),
                "verifiedSubjects": 13,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
