#!/usr/bin/env python3
"""Authority POSIX exact-I/O adapter.

Importing this module performs no platform operation.  Each entry point fails
closed before touching a filesystem when the required POSIX primitives are not
available.  Direct import or isolated operation success is not qualification
evidence: formal use first binds this module into the protected Authority runtime.
Filesystem identity checks do not prove sandboxing or exclude an external writer
with the same uid.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from contextlib import ExitStack, contextmanager
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

if __package__:
    from .release_io import (
        VerificationError,
        normalize_exact_file_limits as _normalize_exact_file_limits,
        normalize_exact_output_files as _normalize_exact_output_files,
        require_safe_basename as _require_safe_basename,
        require_unique_casefold as _require_unique_casefold,
    )
else:
    from release_io import (
        VerificationError,
        normalize_exact_file_limits as _normalize_exact_file_limits,
        normalize_exact_output_files as _normalize_exact_output_files,
        require_safe_basename as _require_safe_basename,
        require_unique_casefold as _require_unique_casefold,
    )

MAX_DIRECTORY_ANCESTORS = 1024
StatIdentity = tuple[int, int, int, int, int, int]
ObjectIdentity = tuple[int, int, int]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


class _PinnedDirectoryLease(_OpaqueExactIoResource):
    """Opaque facade owner for exactly one pinned-directory fd."""

    __slots__ = ("_lifetime", "_view")
    _resource_kind = "pinned directory lease"

    _lifetime: _ExactIoLifetime
    _view: _PinnedDirectory

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("opaque pinned directory lease cannot be subclassed")


class _PinnedOutputLease(_OpaqueExactIoResource):
    """Opaque facade owner for exactly one pinned output-parent fd."""

    __slots__ = ("_lifetime", "_view")
    _resource_kind = "pinned output lease"

    _lifetime: _ExactIoLifetime
    _view: _PinnedOutput

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("opaque pinned output lease cannot be subclassed")

    @property
    def directory_identity(self) -> ObjectIdentity:
        lifetime, view = _require_pinned_output_lease(self)
        with lifetime.operation(self, "pinned output lease"):
            return view.directory_identity

    @property
    def name(self) -> str:
        lifetime, view = _require_pinned_output_lease(self)
        with lifetime.operation(self, "pinned output lease"):
            return view.name


class _CreatedOutputLease(_OpaqueExactIoResource):
    """Opaque facade owner for exactly one created-output file fd."""

    __slots__ = ("_lifetime", "_output", "_view")
    _resource_kind = "created output lease"

    _lifetime: _ExactIoLifetime
    _output: _PinnedOutputLease
    _view: _CreatedOutput

    def __init_subclass__(cls, **_kwargs: Any) -> NoReturn:
        raise TypeError("opaque created output lease cannot be subclassed")


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


def _require_pinned_directory_lease(
    resource: object,
) -> tuple[_ExactIoLifetime, _PinnedDirectory]:
    lifetime = _require_exact_io_owner(
        resource, _PinnedDirectoryLease, "pinned directory lease"
    )
    try:
        view = object.__getattribute__(resource, "_view")
    except AttributeError as error:
        raise VerificationError(
            "exact pinned directory lease has invalid resource ownership"
        ) from error
    if type(view) is not _PinnedDirectory:
        raise VerificationError(
            "exact pinned directory lease has invalid resource ownership"
        )
    return lifetime, view


def _require_pinned_output_lease(
    resource: object,
) -> tuple[_ExactIoLifetime, _PinnedOutput]:
    lifetime = _require_exact_io_owner(
        resource, _PinnedOutputLease, "pinned output lease"
    )
    try:
        view = object.__getattribute__(resource, "_view")
    except AttributeError as error:
        raise VerificationError(
            "exact pinned output lease has invalid resource ownership"
        ) from error
    if type(view) is not _PinnedOutput:
        raise VerificationError(
            "exact pinned output lease has invalid resource ownership"
        )
    return lifetime, view


def _require_created_output_lease(
    resource: object,
) -> tuple[
    _ExactIoLifetime,
    _CreatedOutput,
    _PinnedOutputLease,
    _ExactIoLifetime,
    _PinnedOutput,
]:
    lifetime = _require_exact_io_owner(
        resource, _CreatedOutputLease, "created output lease"
    )
    try:
        view = object.__getattribute__(resource, "_view")
        output = object.__getattribute__(resource, "_output")
    except AttributeError as error:
        raise VerificationError(
            "exact created output lease has invalid resource ownership"
        ) from error
    if type(view) is not _CreatedOutput:
        raise VerificationError(
            "exact created output lease has invalid resource ownership"
        )
    output_lifetime, output_view = _require_pinned_output_lease(output)
    if view.output is not output_view:
        raise VerificationError(
            "exact created output lease has invalid parent ownership"
        )
    return lifetime, view, output, output_lifetime, output_view


def _new_pinned_directory_lease(view: _PinnedDirectory) -> _PinnedDirectoryLease:
    result = object.__new__(_PinnedDirectoryLease)
    lifetime = _ExactIoLifetime(_EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_view", view)
    lifetime.bind(result, _EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_lifetime", lifetime)
    return result


def _new_pinned_output_lease(view: _PinnedOutput) -> _PinnedOutputLease:
    result = object.__new__(_PinnedOutputLease)
    lifetime = _ExactIoLifetime(_EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_view", view)
    lifetime.bind(result, _EXACT_IO_CONSTRUCTION_TOKEN)
    object.__setattr__(result, "_lifetime", lifetime)
    return result


def _new_created_output_lease(
    view: _CreatedOutput, output: _PinnedOutputLease
) -> _CreatedOutputLease:
    output_lifetime, output_view = _require_pinned_output_lease(output)
    with output_lifetime.operation(output, "pinned output lease"):
        if view.output is not output_view:
            raise VerificationError(
                "created output does not belong to its pinned output lease"
            )
        result = object.__new__(_CreatedOutputLease)
        lifetime = _ExactIoLifetime(_EXACT_IO_CONSTRUCTION_TOKEN)
        object.__setattr__(result, "_view", view)
        object.__setattr__(result, "_output", output)
        lifetime.bind(result, _EXACT_IO_CONSTRUCTION_TOKEN)
        object.__setattr__(result, "_lifetime", lifetime)
        return result


@contextmanager
def _lease_operations(
    resources: Sequence[tuple[object, _ExactIoLifetime, str]],
) -> Iterator[None]:
    """Hold each distinct lease in a deadlock-stable order for one operation."""
    unique: dict[int, tuple[object, _ExactIoLifetime, str]] = {}
    for resource, lifetime, label in resources:
        unique.setdefault(id(resource), (resource, lifetime, label))
    with ExitStack() as stack:
        for resource_id in sorted(unique):
            resource, lifetime, label = unique[resource_id]
            stack.enter_context(lifetime.operation(resource, label))
        yield


def _validated_pinned_directory_leases(
    resources: Sequence[object], label: str
) -> list[tuple[_PinnedDirectoryLease, _ExactIoLifetime, _PinnedDirectory]]:
    result: list[tuple[_PinnedDirectoryLease, _ExactIoLifetime, _PinnedDirectory]] = []
    seen: set[int] = set()
    for resource in resources:
        lifetime, view = _require_pinned_directory_lease(resource)
        if id(resource) in seen:
            raise VerificationError(f"{label} contains a duplicate lease")
        seen.add(id(resource))
        result.append((cast(_PinnedDirectoryLease, resource), lifetime, view))
    return result


def _validated_pinned_output_leases(
    resources: Sequence[object], label: str
) -> list[tuple[_PinnedOutputLease, _ExactIoLifetime, _PinnedOutput]]:
    result: list[tuple[_PinnedOutputLease, _ExactIoLifetime, _PinnedOutput]] = []
    seen: set[int] = set()
    for resource in resources:
        lifetime, view = _require_pinned_output_lease(resource)
        if id(resource) in seen:
            raise VerificationError(f"{label} contains a duplicate lease")
        seen.add(id(resource))
        result.append((cast(_PinnedOutputLease, resource), lifetime, view))
    return result


def _validated_created_output_leases(
    resources: Sequence[object], label: str
) -> list[
    tuple[
        _CreatedOutputLease,
        _ExactIoLifetime,
        _CreatedOutput,
        _PinnedOutputLease,
        _ExactIoLifetime,
    ]
]:
    result: list[
        tuple[
            _CreatedOutputLease,
            _ExactIoLifetime,
            _CreatedOutput,
            _PinnedOutputLease,
            _ExactIoLifetime,
        ]
    ] = []
    seen: set[int] = set()
    for resource in resources:
        lifetime, view, output, output_lifetime, _output_view = (
            _require_created_output_lease(resource)
        )
        if id(resource) in seen:
            raise VerificationError(f"{label} contains a duplicate lease")
        seen.add(id(resource))
        result.append(
            (
                cast(_CreatedOutputLease, resource),
                lifetime,
                view,
                output,
                output_lifetime,
            )
        )
    return result


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
            "required exact-I/O POSIX capabilities unavailable: " + ", ".join(missing)
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

    def snapshot(
        kind: str, absolute_path: Path
    ) -> list[tuple[str, str, ObjectIdentity]]:
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
        if _stat_identity(visible_final) != entry_identities[name] or (
            require_single_link and visible_final.st_nlink != 1
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
            visible = os.stat(
                name, dir_fd=directory.directory_fd, follow_symlinks=False
            )
        except OSError as error:
            raise VerificationError(
                f"cannot inspect {label}/{name}: {error}"
            ) from error
        if not stat.S_ISREG(visible.st_mode) or stat.S_ISLNK(visible.st_mode):
            raise VerificationError(
                f"{label}/{name} must be a non-symlink regular file"
            )
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
    if (
        _bounded_directory_names(directory.directory_fd, len(expected), label)
        != expected
    ):
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
    """Open a local exact input utility; success alone is not Authority evidence."""
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
    names = _bounded_directory_names(directory.directory_fd, maximum_file_count, label)
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
            visible = os.stat(
                name, dir_fd=directory.directory_fd, follow_symlinks=False
            )
        except OSError as error:
            raise VerificationError(
                f"cannot inspect {label}/{name}: {error}"
            ) from error
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
    """Create a local exact output utility; success alone is not Authority evidence.

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
            raise VerificationError(
                f"cannot sync {label} directory: {error}"
            ) from error
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


def pin_directory(path: Path, label: str) -> _PinnedDirectoryLease:
    """Pin one POSIX directory behind an opaque caller-managed lease."""
    view = _pin_directory(path, label)
    try:
        return _new_pinned_directory_lease(view)
    except BaseException:
        _close_pinned_directory(view)
        raise


def close_pinned_directory(directory: _PinnedDirectoryLease) -> None:
    """Close one adapter-created directory lease at most once."""
    lifetime, view = _require_pinned_directory_lease(directory)

    def cleanup(attempt: _ExactIoCloseAttempt) -> None:
        attempt.started = True
        _close_pinned_directory(view)

    lifetime.close_with(directory, "pinned directory lease", cleanup)


def read_exact_pinned_directory(
    directory: _PinnedDirectoryLease,
    expected_names: Sequence[str],
    size_limit: Callable[[str], int],
    total_limit: int,
    label: str,
) -> dict[str, bytes]:
    """Read one exact byte set while its opaque directory lease is live."""
    lifetime, view = _require_pinned_directory_lease(directory)
    with lifetime.operation(directory, "pinned directory lease"):
        return _read_exact_pinned_directory(
            view, expected_names, size_limit, total_limit, label
        )


def pin_output(
    output: Path, input_directories: Sequence[_PinnedDirectoryLease]
) -> _PinnedOutputLease:
    """Pin one create-only output outside each supplied live input lease."""
    inputs = _validated_pinned_directory_leases(
        input_directories, "pinned output input directories"
    )
    operations = [
        (lease, lifetime, "pinned directory lease") for lease, lifetime, _view in inputs
    ]
    with _lease_operations(operations):
        view = _pin_output(output, [view for _lease, _lifetime, view in inputs])
        try:
            return _new_pinned_output_lease(view)
        except BaseException:
            _close_fd(view.directory_fd)
            raise


def require_pinned_output_parents_stable(
    outputs: Sequence[_PinnedOutputLease],
    input_directories: Sequence[_PinnedDirectoryLease],
) -> None:
    output_leases = _validated_pinned_output_leases(outputs, "pinned output parents")
    input_leases = _validated_pinned_directory_leases(
        input_directories, "pinned output input directories"
    )
    operations = [
        (lease, lifetime, "pinned output lease")
        for lease, lifetime, _view in output_leases
    ] + [
        (lease, lifetime, "pinned directory lease")
        for lease, lifetime, _view in input_leases
    ]
    with _lease_operations(operations):
        _require_pinned_output_parents_stable(
            [view for _lease, _lifetime, view in output_leases],
            [view for _lease, _lifetime, view in input_leases],
        )


def require_outputs_absent(outputs: Sequence[_PinnedOutputLease]) -> None:
    output_leases = _validated_pinned_output_leases(outputs, "pinned outputs")
    operations = [
        (lease, lifetime, "pinned output lease")
        for lease, lifetime, _view in output_leases
    ]
    with _lease_operations(operations):
        _require_outputs_absent([view for _lease, _lifetime, view in output_leases])


def require_fresh_private_output_directories(
    outputs: Sequence[_PinnedOutputLease],
) -> None:
    output_leases = _validated_pinned_output_leases(
        outputs, "private output directories"
    )
    operations = [
        (lease, lifetime, "pinned output lease")
        for lease, lifetime, _view in output_leases
    ]
    with _lease_operations(operations):
        _require_fresh_private_output_directories(
            [view for _lease, _lifetime, view in output_leases]
        )


def write_create_only(output: _PinnedOutputLease, data: bytes) -> _CreatedOutputLease:
    """Create one formal output with the frozen historical mode semantics."""
    lifetime, view = _require_pinned_output_lease(output)
    with lifetime.operation(output, "pinned output lease"):
        created = _write_create_only(view, data)
        try:
            return _new_created_output_lease(created, output)
        except BaseException:
            _close_fd(created.file_fd)
            raise


def require_created_outputs_stable(
    outputs: Sequence[_CreatedOutputLease],
) -> None:
    created_leases = _validated_created_output_leases(outputs, "created outputs")
    operations: list[tuple[object, _ExactIoLifetime, str]] = []
    for lease, lifetime, _view, output, output_lifetime in created_leases:
        operations.append((lease, lifetime, "created output lease"))
        operations.append((output, output_lifetime, "pinned output lease"))
    with _lease_operations(operations):
        _require_created_outputs_stable(
            [
                view
                for _lease, _lifetime, view, _output, _output_lifetime in created_leases
            ]
        )


def close_created_output(output: _CreatedOutputLease) -> None:
    lifetime, view, _parent, _parent_lifetime, _parent_view = (
        _require_created_output_lease(output)
    )

    def cleanup(attempt: _ExactIoCloseAttempt) -> None:
        attempt.started = True
        _close_fd(view.file_fd)

    lifetime.close_with(output, "created output lease", cleanup)


def close_pinned_output(output: _PinnedOutputLease) -> None:
    lifetime, view = _require_pinned_output_lease(output)

    def cleanup(attempt: _ExactIoCloseAttempt) -> None:
        attempt.started = True
        _close_fd(view.directory_fd)

    lifetime.close_with(output, "pinned output lease", cleanup)
