#!/usr/bin/env python3
"""Portable value and lifecycle contracts for Authority exact I/O.

This module deliberately contains no operating-system handle operations.  A
``FrozenFileSet`` is only an immutable observation of bytes that a backend already
captured; it is not evidence that the source tree was externally read-only or
isolated from writers.  Concrete backends must establish and retain the handles
needed to make the resource protocols below meaningful.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

MAX_PORTABLE_FILE_NAME_BYTES = 255
MAX_EXACT_FILE_COUNT = 4096
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class VerificationError(ValueError):
    """An input did not satisfy an Authority verification contract."""


def require_safe_basename(value: Any, path: str) -> str:
    """Return one portable, relative filename or reject it."""
    if type(value) is not str:
        raise VerificationError(f"{path} must be a string")
    if not value or value in {".", ".."}:
        raise VerificationError(f"{path} must be a non-empty portable basename")
    if (
        not value.isascii()
        or len(value.encode("ascii")) > MAX_PORTABLE_FILE_NAME_BYTES
        or re.fullmatch(r"[A-Za-z0-9._+-]+", value) is None
        or value.endswith((".", " "))
    ):
        raise VerificationError(f"{path} must be a portable ASCII basename")
    stem = value.split(".", 1)[0].casefold()
    if stem in _WINDOWS_RESERVED_STEMS:
        raise VerificationError(f"{path} must be a portable basename")
    return value


def require_unique_casefold(names: Sequence[str], path: str) -> None:
    """Reject names that collide on a case-insensitive filesystem."""
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for name in names:
        _insert_unique_name(name, path, exact, folded)


def _insert_unique_name(
    name: object, path: str, exact: set[str], folded: dict[str, str]
) -> None:
    if type(name) is not str:
        raise VerificationError(f"{path} names must be strings")
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


def _require_positive_integer(value: object, path: str) -> int:
    if type(value) is not int or value <= 0:
        raise VerificationError(f"{path} must be a positive integer")
    return value


def normalize_exact_file_limits(
    limits_by_name: Mapping[str, int],
    total_limit: int,
    label: str,
    *,
    maximum_file_count: int = MAX_EXACT_FILE_COUNT,
) -> Mapping[str, int]:
    """Freeze the exact input names and their positive byte budgets."""
    if type(total_limit) is not int:
        raise VerificationError(f"{label} total byte limit must be an integer")
    if total_limit <= 0:
        raise VerificationError(f"{label} total byte limit must be positive")
    _require_positive_integer(maximum_file_count, f"{label} maximum file count")
    if maximum_file_count > MAX_EXACT_FILE_COUNT:
        raise VerificationError(
            f"{label} maximum file count exceeds the {MAX_EXACT_FILE_COUNT}-file hard cap"
        )
    if len(limits_by_name) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file input limit"
        )
    normalized: dict[str, int] = {}
    exact: set[str] = set()
    folded: dict[str, str] = {}
    for index, (candidate_name, candidate_limit) in enumerate(limits_by_name.items()):
        if index >= maximum_file_count:
            raise VerificationError(
                f"{label} exceeds the {maximum_file_count}-file input limit"
            )
        name = require_safe_basename(candidate_name, f"{label} input name")
        _insert_unique_name(name, f"{label} input names", exact, folded)
        if type(candidate_limit) is not int:
            raise VerificationError(f"{label}/{name} byte limit must be an integer")
        if candidate_limit <= 0:
            raise VerificationError(f"{label}/{name} byte limit must be positive")
        normalized[name] = candidate_limit
    return MappingProxyType(normalized)


def normalize_exact_output_files(
    files: Mapping[str, bytes],
    label: str,
    *,
    maximum_file_count: int,
    maximum_file_bytes: int,
    maximum_total_bytes: int,
) -> Mapping[str, bytes]:
    """Copy and freeze one exact output byte set under explicit budgets."""
    for name, value in (
        ("maximum file count", maximum_file_count),
        ("maximum file bytes", maximum_file_bytes),
        ("maximum total bytes", maximum_total_bytes),
    ):
        _require_positive_integer(value, f"{label} {name}")
    if maximum_file_count > MAX_EXACT_FILE_COUNT:
        raise VerificationError(
            f"{label} maximum file count exceeds the {MAX_EXACT_FILE_COUNT}-file hard cap"
        )
    if len(files) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file output limit"
        )
    normalized: dict[str, bytes] = {}
    exact: set[str] = set()
    folded: dict[str, str] = {}
    total = 0
    for index, (candidate_name, data) in enumerate(files.items()):
        if index >= maximum_file_count:
            raise VerificationError(
                f"{label} exceeds the {maximum_file_count}-file output limit"
            )
        name = require_safe_basename(candidate_name, f"{label} output name")
        _insert_unique_name(name, f"{label} output names", exact, folded)
        if type(data) is not bytes:
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
    if len(normalized) > maximum_file_count:
        raise VerificationError(
            f"{label} exceeds the {maximum_file_count}-file output limit"
        )
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class FrozenFileSet:
    """An immutable, budgeted byte observation; never an isolation proof."""

    files: Mapping[str, bytes]
    label: str
    maximum_file_count: int
    maximum_file_bytes: int
    maximum_total_bytes: int
    names: tuple[str, ...] = field(init=False)
    sha256_by_name: Mapping[str, str] = field(init=False)
    total_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        if type(self.label) is not str or not self.label:
            raise VerificationError("FrozenFileSet label must be a non-empty string")
        normalized = normalize_exact_output_files(
            self.files,
            self.label,
            maximum_file_count=self.maximum_file_count,
            maximum_file_bytes=self.maximum_file_bytes,
            maximum_total_bytes=self.maximum_total_bytes,
        )
        names = tuple(sorted(normalized))
        object.__setattr__(self, "files", normalized)
        object.__setattr__(self, "names", names)
        object.__setattr__(
            self,
            "sha256_by_name",
            MappingProxyType(
                {name: hashlib.sha256(normalized[name]).hexdigest() for name in names}
            ),
        )
        object.__setattr__(self, "total_bytes", sum(map(len, normalized.values())))


class ExactInputView(Protocol):
    """A backend-held exact input snapshot valid only for its live lease."""

    @property
    def files(self) -> Mapping[str, bytes]: ...

    @property
    def resolved_path(self) -> Path: ...

    def revalidate(self, rehash: bool = True) -> None: ...


class ExactOutputView(Protocol):
    """A backend-held exact create-only output set."""

    @property
    def names(self) -> tuple[str, ...]: ...

    @property
    def resolved_path(self) -> Path: ...

    def revalidate(self) -> None: ...

    def close(self) -> None: ...
