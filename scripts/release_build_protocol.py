#!/usr/bin/env python3
"""Pure Authority-side parser and projector for Forge release-build protocol v1.

The functions in this module deliberately do no file, process, path, environment,
or network I/O.  A trusted Authority driver owns those capabilities and supplies
already captured bytes plus independently observed identities.  This module only
validates bounded values and constructs deterministic protocol bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import tomllib
from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence, cast


PLAN_SCHEMA = "forge.release-build-plan/v1"
APPLY_DESCRIPTOR_SCHEMA = "forge.release-build-apply-descriptor/v1"
PLAN_PURPOSE = "authority-execution-request-not-release-evidence"
APPLY_DESCRIPTOR_PURPOSE = "candidate-apply-input-not-authority-evidence"
POLICY_SCHEMA = "forge.release-authority-policy/v1"
SBOM_GRAPH_SCHEMA = "forge.release-sbom-graph/v1"
RELEASE_PACKAGE = "forge-cli"
RELEASE_BINARY = "forge"
RELEASE_VERSION = "0.1.0-rc.2"
RELEASE_RUST_TOOLCHAIN = "1.96.0"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MAX_PLAN_BYTES = 16 * 1024
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_BUILD_MESSAGES_BYTES = 32 * 1024 * 1024
MAX_BUILD_MESSAGES = 1_000_000
MAX_TREE_LINES = 1_000_000
MAX_METADATA_PACKAGES = 100_000
MAX_GRAPH_PACKAGES = 512
MAX_DEPENDENCIES_PER_PACKAGE = 512
MAX_GRAPH_EDGES = 4096
MAX_PROTOCOL_BINARY_BYTES = 256 * 1024 * 1024
MAX_JSON_INTEGER_CHARACTERS = 64
MAX_INVENTORY_ENTRIES = 100_000
MAX_INVENTORY_PATH_BYTES = 4096
MAX_INVENTORY_UTF8_BYTES = 16 * 1024 * 1024

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]{0,127}\Z")
_SOURCE_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._+~-]{1,255}\Z")
_TARGET_PROFILES = {
    "x86_64-unknown-linux-musl": ("ubuntu-24.04", "elf64-x86_64-static"),
    "aarch64-unknown-linux-musl": ("ubuntu-24.04-arm", "elf64-aarch64-static"),
    "x86_64-apple-darwin": ("macos-15-intel", "macho64-x86_64"),
    "aarch64-apple-darwin": ("macos-15", "macho64-aarch64"),
    "x86_64-pc-windows-msvc": ("windows-2025", "pe64-x86_64"),
}
_LICENSE_EXPRESSIONS = frozenset(
    {
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "Apache-2.0",
        "Apache-2.0 OR BSL-1.0",
        "Apache-2.0 OR MIT",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
        "BSD-2-Clause",
        "BSD-2-Clause OR Apache-2.0 OR MIT",
        "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception",
        "CC0-1.0 OR MIT-0 OR Apache-2.0",
        "MIT",
        "MIT OR Apache-2.0",
        "MIT-0",
        "Unicode-3.0",
        "Unlicense OR MIT",
        "Zlib",
    }
)
_LICENSE_REWRITES = {
    ("ctrlc", "3.4.7", "MIT/Apache-2.0"): "MIT OR Apache-2.0",
    ("fs2", "0.4.3", "MIT/Apache-2.0"): "MIT OR Apache-2.0",
    ("winapi", "0.3.9", "MIT/Apache-2.0"): "MIT OR Apache-2.0",
    ("same-file", "1.0.6", "Unlicense/MIT"): "Unlicense OR MIT",
    ("walkdir", "2.5.0", "Unlicense/MIT"): "Unlicense OR MIT",
}
_PLAN_FIELDS = (
    "schema",
    "purpose",
    "source_commit",
    "cargo_lock_sha256",
    "target",
    "package",
    "binary",
    "profile",
    "dependency_resolution",
    "network",
    "outputs",
)


class ProtocolError(ValueError):
    """One candidate or captured value violates release-build protocol v1."""


@dataclass(frozen=True)
class AuthorityExecutionSpec:
    """Fixed semantics that the Authority, never the candidate, turns into calls."""

    target: str
    runner_label: str
    binary_format: str
    rust_toolchain: str
    source_root: str
    source_inventory_sha256: str
    dependency_root: str
    dependency_inventory_sha256: str
    target_root: str
    package: str = RELEASE_PACKAGE
    binary: str = RELEASE_BINARY
    profile: str = "release"
    dependency_resolution: str = "locked"
    network: str = "offline"
    features: tuple[str, ...] = ()
    environment_overrides: tuple[tuple[str, str], ...] = ()

    def cargo_build_arguments(self, target_directory: str) -> tuple[str, ...]:
        """Return the closed Cargo argv after the driver supplies its fresh target dir."""
        _require_absolute_synthetic_path(
            target_directory, "Authority Cargo target directory"
        )
        _require_value(
            target_directory,
            self.target_root,
            "Authority Cargo target directory",
        )
        return (
            "build",
            "--release",
            "--locked",
            "--offline",
            "-p",
            self.package,
            "--bin",
            self.binary,
            "--message-format=json-render-diagnostics",
            "--target",
            self.target,
            "--target-dir",
            target_directory,
        )

    def cargo_metadata_arguments(self) -> tuple[str, ...]:
        """Return the fixed target-filtered Cargo metadata argv."""
        return (
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            self.target,
        )

    def cargo_tree_arguments(self) -> tuple[str, ...]:
        """Return the fixed target-specific normal/build dependency traversal."""
        return (
            "tree",
            "--locked",
            "--offline",
            "-p",
            self.package,
            "--target",
            self.target,
            "-e",
            "normal,build",
            "--prefix",
            "depth",
            "--format",
            "@@{p}@@",
            "--no-dedupe",
        )


@dataclass(frozen=True)
class AcceptedReleaseBuildPlan:
    """An accepted plan plus only the semantics a driver may consume.

    Inventory values bind identities already verified by the trusted driver;
    they do not by themselves prove regular files, read-only mounts, or sandboxing.
    """

    canonical_bytes: bytes
    plan_sha256: str
    source_commit: str
    cargo_lock_sha256: str
    version: str
    binary_name: str
    sbom_name: str
    binary_limit: int
    cargo_lock_limit: int
    project_license_expression: str
    source_root: str
    source_inventory: frozenset[str]
    source_inventory_sha256: str
    dependency_root: str
    dependency_inventory: tuple[tuple[str, str], ...]
    dependency_inventory_sha256: str
    target_root: str
    authority_context_sha256: str
    sbom_graph: _SbomGraphContract
    execution: AuthorityExecutionSpec


@dataclass(frozen=True)
class ReleaseBinaryArtifactBinding:
    """Closed Cargo observation a driver must open relative to its pinned target root.

    This value binds protocol inputs and a canonical relative path.  It is not
    filesystem or sandbox proof; the Authority driver must still use a pinned,
    no-follow regular-file handle and independently observe the file identity.
    """

    plan_sha256: str
    authority_context_sha256: str
    target_root: str
    relative_path: str
    metadata_sha256: str
    tree_sha256: str
    build_messages_sha256: str
    identity_sha256: str


@dataclass(frozen=True)
class CapturedReleaseBinary:
    """A trusted driver's digest observation tied to one artifact binding."""

    artifact: ReleaseBinaryArtifactBinding
    length: int
    sha256: str


@dataclass(frozen=True)
class _PolicyContract:
    version: str
    rust_toolchain: str
    binary_limit: int
    cargo_lock_limit: int
    project_license_expression: str
    targets: Mapping[str, _TargetContract]


@dataclass(frozen=True)
class _SbomGraphContract:
    component_count: int
    dependency_edge_count: int
    canonical_sha256: str


@dataclass(frozen=True)
class _TargetContract:
    runner_label: str
    binary_format: str
    binary: str
    sbom: str
    sbom_graph: _SbomGraphContract


@dataclass(frozen=True)
class _CargoTarget:
    name: str
    kinds: tuple[str, ...]
    crate_types: tuple[str, ...]
    src_path: str


@dataclass(frozen=True)
class _CargoPackage:
    package_id: str
    name: str
    version: str
    license_expression: str | None
    source: str | None
    manifest_path: str | None
    targets: tuple[_CargoTarget, ...]


@dataclass(frozen=True)
class _CargoMetadata:
    packages_by_id: Mapping[str, _CargoPackage]
    packages_by_name_version: Mapping[tuple[str, str], tuple[_CargoPackage, ...]]
    workspace_members: frozenset[str]
    workspace_root: str


@dataclass(frozen=True)
class _SelectedGraph:
    root_id: str
    package_ids: frozenset[str]
    edges: Mapping[str, frozenset[str]]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_BLAKE3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_BLAKE3_MESSAGE_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_BLAKE3_CHUNK_START = 1
_BLAKE3_CHUNK_END = 2
_BLAKE3_ROOT = 8


def _rotate_right_32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFF_FFFF


def _blake3_mix(
    state: list[int], a: int, b: int, c: int, d: int, left: int, right: int
) -> None:
    state[a] = (state[a] + state[b] + left) & 0xFFFF_FFFF
    state[d] = _rotate_right_32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFF_FFFF
    state[b] = _rotate_right_32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + right) & 0xFFFF_FFFF
    state[d] = _rotate_right_32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFF_FFFF
    state[b] = _rotate_right_32(state[b] ^ state[c], 7)


def _blake3_compress(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    block_length: int,
    flags: int,
) -> tuple[int, ...]:
    state = list(chaining_value) + list(_BLAKE3_IV[:4]) + [0, 0, block_length, flags]
    message = list(block_words)
    for _round in range(7):
        _blake3_mix(state, 0, 4, 8, 12, message[0], message[1])
        _blake3_mix(state, 1, 5, 9, 13, message[2], message[3])
        _blake3_mix(state, 2, 6, 10, 14, message[4], message[5])
        _blake3_mix(state, 3, 7, 11, 15, message[6], message[7])
        _blake3_mix(state, 0, 5, 10, 15, message[8], message[9])
        _blake3_mix(state, 1, 6, 11, 12, message[10], message[11])
        _blake3_mix(state, 2, 7, 8, 13, message[12], message[13])
        _blake3_mix(state, 3, 4, 9, 14, message[14], message[15])
        message = [message[index] for index in _BLAKE3_MESSAGE_PERMUTATION]
    return tuple(
        [state[index] ^ state[index + 8] for index in range(8)]
        + [state[index + 8] ^ chaining_value[index] for index in range(8)]
    )


def _blake3_hex(data: bytes) -> str:
    """Return BLAKE3 for one bounded package identity without an external module."""
    if len(data) > 1024:
        raise ProtocolError("release package identity exceeds one BLAKE3 chunk")
    block_count = max(1, (len(data) + 63) // 64)
    chaining_value: tuple[int, ...] = _BLAKE3_IV
    for block_index in range(block_count - 1):
        block = data[block_index * 64 : (block_index + 1) * 64]
        words = struct.unpack("<16I", block)
        flags = _BLAKE3_CHUNK_START if block_index == 0 else 0
        chaining_value = _blake3_compress(chaining_value, words, len(block), flags)[:8]
    final = data[(block_count - 1) * 64 :]
    padded = final + bytes(64 - len(final))
    final_words = struct.unpack("<16I", padded)
    final_flags = _BLAKE3_CHUNK_END
    if block_count == 1:
        final_flags |= _BLAKE3_CHUNK_START
    output = _blake3_compress(
        chaining_value,
        final_words,
        len(final),
        final_flags | _BLAKE3_ROOT,
    )
    return struct.pack("<16I", *output)[:32].hex()


def canonical_json(value: Any) -> bytes:
    """Render the exact pretty JSON form shared with Forge protocol structs."""
    try:
        text = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            separators=(",", ": "),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ProtocolError(
            "protocol value cannot be rendered as canonical JSON"
        ) from error
    return (text + "\n").encode("utf-8")


def _duplicate_rejecting_object(
    pairs: Sequence[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ProtocolError(f"JSON contains forbidden constant {value!r}")


def _reject_json_float(value: str) -> None:
    raise ProtocolError(f"JSON contains forbidden non-integer number {value!r}")


def _parse_bounded_json_integer(value: str) -> int:
    if len(value) > MAX_JSON_INTEGER_CHARACTERS:
        raise ProtocolError("JSON integer exceeds the 64-character protocol limit")
    return int(value, 10)


def _load_json_bytes(data: bytes, maximum: int, label: str) -> Any:
    if not isinstance(data, bytes):
        raise ProtocolError(f"{label} must be bytes")
    if not data or len(data) > maximum:
        raise ProtocolError(f"{label} must contain 1..={maximum} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError(f"{label} is not UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_bounded_json_integer,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ProtocolError(f"{label} is not valid bounded JSON") from error


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(f"{path} must be an object")
    return cast(Mapping[str, Any], value)


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProtocolError(f"{path} must be an array")
    return value


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{path} must be a string")
    return value


def _require_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{path} must be an integer")
    return cast(int, value)


def _require_exact_keys(
    value: Mapping[str, Any], expected: Sequence[str], path: str
) -> None:
    expected_set = set(expected)
    actual = set(value)
    if actual != expected_set:
        missing = sorted(expected_set - actual)
        extra = sorted(actual - expected_set)
        raise ProtocolError(
            f"{path} fields differ from protocol; missing={missing}, extra={extra}"
        )


def _require_ordered_keys(
    value: Mapping[str, Any], expected: Sequence[str], path: str
) -> None:
    _require_exact_keys(value, expected, path)
    if tuple(value) != tuple(expected):
        raise ProtocolError(f"{path} fields are not in canonical protocol order")


def _require_value(actual: Any, expected: Any, path: str) -> None:
    if actual != expected or type(actual) is not type(expected):
        raise ProtocolError(f"{path} does not match the frozen protocol value")


def _require_sha256(value: Any, path: str) -> str:
    digest = _require_string(value, path)
    if _SHA256.fullmatch(digest) is None:
        raise ProtocolError(f"{path} must be a lowercase SHA-256 digest")
    return digest


def _require_package_name(value: Any, path: str) -> str:
    name = _require_string(value, path)
    if _PACKAGE_NAME.fullmatch(name) is None:
        raise ProtocolError(f"{path} is outside the package-name protocol")
    return name


def _require_package_version(value: Any, path: str) -> str:
    version = _require_string(value, path)
    if _PACKAGE_VERSION.fullmatch(version) is None:
        raise ProtocolError(f"{path} is outside the package-version protocol")
    return version


def _require_bounded_string(value: Any, maximum: int, path: str) -> str:
    text = _require_string(value, path)
    if not text or len(text) > maximum or "\x00" in text:
        raise ProtocolError(f"{path} must be a non-empty NUL-free bounded string")
    return text


def _require_absolute_synthetic_path(value: str, path: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise ProtocolError(f"{path} must be a bounded synthetic absolute path")
    posix = value.startswith("/")
    drive = bool(re.match(r"[A-Za-z]:[\\/]", value))
    unc = value.startswith("\\\\")
    if not (posix or drive or unc):
        raise ProtocolError(f"{path} must be a synthetic absolute path")


def _require_canonical_root(value: Any, label: str) -> str:
    root = _require_string(value, label)
    _require_absolute_synthetic_path(root, label)
    if root.startswith("/"):
        if "\\" in root or root.endswith("/"):
            raise ProtocolError(f"{label} is not canonical")
        parts = root[1:].split("/")
    elif re.match(r"[A-Za-z]:\\", root) is not None:
        if "/" in root or root.endswith("\\"):
            raise ProtocolError(f"{label} is not canonical")
        parts = root[3:].split("\\")
    else:
        raise ProtocolError(f"{label} must use canonical POSIX or drive syntax")
    if not parts or any(
        part in {".", ".."} or _SOURCE_PATH_SEGMENT.fullmatch(part) is None
        for part in parts
    ):
        raise ProtocolError(f"{label} has an unsafe path segment")
    return root


def _require_source_root(value: Any) -> str:
    return _require_canonical_root(value, "Authority synthetic source root")


def _require_dependency_root(value: Any) -> str:
    return _require_canonical_root(value, "Authority verified dependency root")


def _require_target_root(value: Any) -> str:
    return _require_canonical_root(value, "Authority fresh Cargo target root")


def _roots_overlap(first: str, second: str) -> bool:
    if first.startswith("/") != second.startswith("/"):
        return False
    separator = "/" if first.startswith("/") else "\\"
    if separator == "\\":
        first = first.casefold()
        second = second.casefold()
    return (
        first == second
        or first.startswith(second + separator)
        or second.startswith(first + separator)
    )


def _require_inventory_path(value: Any, label: str) -> str:
    path = _require_bounded_string(value, MAX_INVENTORY_PATH_BYTES, label)
    if len(path.encode("utf-8")) > MAX_INVENTORY_PATH_BYTES:
        raise ProtocolError(f"{label} exceeds its UTF-8 byte bound")
    parts = path.split("/")
    if (
        path.startswith("/")
        or "\\" in path
        or any(
            part in {".", ".."} or _SOURCE_PATH_SEGMENT.fullmatch(part) is None
            for part in parts
        )
    ):
        raise ProtocolError(f"{label} is a non-canonical relative path")
    return path


def _require_source_inventory(values: Sequence[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ProtocolError("Authority source inventory must be a sequence of paths")
    if not values or len(values) > MAX_INVENTORY_ENTRIES:
        raise ProtocolError("Authority source inventory count exceeds bounds")
    inventory: set[str] = set()
    total_bytes = 0
    for index, value in enumerate(values):
        path = _require_inventory_path(value, f"Authority source inventory[{index}]")
        if path in inventory:
            raise ProtocolError("Authority source inventory repeats a path")
        inventory.add(path)
        total_bytes += len(path.encode("utf-8"))
        if total_bytes > MAX_INVENTORY_UTF8_BYTES:
            raise ProtocolError(
                "Authority source inventory exceeds its UTF-8 byte budget"
            )
    if "Cargo.toml" not in inventory:
        raise ProtocolError("Authority source inventory omits workspace Cargo.toml")
    return frozenset(inventory)


def _require_dependency_inventory(
    values: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, Mapping):
        raise ProtocolError(
            "Authority dependency inventory must map paths to SHA-256 digests"
        )
    if not values or len(values) > MAX_INVENTORY_ENTRIES:
        raise ProtocolError("Authority dependency inventory count exceeds bounds")
    inventory: dict[str, str] = {}
    total_bytes = 0
    for index, (raw_path, raw_digest) in enumerate(values.items()):
        path = _require_inventory_path(
            raw_path, f"Authority dependency inventory[{index}].path"
        )
        digest = _require_sha256(
            raw_digest, f"Authority dependency inventory[{index}].sha256"
        )
        if path in inventory:
            raise ProtocolError("Authority dependency inventory repeats a path")
        inventory[path] = digest
        total_bytes += len(path.encode("utf-8")) + len(digest.encode("utf-8"))
        if total_bytes > MAX_INVENTORY_UTF8_BYTES:
            raise ProtocolError(
                "Authority dependency inventory exceeds its UTF-8 byte budget"
            )
    return tuple(sorted(inventory.items()))


def _source_inventory_sha256(inventory: frozenset[str]) -> str:
    return _sha256(canonical_json({"paths": sorted(inventory)}))


def _dependency_inventory_sha256(
    inventory: tuple[tuple[str, str], ...],
) -> str:
    return _sha256(
        canonical_json(
            {"files": [{"path": path, "sha256": digest} for path, digest in inventory]}
        )
    )


def _source_path_separator(root: str) -> str:
    return "/" if root.startswith("/") else "\\"


def _source_absolute_path(root: str, relative: str) -> str:
    separator = _source_path_separator(root)
    return root + separator + relative.replace("/", separator)


def _bound_source_relative_path(
    absolute: str,
    source_root: str,
    source_inventory: frozenset[str],
    label: str,
) -> str:
    _require_absolute_synthetic_path(absolute, label)
    separator = _source_path_separator(source_root)
    prefix = source_root + separator
    if not absolute.startswith(prefix):
        raise ProtocolError(f"{label} escapes the Authority synthetic source root")
    relative = absolute[len(prefix) :].replace(separator, "/")
    if _source_absolute_path(source_root, relative) != absolute:
        raise ProtocolError(f"{label} is not a canonical source path")
    if relative not in source_inventory:
        raise ProtocolError(f"{label} is unbound by the Authority source inventory")
    return relative


def _bound_dependency_relative_path(
    absolute: str,
    dependency_root: str,
    dependency_paths: frozenset[str],
    label: str,
) -> str:
    _require_absolute_synthetic_path(absolute, label)
    separator = _source_path_separator(dependency_root)
    prefix = dependency_root + separator
    if not absolute.startswith(prefix):
        raise ProtocolError(f"{label} escapes the Authority dependency root")
    relative = absolute[len(prefix) :].replace(separator, "/")
    if _source_absolute_path(dependency_root, relative) != absolute:
        raise ProtocolError(f"{label} is not a canonical dependency path")
    if relative not in dependency_paths:
        raise ProtocolError(f"{label} is unbound by the Authority dependency inventory")
    return relative


def _bound_target_relative_path(
    absolute: str,
    target_root: str,
    label: str,
) -> str:
    _require_absolute_synthetic_path(absolute, label)
    separator = _source_path_separator(target_root)
    prefix = target_root + separator
    if not absolute.startswith(prefix):
        raise ProtocolError(f"{label} escapes the Authority Cargo target root")
    relative = absolute[len(prefix) :].replace(separator, "/")
    if _source_absolute_path(target_root, relative) != absolute:
        raise ProtocolError(f"{label} is not a canonical target path")
    return _require_inventory_path(relative, label)


def _workspace_package_id(
    source_root: str, manifest_relative: str, version: str
) -> str:
    package_directory = manifest_relative.removesuffix("/Cargo.toml")
    if manifest_relative == "Cargo.toml":
        package_directory = ""
    elif package_directory == manifest_relative:
        raise ProtocolError("workspace package manifest is not named Cargo.toml")
    uri_root = source_root.replace("\\", "/")
    if source_root.startswith("/"):
        uri = "file://" + uri_root
    else:
        uri = "file:///" + uri_root
    if package_directory:
        uri += "/" + package_directory
    return f"path+{uri}#{version}"


def _policy_contract(policy: Mapping[str, Any]) -> _PolicyContract:
    policy = _require_mapping(policy, "policy")
    _require_exact_keys(
        policy,
        (
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
        ),
        "policy",
    )
    _require_value(policy.get("schema"), POLICY_SCHEMA, "policy.schema")
    source = _require_mapping(policy.get("source"), "policy.source")
    _require_exact_keys(
        source, ("owner", "repository", "ownerId", "repositoryId"), "policy.source"
    )
    for key, expected in (
        ("owner", "jmp0xf"),
        ("repository", "forge"),
        ("ownerId", 2247932),
        ("repositoryId", 1312750430),
    ):
        _require_value(source.get(key), expected, f"policy.source.{key}")

    authority = _require_mapping(policy.get("authority"), "policy.authority")
    _require_exact_keys(
        authority,
        (
            "owner",
            "repository",
            "ownerId",
            "repositoryId",
            "oidcIssuer",
            "oidcSubjectPrefix",
            "environment",
        ),
        "policy.authority",
    )
    for key, expected in (
        ("owner", "jmp0xf"),
        ("repository", "forge-release-authority"),
        ("ownerId", 2247932),
        ("repositoryId", 1317240187),
        ("oidcIssuer", "https://token.actions.githubusercontent.com"),
        (
            "oidcSubjectPrefix",
            "repo:jmp0xf@2247932/forge-release-authority@1317240187",
        ),
        ("environment", "forge-release"),
    ):
        _require_value(authority.get(key), expected, f"policy.authority.{key}")

    release = _require_mapping(policy.get("release"), "policy.release")
    _require_exact_keys(
        release,
        (
            "version",
            "tag",
            "manifestSchema",
            "artifactCount",
            "subjectCount",
            "checksumLineCount",
            "binaryStructureCheckRequired",
            "notice",
            "assets",
        ),
        "policy.release",
    )
    version = _require_package_version(release.get("version"), "policy.release.version")
    _require_value(version, RELEASE_VERSION, "policy.release.version")
    for key, expected in (
        ("tag", f"v{version}"),
        ("manifestSchema", "forge.release-manifest/v2"),
        ("artifactCount", 11),
        ("subjectCount", 13),
        ("checksumLineCount", 12),
        ("binaryStructureCheckRequired", True),
    ):
        _require_value(release.get(key), expected, f"policy.release.{key}")
    notice = _require_mapping(release.get("notice"), "policy.release.notice")
    _require_exact_keys(notice, ("name", "target"), "policy.release.notice")
    _require_value(
        notice.get("name"),
        "THIRD-PARTY-LICENSES.txt",
        "policy.release.notice.name",
    )
    _require_value(notice.get("target"), "all", "policy.release.notice.target")
    project_license = _require_string(
        policy.get("projectLicenseExpression"),
        "policy.projectLicenseExpression",
    )
    _require_value(
        project_license, "MIT OR Apache-2.0", "policy.projectLicenseExpression"
    )
    toolchain = _require_mapping(policy.get("toolchain"), "policy.toolchain")
    _require_exact_keys(toolchain, ("rust",), "policy.toolchain")
    rust_toolchain = _require_bounded_string(
        toolchain.get("rust"), 64, "policy.toolchain.rust"
    )
    _require_value(rust_toolchain, RELEASE_RUST_TOOLCHAIN, "policy.toolchain.rust")

    limits = _require_mapping(policy.get("limits"), "policy.limits")
    limit_fields = (
        "binaryBytes",
        "cargoLockBytes",
        "sbomBytes",
        "noticeBytes",
        "manifestBytes",
        "checksumsBytes",
        "builderRecordBytes",
        "totalAssetBytes",
        "totalBuilderRecordBytes",
    )
    _require_exact_keys(limits, limit_fields, "policy.limits")
    validated_limits: dict[str, int] = {}
    for key in limit_fields:
        value = _require_integer(limits.get(key), f"policy.limits.{key}")
        if not 1 <= value <= 4 * 1024 * 1024 * 1024:
            raise ProtocolError(f"policy.limits.{key} exceeds protocol bounds")
        validated_limits[key] = value
    binary_limit = _require_integer(
        limits.get("binaryBytes"), "policy.limits.binaryBytes"
    )
    cargo_lock_limit = _require_integer(
        limits.get("cargoLockBytes"), "policy.limits.cargoLockBytes"
    )
    if not 1 <= binary_limit <= MAX_PROTOCOL_BINARY_BYTES:
        raise ProtocolError("policy.limits.binaryBytes exceeds protocol bounds")
    if not 1 <= cargo_lock_limit <= MAX_METADATA_BYTES:
        raise ProtocolError("policy.limits.cargoLockBytes exceeds protocol bounds")
    maximum_asset_total = (
        5 * validated_limits["binaryBytes"]
        + 5 * validated_limits["sbomBytes"]
        + 5 * validated_limits["sbomBytes"]
        + validated_limits["noticeBytes"]
        + validated_limits["manifestBytes"]
        + validated_limits["checksumsBytes"]
    )
    if validated_limits["totalAssetBytes"] > maximum_asset_total:
        raise ProtocolError(
            "policy.limits.totalAssetBytes exceeds the sum of per-file limits"
        )
    if (
        validated_limits["totalBuilderRecordBytes"]
        > 5 * validated_limits["builderRecordBytes"]
    ):
        raise ProtocolError(
            "policy.limits.totalBuilderRecordBytes exceeds the five-record limit"
        )

    raw_targets = _require_list(policy.get("targets"), "policy.targets")
    if len(raw_targets) != len(_TARGET_PROFILES):
        raise ProtocolError("policy.targets must contain the five frozen targets")
    targets: dict[str, _TargetContract] = {}
    for index, raw_target in enumerate(raw_targets):
        path = f"policy.targets[{index}]"
        target = _require_mapping(raw_target, path)
        _require_exact_keys(
            target,
            (
                "triple",
                "runnerLabel",
                "binaryFormat",
                "binary",
                "sbom",
                "sbomGraph",
                "builderRecord",
            ),
            path,
        )
        triple = _require_string(target.get("triple"), f"{path}.triple")
        profile = _TARGET_PROFILES.get(triple)
        if profile is None or triple in targets:
            raise ProtocolError(f"{path}.triple is not one unique frozen target")
        runner_label, binary_format = profile
        _require_value(target.get("runnerLabel"), runner_label, f"{path}.runnerLabel")
        _require_value(
            target.get("binaryFormat"), binary_format, f"{path}.binaryFormat"
        )
        suffix = ".exe" if triple == "x86_64-pc-windows-msvc" else ""
        binary = f"forge-{version}-{triple}{suffix}"
        _require_value(target.get("binary"), binary, f"{path}.binary")
        _require_value(target.get("sbom"), f"{binary}.cdx.json", f"{path}.sbom")
        _require_value(
            target.get("builderRecord"),
            f"builder-record-{triple}.json",
            f"{path}.builderRecord",
        )
        graph = _require_mapping(target.get("sbomGraph"), f"{path}.sbomGraph")
        _require_exact_keys(
            graph,
            ("componentCount", "dependencyEdgeCount", "canonicalSha256"),
            f"{path}.sbomGraph",
        )
        components = _require_integer(
            graph.get("componentCount"), f"{path}.sbomGraph.componentCount"
        )
        edges = _require_integer(
            graph.get("dependencyEdgeCount"),
            f"{path}.sbomGraph.dependencyEdgeCount",
        )
        canonical_sha256 = _require_sha256(
            graph.get("canonicalSha256"), f"{path}.sbomGraph.canonicalSha256"
        )
        if not 1 <= components <= MAX_GRAPH_PACKAGES:
            raise ProtocolError(f"{path}.sbomGraph.componentCount exceeds bounds")
        if not 1 <= edges <= MAX_GRAPH_EDGES:
            raise ProtocolError(f"{path}.sbomGraph.dependencyEdgeCount exceeds bounds")
        targets[triple] = _TargetContract(
            runner_label=runner_label,
            binary_format=binary_format,
            binary=binary,
            sbom=f"{binary}.cdx.json",
            sbom_graph=_SbomGraphContract(
                component_count=components,
                dependency_edge_count=edges,
                canonical_sha256=canonical_sha256,
            ),
        )
    if set(targets) != set(_TARGET_PROFILES):
        raise ProtocolError("policy.targets differs from the frozen target set")

    raw_assets = _require_list(release.get("assets"), "policy.release.assets")
    assets = [
        _require_bounded_string(value, 255, f"policy.release.assets[{index}]")
        for index, value in enumerate(raw_assets)
    ]
    expected_assets = sorted(
        [contract.binary for contract in targets.values()]
        + [contract.sbom for contract in targets.values()]
        + [
            "SHA256SUMS",
            "THIRD-PARTY-LICENSES.txt",
            "release-manifest.json",
        ]
    )
    if assets != expected_assets or len(set(assets)) != len(assets):
        raise ProtocolError("policy.release.assets differs from the exact asset set")

    builder_records = _require_mapping(
        policy.get("builderRecords"), "policy.builderRecords"
    )
    _require_exact_keys(builder_records, ("schema", "count"), "policy.builderRecords")
    _require_value(
        builder_records.get("schema"),
        "forge.release-authority-builder-record/v1",
        "policy.builderRecords.schema",
    )
    _require_value(builder_records.get("count"), 5, "policy.builderRecords.count")

    provenance = _require_mapping(policy.get("provenance"), "policy.provenance")
    _require_exact_keys(
        provenance,
        ("predicateType", "buildType", "builderId"),
        "policy.provenance",
    )
    for key, expected in (
        ("predicateType", "https://slsa.dev/provenance/v1"),
        (
            "buildType",
            "https://github.com/jmp0xf/forge-release-authority/blob/main/"
            "docs/build-types/qualify-v1.md",
        ),
        (
            "builderId",
            "https://github.com/jmp0xf/forge-release-authority/blob/main/"
            "docs/builders/github-actions-protected-v1.md",
        ),
    ):
        _require_value(provenance.get(key), expected, f"policy.provenance.{key}")
    return _PolicyContract(
        version=version,
        rust_toolchain=rust_toolchain,
        binary_limit=binary_limit,
        cargo_lock_limit=cargo_lock_limit,
        project_license_expression=project_license,
        targets=targets,
    )


def _object_id(value: str, path: str) -> tuple[str, str]:
    if _SHA1.fullmatch(value) is not None:
        return "sha1", value
    if _SHA256.fullmatch(value) is not None:
        return "sha256", value
    raise ProtocolError(f"{path} must be one full lowercase Git object ID")


def _execution_context_value(execution: AuthorityExecutionSpec) -> Mapping[str, Any]:
    return {
        "target": execution.target,
        "runner_label": execution.runner_label,
        "binary_format": execution.binary_format,
        "rust_toolchain": execution.rust_toolchain,
        "source_root": execution.source_root,
        "source_inventory_sha256": execution.source_inventory_sha256,
        "dependency_root": execution.dependency_root,
        "dependency_inventory_sha256": execution.dependency_inventory_sha256,
        "target_root": execution.target_root,
        "package": execution.package,
        "binary": execution.binary,
        "profile": execution.profile,
        "dependency_resolution": execution.dependency_resolution,
        "network": execution.network,
        "features": list(execution.features),
        "environment_overrides": [
            {"name": name, "value": value}
            for name, value in execution.environment_overrides
        ],
    }


def _accepted_plan_context_sha256(plan: AcceptedReleaseBuildPlan) -> str:
    context = {
        "schema": "forge.release-authority-acceptance-context/v1",
        "plan": {
            "canonical_utf8": plan.canonical_bytes.decode("utf-8"),
            "sha256": plan.plan_sha256,
        },
        "source_commit": plan.source_commit,
        "cargo_lock_sha256": plan.cargo_lock_sha256,
        "policy": {
            "version": plan.version,
            "binary_name": plan.binary_name,
            "sbom_name": plan.sbom_name,
            "binary_limit": plan.binary_limit,
            "cargo_lock_limit": plan.cargo_lock_limit,
            "project_license_expression": plan.project_license_expression,
            "sbom_graph": {
                "component_count": plan.sbom_graph.component_count,
                "dependency_edge_count": plan.sbom_graph.dependency_edge_count,
                "canonical_sha256": plan.sbom_graph.canonical_sha256,
            },
        },
        "roots": {
            "source": plan.source_root,
            "dependency": plan.dependency_root,
            "target": plan.target_root,
        },
        "inventories": {
            "source_sha256": plan.source_inventory_sha256,
            "dependency_sha256": plan.dependency_inventory_sha256,
        },
        "execution": _execution_context_value(plan.execution),
    }
    return _sha256(canonical_json(context))


def _validate_accepted_plan(plan: AcceptedReleaseBuildPlan) -> None:
    if type(plan) is not AcceptedReleaseBuildPlan:
        raise ProtocolError("plan must be an exact accepted release-build plan")

    document = _require_mapping(
        _load_json_bytes(
            plan.canonical_bytes,
            MAX_PLAN_BYTES,
            "accepted release-build plan canonical bytes",
        ),
        "accepted release-build plan",
    )
    _require_ordered_keys(document, _PLAN_FIELDS, "accepted release-build plan")
    source = _require_mapping(
        document["source_commit"], "accepted release-build plan.source_commit"
    )
    _require_ordered_keys(
        source,
        ("object_format", "oid"),
        "accepted release-build plan.source_commit",
    )
    package = _require_mapping(
        document["package"], "accepted release-build plan.package"
    )
    _require_ordered_keys(
        package, ("name", "version"), "accepted release-build plan.package"
    )
    outputs = _require_mapping(
        document["outputs"], "accepted release-build plan.outputs"
    )
    _require_ordered_keys(
        outputs, ("binary", "sbom"), "accepted release-build plan.outputs"
    )
    if canonical_json(document) != plan.canonical_bytes:
        raise ProtocolError("accepted release-build plan bytes are not canonical")
    _require_value(
        _require_sha256(plan.plan_sha256, "accepted plan SHA-256"),
        _sha256(plan.canonical_bytes),
        "accepted plan SHA-256",
    )
    _require_value(document["schema"], PLAN_SCHEMA, "accepted plan.schema")
    _require_value(document["purpose"], PLAN_PURPOSE, "accepted plan.purpose")
    source_commit = _require_string(plan.source_commit, "accepted plan source commit")
    source_format, source_commit = _object_id(
        source_commit, "accepted plan source commit"
    )
    _require_value(
        source["object_format"], source_format, "accepted plan source object format"
    )
    _require_value(source["oid"], source_commit, "accepted plan source commit")
    cargo_lock_sha256 = _require_sha256(
        plan.cargo_lock_sha256, "accepted Cargo.lock SHA-256"
    )
    _require_value(
        _require_sha256(
            document["cargo_lock_sha256"], "accepted plan.cargo_lock_sha256"
        ),
        cargo_lock_sha256,
        "accepted plan.cargo_lock_sha256",
    )
    target = _require_string(document["target"], "accepted plan.target")
    profile = _TARGET_PROFILES.get(target)
    if profile is None:
        raise ProtocolError("accepted plan target is not frozen")
    version = _require_package_version(plan.version, "accepted policy version")
    _require_value(version, RELEASE_VERSION, "accepted policy version")
    _require_value(package["name"], RELEASE_PACKAGE, "accepted plan.package.name")
    _require_value(package["version"], version, "accepted plan.package.version")
    for field, expected in (
        ("binary", RELEASE_BINARY),
        ("profile", "release"),
        ("dependency_resolution", "locked"),
        ("network", "offline"),
    ):
        _require_value(document[field], expected, f"accepted plan.{field}")
    suffix = ".exe" if target == "x86_64-pc-windows-msvc" else ""
    binary_name = f"forge-{version}-{target}{suffix}"
    sbom_name = f"{binary_name}.cdx.json"
    _require_value(
        _require_bounded_string(plan.binary_name, 255, "accepted binary name"),
        binary_name,
        "accepted binary name",
    )
    _require_value(
        _require_bounded_string(plan.sbom_name, 255, "accepted SBOM name"),
        sbom_name,
        "accepted SBOM name",
    )
    _require_value(outputs["binary"], binary_name, "accepted plan.outputs.binary")
    _require_value(outputs["sbom"], sbom_name, "accepted plan.outputs.sbom")

    binary_limit = _require_integer(plan.binary_limit, "accepted binary limit")
    cargo_lock_limit = _require_integer(
        plan.cargo_lock_limit, "accepted Cargo.lock limit"
    )
    if not 1 <= binary_limit <= MAX_PROTOCOL_BINARY_BYTES:
        raise ProtocolError("accepted binary limit exceeds protocol bounds")
    if not 1 <= cargo_lock_limit <= MAX_METADATA_BYTES:
        raise ProtocolError("accepted Cargo.lock limit exceeds protocol bounds")
    _require_value(
        _require_string(
            plan.project_license_expression,
            "accepted project license expression",
        ),
        "MIT OR Apache-2.0",
        "accepted project license expression",
    )
    if type(plan.sbom_graph) is not _SbomGraphContract:
        raise ProtocolError("accepted SBOM graph must have its exact contract type")
    component_count = _require_integer(
        plan.sbom_graph.component_count, "accepted SBOM component count"
    )
    edge_count = _require_integer(
        plan.sbom_graph.dependency_edge_count,
        "accepted SBOM dependency edge count",
    )
    if not 1 <= component_count <= MAX_GRAPH_PACKAGES:
        raise ProtocolError("accepted SBOM component count exceeds bounds")
    if not 1 <= edge_count <= MAX_GRAPH_EDGES:
        raise ProtocolError("accepted SBOM dependency edge count exceeds bounds")
    _require_sha256(
        plan.sbom_graph.canonical_sha256,
        "accepted SBOM graph canonical SHA-256",
    )

    source_root = _require_source_root(plan.source_root)
    dependency_root = _require_dependency_root(plan.dependency_root)
    target_root = _require_target_root(plan.target_root)
    if type(plan.source_inventory) is not frozenset:
        raise ProtocolError("accepted source inventory must be an exact frozenset")
    normalized_source_inventory = _require_source_inventory(
        tuple(plan.source_inventory)
    )
    _require_value(
        plan.source_inventory,
        normalized_source_inventory,
        "accepted source inventory",
    )
    source_inventory_sha256 = _source_inventory_sha256(normalized_source_inventory)
    _require_value(
        _require_sha256(
            plan.source_inventory_sha256,
            "accepted source inventory SHA-256",
        ),
        source_inventory_sha256,
        "accepted source inventory SHA-256",
    )
    if type(plan.dependency_inventory) is not tuple:
        raise ProtocolError("accepted dependency inventory must be an exact tuple")
    dependency_mapping: dict[str, str] = {}
    for index, entry in enumerate(plan.dependency_inventory):
        if type(entry) is not tuple or len(entry) != 2:
            raise ProtocolError(
                f"accepted dependency inventory[{index}] must be a path-digest tuple"
            )
        path = _require_inventory_path(
            entry[0], f"accepted dependency inventory[{index}].path"
        )
        digest = _require_sha256(
            entry[1], f"accepted dependency inventory[{index}].sha256"
        )
        if path in dependency_mapping:
            raise ProtocolError("accepted dependency inventory repeats a path")
        dependency_mapping[path] = digest
    normalized_dependency_inventory = _require_dependency_inventory(dependency_mapping)
    _require_value(
        plan.dependency_inventory,
        normalized_dependency_inventory,
        "accepted dependency inventory",
    )
    dependency_inventory_sha256 = _dependency_inventory_sha256(
        normalized_dependency_inventory
    )
    _require_value(
        _require_sha256(
            plan.dependency_inventory_sha256,
            "accepted dependency inventory SHA-256",
        ),
        dependency_inventory_sha256,
        "accepted dependency inventory SHA-256",
    )
    roots = (
        ("source", source_root),
        ("dependency", dependency_root),
        ("target", target_root),
    )
    for index, (first_label, first_root) in enumerate(roots):
        for second_label, second_root in roots[index + 1 :]:
            if _roots_overlap(first_root, second_root):
                raise ProtocolError(
                    f"accepted {first_label} and {second_label} roots overlap"
                )

    if type(plan.execution) is not AuthorityExecutionSpec:
        raise ProtocolError("accepted execution must have its exact contract type")
    runner_label, binary_format = profile
    expected_execution = AuthorityExecutionSpec(
        target=target,
        runner_label=runner_label,
        binary_format=binary_format,
        rust_toolchain=RELEASE_RUST_TOOLCHAIN,
        source_root=source_root,
        source_inventory_sha256=source_inventory_sha256,
        dependency_root=dependency_root,
        dependency_inventory_sha256=dependency_inventory_sha256,
        target_root=target_root,
        environment_overrides=(("CARGO_TARGET_DIR", target_root),),
    )
    _require_value(
        plan.execution, expected_execution, "accepted Authority execution spec"
    )
    _require_value(
        _require_sha256(
            plan.authority_context_sha256,
            "accepted Authority context SHA-256",
        ),
        _accepted_plan_context_sha256(plan),
        "accepted Authority context SHA-256",
    )


def accept_release_build_plan(
    plan_bytes: bytes,
    policy: Mapping[str, Any],
    expected_source_commit: str,
    cargo_lock_bytes: bytes,
    expected_rust_toolchain: str,
    expected_source_root: str,
    source_inventory: Sequence[str],
    expected_dependency_root: str,
    dependency_inventory: Mapping[str, str],
    expected_target_root: str,
) -> AcceptedReleaseBuildPlan:
    """Accept one canonical request against independently bound Authority inputs."""
    contract = _policy_contract(policy)
    expected_rust_toolchain = _require_bounded_string(
        expected_rust_toolchain, 64, "Authority expected Rust toolchain"
    )
    _require_value(
        expected_rust_toolchain,
        contract.rust_toolchain,
        "Authority expected Rust toolchain",
    )
    expected_source_root = _require_source_root(expected_source_root)
    bound_source_inventory = _require_source_inventory(source_inventory)
    source_inventory_sha256 = _source_inventory_sha256(bound_source_inventory)
    expected_dependency_root = _require_dependency_root(expected_dependency_root)
    bound_dependency_inventory = _require_dependency_inventory(dependency_inventory)
    dependency_inventory_sha256 = _dependency_inventory_sha256(
        bound_dependency_inventory
    )
    expected_target_root = _require_target_root(expected_target_root)
    roots = (
        ("source", expected_source_root),
        ("dependency", expected_dependency_root),
        ("target", expected_target_root),
    )
    for index, (first_label, first_root) in enumerate(roots):
        for second_label, second_root in roots[index + 1 :]:
            if _roots_overlap(first_root, second_root):
                raise ProtocolError(
                    f"Authority {first_label} and {second_label} roots overlap"
                )
    source_format, expected_source_commit = _object_id(
        expected_source_commit, "expected source commit"
    )
    _parse_cargo_lock(cargo_lock_bytes, contract.cargo_lock_limit)
    cargo_lock_sha256 = _sha256(cargo_lock_bytes)

    document = _require_mapping(
        _load_json_bytes(plan_bytes, MAX_PLAN_BYTES, "release-build plan"),
        "release-build plan",
    )
    _require_ordered_keys(document, _PLAN_FIELDS, "release-build plan")
    source = _require_mapping(
        document["source_commit"], "release-build plan.source_commit"
    )
    _require_ordered_keys(
        source, ("object_format", "oid"), "release-build plan.source_commit"
    )
    package = _require_mapping(document["package"], "release-build plan.package")
    _require_ordered_keys(package, ("name", "version"), "release-build plan.package")
    outputs = _require_mapping(document["outputs"], "release-build plan.outputs")
    _require_ordered_keys(outputs, ("binary", "sbom"), "release-build plan.outputs")
    if canonical_json(document) != plan_bytes:
        raise ProtocolError(
            "release-build plan is not canonical pretty JSON with one LF terminator"
        )

    _require_value(document["schema"], PLAN_SCHEMA, "release-build plan.schema")
    _require_value(document["purpose"], PLAN_PURPOSE, "release-build plan.purpose")
    _require_value(
        source["object_format"],
        source_format,
        "release-build plan.source_commit.object_format",
    )
    _require_value(
        source["oid"], expected_source_commit, "release-build plan.source_commit.oid"
    )
    _require_value(
        _require_sha256(
            document["cargo_lock_sha256"], "release-build plan.cargo_lock_sha256"
        ),
        cargo_lock_sha256,
        "release-build plan.cargo_lock_sha256",
    )
    target = _require_string(document["target"], "release-build plan.target")
    target_policy = contract.targets.get(target)
    if target_policy is None:
        raise ProtocolError("release-build plan.target is not a frozen policy target")
    _require_value(
        _require_package_name(package["name"], "release-build plan.package.name"),
        RELEASE_PACKAGE,
        "release-build plan.package.name",
    )
    _require_value(
        _require_package_version(
            package["version"], "release-build plan.package.version"
        ),
        contract.version,
        "release-build plan.package.version",
    )
    for field, expected in (
        ("binary", RELEASE_BINARY),
        ("profile", "release"),
        ("dependency_resolution", "locked"),
        ("network", "offline"),
    ):
        _require_value(document[field], expected, f"release-build plan.{field}")
    _require_value(
        outputs["binary"],
        target_policy.binary,
        "release-build plan.outputs.binary",
    )
    _require_value(
        outputs["sbom"], target_policy.sbom, "release-build plan.outputs.sbom"
    )
    runner_label, binary_format = _TARGET_PROFILES[target]
    execution = AuthorityExecutionSpec(
        target=target,
        runner_label=runner_label,
        binary_format=binary_format,
        rust_toolchain=expected_rust_toolchain,
        source_root=expected_source_root,
        source_inventory_sha256=source_inventory_sha256,
        dependency_root=expected_dependency_root,
        dependency_inventory_sha256=dependency_inventory_sha256,
        target_root=expected_target_root,
        environment_overrides=(("CARGO_TARGET_DIR", expected_target_root),),
    )
    accepted = AcceptedReleaseBuildPlan(
        canonical_bytes=plan_bytes,
        plan_sha256=_sha256(plan_bytes),
        source_commit=expected_source_commit,
        cargo_lock_sha256=cargo_lock_sha256,
        version=contract.version,
        binary_name=target_policy.binary,
        sbom_name=target_policy.sbom,
        binary_limit=contract.binary_limit,
        cargo_lock_limit=contract.cargo_lock_limit,
        project_license_expression=contract.project_license_expression,
        source_root=expected_source_root,
        source_inventory=bound_source_inventory,
        source_inventory_sha256=source_inventory_sha256,
        dependency_root=expected_dependency_root,
        dependency_inventory=bound_dependency_inventory,
        dependency_inventory_sha256=dependency_inventory_sha256,
        target_root=expected_target_root,
        authority_context_sha256="0" * 64,
        sbom_graph=target_policy.sbom_graph,
        execution=execution,
    )
    accepted = replace(
        accepted,
        authority_context_sha256=_accepted_plan_context_sha256(accepted),
    )
    _validate_accepted_plan(accepted)
    return accepted


def _parse_cargo_lock(
    data: bytes, maximum: int
) -> Mapping[tuple[str, str, str | None], str | None]:
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise ProtocolError(f"Cargo.lock must contain 1..={maximum} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("Cargo.lock is not UTF-8") from error
    if "\x00" in text or "\r" in text or not text.endswith("\n"):
        raise ProtocolError("Cargo.lock is not canonical LF-terminated text")
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ProtocolError("Cargo.lock is not valid bounded TOML") from error
    if set(document) != {"version", "package"} or document.get("version") != 4:
        raise ProtocolError("Cargo.lock must contain only format-4 package data")
    packages = _require_list(document["package"], "Cargo.lock.package")
    if not packages or len(packages) > MAX_METADATA_PACKAGES:
        raise ProtocolError("Cargo.lock package count exceeds bounds")
    result: dict[tuple[str, str, str | None], str | None] = {}
    for index, raw_package in enumerate(packages):
        path = f"Cargo.lock.package[{index}]"
        package = _require_mapping(raw_package, path)
        required = {"name", "version"}
        allowed = required | {"source", "checksum", "dependencies"}
        if not required.issubset(package) or not set(package).issubset(allowed):
            raise ProtocolError(f"{path} has unknown or missing fields")
        name = _require_package_name(package["name"], f"{path}.name")
        version = _require_package_version(package["version"], f"{path}.version")
        source = None
        if "source" in package:
            source = _require_bounded_string(package["source"], 2048, f"{path}.source")
        checksum = None
        if "checksum" in package:
            checksum = _require_sha256(package["checksum"], f"{path}.checksum")
        if (source is None) != (checksum is None):
            raise ProtocolError(f"{path} must bind source and checksum together")
        if "dependencies" in package:
            dependencies = _require_list(
                package["dependencies"], f"{path}.dependencies"
            )
            if len(dependencies) > MAX_METADATA_PACKAGES or any(
                not isinstance(dependency, str) for dependency in dependencies
            ):
                raise ProtocolError(
                    f"{path}.dependencies exceeds its string-list bound"
                )
        identity = (name, version, source)
        if identity in result:
            raise ProtocolError("Cargo.lock repeats a package identity")
        result[identity] = checksum
    return result


def _metadata_string_tuple(value: Any, path: str) -> tuple[str, ...]:
    values = _require_list(value, path)
    if not values or len(values) > 64:
        raise ProtocolError(f"{path} count exceeds bounds")
    result: list[str] = []
    for index, raw in enumerate(values):
        item = _require_bounded_string(raw, 128, f"{path}[{index}]")
        if item in result:
            raise ProtocolError(f"{path} repeats a value")
        result.append(item)
    return tuple(result)


def _parse_metadata(data: bytes, plan: AcceptedReleaseBuildPlan) -> _CargoMetadata:
    document = _require_mapping(
        _load_json_bytes(data, MAX_METADATA_BYTES, "Cargo metadata"),
        "Cargo metadata",
    )
    _require_value(document.get("version"), 1, "Cargo metadata.version")
    workspace_root = _require_bounded_string(
        document.get("workspace_root"), 4096, "Cargo metadata.workspace_root"
    )
    _require_value(workspace_root, plan.source_root, "Cargo metadata.workspace_root")
    target_directory = _require_bounded_string(
        document.get("target_directory"),
        4096,
        "Cargo metadata.target_directory",
    )
    _require_value(
        target_directory,
        plan.target_root,
        "Cargo metadata.target_directory",
    )
    raw_packages = _require_list(document.get("packages"), "Cargo metadata.packages")
    if not raw_packages or len(raw_packages) > MAX_METADATA_PACKAGES:
        raise ProtocolError("Cargo metadata package count exceeds bounds")
    packages_by_id: dict[str, _CargoPackage] = {}
    identities: dict[tuple[str, str], list[_CargoPackage]] = {}
    for index, raw_package in enumerate(raw_packages):
        path = f"Cargo metadata.packages[{index}]"
        package = _require_mapping(raw_package, path)
        for field in ("id", "name", "version", "license", "source"):
            if field not in package:
                raise ProtocolError(f"{path} omits required field {field!r}")
        package_id = _require_bounded_string(package["id"], 4096, f"{path}.id")
        name = _require_bounded_string(package["name"], 512, f"{path}.name")
        version = _require_bounded_string(package["version"], 512, f"{path}.version")
        raw_license = package["license"]
        if raw_license is not None and not isinstance(raw_license, str):
            raise ProtocolError(f"{path}.license must be a string or null")
        if isinstance(raw_license, str) and (
            not raw_license or len(raw_license) > 1024 or "\x00" in raw_license
        ):
            raise ProtocolError(f"{path}.license exceeds bounds")
        raw_source = package["source"]
        if raw_source is not None and not isinstance(raw_source, str):
            raise ProtocolError(f"{path}.source must be a string or null")
        if isinstance(raw_source, str) and (
            not raw_source or len(raw_source) > 2048 or "\x00" in raw_source
        ):
            raise ProtocolError(f"{path}.source exceeds bounds")
        raw_manifest = package.get("manifest_path")
        if raw_manifest is not None and not isinstance(raw_manifest, str):
            raise ProtocolError(f"{path}.manifest_path must be a string or null")
        if isinstance(raw_manifest, str) and (
            not raw_manifest or len(raw_manifest) > 4096 or "\x00" in raw_manifest
        ):
            raise ProtocolError(f"{path}.manifest_path exceeds bounds")
        raw_targets = _require_list(package.get("targets"), f"{path}.targets")
        if not raw_targets or len(raw_targets) > 512:
            raise ProtocolError(f"{path}.targets count exceeds bounds")
        targets: list[_CargoTarget] = []
        target_identities: set[tuple[str, tuple[str, ...], tuple[str, ...], str]] = (
            set()
        )
        for target_index, raw_target in enumerate(raw_targets):
            target_path = f"{path}.targets[{target_index}]"
            target = _require_mapping(raw_target, target_path)
            target_name = _require_bounded_string(
                target.get("name"), 128, f"{target_path}.name"
            )
            kinds = _metadata_string_tuple(target.get("kind"), f"{target_path}.kind")
            crate_types = _metadata_string_tuple(
                target.get("crate_types"), f"{target_path}.crate_types"
            )
            src_path = _require_bounded_string(
                target.get("src_path"), 4096, f"{target_path}.src_path"
            )
            identity = (target_name, kinds, crate_types, src_path)
            if identity in target_identities:
                raise ProtocolError(f"{path}.targets repeats a target identity")
            target_identities.add(identity)
            targets.append(
                _CargoTarget(
                    name=target_name,
                    kinds=kinds,
                    crate_types=crate_types,
                    src_path=src_path,
                )
            )
        parsed = _CargoPackage(
            package_id=package_id,
            name=name,
            version=version,
            license_expression=raw_license,
            source=raw_source,
            manifest_path=raw_manifest,
            targets=tuple(targets),
        )
        if package_id in packages_by_id:
            raise ProtocolError("Cargo metadata repeats a package ID")
        packages_by_id[package_id] = parsed
        identities.setdefault((name, version), []).append(parsed)

    workspace_raw = _require_list(
        document.get("workspace_members"), "Cargo metadata.workspace_members"
    )
    if not workspace_raw or len(workspace_raw) > MAX_METADATA_PACKAGES:
        raise ProtocolError("Cargo metadata workspace-member count exceeds bounds")
    workspace_members: set[str] = set()
    for index, raw_member in enumerate(workspace_raw):
        member = _require_bounded_string(
            raw_member, 4096, f"Cargo metadata.workspace_members[{index}]"
        )
        if member in workspace_members or member not in packages_by_id:
            raise ProtocolError("Cargo metadata has an invalid workspace member")
        workspace_members.add(member)
    dependency_paths = frozenset(path for path, _digest in plan.dependency_inventory)
    dependency_package_directories: set[str] = set()
    for parsed_package in packages_by_id.values():
        if parsed_package.source is not None:
            if parsed_package.package_id in workspace_members:
                raise ProtocolError("Cargo metadata names a sourced workspace member")
            if parsed_package.source != CRATES_IO_SOURCE:
                raise ProtocolError(
                    "Cargo metadata package source is outside protocol v1"
                )
            if parsed_package.manifest_path is None:
                raise ProtocolError(
                    "Cargo metadata crates.io package omits manifest_path"
                )
            manifest_relative = _bound_dependency_relative_path(
                parsed_package.manifest_path,
                plan.dependency_root,
                dependency_paths,
                "Cargo metadata crates.io manifest_path",
            )
            if not manifest_relative.endswith("/Cargo.toml"):
                raise ProtocolError(
                    "Cargo metadata crates.io manifest is not named Cargo.toml"
                )
            package_directory = manifest_relative.removesuffix("/Cargo.toml")
            package_name = _require_package_name(
                parsed_package.name, "Cargo metadata crates.io package name"
            )
            package_version = _require_package_version(
                parsed_package.version, "Cargo metadata crates.io package version"
            )
            if package_directory.rsplit("/", 1)[-1] != (
                f"{package_name}-{package_version}"
            ):
                raise ProtocolError(
                    "Cargo metadata crates.io manifest directory differs from "
                    "its package identity"
                )
            if package_directory in dependency_package_directories:
                raise ProtocolError(
                    "Cargo metadata repeats a crates.io package directory"
                )
            dependency_package_directories.add(package_directory)
            _require_value(
                parsed_package.package_id,
                f"{CRATES_IO_SOURCE}#{package_name}@{package_version}",
                "Cargo metadata crates.io package ID",
            )
            for parsed_target in parsed_package.targets:
                target_relative = _bound_dependency_relative_path(
                    parsed_target.src_path,
                    plan.dependency_root,
                    dependency_paths,
                    "Cargo metadata crates.io target src_path",
                )
                if not target_relative.startswith(package_directory + "/"):
                    raise ProtocolError(
                        "Cargo metadata crates.io target escapes its package directory"
                    )
            continue
        if parsed_package.package_id not in workspace_members:
            raise ProtocolError(
                "Cargo metadata has a local package outside the workspace"
            )
        if parsed_package.manifest_path is None:
            raise ProtocolError("Cargo metadata workspace package omits manifest_path")
        manifest_relative = _bound_source_relative_path(
            parsed_package.manifest_path,
            plan.source_root,
            plan.source_inventory,
            "Cargo metadata workspace manifest_path",
        )
        expected_id = _workspace_package_id(
            plan.source_root,
            manifest_relative,
            _require_package_version(
                parsed_package.version, "Cargo metadata workspace version"
            ),
        )
        _require_value(
            parsed_package.package_id,
            expected_id,
            "Cargo metadata workspace package ID",
        )
        for parsed_target in parsed_package.targets:
            _bound_source_relative_path(
                parsed_target.src_path,
                plan.source_root,
                plan.source_inventory,
                "Cargo metadata workspace target src_path",
            )
    return _CargoMetadata(
        packages_by_id=packages_by_id,
        packages_by_name_version={
            identity: tuple(packages) for identity, packages in identities.items()
        },
        workspace_members=frozenset(workspace_members),
        workspace_root=workspace_root,
    )


def _lexical_parent(path: str) -> str | None:
    index = max(path.rfind("/"), path.rfind("\\"))
    if index < 0:
        return None
    if index == 0:
        return path[:1]
    return path[:index]


def _parse_tree(
    metadata: _CargoMetadata, data: bytes, plan: AcceptedReleaseBuildPlan
) -> _SelectedGraph:
    if not isinstance(data, bytes) or not data or len(data) > MAX_TREE_BYTES:
        raise ProtocolError(f"Cargo tree must contain 1..={MAX_TREE_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("Cargo tree is not UTF-8") from error
    if (
        "\x00" in text
        or "\r" in text
        or not text.endswith("\n")
        or text.endswith("\n\n")
    ):
        raise ProtocolError("Cargo tree is not canonical single-LF-terminated text")
    stack: list[str] = []
    selected: set[str] = set()
    edges: dict[str, set[str]] = {}
    root_id: str | None = None
    lines = text.splitlines()
    if len(lines) > MAX_TREE_LINES:
        raise ProtocolError("Cargo tree line count exceeds bounds")
    for index, line in enumerate(lines):
        marker = line.find("@@")
        if marker <= 0:
            raise ProtocolError("Cargo tree line lacks its package sentinel")
        depth_text = line[:marker]
        if (
            not depth_text.isascii()
            or not depth_text.isdigit()
            or (len(depth_text) > 1 and depth_text.startswith("0"))
        ):
            raise ProtocolError("Cargo tree line has a non-canonical depth")
        depth = int(depth_text, 10)
        if depth > MAX_GRAPH_PACKAGES or depth > len(stack):
            raise ProtocolError("Cargo tree has a depth discontinuity")
        framed = line[marker:]
        if (
            not framed.startswith("@@")
            or not framed.endswith("@@")
            or "@@" in framed[2:-2]
        ):
            raise ProtocolError("Cargo tree has malformed package sentinels")
        display = framed[2:-2]
        if not display.isascii():
            raise ProtocolError("Cargo tree package display is not synthetic ASCII")
        words = display.split()
        if len(words) < 2 or " ".join(words) != display:
            raise ProtocolError("Cargo tree package display is not canonical")
        name = words[0]
        version = words[1][1:] if words[1].startswith("v") else ""
        if not name or not version:
            raise ProtocolError("Cargo tree package identity is incomplete")
        candidates = metadata.packages_by_name_version.get((name, version), ())
        if len(candidates) != 1:
            raise ProtocolError(
                "Cargo tree package identity is absent or ambiguous in metadata"
            )
        package = candidates[0]
        suffix = " ".join(words[2:])
        suffix_valid = suffix in ("", "(proc-macro)")
        if not suffix_valid and package.source is None:
            displayed_parent = (
                suffix[1:-1]
                if suffix.startswith("(") and suffix.endswith(")")
                else None
            )
            suffix_valid = (
                displayed_parent is not None
                and package.manifest_path is not None
                and displayed_parent == _lexical_parent(package.manifest_path)
            )
        if not suffix_valid:
            raise ProtocolError("Cargo tree package display suffix is unsupported")
        if (
            package.source is None
            and package.package_id not in metadata.workspace_members
        ):
            raise ProtocolError(
                "Cargo tree selected a local package outside the workspace"
            )
        if index == 0:
            if (
                depth != 0
                or package.name != RELEASE_PACKAGE
                or package.version != plan.version
                or package.source is not None
            ):
                raise ProtocolError("Cargo tree does not start at the accepted root")
            root_id = package.package_id
        elif depth == 0:
            raise ProtocolError("Cargo tree contains more than one root")
        stack[depth:] = []
        if stack:
            parent = stack[-1]
            if parent == package.package_id:
                raise ProtocolError("Cargo tree contains a self dependency")
            edges.setdefault(parent, set()).add(package.package_id)
        selected.add(package.package_id)
        edges.setdefault(package.package_id, set())
        stack.append(package.package_id)
    if root_id is None:
        raise ProtocolError("Cargo tree is empty")
    return _SelectedGraph(
        root_id=root_id,
        package_ids=frozenset(selected),
        edges={
            package: frozenset(dependencies) for package, dependencies in edges.items()
        },
    )


def _parse_artifact_target(value: Any, path: str) -> _CargoTarget:
    target = _require_mapping(value, path)
    return _CargoTarget(
        name=_require_bounded_string(target.get("name"), 128, f"{path}.name"),
        kinds=_metadata_string_tuple(target.get("kind"), f"{path}.kind"),
        crate_types=_metadata_string_tuple(
            target.get("crate_types"), f"{path}.crate_types"
        ),
        src_path=_require_bounded_string(
            target.get("src_path"), 4096, f"{path}.src_path"
        ),
    )


def _parse_build_artifacts(
    data: bytes,
    metadata: _CargoMetadata,
    selection: _SelectedGraph,
    plan: AcceptedReleaseBuildPlan,
) -> tuple[str, str]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_BUILD_MESSAGES_BYTES:
        raise ProtocolError(
            f"Cargo build messages must contain 1..={MAX_BUILD_MESSAGES_BYTES} bytes"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("Cargo build messages are not UTF-8") from error
    if (
        "\x00" in text
        or "\r" in text
        or not text.endswith("\n")
        or text.endswith("\n\n")
    ):
        raise ProtocolError(
            "Cargo build messages are not canonical single-LF-terminated JSON lines"
        )
    lines = text.splitlines()
    if len(lines) > MAX_BUILD_MESSAGES:
        raise ProtocolError("Cargo build message count exceeds bounds")

    observed_packages: set[str] = set()
    artifact_fingerprints: set[bytes] = set()
    artifact_targets: set[tuple[str, _CargoTarget]] = set()
    artifact_paths: set[str] = set()
    root_artifact: tuple[str, str] | None = None
    build_finished = False
    for index, line in enumerate(lines):
        path = f"Cargo build messages[{index}]"
        if build_finished:
            raise ProtocolError("Cargo build emitted a message after build-finished")
        message = _require_mapping(
            _load_json_bytes(line.encode("utf-8"), len(line.encode("utf-8")), path),
            path,
        )
        reason = _require_bounded_string(message.get("reason"), 64, f"{path}.reason")
        if reason == "compiler-artifact":
            fingerprint = json.dumps(
                message,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            if fingerprint in artifact_fingerprints:
                raise ProtocolError("Cargo build repeats a compiler-artifact message")
            artifact_fingerprints.add(fingerprint)
            package_id = _require_bounded_string(
                message.get("package_id"), 4096, f"{path}.package_id"
            )
            package = metadata.packages_by_id.get(package_id)
            if package is None or package_id not in selection.package_ids:
                raise ProtocolError(
                    "Cargo compiler-artifact package is outside the selected graph"
                )
            target = _parse_artifact_target(message.get("target"), f"{path}.target")
            if target not in package.targets:
                raise ProtocolError(
                    "Cargo compiler-artifact target differs from bound metadata"
                )
            artifact_target = (package_id, target)
            if artifact_target in artifact_targets:
                raise ProtocolError(
                    "Cargo build repeats a package target compiler-artifact"
                )
            artifact_targets.add(artifact_target)
            if package.manifest_path is None:
                raise ProtocolError("Cargo compiler-artifact package has no manifest")
            _require_value(
                message.get("manifest_path"),
                package.manifest_path,
                f"{path}.manifest_path",
            )
            raw_filenames = _require_list(message.get("filenames"), f"{path}.filenames")
            if not raw_filenames or len(raw_filenames) > 64:
                raise ProtocolError(
                    "Cargo compiler-artifact filenames count exceeds bounds"
                )
            filenames: set[str] = set()
            for filename_index, raw_filename in enumerate(raw_filenames):
                filename = _require_bounded_string(
                    raw_filename,
                    4096,
                    f"{path}.filenames[{filename_index}]",
                )
                relative = _bound_target_relative_path(
                    filename,
                    plan.target_root,
                    f"{path}.filenames[{filename_index}]",
                )
                if relative in filenames or relative in artifact_paths:
                    raise ProtocolError(
                        "Cargo compiler-artifact repeats an output path"
                    )
                filenames.add(relative)
            artifact_paths.update(filenames)
            raw_executable = message.get("executable")
            executable_relative: str | None = None
            if raw_executable is not None:
                executable = _require_bounded_string(
                    raw_executable, 4096, f"{path}.executable"
                )
                executable_relative = _bound_target_relative_path(
                    executable, plan.target_root, f"{path}.executable"
                )
                if executable_relative not in filenames:
                    raise ProtocolError(
                        "Cargo compiler-artifact executable is absent from filenames"
                    )
            observed_packages.add(package_id)
            if package_id == selection.root_id:
                if not (
                    target.name == RELEASE_BINARY
                    and target.kinds == ("bin",)
                    and target.crate_types == ("bin",)
                ):
                    raise ProtocolError(
                        "Cargo compiler-artifact selected the wrong root target"
                    )
                if executable_relative is None:
                    raise ProtocolError(
                        "Cargo root compiler-artifact omits its executable"
                    )
                suffix = (
                    ".exe" if plan.execution.target.endswith("windows-msvc") else ""
                )
                expected_relative = (
                    f"{plan.execution.target}/{plan.execution.profile}/"
                    f"{plan.execution.binary}{suffix}"
                )
                if executable_relative != expected_relative:
                    raise ProtocolError(
                        "Cargo root compiler-artifact executable is not the frozen "
                        "target output"
                    )
                if root_artifact is not None:
                    raise ProtocolError(
                        "Cargo build repeats the root executable artifact"
                    )
                root_artifact = (package_id, executable_relative)
            elif target.kinds not in {
                ("lib",),
                ("proc-macro",),
                ("custom-build",),
            }:
                raise ProtocolError(
                    "Cargo compiler-artifact selected a non-dependency target"
                )
        elif reason in {"compiler-message", "build-script-executed"}:
            continue
        elif reason == "build-finished":
            _require_value(message.get("success"), True, f"{path}.success")
            build_finished = True
        else:
            raise ProtocolError("Cargo build emitted an unsupported message reason")
    if not build_finished:
        raise ProtocolError("Cargo build messages omit successful build-finished")
    if observed_packages != set(selection.package_ids):
        missing = sorted(set(selection.package_ids) - observed_packages)
        extra = sorted(observed_packages - set(selection.package_ids))
        raise ProtocolError(
            "Cargo compiler-artifact package closure differs from selected graph; "
            f"missing={missing[:8]}, extra={extra[:8]}"
        )
    if root_artifact is None:
        raise ProtocolError("Cargo build omits the selected Forge binary target")
    return root_artifact


def _release_binary_artifact_binding(
    plan: AcceptedReleaseBuildPlan,
    metadata_bytes: bytes,
    tree_bytes: bytes,
    cargo_build_messages_bytes: bytes,
    root_artifact: tuple[str, str],
) -> ReleaseBinaryArtifactBinding:
    package_id, relative_path = root_artifact
    metadata_sha256 = _sha256(metadata_bytes)
    tree_sha256 = _sha256(tree_bytes)
    build_messages_sha256 = _sha256(cargo_build_messages_bytes)
    identity = {
        "schema": "forge.release-binary-artifact-binding/v1",
        "plan_sha256": plan.plan_sha256,
        "authority_context_sha256": plan.authority_context_sha256,
        "source_commit": plan.source_commit,
        "cargo_lock_sha256": plan.cargo_lock_sha256,
        "source_root": plan.source_root,
        "source_inventory_sha256": plan.source_inventory_sha256,
        "dependency_root": plan.dependency_root,
        "dependency_inventory_sha256": plan.dependency_inventory_sha256,
        "target_root": plan.target_root,
        "target": plan.execution.target,
        "package_id": package_id,
        "relative_path": relative_path,
        "metadata_sha256": metadata_sha256,
        "tree_sha256": tree_sha256,
        "build_messages_sha256": build_messages_sha256,
    }
    return ReleaseBinaryArtifactBinding(
        plan_sha256=plan.plan_sha256,
        authority_context_sha256=plan.authority_context_sha256,
        target_root=plan.target_root,
        relative_path=relative_path,
        metadata_sha256=metadata_sha256,
        tree_sha256=tree_sha256,
        build_messages_sha256=build_messages_sha256,
        identity_sha256=_sha256(canonical_json(identity)),
    )


def resolve_release_binary_artifact(
    plan: AcceptedReleaseBuildPlan,
    metadata_bytes: bytes,
    tree_bytes: bytes,
    cargo_build_messages_bytes: bytes,
) -> ReleaseBinaryArtifactBinding:
    """Resolve the sole root executable the trusted driver must open and digest."""
    _validate_accepted_plan(plan)
    metadata = _parse_metadata(metadata_bytes, plan)
    selection = _parse_tree(metadata, tree_bytes, plan)
    root_artifact = _parse_build_artifacts(
        cargo_build_messages_bytes, metadata, selection, plan
    )
    return _release_binary_artifact_binding(
        plan,
        metadata_bytes,
        tree_bytes,
        cargo_build_messages_bytes,
        root_artifact,
    )


def bind_captured_release_binary(
    plan: AcceptedReleaseBuildPlan,
    artifact: ReleaseBinaryArtifactBinding,
    length: int,
    sha256: str,
) -> CapturedReleaseBinary:
    """Bind one trusted pinned-handle observation; this function performs no I/O."""
    _validate_accepted_plan(plan)
    if type(artifact) is not ReleaseBinaryArtifactBinding:
        raise ProtocolError("artifact must be an exact release binary binding")
    _require_value(
        _require_sha256(
            artifact.authority_context_sha256,
            "artifact Authority context SHA-256",
        ),
        plan.authority_context_sha256,
        "artifact Authority context SHA-256",
    )
    _require_value(
        _require_sha256(artifact.plan_sha256, "artifact plan SHA-256"),
        plan.plan_sha256,
        "artifact plan SHA-256",
    )
    _require_value(
        _require_target_root(artifact.target_root),
        plan.target_root,
        "artifact target root",
    )
    relative_path = _require_inventory_path(
        artifact.relative_path, "artifact relative path"
    )
    suffix = ".exe" if plan.execution.target == "x86_64-pc-windows-msvc" else ""
    _require_value(
        relative_path,
        f"{plan.execution.target}/{plan.execution.profile}/"
        f"{plan.execution.binary}{suffix}",
        "artifact relative path",
    )
    for digest, label in (
        (artifact.metadata_sha256, "artifact metadata SHA-256"),
        (artifact.tree_sha256, "artifact tree SHA-256"),
        (artifact.build_messages_sha256, "artifact build-messages SHA-256"),
        (artifact.identity_sha256, "artifact identity SHA-256"),
    ):
        _require_sha256(digest, label)
    if isinstance(length, bool) or not isinstance(length, int):
        raise ProtocolError("captured binary length must be an integer")
    if not 1 <= length <= min(plan.binary_limit, MAX_PROTOCOL_BINARY_BYTES):
        raise ProtocolError(
            "captured binary length exceeds Authority and protocol bounds"
        )
    return CapturedReleaseBinary(
        artifact=artifact,
        length=length,
        sha256=_require_sha256(sha256, "captured binary SHA-256"),
    )


def _normalized_license(package: _CargoPackage) -> str:
    raw = package.license_expression
    if raw is None:
        raise ProtocolError("selected Cargo package has no license expression")
    expression = _LICENSE_REWRITES.get((package.name, package.version, raw), raw)
    if expression not in _LICENSE_EXPRESSIONS:
        raise ProtocolError(
            "selected Cargo package has an unreviewed license expression"
        )
    return expression


def _validate_closed_dag(root: str, edges: Mapping[str, set[str]]) -> None:
    packages = set(edges)
    if root not in packages:
        raise ProtocolError("projected graph omits its root")
    incoming = {package: 0 for package in packages}
    edge_count = 0
    for package, dependencies in edges.items():
        if len(dependencies) > MAX_DEPENDENCIES_PER_PACKAGE:
            raise ProtocolError("projected dependency row exceeds bounds")
        for dependency in dependencies:
            if dependency == package or dependency not in packages:
                raise ProtocolError("projected graph has a self or dangling dependency")
            edge_count += 1
            if edge_count > MAX_GRAPH_EDGES:
                raise ProtocolError("projected graph edge count exceeds bounds")
            incoming[dependency] += 1
    if incoming[root] != 0:
        raise ProtocolError("projected graph root has an incoming dependency")

    reachable: set[str] = set()
    pending = [root]
    while pending:
        package = pending.pop()
        if package in reachable:
            continue
        reachable.add(package)
        pending.extend(edges[package])
    if reachable != packages:
        raise ProtocolError("projected graph contains an unreachable package")

    ready = [package for package, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        package = ready.pop()
        visited += 1
        for dependency in edges[package]:
            incoming[dependency] -= 1
            if incoming[dependency] == 0:
                ready.append(dependency)
    if visited != len(packages):
        raise ProtocolError("projected graph contains a dependency cycle")


def _canonical_sorted_json(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ProtocolError(
            "SBOM graph cannot be rendered as canonical JSON"
        ) from error
    return (text + "\n").encode("utf-8")


def _sbom_graph_sort_key(component: Mapping[str, Any]) -> tuple[str, ...]:
    checksum = component["checksum"]
    return (
        cast(str, component["type"]),
        cast(str, component["name"]),
        cast(str, component["version"]),
        cast(str, component["source"]),
        "" if checksum is None else cast(str, checksum),
        cast(str, component["licenseExpression"]),
        cast(str, component["bomRef"]),
    )


def _descriptor_sbom_graph_contract(
    plan: AcceptedReleaseBuildPlan, graph_value: Any
) -> _SbomGraphContract:
    graph = _require_mapping(graph_value, "release-build descriptor.sbom_graph")
    root_key = _require_bounded_string(
        graph.get("root"), 384, "release-build descriptor.sbom_graph.root"
    )
    raw_packages = _require_list(
        graph.get("packages"), "release-build descriptor.sbom_graph.packages"
    )
    nodes_by_key: dict[str, dict[str, Any]] = {}
    for index, raw_package in enumerate(raw_packages):
        path = f"release-build descriptor.sbom_graph.packages[{index}]"
        package = _require_mapping(raw_package, path)
        key = _require_bounded_string(package.get("key"), 384, f"{path}.key")
        name = _require_package_name(package.get("name"), f"{path}.name")
        version = _require_package_version(package.get("version"), f"{path}.version")
        license_expression = _require_string(
            package.get("sbom_license_expression"),
            f"{path}.sbom_license_expression",
        )
        source = _require_mapping(package.get("source"), f"{path}.source")
        source_kind = _require_string(source.get("kind"), f"{path}.source.kind")
        if source_kind == "workspace":
            _require_exact_keys(source, ("kind",), f"{path}.source")
            source_identity = "workspace"
            checksum = None
        elif source_kind == "crates-io":
            _require_exact_keys(
                source, ("kind", "crate_archive_sha256"), f"{path}.source"
            )
            source_identity = CRATES_IO_SOURCE
            checksum = _require_sha256(
                source.get("crate_archive_sha256"),
                f"{path}.source.crate_archive_sha256",
            )
        else:
            raise ProtocolError("release-build descriptor has an unsupported source")
        if key == root_key:
            if source_kind != "workspace":
                raise ProtocolError(
                    "release-build descriptor root is not a workspace package"
                )
            bom_ref = f"pkg:cargo/forge@{plan.version}"
            component_type = "application"
            node_name = RELEASE_BINARY
        else:
            identity = f"{name}\0{version}\0{source_identity}".encode("utf-8")
            bom_ref = f"urn:forge:cargo:blake3:{_blake3_hex(identity)}"
            component_type = "library"
            node_name = name
        node = {
            "bomRef": bom_ref,
            "type": component_type,
            "name": node_name,
            "version": version,
            "source": source_identity,
            "checksum": checksum,
            "licenseExpression": license_expression,
        }
        if key in nodes_by_key:
            raise ProtocolError("release-build descriptor repeats a package key")
        nodes_by_key[key] = node
    root = nodes_by_key.get(root_key)
    if root is None:
        raise ProtocolError("release-build descriptor graph omits its root")

    raw_dependencies = _require_list(
        graph.get("dependencies"), "release-build descriptor.sbom_graph.dependencies"
    )
    dependencies_by_key: dict[str, list[str]] = {}
    edge_count = 0
    for index, raw_row in enumerate(raw_dependencies):
        path = f"release-build descriptor.sbom_graph.dependencies[{index}]"
        row = _require_mapping(raw_row, path)
        package_key = _require_bounded_string(
            row.get("package"), 384, f"{path}.package"
        )
        raw_depends_on = _require_list(row.get("depends_on"), f"{path}.depends_on")
        dependency_keys = [
            _require_bounded_string(value, 384, f"{path}.depends_on[{item_index}]")
            for item_index, value in enumerate(raw_depends_on)
        ]
        if package_key in dependencies_by_key:
            raise ProtocolError("release-build descriptor repeats a dependency row")
        dependencies_by_key[package_key] = dependency_keys
        edge_count += len(dependency_keys)
    if set(dependencies_by_key) != set(nodes_by_key):
        raise ProtocolError("release-build descriptor dependency rows are not exact")
    if any(
        dependency not in nodes_by_key
        for dependencies in dependencies_by_key.values()
        for dependency in dependencies
    ):
        raise ProtocolError("release-build descriptor dependency escapes its graph")

    components = sorted(
        (node for key, node in nodes_by_key.items() if key != root_key),
        key=_sbom_graph_sort_key,
    )
    dependencies = []
    for key in sorted(
        nodes_by_key, key=lambda item: _sbom_graph_sort_key(nodes_by_key[item])
    ):
        depends_on = sorted(
            (nodes_by_key[dependency] for dependency in dependencies_by_key[key]),
            key=_sbom_graph_sort_key,
        )
        dependencies.append({"component": nodes_by_key[key], "dependsOn": depends_on})
    projection = {
        "schema": SBOM_GRAPH_SCHEMA,
        "root": root,
        "components": components,
        "dependencies": dependencies,
    }
    return _SbomGraphContract(
        component_count=len(nodes_by_key),
        dependency_edge_count=edge_count,
        canonical_sha256=_sha256(_canonical_sorted_json(projection)),
    )


def _require_policy_sbom_graph(
    plan: AcceptedReleaseBuildPlan, graph_value: Any
) -> None:
    actual = _descriptor_sbom_graph_contract(plan, graph_value)
    if actual != plan.sbom_graph:
        raise ProtocolError(
            "release-build descriptor SBOM graph differs from Authority policy; "
            f"components={actual.component_count}, edges={actual.dependency_edge_count}, "
            f"canonical_sha256={actual.canonical_sha256}"
        )


def build_release_build_apply_descriptor(
    plan: AcceptedReleaseBuildPlan,
    metadata_bytes: bytes,
    tree_bytes: bytes,
    cargo_build_messages_bytes: bytes,
    cargo_lock_bytes: bytes,
    captured_binary: CapturedReleaseBinary,
) -> bytes:
    """Project Authority-captured build facts into canonical candidate apply input."""
    _validate_accepted_plan(plan)
    if type(captured_binary) is not CapturedReleaseBinary:
        raise ProtocolError("binary must be an exact captured release descriptor")
    validated_capture = bind_captured_release_binary(
        plan,
        captured_binary.artifact,
        captured_binary.length,
        captured_binary.sha256,
    )
    _require_value(captured_binary, validated_capture, "captured release binary")
    lock_packages = _parse_cargo_lock(cargo_lock_bytes, plan.cargo_lock_limit)
    if _sha256(cargo_lock_bytes) != plan.cargo_lock_sha256:
        raise ProtocolError("Cargo.lock no longer matches the accepted plan")
    metadata = _parse_metadata(metadata_bytes, plan)
    selection = _parse_tree(metadata, tree_bytes, plan)
    root_artifact = _parse_build_artifacts(
        cargo_build_messages_bytes, metadata, selection, plan
    )
    expected_artifact = _release_binary_artifact_binding(
        plan,
        metadata_bytes,
        tree_bytes,
        cargo_build_messages_bytes,
        root_artifact,
    )
    _require_value(
        captured_binary.artifact,
        expected_artifact,
        "captured root artifact binding",
    )
    if not 1 <= len(selection.package_ids) <= MAX_GRAPH_PACKAGES:
        raise ProtocolError("selected package count exceeds protocol bounds")

    keys_by_id: dict[str, str] = {}
    packages: list[dict[str, Any]] = []
    semantic_identities: set[tuple[str, str]] = set()
    for package_id in selection.package_ids:
        package = metadata.packages_by_id[package_id]
        name = _require_package_name(package.name, "selected package name")
        version = _require_package_version(package.version, "selected package version")
        if (name, version) in semantic_identities:
            raise ProtocolError("selected graph repeats a package name and version")
        semantic_identities.add((name, version))
        lock_identity = (name, version, package.source)
        if lock_identity not in lock_packages:
            raise ProtocolError(
                "selected package is absent from the accepted Cargo.lock"
            )
        lock_checksum = lock_packages[lock_identity]
        if package.source is None:
            if (
                package_id not in metadata.workspace_members
                or lock_checksum is not None
            ):
                raise ProtocolError(
                    "selected workspace package has invalid lock semantics"
                )
            key = f"workspace:{name}@{version}"
            source = {"kind": "workspace"}
        elif package.source == CRATES_IO_SOURCE:
            if lock_checksum is None:
                raise ProtocolError("selected crates.io package lacks a lock checksum")
            key = f"crates-io:{name}@{version}"
            source = {
                "kind": "crates-io",
                "crate_archive_sha256": lock_checksum,
            }
        else:
            raise ProtocolError("selected package source is outside protocol v1")
        if len(key) > 384:
            raise ProtocolError("selected package key exceeds protocol bounds")
        keys_by_id[package_id] = key
        packages.append(
            {
                "key": key,
                "name": name,
                "version": version,
                "sbom_license_expression": _normalized_license(package),
                "source": source,
            }
        )
    packages.sort(key=lambda package: cast(str, package["key"]))

    root_key = keys_by_id[selection.root_id]
    expected_root = f"workspace:{RELEASE_PACKAGE}@{plan.version}"
    if root_key != expected_root:
        raise ProtocolError("projected graph root does not match the accepted plan")
    root_package = metadata.packages_by_id[selection.root_id]
    if _normalized_license(root_package) != plan.project_license_expression:
        raise ProtocolError(
            "projected graph root license differs from Authority policy"
        )

    key_edges: dict[str, set[str]] = {}
    for package_id, dependency_ids in selection.edges.items():
        package_key = keys_by_id.get(package_id)
        if package_key is None:
            raise ProtocolError(
                "Cargo tree dependency row escaped its selected closure"
            )
        dependency_keys: set[str] = set()
        for dependency_id in dependency_ids:
            dependency_key = keys_by_id.get(dependency_id)
            if dependency_key is None:
                raise ProtocolError(
                    "Cargo tree dependency escaped its selected closure"
                )
            dependency_keys.add(dependency_key)
        key_edges[package_key] = dependency_keys
    if set(key_edges) != set(keys_by_id.values()):
        raise ProtocolError("projected graph does not contain one row per package")
    _validate_closed_dag(root_key, key_edges)
    dependencies = [
        {
            "package": package,
            "depends_on": sorted(key_edges[package]),
        }
        for package in sorted(key_edges)
    ]
    descriptor = {
        "schema": APPLY_DESCRIPTOR_SCHEMA,
        "purpose": APPLY_DESCRIPTOR_PURPOSE,
        "plan_sha256": plan.plan_sha256,
        "binary": {
            "length": captured_binary.length,
            "sha256": captured_binary.sha256,
        },
        "sbom_graph": {
            "root": root_key,
            "packages": packages,
            "dependencies": dependencies,
        },
    }
    _require_policy_sbom_graph(plan, descriptor["sbom_graph"])
    rendered = canonical_json(descriptor)
    if len(rendered) > MAX_DESCRIPTOR_BYTES:
        raise ProtocolError("release-build apply descriptor exceeds its byte bound")
    return rendered
