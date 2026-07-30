#!/usr/bin/env python3
"""Write one deterministic, unprivileged native-build record.

The record is workload evidence, not authority. The protected verifier later
recomputes every descriptor and rejects policy, identity, or target drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence, cast


POLICY_SCHEMA = "forge.release-authority-policy/v1"
LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_POLICY_BYTES = 1024 * 1024


class RecordError(ValueError):
    """The requested builder record is outside the fixed input contract."""


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RecordError(f"builder-record policy repeats key {key!r}")
        value[key] = item
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecordError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecordError(f"{label} must be a non-empty string")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RecordError(f"{label} must be a positive integer")
    return cast(int, value)


def _git_sha(value: str, label: str) -> str:
    if LOWER_GIT_SHA.fullmatch(value) is None:
        raise RecordError(f"{label} must be 40 lowercase hexadecimal characters")
    return value


def _read_policy(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_POLICY_BYTES:
            raise RecordError("builder-record policy is not a bounded regular file")
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except RecordError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordError("cannot read builder-record policy") from error
    policy = _object(value, "builder-record policy")
    if policy.get("schema") != POLICY_SCHEMA:
        raise RecordError("builder-record policy schema is not supported")
    return policy


def _read_asset(directory: Path, name: str, limit: int, label: str) -> bytes:
    if Path(name).name != name or name in {".", ".."}:
        raise RecordError(f"{label} name is not a safe basename")
    path = directory / name
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise RecordError(f"{label} is not a bounded regular file")
        data = path.read_bytes()
    except RecordError:
        raise
    except OSError as error:
        raise RecordError(f"cannot read {label}") from error
    if len(data) != metadata.st_size:
        raise RecordError(f"{label} changed while being read")
    return data


def _descriptor(name: str, data: bytes) -> dict[str, Any]:
    return {
        "length": len(data),
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def write_builder_record(
    policy_path: Path,
    assets_directory: Path,
    output_directory: Path,
    target_triple: str,
    source_commit: str,
    authority_commit: str,
) -> Path:
    """Create one record without overwriting an existing output."""
    source_commit = _git_sha(source_commit, "source commit")
    authority_commit = _git_sha(authority_commit, "authority commit")
    policy = _read_policy(policy_path)
    targets = policy.get("targets")
    if not isinstance(targets, list):
        raise RecordError("builder-record policy targets must be an array")
    matches = [
        _object(target, "builder-record target")
        for target in targets
        if isinstance(target, Mapping) and target.get("triple") == target_triple
    ]
    if len(matches) != 1:
        raise RecordError("target is not exactly represented by policy")
    target = matches[0]
    limits = _object(policy.get("limits"), "builder-record policy limits")
    binary_name = _string(target.get("binary"), "builder-record binary name")
    sbom_name = _string(target.get("sbom"), "builder-record SBOM name")
    binary = _read_asset(
        assets_directory,
        binary_name,
        _positive_integer(limits.get("binaryBytes"), "binary byte limit"),
        "builder-record binary",
    )
    sbom = _read_asset(
        assets_directory,
        sbom_name,
        _positive_integer(limits.get("sbomBytes"), "SBOM byte limit"),
        "builder-record SBOM",
    )
    source = _object(policy.get("source"), "builder-record source identity")
    authority = _object(policy.get("authority"), "builder-record authority identity")
    toolchain = _object(policy.get("toolchain"), "builder-record toolchain")
    records = _object(policy.get("builderRecords"), "builder-record contract")
    record = {
        "authority": {
            "commit": authority_commit,
            "owner_id": _positive_integer(
                authority.get("ownerId"), "authority owner ID"
            ),
            "repository_id": _positive_integer(
                authority.get("repositoryId"), "authority repository ID"
            ),
        },
        "binary": _descriptor(binary_name, binary),
        "runner_label": _string(target.get("runnerLabel"), "runner label"),
        "rust_version": _string(toolchain.get("rust"), "Rust version"),
        "sbom": _descriptor(sbom_name, sbom),
        "schema": _string(records.get("schema"), "builder-record schema"),
        "source": {
            "commit": source_commit,
            "owner_id": _positive_integer(source.get("ownerId"), "source owner ID"),
            "repository_id": _positive_integer(
                source.get("repositoryId"), "source repository ID"
            ),
        },
        "target": _string(target.get("triple"), "target triple"),
    }
    record_name = _string(target.get("builderRecord"), "builder-record name")
    if Path(record_name).name != record_name:
        raise RecordError("builder-record name is not a safe basename")
    rendered = (
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    output = output_directory / record_name
    try:
        file_descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(rendered)
    except OSError as error:
        raise RecordError("cannot create builder record") from error
    return output


def _parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--authority-commit", required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parse_arguments(arguments)
    try:
        output = write_builder_record(
            options.policy,
            options.assets,
            options.output_dir,
            options.target,
            options.source_commit,
            options.authority_commit,
        )
    except RecordError as error:
        print(f"builder record failed: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
