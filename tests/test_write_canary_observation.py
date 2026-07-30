from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

from scripts import write_canary_observation as observations


SOURCE_COMMIT = "1" * 40
AUTHORITY_COMMIT = "2" * 40
TARGET = "x86_64-apple-darwin"


def _stat_view(
    source: os.stat_result,
    *,
    device: int | None = None,
    inode: int | None = None,
    mode: int | None = None,
    size: int | None = None,
    mtime_ns: int | None = None,
    ctime_ns: int | None = None,
) -> os.stat_result:
    return cast(
        os.stat_result,
        SimpleNamespace(
            st_dev=source.st_dev if device is None else device,
            st_ino=source.st_ino if inode is None else inode,
            st_mode=source.st_mode if mode is None else mode,
            st_size=source.st_size if size is None else size,
            st_mtime_ns=source.st_mtime_ns if mtime_ns is None else mtime_ns,
            st_ctime_ns=source.st_ctime_ns if ctime_ns is None else ctime_ns,
        ),
    )


class CanaryObservationTests(unittest.TestCase):
    def test_builds_allowlisted_record_and_writes_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "forge"
            binary.write_bytes(b"native-binary")
            cargo_home = root / "cargo-home"
            cache = cargo_home / "registry" / "cache" / "index.example-123"
            cache.mkdir(parents=True)
            (cache / "alpha-1.0.0.crate").write_bytes(b"alpha")
            (cache / "beta-2.0.0.crate").write_bytes(b"beta")
            rustlib = root / "rustlib"
            rustlib.mkdir()
            (rustlib / "libcore.rlib").write_bytes(b"core")
            environment = {
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-must-not-appear",
                "GITHUB_TOKEN": "github-must-not-appear",
                "GITHUB_WORKSPACE": os.fspath(root),
                "ImageOS": "macos15",
                "ImageVersion": "20260728.1",
                "RUNNER_ARCH": "X64",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "macOS",
            }

            with (
                mock.patch.object(
                    observations,
                    "_tool_observations",
                    return_value=(
                        {"commands": {}, "executables": {}, "python": {}},
                        rustlib,
                    ),
                ),
                mock.patch.object(
                    observations,
                    "_platform_observation",
                    return_value=({"commands": {}, "executables": {}}, {}, []),
                ),
            ):
                record = observations.build_observation(
                    target=TARGET,
                    source_commit=SOURCE_COMMIT,
                    authority_commit=AUTHORITY_COMMIT,
                    binary=binary,
                    cargo_home=cargo_home,
                    environment=environment,
                    system="Darwin",
                )

            self.assertEqual(record["schema"], observations.SCHEMA)
            self.assertEqual(record["purpose"], observations.PURPOSE)
            self.assertEqual(record["target"], TARGET)
            self.assertEqual(
                record["binary"]["sha256"], hashlib.sha256(b"native-binary").hexdigest()
            )
            cache_record = record["cargo_registry_archive_cache"]
            self.assertEqual(cache_record["entry_count"], 2)
            self.assertEqual(
                [entry["name"] for entry in cache_record["entries"]],
                [
                    "index.example-123/alpha-1.0.0.crate",
                    "index.example-123/beta-2.0.0.crate",
                ],
            )
            self.assertEqual(record["target_rustlib"]["entry_count"], 1)
            serialized = json.dumps(record, sort_keys=True)
            self.assertNotIn("oidc-must-not-appear", serialized)
            self.assertNotIn("github-must-not-appear", serialized)
            self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", serialized)
            self.assertNotIn("GITHUB_TOKEN", serialized)

            output_directory = root / "observation"
            output = observations.write_observation(output_directory, TARGET, record)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), record)
            self.assertLessEqual(output.stat().st_size, observations.MAX_OUTPUT_BYTES)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(output_directory.stat().st_mode), 0o700)
            with self.assertRaisesRegex(
                observations.ObservationError, "fresh observation output directory"
            ):
                observations.write_observation(output_directory, TARGET, record)

    def test_command_capture_redacts_paths_and_secret_assignments(self) -> None:
        workspace = "/private/runner/work/repository"
        environment = {"GITHUB_WORKSPACE": workspace}
        replacements = observations._path_replacements(environment)
        command = observations._run_command(
            [
                sys.executable,
                "-c",
                f"print({workspace!r} + '/tool'); "
                "print('token=visible-value'); "
                "print('Authorization: Bearer visible-bearer'); "
                "print('GITHUB_TOKEN=visible-github'); "
                "print('API_KEY=visible-api'); "
                "print('AWS_SECRET_ACCESS_KEY=visible-aws'); "
                "print('OAUTH_CLIENT_SECRET=visible-oauth'); "
                "print('https://runner:visible-password@example.test/path')",
            ],
            environment,
            replacements,
        )
        rendered = json.dumps(command, sort_keys=True)
        self.assertEqual(command["status"], "ok")
        self.assertIn("$GITHUB_WORKSPACE/tool", rendered)
        self.assertNotIn(workspace, rendered)
        self.assertNotIn("visible-value", rendered)
        self.assertNotIn("visible-bearer", rendered)
        self.assertNotIn("visible-github", rendered)
        self.assertNotIn("visible-api", rendered)
        self.assertNotIn("visible-aws", rendered)
        self.assertNotIn("visible-oauth", rendered)
        self.assertNotIn("visible-password", rendered)
        self.assertIn("token=<redacted>", rendered)
        self.assertIn("Authorization: <redacted>", rendered)
        self.assertIn("GITHUB_TOKEN=<redacted>", rendered)
        self.assertIn("API_KEY=<redacted>", rendered)
        self.assertIn("AWS_SECRET_ACCESS_KEY=<redacted>", rendered)
        self.assertIn("OAUTH_CLIENT_SECRET=<redacted>", rendered)
        self.assertIn("https://<redacted>@example.test/path", rendered)

    def test_command_capture_refuses_search_result_outside_explicit_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout_tool = Path(temporary) / "cargo.exe"
            checkout_tool.write_bytes(b"not an executable")
            environment = {
                "GITHUB_WORKSPACE": temporary,
                "PATH": os.pathsep.join((os.fspath(Path(temporary) / "safe"),)),
            }
            with mock.patch.object(shutil, "which", return_value=os.fspath(checkout_tool)):
                command = observations._run_command(
                    ["cargo.exe", "-V"],
                    environment,
                    observations._path_replacements(environment),
                )
        self.assertEqual(command["status"], "refused-unsafe-search-result")

    def test_command_capture_marks_retained_prefix_as_truncated(self) -> None:
        with (
            mock.patch.object(observations, "MAX_COMMAND_STREAM_BYTES", 4096),
            mock.patch.object(observations, "MAX_RETAINED_STREAM_BYTES", 128),
        ):
            command = observations._run_command(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 512)"],
                {},
                [],
            )
        self.assertEqual(command["status"], "ok")
        self.assertEqual(command["stdout_total_bytes"], 512)
        self.assertEqual(len(command["stdout"]), 128)
        self.assertTrue(command["stdout_truncated"])

    def test_command_capture_kills_output_above_hard_limit(self) -> None:
        with (
            mock.patch.object(observations, "MAX_COMMAND_STREAM_BYTES", 1024),
            mock.patch.object(observations, "MAX_RETAINED_STREAM_BYTES", 128),
            mock.patch.object(observations, "MAX_COMMAND_SECONDS", 2.0),
        ):
            command = observations._run_command(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 65536)"],
                {},
                [],
            )
        self.assertEqual(command["status"], "output-limit")
        self.assertGreater(command["stdout_total_bytes"], 1024)
        self.assertLessEqual(len(command["stdout"]), 128)
        self.assertTrue(command["stdout_truncated"])

    def test_path_command_keeps_raw_path_private_but_available_to_collector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            selected = Path(temporary) / "selected-tool"
            environment = {"GITHUB_WORKSPACE": temporary}
            command, raw_path = observations._run_path_command(
                [sys.executable, "-c", f"print({os.fspath(selected)!r})"],
                environment,
                observations._path_replacements(environment),
            )
        self.assertEqual(raw_path, selected)
        rendered = json.dumps(command, sort_keys=True)
        self.assertIn("$GITHUB_WORKSPACE/selected-tool", rendered)
        self.assertNotIn(temporary, rendered)

    def test_cache_manifest_rejects_symlink_and_entry_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside.crate"
            outside.write_bytes(b"outside")
            cache = root / "cache"
            cache.mkdir()
            (cache / "linked.crate").symlink_to(outside)
            with self.assertRaisesRegex(observations.ObservationError, "symbolic link"):
                observations._directory_manifest(
                    cache,
                    observations.HashBudget(),
                    suffix=".crate",
                    per_file_limit=1024,
                    label="cache",
                )

            (cache / "linked.crate").unlink()
            (cache / "one.crate").write_bytes(b"one")
            (cache / "two.crate").write_bytes(b"two")
            with (
                mock.patch.object(observations, "MAX_MANIFEST_ENTRIES", 10),
                mock.patch.object(observations, "MAX_SCAN_ENTRIES", 1),
                self.assertRaisesRegex(observations.ObservationError, "scan entry limit"),
            ):
                observations._directory_manifest(
                    cache,
                    observations.HashBudget(),
                    suffix=".crate",
                    per_file_limit=1024,
                    label="cache",
                )

            with (
                mock.patch.object(observations, "MAX_MANIFEST_ENTRIES", 1),
                self.assertRaisesRegex(observations.ObservationError, "manifest entry limit"),
            ):
                observations._directory_manifest(
                    cache,
                    observations.HashBudget(),
                    suffix=".crate",
                    per_file_limit=1024,
                    label="cache",
                )

    def test_hash_budget_rejects_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large"
            path.write_bytes(b"12345")
            budget = observations.HashBudget(remaining=4)
            with self.assertRaisesRegex(observations.ObservationError, "total byte limit"):
                budget.digest_regular_file(path, 1024, "large input")

    def test_hash_budget_accepts_windows_path_and_descriptor_projections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forge.exe"
            content = b"native-binary"
            path.write_bytes(content)
            actual = path.stat()
            path_view = _stat_view(
                actual,
                mode=actual.st_mode | 0o111,
                ctime_ns=actual.st_ctime_ns + 1,
            )
            descriptor_view = _stat_view(
                actual,
                mode=actual.st_mode & ~0o111,
                ctime_ns=actual.st_ctime_ns + 2,
            )
            budget = observations.HashBudget(remaining=1024)
            with (
                mock.patch.object(Path, "stat", side_effect=[path_view, path_view]),
                mock.patch.object(os, "fstat", side_effect=[descriptor_view, descriptor_view]),
            ):
                size, digest = budget.digest_regular_file(path, 1024, "staged binary")

        self.assertEqual(size, len(content))
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())
        self.assertEqual(budget.remaining, 1024 - len(content))

    def test_hash_budget_hashes_real_executable_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forge.exe"
            content = b"native-binary"
            path.write_bytes(content)
            metadata = path.stat()
            os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

            size, digest = observations.HashBudget().digest_regular_file(
                path, 1024, "staged binary"
            )

        self.assertEqual(size, len(content))
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_hash_budget_rejects_same_view_metadata_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forge.exe"
            path.write_bytes(b"native-binary")
            actual = path.stat()
            path_after = _stat_view(actual, ctime_ns=actual.st_ctime_ns + 1)
            descriptor_after = _stat_view(actual, ctime_ns=actual.st_ctime_ns + 1)

            with (
                mock.patch.object(Path, "stat", side_effect=[actual, path_after]),
                mock.patch.object(os, "fstat", side_effect=[actual, actual]),
                self.assertRaisesRegex(observations.ObservationError, "changed while"),
            ):
                observations.HashBudget().digest_regular_file(
                    path, 1024, "path-changing input"
                )

            with (
                mock.patch.object(Path, "stat", side_effect=[actual, actual]),
                mock.patch.object(os, "fstat", side_effect=[actual, descriptor_after]),
                self.assertRaisesRegex(observations.ObservationError, "changed while"),
            ):
                observations.HashBudget().digest_regular_file(
                    path, 1024, "descriptor-changing input"
                )

    def test_cross_view_snapshot_rejects_unknown_or_different_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forge.exe"
            path.write_bytes(b"native-binary")
            actual = path.stat()

        self.assertFalse(
            observations._same_file_snapshot(actual, _stat_view(actual, inode=0))
        )
        self.assertFalse(
            observations._same_file_snapshot(
                actual, _stat_view(actual, inode=actual.st_ino + 1)
            )
        )

    def test_build_observation_preserves_staged_binary_failure_reason(self) -> None:
        with mock.patch.object(
            observations,
            "_file_summary",
            return_value={
                "reason": "staged binary changed before it was opened",
                "status": "unavailable",
            },
        ):
            with self.assertRaisesRegex(
                observations.ObservationError,
                "staged binary changed before it was opened",
            ):
                observations.build_observation(
                    target=TARGET,
                    source_commit=SOURCE_COMMIT,
                    authority_commit=AUTHORITY_COMMIT,
                    binary=Path("forge"),
                    cargo_home=Path("cargo-home"),
                    environment={},
                    system="Darwin",
                )

    def test_windows_probe_declares_internal_msvc_environment_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "forge.exe"
            binary.write_bytes(b"MZ")
            environment = {
                "INCLUDE": "must-not-be-recorded",
                "LIB": "must-not-be-recorded",
                "PATH": os.environ.get("PATH", ""),
                "VCToolsInstallDir": "must-not-be-recorded",
            }
            platform_record, runtime, limitations = observations._platform_observation(
                "Windows",
                binary,
                environment,
                observations.HashBudget(),
                observations._path_replacements(environment),
            )
        rendered = json.dumps(
            {"platform": platform_record, "runtime": runtime, "limitations": limitations},
            sort_keys=True,
        )
        self.assertIn("internal environment is unavailable", rendered)
        self.assertNotIn("must-not-be-recorded", rendered)
        self.assertNotIn('"INCLUDE"', rendered)
        self.assertNotIn('"LIB"', rendered)
        self.assertNotIn("VCToolsInstallDir", rendered)

    def test_rejects_unknown_target_and_relative_output(self) -> None:
        with self.assertRaisesRegex(observations.ObservationError, "five-target"):
            observations._safe_target("invented-target")
        with self.assertRaisesRegex(observations.ObservationError, "must be absolute"):
            observations.write_observation(Path("relative"), TARGET, {})


if __name__ == "__main__":
    unittest.main()
