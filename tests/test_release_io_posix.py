from __future__ import annotations

import copy
import inspect
import os
import pickle
import stat
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

from tests.release_io_test_support import load_release_io_modules


_release_io, posix_io = load_release_io_modules()


EXACT_OUTPUT_TEST_BUDGETS = {
    "maximum_file_count": 4,
    "maximum_file_bytes": 64,
    "maximum_total_bytes": 128,
}


class ReleaseIoPosixTests(unittest.TestCase):
    def test_secure_posix_capabilities_fail_closed(self) -> None:
        with mock.patch.object(os, "name", "nt"):
            with self.assertRaisesRegex(posix_io.VerificationError, "POSIX"):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(posix_io.VerificationError, "O_NOFOLLOW"):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_dir_fd", set()):
            with self.assertRaisesRegex(posix_io.VerificationError, r"open\(dir_fd\)"):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_follow_symlinks", set()):
            with self.assertRaisesRegex(
                posix_io.VerificationError, "follow_symlinks=False"
            ):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_fd", set()):
            with self.assertRaisesRegex(posix_io.VerificationError, r"scandir\(fd\)"):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "geteuid", None):
            with self.assertRaisesRegex(posix_io.VerificationError, "geteuid"):
                posix_io._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "fchmod", None):
            with self.assertRaisesRegex(posix_io.VerificationError, "fchmod"):
                posix_io._require_exact_io_capabilities()

    def test_directory_enumeration_work_is_bounded(self) -> None:
        class EndlessEntries:
            def __init__(self) -> None:
                self.count = 0

            def __enter__(self) -> EndlessEntries:
                return self

            def __exit__(self, *_args: Any) -> None:
                return None

            def __iter__(self) -> EndlessEntries:
                return self

            def __next__(self) -> Any:
                self.count += 1
                return type("Entry", (), {"name": f"entry-{self.count}"})()

        entries = EndlessEntries()
        with mock.patch.object(os, "scandir", return_value=entries):
            with self.assertRaisesRegex(posix_io.VerificationError, "more than 2"):
                posix_io._bounded_directory_names(123, 2, "oversized directory")
        self.assertEqual(entries.count, 3)

    def test_output_pin_binds_the_canonical_parent_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "inputs"
            (inputs / "leaf").mkdir(parents=True)
            output_ancestor = root / "output"
            (output_ancestor / "leaf").mkdir(parents=True)
            detached = root / "detached-output"
            pinned_input = posix_io.pin_directory(inputs, "test input")
            real_open = posix_io._open_resolved_directory
            expected_resolved = (output_ancestor / "leaf").resolve()
            swapped = False

            def swap_before_component_open(path: Path, label: str) -> int:
                nonlocal swapped
                if not swapped and path == expected_resolved:
                    swapped = True
                    output_ancestor.rename(detached)
                    output_ancestor.symlink_to(inputs, target_is_directory=True)
                return real_open(path, label)

            try:
                with mock.patch.object(
                    posix_io,
                    "_open_resolved_directory",
                    side_effect=swap_before_component_open,
                ):
                    with self.assertRaises(posix_io.VerificationError):
                        posix_io.pin_output(
                            output_ancestor / "leaf" / "predicate.json",
                            [pinned_input],
                        )
            finally:
                posix_io.close_pinned_directory(pinned_input)
            self.assertTrue(swapped)
            self.assertFalse((inputs / "leaf" / "predicate.json").exists())

    def test_created_output_growth_is_rejected_before_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "outputs"
            output_directory.mkdir(mode=0o700)
            pinned = posix_io.pin_output(output_directory / "result", [])
            created = posix_io.write_create_only(pinned, b"ok")
            try:
                created_view = object.__getattribute__(created, "_view")
                os.ftruncate(created_view.file_fd, 32 * 1024 * 1024)
                with mock.patch.object(
                    os,
                    "read",
                    side_effect=AssertionError("readback must remain bounded"),
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "changed before completion"
                    ):
                        posix_io.require_created_outputs_stable([created])
            finally:
                posix_io.close_created_output(created)
                posix_io.close_pinned_output(pinned)

    def test_formal_facade_leases_are_opaque_and_owner_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_directory = root / "input"
            output_directory = root / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "item").write_bytes(b"item")

            pinned_directory = posix_io.pin_directory(
                input_directory, "opaque facade input"
            )
            pinned_output = posix_io.pin_output(
                output_directory / "result", [pinned_directory]
            )
            created_output = posix_io.write_create_only(pinned_output, b"result")
            resources = (
                (
                    pinned_directory,
                    posix_io._PinnedDirectoryLease,
                    posix_io.close_pinned_directory,
                ),
                (
                    pinned_output,
                    posix_io._PinnedOutputLease,
                    posix_io.close_pinned_output,
                ),
                (
                    created_output,
                    posix_io._CreatedOutputLease,
                    posix_io.close_created_output,
                ),
            )
            try:
                for lease, lease_type, close in resources:
                    with self.subTest(kind=lease_type.__name__, check="construct"):
                        with self.assertRaisesRegex(
                            TypeError, "cannot be constructed directly"
                        ):
                            lease_type()
                    with self.subTest(kind=lease_type.__name__, check="subclass"):
                        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
                            type(f"Forged{lease_type.__name__}", (lease_type,), {})
                    for check, operation in (
                        ("copy", lambda lease=lease: copy.copy(lease)),
                        ("deepcopy", lambda lease=lease: copy.deepcopy(lease)),
                        ("pickle", lambda lease=lease: pickle.dumps(lease)),
                    ):
                        with self.subTest(kind=lease_type.__name__, check=check):
                            with self.assertRaisesRegex(
                                TypeError, "cannot be copied or serialized"
                            ):
                                operation()
                    with self.subTest(kind=lease_type.__name__, check="replace"):
                        with self.assertRaises(TypeError):
                            replace(lease)
                    copy_replace = getattr(copy, "replace", None)
                    if copy_replace is not None:
                        with self.subTest(
                            kind=lease_type.__name__, check="copy.replace"
                        ):
                            with self.assertRaisesRegex(
                                TypeError, "cannot be copied or serialized"
                            ):
                                copy_replace(lease)
                    with self.subTest(kind=lease_type.__name__, check="mutate"):
                        with self.assertRaisesRegex(TypeError, "read-only"):
                            lease._view = object()  # type: ignore[attr-defined]

                    forged = object.__new__(lease_type)
                    with self.subTest(kind=lease_type.__name__, check="forge"):
                        with self.assertRaisesRegex(
                            posix_io.VerificationError, "ownership"
                        ):
                            close(forged)
                    stolen = object.__new__(lease_type)
                    for attribute in lease_type.__slots__:
                        object.__setattr__(
                            stolen,
                            attribute,
                            object.__getattribute__(lease, attribute),
                        )
                    with self.subTest(
                        kind=lease_type.__name__, check="stolen lifetime"
                    ):
                        with self.assertRaisesRegex(
                            posix_io.VerificationError, "ownership"
                        ):
                            close(stolen)
                    raw_view = object.__getattribute__(lease, "_view")
                    with self.subTest(kind=lease_type.__name__, check="raw view"):
                        with self.assertRaisesRegex(
                            posix_io.VerificationError, "exact backend type"
                        ):
                            close(raw_view)
            finally:
                posix_io.close_created_output(created_output)
                posix_io.close_pinned_output(pinned_output)
                posix_io.close_pinned_directory(pinned_directory)

    def test_formal_facade_rejects_closed_and_invalid_sequence_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_directory = root / "input"
            output_directory = root / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "item").write_bytes(b"item")

            pinned_directory = posix_io.pin_directory(
                input_directory, "closed facade input"
            )
            with self.assertRaisesRegex(
                posix_io.VerificationError, "exact backend type"
            ):
                posix_io.pin_output(output_directory / "invalid", [object()])

            pinned_output = posix_io.pin_output(
                output_directory / "result", [pinned_directory]
            )
            created_output = posix_io.write_create_only(pinned_output, b"result")
            try:
                for operation in (
                    lambda: posix_io.require_pinned_output_parents_stable(
                        [pinned_output, object()], [pinned_directory]
                    ),
                    lambda: posix_io.require_pinned_output_parents_stable(
                        [pinned_output], [pinned_directory, object()]
                    ),
                    lambda: posix_io.require_outputs_absent([pinned_output, object()]),
                    lambda: posix_io.require_fresh_private_output_directories(
                        [pinned_output, object()]
                    ),
                    lambda: posix_io.require_created_outputs_stable(
                        [created_output, object()]
                    ),
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "exact backend type"
                    ):
                        operation()
                for operation in (
                    lambda: posix_io.require_outputs_absent(
                        [pinned_output, pinned_output]
                    ),
                    lambda: posix_io.require_created_outputs_stable(
                        [created_output, created_output]
                    ),
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "duplicate lease"
                    ):
                        operation()

                posix_io.close_created_output(created_output)
                with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                    posix_io.require_created_outputs_stable([created_output])

                posix_io.close_pinned_output(pinned_output)
                for operation in (
                    lambda: pinned_output.name,
                    lambda: pinned_output.directory_identity,
                    lambda: posix_io.require_outputs_absent([pinned_output]),
                    lambda: posix_io.write_create_only(pinned_output, b"again"),
                ):
                    with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                        operation()

                posix_io.close_pinned_directory(pinned_directory)
                for operation in (
                    lambda: posix_io.read_exact_pinned_directory(
                        pinned_directory,
                        ["item"],
                        lambda _name: 8,
                        8,
                        "closed facade input",
                    ),
                    lambda: posix_io.pin_output(
                        output_directory / "closed-input", [pinned_directory]
                    ),
                ):
                    with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                        operation()
            finally:
                posix_io.close_created_output(created_output)
                posix_io.close_pinned_output(pinned_output)
                posix_io.close_pinned_directory(pinned_directory)

    def test_formal_facade_double_close_never_touches_reused_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_directory = root / "input"
            output_directory = root / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)

            pinned_directory = posix_io.pin_directory(
                input_directory, "reused facade input"
            )
            directory_view = object.__getattribute__(pinned_directory, "_view")
            released_directory_fd = directory_view.directory_fd
            posix_io.close_pinned_directory(pinned_directory)
            reused_fd = os.open(input_directory, os.O_RDONLY | os.O_DIRECTORY)
            if reused_fd != released_directory_fd:
                os.dup2(reused_fd, released_directory_fd)
                os.close(reused_fd)
            try:
                posix_io.close_pinned_directory(pinned_directory)
                os.fstat(released_directory_fd)
            finally:
                os.close(released_directory_fd)

            pinned_output = posix_io.pin_output(output_directory / "result", [])
            output_view = object.__getattribute__(pinned_output, "_view")
            released_output_fd = output_view.directory_fd
            posix_io.close_pinned_output(pinned_output)
            reused_fd = os.open(output_directory, os.O_RDONLY | os.O_DIRECTORY)
            if reused_fd != released_output_fd:
                os.dup2(reused_fd, released_output_fd)
                os.close(reused_fd)
            try:
                posix_io.close_pinned_output(pinned_output)
                os.fstat(released_output_fd)
            finally:
                os.close(released_output_fd)

            pinned_output = posix_io.pin_output(output_directory / "result", [])
            created_output = posix_io.write_create_only(pinned_output, b"result")
            created_view = object.__getattribute__(created_output, "_view")
            released_created_fd = created_view.file_fd
            posix_io.close_created_output(created_output)
            reused_fd = os.open(output_directory / "result", os.O_RDONLY)
            if reused_fd != released_created_fd:
                os.dup2(reused_fd, released_created_fd)
                os.close(reused_fd)
            try:
                posix_io.close_created_output(created_output)
                os.fstat(released_created_fd)
            finally:
                os.close(released_created_fd)
                posix_io.close_pinned_output(pinned_output)

    def test_formal_facade_close_interruption_permanently_poison_leases(self) -> None:
        interruption = KeyboardInterrupt("synthetic facade close interruption")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_directory = root / "input"
            output_directory = root / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "item").write_bytes(b"item")

            pinned_directory = posix_io.pin_directory(
                input_directory, "interrupted facade input"
            )
            directory_view = object.__getattribute__(pinned_directory, "_view")
            with (
                mock.patch.object(posix_io, "_close_fd", side_effect=interruption),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                posix_io.close_pinned_directory(pinned_directory)
            self.assertIs(raised.exception, interruption)
            with mock.patch.object(posix_io, "_close_fd") as retried:
                posix_io.close_pinned_directory(pinned_directory)
            retried.assert_not_called()
            with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                posix_io.read_exact_pinned_directory(
                    pinned_directory,
                    ["item"],
                    lambda _name: 8,
                    8,
                    "interrupted facade input",
                )
            os.close(directory_view.directory_fd)

            pinned_output = posix_io.pin_output(output_directory / "result", [])
            output_view = object.__getattribute__(pinned_output, "_view")
            with (
                mock.patch.object(posix_io, "_close_fd", side_effect=interruption),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                posix_io.close_pinned_output(pinned_output)
            self.assertIs(raised.exception, interruption)
            with mock.patch.object(posix_io, "_close_fd") as retried:
                posix_io.close_pinned_output(pinned_output)
            retried.assert_not_called()
            with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                posix_io.require_outputs_absent([pinned_output])
            os.close(output_view.directory_fd)

            pinned_output = posix_io.pin_output(output_directory / "result", [])
            created_output = posix_io.write_create_only(pinned_output, b"result")
            created_view = object.__getattribute__(created_output, "_view")
            with (
                mock.patch.object(posix_io, "_close_fd", side_effect=interruption),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                posix_io.close_created_output(created_output)
            self.assertIs(raised.exception, interruption)
            with mock.patch.object(posix_io, "_close_fd") as retried:
                posix_io.close_created_output(created_output)
            retried.assert_not_called()
            with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                posix_io.require_created_outputs_stable([created_output])
            os.close(created_view.file_fd)
            posix_io.close_pinned_output(pinned_output)

    def test_exact_directory_enforces_cumulative_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"aaaaaa")
            (root / "b").write_bytes(b"bbbbbb")
            with self.assertRaisesRegex(
                posix_io.VerificationError, "remaining directory total limit"
            ):
                posix_io._read_exact_directory(
                    root,
                    ["a", "b"],
                    lambda _name: 6,
                    11,
                    "budget fixture",
                )
            self.assertEqual(
                posix_io._read_exact_directory(
                    root,
                    ["a", "b"],
                    lambda _name: 6,
                    12,
                    "budget fixture",
                ),
                {"a": b"aaaaaa", "b": b"bbbbbb"},
            )

            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(os, "read", return_value=b"1234567"):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError,
                        "remaining directory total limit",
                    ):
                        posix_io._read_regular_file_at(
                            directory_fd,
                            "a",
                            64,
                            6,
                            "growing budget fixture/a",
                        )
            finally:
                os.close(directory_fd)

    def test_directory_and_entry_identities_are_stable_end_to_end(self) -> None:
        with self.subTest("directory changes between lstat and open"):
            with tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "input"
                moved = parent / "moved-input"
                root.mkdir()
                (root / "item").write_bytes(b"original")
                real_open = os.open
                swapped = False

                def swap_directory_open(
                    path: Any,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal swapped
                    if not swapped and path == root.name and dir_fd is not None:
                        swapped = True
                        root.rename(moved)
                        root.mkdir()
                        (root / "item").write_bytes(b"replacement")
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with (
                    mock.patch.object(
                        posix_io, "_require_secure_posix_fs_capabilities"
                    ),
                    mock.patch.object(os, "open", side_effect=swap_directory_open),
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "directory changed before"
                    ):
                        posix_io._read_exact_directory(
                            root,
                            ["item"],
                            lambda _name: 64,
                            64,
                            "identity fixture",
                        )

        with self.subTest("entry changes between visible stat and open"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                item = root / "item"
                moved = root / "moved"
                item.write_bytes(b"original")
                real_open = os.open
                swapped = False

                def swap_entry_open(
                    path: Any,
                    flags: int,
                    mode: int = 0o777,
                    *,
                    dir_fd: int | None = None,
                ) -> int:
                    nonlocal swapped
                    if not swapped and path == "item" and dir_fd is not None:
                        swapped = True
                        item.rename(moved)
                        item.write_bytes(b"replacement")
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with (
                    mock.patch.object(
                        posix_io, "_require_secure_posix_fs_capabilities"
                    ),
                    mock.patch.object(os, "open", side_effect=swap_entry_open),
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "changed before it was opened"
                    ):
                        posix_io._read_exact_directory(
                            root,
                            ["item"],
                            lambda _name: 64,
                            64,
                            "identity fixture",
                        )

        with self.subTest("entry changes after its read"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                item = root / "item"
                item.write_bytes(b"original")
                real_reader = posix_io._read_regular_file_at

                def replace_after_read(
                    directory_fd: int,
                    name: str,
                    limit: int,
                    remaining_total: int,
                    label: str,
                ) -> tuple[bytes, posix_io.StatIdentity]:
                    result = real_reader(
                        directory_fd, name, limit, remaining_total, label
                    )
                    item.unlink()
                    item.write_bytes(b"replaced")
                    return result

                with mock.patch.object(
                    posix_io,
                    "_read_regular_file_at",
                    side_effect=replace_after_read,
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "changed after it was read"
                    ):
                        posix_io._read_exact_directory(
                            root,
                            ["item"],
                            lambda _name: 64,
                            64,
                            "identity fixture",
                        )

        with self.subTest("directory changes after its entries are read"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "item").write_bytes(b"original")
                real_reader = posix_io._read_regular_file_at

                def mutate_directory_after_read(
                    directory_fd: int,
                    name: str,
                    limit: int,
                    remaining_total: int,
                    label: str,
                ) -> tuple[bytes, posix_io.StatIdentity]:
                    result = real_reader(
                        directory_fd, name, limit, remaining_total, label
                    )
                    transient = root / "transient"
                    transient.write_bytes(b"change")
                    transient.unlink()
                    return result

                with mock.patch.object(
                    posix_io,
                    "_read_regular_file_at",
                    side_effect=mutate_directory_after_read,
                ):
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "directory changed during"
                    ):
                        posix_io._read_exact_directory(
                            root,
                            ["item"],
                            lambda _name: 64,
                            64,
                            "identity fixture",
                        )

    def test_exact_input_is_immutable_stable_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "descriptor.json").write_bytes(b'{"schema":"fixture"}\n')
            (root / "payload").write_bytes(b"payload\n")
            limits = {"descriptor.json": 128, "payload": 128}
            self.assertFalse(hasattr(posix_io, "_resolve_github_materials"))
            self.assertFalse(
                hasattr(posix_io, "_authority_commit_from_actions_environment")
            )
            self.assertFalse(hasattr(posix_io, "build_opener"))
            with posix_io.open_exact_input(root, limits, 256, "build input") as opened:
                self.assertEqual(opened.resolved_path, root.resolve())
                self.assertEqual(opened.files["payload"], b"payload\n")
                with self.assertRaises(TypeError):
                    opened.files["payload"] = b"changed"  # type: ignore[index]
                opened.revalidate(rehash=False)
                opened.revalidate()
                held_fd = opened._directory.directory_fd
                os.fstat(held_fd)
            with self.assertRaises(OSError):
                os.fstat(held_fd)

    def test_exact_input_rejects_reused_fd_after_context_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "item").write_bytes(b"value")
            with posix_io.open_exact_input(
                root, {"item": 16}, 16, "short-lived input"
            ) as opened:
                stale = opened
                released_fd = opened._directory.directory_fd

            reopened_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            if reopened_fd != released_fd:
                os.dup2(reopened_fd, released_fd)
                os.close(reopened_fd)
            try:
                self.assertEqual(os.fstat(released_fd).st_ino, root.stat().st_ino)
                with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                    stale.revalidate()
            finally:
                os.close(released_fd)

    def test_exact_input_is_opaque_and_closes_before_releasing_fd(self) -> None:
        with self.assertRaisesRegex(TypeError, "cannot be constructed directly"):
            posix_io.ExactInput()
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("ForgedExactInput", (posix_io.ExactInput,), {})
        forged = object.__new__(posix_io.ExactInput)
        with self.assertRaisesRegex(posix_io.VerificationError, "ownership"):
            forged.revalidate()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "item").write_bytes(b"value")
            real_close = posix_io._close_pinned_directory
            opened: posix_io.ExactInput | None = None

            def require_closed_before_release(
                pinned: posix_io._PinnedDirectory,
            ) -> None:
                if opened is not None and pinned is opened._directory:
                    self.assertTrue(opened._closed)
                real_close(pinned)

            with mock.patch.object(
                posix_io,
                "_close_pinned_directory",
                side_effect=require_closed_before_release,
            ):
                with posix_io.open_exact_input(
                    root, {"item": 16}, 16, "opaque input"
                ) as opened:
                    forged_with_stolen_lifetime = object.__new__(posix_io.ExactInput)
                    object.__setattr__(
                        forged_with_stolen_lifetime, "_lifetime", opened._lifetime
                    )
                    with self.assertRaisesRegex(
                        posix_io.VerificationError, "ownership"
                    ):
                        forged_with_stolen_lifetime.revalidate()
                    for operation in (
                        lambda: copy.copy(opened),
                        lambda: copy.deepcopy(opened),
                        lambda: pickle.dumps(opened),
                    ):
                        with self.assertRaisesRegex(
                            TypeError, "opaque input cannot be copied or serialized"
                        ):
                            operation()
                    with self.assertRaisesRegex(TypeError, "dataclass"):
                        replace(opened, _lifetime=object())
                    copy_replace = getattr(copy, "replace", None)
                    if copy_replace is not None:
                        with self.assertRaisesRegex(
                            TypeError, "opaque input cannot be copied or serialized"
                        ):
                            copy_replace(opened, _lifetime=object())
                    opened.revalidate()

    def test_exact_input_cleanup_rethrows_after_one_close_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "item").write_bytes(b"value")
            interruption = KeyboardInterrupt("synthetic input close interruption")
            attempts = 0
            opened: posix_io.ExactInput | None = None
            real_close = posix_io._close_pinned_directory

            def interrupt_owned_close(pinned: posix_io._PinnedDirectory) -> None:
                nonlocal attempts
                if opened is not None and pinned is opened._directory:
                    attempts += 1
                    raise interruption
                real_close(pinned)

            with self.assertRaises(KeyboardInterrupt) as raised:
                with mock.patch.object(
                    posix_io,
                    "_close_pinned_directory",
                    side_effect=interrupt_owned_close,
                ):
                    with posix_io.open_exact_input(
                        root, {"item": 16}, 16, "interrupted input"
                    ) as opened:
                        released_fd = opened._directory.directory_fd

            self.assertIs(raised.exception, interruption)
            self.assertEqual(attempts, 1)
            assert opened is not None
            self.assertTrue(opened._closed)
            with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                opened.revalidate()
            os.fstat(released_fd)
            os.close(released_fd)

    def test_exact_output_rejects_closed_disjoint_input_with_reused_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            input_directory = parent / "input"
            output_directory = parent / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "item").write_bytes(b"value")
            with posix_io.open_exact_input(
                input_directory, {"item": 16}, 16, "closed input"
            ) as opened:
                stale = opened
                released_fd = opened._directory.directory_fd

            reopened_fd = os.open(input_directory, os.O_RDONLY | os.O_DIRECTORY)
            if reopened_fd != released_fd:
                os.dup2(reopened_fd, released_fd)
                os.close(reopened_fd)
            created: posix_io.ExactOutput | None = None
            try:
                with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                    created = posix_io.create_exact_output(
                        output_directory,
                        {"result": b"result"},
                        [stale],
                        "stale-bound output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )
            finally:
                if created is not None:
                    created.close()
                os.close(released_fd)
            self.assertEqual(list(output_directory.iterdir()), [])

    def test_exact_input_rejects_path_file_and_content_drift(self) -> None:
        with self.subTest("directory replacement"):
            with tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "input"
                moved = parent / "moved"
                root.mkdir()
                (root / "item").write_bytes(b"same")
                with self.assertRaises(posix_io.VerificationError):
                    with posix_io.open_exact_input(
                        root, {"item": 16}, 16, "replaceable input"
                    ):
                        root.rename(moved)
                        root.mkdir()
                        (root / "item").write_bytes(b"same")

        with self.subTest("ancestor replacement"):
            with tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                ancestor = parent / "ancestor"
                root = ancestor / "input"
                moved = parent / "moved-ancestor"
                root.mkdir(parents=True)
                (root / "item").write_bytes(b"same")
                with self.assertRaises(posix_io.VerificationError):
                    with posix_io.open_exact_input(
                        root, {"item": 16}, 16, "ancestor-bound input"
                    ):
                        ancestor.rename(moved)
                        root.mkdir(parents=True)
                        (root / "item").write_bytes(b"same")

        for mutation_name, mutate in (
            (
                "file replacement",
                lambda item: (item.unlink(), item.write_bytes(b"same")),
            ),
            ("content rewrite", lambda item: item.write_bytes(b"diff")),
        ):
            with self.subTest(
                mutation_name
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "input"
                root.mkdir()
                item = root / "item"
                item.write_bytes(b"same")
                with self.assertRaises(posix_io.VerificationError):
                    with posix_io.open_exact_input(
                        root, {"item": 16}, 16, "mutable input"
                    ):
                        mutate(item)

    def test_exact_input_rejects_non_exact_and_aliased_files(self) -> None:
        for mutation_name in ("missing", "extra", "casefold", "symlink", "hardlink"):
            with self.subTest(
                mutation_name
            ), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "input"
                root.mkdir()
                limits = {"item": 16}
                item = root / "item"
                if mutation_name != "missing":
                    item.write_bytes(b"value")
                if mutation_name == "extra":
                    (root / "extra").write_bytes(b"extra")
                elif mutation_name == "casefold":
                    limits["ITEM"] = 16
                elif mutation_name == "symlink":
                    item.unlink()
                    outside = parent / "outside"
                    outside.write_bytes(b"value")
                    item.symlink_to(outside)
                elif mutation_name == "hardlink":
                    os.link(item, parent / "outside-link")
                with self.assertRaises(posix_io.VerificationError):
                    with posix_io.open_exact_input(root, limits, 32, "unsafe input"):
                        self.fail("unsafe exact input was accepted")

    def test_exact_output_is_private_durable_exact_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            input_directory = parent / "input"
            output_directory = parent / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "source").write_bytes(b"source")
            real_fsync = os.fsync
            synced_directory = False

            def track_fsync(file_fd: int) -> None:
                nonlocal synced_directory
                if stat.S_ISDIR(os.fstat(file_fd).st_mode):
                    synced_directory = True
                real_fsync(file_fd)

            with posix_io.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                self.assertFalse(hasattr(posix_io, "_resolve_github_materials"))
                self.assertFalse(
                    hasattr(posix_io, "_authority_commit_from_actions_environment")
                )
                self.assertFalse(hasattr(posix_io, "build_opener"))
                with mock.patch.object(os, "fsync", side_effect=track_fsync):
                    output = posix_io.create_exact_output(
                        output_directory,
                        {"binary": b"binary", "sbom.json": b"{}\n"},
                        [opened],
                        "build output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )
                    with output:
                        resolved = output.resolved_path
                        output.revalidate()
                        held_output_directory_fd = output._directory.directory_fd
                        os.fstat(held_output_directory_fd)
            self.assertEqual(resolved, output_directory.resolve())
            with self.assertRaises(OSError):
                os.fstat(held_output_directory_fd)
            self.assertTrue(synced_directory)
            self.assertEqual(
                sorted(path.name for path in output_directory.iterdir()),
                ["binary", "sbom.json"],
            )
            self.assertEqual((output_directory / "binary").read_bytes(), b"binary")
            for path in output_directory.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)

    def test_exact_output_is_opaque_and_closes_before_releasing_fds(self) -> None:
        with self.assertRaisesRegex(TypeError, "cannot be constructed directly"):
            posix_io.ExactOutput()
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("ForgedExactOutput", (posix_io.ExactOutput,), {})
        forged = object.__new__(posix_io.ExactOutput)
        with self.assertRaisesRegex(posix_io.VerificationError, "ownership"):
            forged.close()

        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"result": b"result"},
                [],
                "opaque output",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            forged_with_stolen_lifetime = object.__new__(posix_io.ExactOutput)
            object.__setattr__(
                forged_with_stolen_lifetime, "_lifetime", output._lifetime
            )
            with self.assertRaisesRegex(posix_io.VerificationError, "ownership"):
                forged_with_stolen_lifetime.close()
            for operation in (
                lambda: copy.copy(output),
                lambda: copy.deepcopy(output),
                lambda: pickle.dumps(output),
            ):
                with self.assertRaisesRegex(
                    TypeError, "opaque output cannot be copied or serialized"
                ):
                    operation()
            with self.assertRaisesRegex(TypeError, "dataclass"):
                replace(output, _lifetime=object())
            copy_replace = getattr(copy, "replace", None)
            if copy_replace is not None:
                with self.assertRaisesRegex(
                    TypeError, "opaque output cannot be copied or serialized"
                ):
                    copy_replace(output, _lifetime=object())

            released_directory_fd = output._directory.directory_fd
            released_file_fd = output._created_outputs[0].file_fd
            real_close = posix_io._close_fd

            def require_closed_before_release(file_fd: int) -> None:
                self.assertTrue(output._closed)
                real_close(file_fd)

            with mock.patch.object(
                posix_io, "_close_fd", side_effect=require_closed_before_release
            ):
                output.close()

            reused_directory_fd = os.open(
                output_directory, os.O_RDONLY | os.O_DIRECTORY
            )
            if reused_directory_fd != released_directory_fd:
                os.dup2(reused_directory_fd, released_directory_fd)
                os.close(reused_directory_fd)
            reused_file_fd = os.open(output_directory / "result", os.O_RDONLY)
            if reused_file_fd != released_file_fd:
                os.dup2(reused_file_fd, released_file_fd)
                os.close(reused_file_fd)
            try:
                with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                    output.revalidate()
                output.close()
                os.fstat(released_directory_fd)
                os.fstat(released_file_fd)
            finally:
                os.close(released_file_fd)
                os.close(released_directory_fd)

    def test_exact_output_concurrent_close_has_one_cleanup_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"one": b"one", "two": b"two"},
                [],
                "concurrent output",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            owned_fds = tuple(
                created.file_fd for created in output._created_outputs
            ) + (output._directory.directory_fd,)
            start = threading.Barrier(3)
            attempted: list[int] = []
            attempt_lock = threading.Lock()
            errors: list[BaseException] = []
            real_close = posix_io._close_fd
            cleanup_started = threading.Event()
            release_cleanup = threading.Event()

            def track_close(file_fd: int) -> None:
                with attempt_lock:
                    attempted.append(file_fd)
                    first_attempt = len(attempted) == 1
                if first_attempt:
                    cleanup_started.set()
                    if not release_cleanup.wait(timeout=5):
                        raise AssertionError("concurrent close test timed out")
                real_close(file_fd)

            def close_from_thread() -> None:
                try:
                    start.wait()
                    output.close()
                except BaseException as error:
                    errors.append(error)

            threads = [threading.Thread(target=close_from_thread) for _ in range(2)]
            with mock.patch.object(posix_io, "_close_fd", side_effect=track_close):
                for thread in threads:
                    thread.start()
                start.wait()
                self.assertTrue(cleanup_started.wait(timeout=5))
                try:
                    for thread in threads:
                        thread.join(timeout=0.05)
                    self.assertTrue(all(thread.is_alive() for thread in threads))
                finally:
                    release_cleanup.set()
                for thread in threads:
                    thread.join(timeout=5)

            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertCountEqual(attempted, owned_fds)
            self.assertEqual(len(attempted), len(owned_fds))

    def test_exact_output_close_before_cleanup_is_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"one": b"one", "two": b"two"},
                [],
                "pre-cleanup interruption",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            owned_fds = tuple(
                created.file_fd for created in output._created_outputs
            ) + (output._directory.directory_fd,)
            source, start_line = inspect.getsourcelines(
                posix_io._ExactIoLifetime.close_with
            )
            cleanup_line = start_line + next(
                index
                for index, line in enumerate(source)
                if line.strip() == "cleanup(attempt)"
            )
            interruption = KeyboardInterrupt("synthetic pre-cleanup interruption")
            armed = True

            def interrupt_before_cleanup(frame: Any, event: str, _argument: Any) -> Any:
                nonlocal armed
                if (
                    armed
                    and event == "line"
                    and frame.f_code.co_filename
                    == str(Path(posix_io.__file__).resolve())
                    and frame.f_lineno == cleanup_line
                ):
                    armed = False
                    raise interruption
                return interrupt_before_cleanup

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_before_cleanup)
                with (
                    mock.patch.object(posix_io, "_close_fd") as first_attempt,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    output.close()
            finally:
                sys.settrace(previous_trace)

            self.assertIs(raised.exception, interruption)
            first_attempt.assert_not_called()
            self.assertFalse(output._closed)
            attempted: list[int] = []
            real_close = posix_io._close_fd

            def track_close(file_fd: int) -> None:
                attempted.append(file_fd)
                real_close(file_fd)

            with mock.patch.object(posix_io, "_close_fd", side_effect=track_close):
                output.close()
            self.assertEqual(attempted, list(owned_fds))

    def test_exact_output_interrupt_after_cleanup_is_not_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"one": b"one", "two": b"two"},
                [],
                "post-cleanup interruption",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            owned_fds = tuple(
                created.file_fd for created in output._created_outputs
            ) + (output._directory.directory_fd,)
            source, start_line = inspect.getsourcelines(
                posix_io._ExactIoLifetime.close_with
            )
            final_closed_line = start_line + next(
                index
                for index, line in enumerate(source)
                if line.strip() == "self._state = _EXACT_IO_CLOSED"
            )
            interruption = KeyboardInterrupt("synthetic post-cleanup interruption")
            armed = True
            attempted: list[int] = []
            real_close = posix_io._close_fd

            def interrupt_before_final_closed(
                frame: Any, event: str, _argument: Any
            ) -> Any:
                nonlocal armed
                if (
                    armed
                    and event == "line"
                    and frame.f_code.co_filename
                    == str(Path(posix_io.__file__).resolve())
                    and frame.f_lineno == final_closed_line
                ):
                    armed = False
                    raise interruption
                return interrupt_before_final_closed

            def track_close(file_fd: int) -> None:
                attempted.append(file_fd)
                real_close(file_fd)

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_before_final_closed)
                with (
                    mock.patch.object(posix_io, "_close_fd", side_effect=track_close),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    output.close()
            finally:
                sys.settrace(previous_trace)

            self.assertIs(raised.exception, interruption)
            self.assertEqual(attempted, list(owned_fds))
            self.assertTrue(output._closed)
            for file_fd in owned_fds:
                with self.assertRaises(OSError):
                    os.fstat(file_fd)
            with mock.patch.object(posix_io, "_close_fd") as retried:
                output.close()
            retried.assert_not_called()

    def test_exact_output_reentrant_close_is_rejected_while_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"result": b"result"},
                [],
                "reentrant output",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            owned_fds = {
                *(created.file_fd for created in output._created_outputs),
                output._directory.directory_fd,
            }
            close_errors: list[posix_io.VerificationError] = []
            owned_close_attempts: list[int] = []
            attempted = False
            real_components = posix_io._path_component_identities
            real_close = posix_io._close_fd

            def attempt_reentrant_close(*args: Any, **kwargs: Any) -> Any:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    try:
                        output.close()
                    except posix_io.VerificationError as error:
                        close_errors.append(error)
                return real_components(*args, **kwargs)

            def track_owned_close(file_fd: int) -> None:
                if file_fd in owned_fds:
                    owned_close_attempts.append(file_fd)
                real_close(file_fd)

            with (
                mock.patch.object(
                    posix_io,
                    "_path_component_identities",
                    side_effect=attempt_reentrant_close,
                ),
                mock.patch.object(posix_io, "_close_fd", side_effect=track_owned_close),
            ):
                output.revalidate()

            self.assertEqual(len(close_errors), 1)
            self.assertRegex(str(close_errors[0]), "active operation")
            self.assertEqual(owned_close_attempts, [])
            self.assertFalse(output._closed)
            output.close()

    def test_exact_output_close_attempts_all_fds_then_rethrows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = posix_io.create_exact_output(
                output_directory,
                {"one": b"one", "two": b"two"},
                [],
                "interrupted output",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            owned_fds = tuple(
                created.file_fd for created in output._created_outputs
            ) + (output._directory.directory_fd,)
            interruption = KeyboardInterrupt("synthetic output close interruption")
            attempted: list[int] = []
            real_close = posix_io._close_fd

            def interrupt_first_close(file_fd: int) -> None:
                attempted.append(file_fd)
                if len(attempted) == 1:
                    raise interruption
                real_close(file_fd)

            with (
                mock.patch.object(
                    posix_io, "_close_fd", side_effect=interrupt_first_close
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                output.close()

            self.assertIs(raised.exception, interruption)
            self.assertEqual(attempted, list(owned_fds))
            with mock.patch.object(posix_io, "_close_fd") as retried:
                output.close()
            retried.assert_not_called()
            os.fstat(owned_fds[0])
            for file_fd in owned_fds[1:]:
                with self.assertRaises(OSError):
                    os.fstat(file_fd)
            os.close(owned_fds[0])

    def test_failed_exact_output_alias_rejects_reused_fds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            captured: list[posix_io.ExactOutput] = []

            def capture_then_reject(output: posix_io.ExactOutput) -> None:
                captured.append(output)
                raise posix_io.VerificationError("synthetic final rejection")

            with (
                mock.patch.object(
                    posix_io.ExactOutput,
                    "revalidate",
                    autospec=True,
                    side_effect=capture_then_reject,
                ),
                self.assertRaisesRegex(
                    posix_io.VerificationError, "synthetic final rejection"
                ),
            ):
                posix_io.create_exact_output(
                    output_directory,
                    {"result": b"result"},
                    [],
                    "rejected output",
                    **EXACT_OUTPUT_TEST_BUDGETS,
                )

            self.assertEqual(len(captured), 1)
            stale = captured[0]
            released_directory_fd = stale._directory.directory_fd
            released_file_fd = stale._created_outputs[0].file_fd
            reused_directory_fd = os.open(
                output_directory, os.O_RDONLY | os.O_DIRECTORY
            )
            if reused_directory_fd != released_directory_fd:
                os.dup2(reused_directory_fd, released_directory_fd)
                os.close(reused_directory_fd)
            reused_file_fd = os.open(output_directory / "result", os.O_RDONLY)
            if reused_file_fd != released_file_fd:
                os.dup2(reused_file_fd, released_file_fd)
                os.close(reused_file_fd)
            try:
                with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                    stale.revalidate()
                stale.close()
                os.fstat(released_directory_fd)
                os.fstat(released_file_fd)
            finally:
                os.close(released_file_fd)
                os.close(released_directory_fd)

    def test_failed_exact_output_cleanup_attempts_all_fds_then_rethrows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            captured: list[posix_io.ExactOutput] = []
            attempted: list[int] = []
            armed = False
            interruption = KeyboardInterrupt("synthetic failed-create interruption")
            real_close = posix_io._close_fd

            def capture_then_reject(output: posix_io.ExactOutput) -> None:
                nonlocal armed
                captured.append(output)
                armed = True
                raise posix_io.VerificationError("synthetic final rejection")

            def interrupt_first_cleanup(file_fd: int) -> None:
                if not armed:
                    real_close(file_fd)
                    return
                attempted.append(file_fd)
                if len(attempted) == 1:
                    raise interruption
                real_close(file_fd)

            with (
                mock.patch.object(
                    posix_io.ExactOutput,
                    "revalidate",
                    autospec=True,
                    side_effect=capture_then_reject,
                ),
                mock.patch.object(
                    posix_io, "_close_fd", side_effect=interrupt_first_cleanup
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                posix_io.create_exact_output(
                    output_directory,
                    {"one": b"one", "two": b"two"},
                    [],
                    "failed output",
                    **EXACT_OUTPUT_TEST_BUDGETS,
                )

            self.assertIs(raised.exception, interruption)
            self.assertEqual(len(captured), 1)
            stale = captured[0]
            owned_fds = tuple(created.file_fd for created in stale._created_outputs) + (
                stale._directory.directory_fd,
            )
            self.assertEqual(attempted, list(owned_fds))
            with self.assertRaisesRegex(posix_io.VerificationError, "closed"):
                stale.revalidate()
            with mock.patch.object(posix_io, "_close_fd") as retried:
                stale.close()
            retried.assert_not_called()
            os.fstat(owned_fds[0])
            for file_fd in owned_fds[1:]:
                with self.assertRaises(OSError):
                    os.fstat(file_fd)
            os.close(owned_fds[0])

    def test_exact_output_rejects_unsafe_or_nonfresh_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            input_directory = parent / "input"
            input_directory.mkdir()
            (input_directory / "source").write_bytes(b"source")
            with posix_io.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                occupied = parent / "occupied"
                occupied.mkdir(mode=0o700)
                occupied.chmod(0o700)
                (occupied / "existing").write_bytes(b"occupied")
                with self.assertRaises(posix_io.VerificationError):
                    posix_io.create_exact_output(
                        occupied,
                        {"result": b"result"},
                        [opened],
                        "occupied output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

                with self.assertRaises(posix_io.VerificationError):
                    posix_io.create_exact_output(
                        input_directory,
                        {"result": b"result"},
                        [opened],
                        "overlapping output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

                casefold = parent / "casefold"
                casefold.mkdir(mode=0o700)
                casefold.chmod(0o700)
                with self.assertRaises(posix_io.VerificationError):
                    posix_io.create_exact_output(
                        casefold,
                        {"Result": b"one", "result": b"two"},
                        [opened],
                        "casefold output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

                target = parent / "target"
                target.mkdir(mode=0o700)
                target.chmod(0o700)
                alias = parent / "output-link"
                alias.symlink_to(target, target_is_directory=True)
                with self.assertRaises(posix_io.VerificationError):
                    posix_io.create_exact_output(
                        alias,
                        {"result": b"result"},
                        [opened],
                        "linked output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

    def test_exact_output_finally_rechecks_names_after_input_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            input_directory = parent / "input"
            output_directory = parent / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "source").write_bytes(b"source")
            calls = 0
            real_revalidate = posix_io.ExactInput.revalidate

            def replace_output_after_input_check(
                opened: posix_io.ExactInput, rehash: bool = True
            ) -> None:
                nonlocal calls
                real_revalidate(opened, rehash=rehash)
                calls += 1
                if calls == 2:
                    output = output_directory / "result"
                    output.rename(output_directory / "detached-result")
                    output.write_bytes(b"replacement")
                    output.chmod(0o600)

            with posix_io.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                with (
                    mock.patch.object(
                        posix_io.ExactInput,
                        "revalidate",
                        autospec=True,
                        side_effect=replace_output_after_input_check,
                    ),
                    self.assertRaises(posix_io.VerificationError),
                ):
                    posix_io.create_exact_output(
                        output_directory,
                        {"result": b"result"},
                        [opened],
                        "replaceable output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )
            self.assertEqual(calls, 2)
            self.assertEqual((output_directory / "result").read_bytes(), b"replacement")

    def test_exact_output_rechecks_visible_identity_after_final_content_hash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output_directory = parent / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output_path = output_directory / "result"
            detached_path = parent / "detached-result"
            real_sha256 = posix_io._sha256
            result_hash_calls = 0

            def replace_during_final_hash(data: bytes) -> str:
                nonlocal result_hash_calls
                digest = real_sha256(data)
                if data == b"result":
                    result_hash_calls += 1
                    if result_hash_calls == 3:
                        output_path.rename(detached_path)
                        output_path.write_bytes(b"attack")
                        output_path.chmod(0o600)
                return digest

            created: posix_io.ExactOutput | None = None
            try:
                with (
                    mock.patch.object(
                        posix_io, "_sha256", side_effect=replace_during_final_hash
                    ),
                    self.assertRaises(posix_io.VerificationError),
                ):
                    created = posix_io.create_exact_output(
                        output_directory,
                        {"result": b"result"},
                        [],
                        "hash-raced output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )
            finally:
                if created is not None:
                    created.close()
            self.assertEqual(result_hash_calls, 3)
            self.assertEqual(output_path.read_bytes(), b"attack")
            self.assertEqual(detached_path.read_bytes(), b"result")

    def test_exact_output_retains_partial_file_without_name_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            real_write = os.write
            write_calls = 0

            def interrupt_write(file_fd: int, data: bytes | memoryview) -> int:
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    return real_write(file_fd, bytes(data[:1]))
                raise OSError("synthetic interrupted write")

            with (
                mock.patch.object(os, "write", side_effect=interrupt_write),
                mock.patch.object(
                    os,
                    "unlink",
                    side_effect=AssertionError(
                        "visible output names must never be unlinked after failure"
                    ),
                ) as unlink_mock,
                self.assertRaisesRegex(
                    posix_io.VerificationError, "synthetic interrupted write.*retained"
                ),
            ):
                posix_io.create_exact_output(
                    output_directory,
                    {"result": b"complete"},
                    [],
                    "partial output",
                    **EXACT_OUTPUT_TEST_BUDGETS,
                )
            unlink_mock.assert_not_called()
            self.assertEqual((output_directory / "result").read_bytes(), b"c")

    def test_exact_output_enforces_required_count_file_and_total_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            boundary = parent / "boundary"
            boundary.mkdir(mode=0o700)
            boundary.chmod(0o700)
            output = posix_io.create_exact_output(
                boundary,
                {"one": b"1234", "two": b"5678"},
                [],
                "budget boundary",
                maximum_file_count=2,
                maximum_file_bytes=4,
                maximum_total_bytes=8,
            )
            output.close()
            self.assertEqual(
                sorted(path.name for path in boundary.iterdir()), ["one", "two"]
            )

            cases = (
                (
                    "count",
                    {"one": b"1", "two": b"2", "three": b"3"},
                    {
                        "maximum_file_count": 2,
                        "maximum_file_bytes": 4,
                        "maximum_total_bytes": 8,
                    },
                ),
                (
                    "file",
                    {"one": b"12345"},
                    {
                        "maximum_file_count": 2,
                        "maximum_file_bytes": 4,
                        "maximum_total_bytes": 8,
                    },
                ),
                (
                    "total",
                    {"one": b"1234", "two": b"56789"},
                    {
                        "maximum_file_count": 2,
                        "maximum_file_bytes": 5,
                        "maximum_total_bytes": 8,
                    },
                ),
            )
            for name, files, budgets in cases:
                with self.subTest(name=name):
                    target = parent / name
                    target.mkdir(mode=0o700)
                    target.chmod(0o700)
                    with self.assertRaises(posix_io.VerificationError):
                        posix_io.create_exact_output(
                            target, files, [], f"{name} budget output", **budgets
                        )
                    self.assertEqual(list(target.iterdir()), [])

            missing = parent / "missing-budget"
            missing.mkdir(mode=0o700)
            missing.chmod(0o700)
            with self.assertRaises(TypeError):
                posix_io.create_exact_output(
                    missing, {"one": b"1"}, [], "missing budget output"
                )
            self.assertEqual(list(missing.iterdir()), [])

    def test_exact_output_rechecks_final_budget_through_pinned_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            input_directory = parent / "input"
            output_directory = parent / "output"
            input_directory.mkdir()
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            (input_directory / "source").write_bytes(b"source")
            calls = 0
            real_revalidate = posix_io.ExactInput.revalidate

            def grow_output_after_input_check(
                opened: posix_io.ExactInput, rehash: bool = True
            ) -> None:
                nonlocal calls
                real_revalidate(opened, rehash=rehash)
                calls += 1
                if calls == 2:
                    with (output_directory / "result").open("ab") as output:
                        output.write(b"5")

            with posix_io.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                with (
                    mock.patch.object(
                        posix_io.ExactInput,
                        "revalidate",
                        autospec=True,
                        side_effect=grow_output_after_input_check,
                    ),
                    self.assertRaisesRegex(
                        posix_io.VerificationError, "4-byte total output limit"
                    ),
                ):
                    posix_io.create_exact_output(
                        output_directory,
                        {"result": b"1234"},
                        [opened],
                        "growing output",
                        maximum_file_count=1,
                        maximum_file_bytes=8,
                        maximum_total_bytes=4,
                    )
            self.assertEqual((output_directory / "result").read_bytes(), b"12345")
