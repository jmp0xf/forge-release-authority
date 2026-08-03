from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from tests.release_io_test_support import load_release_io_modules


release_io, _release_io_posix = load_release_io_modules()


class DuplicateItems(dict[str, Any]):
    def __init__(self, items: list[tuple[str, Any]]) -> None:
        super().__init__(items[:1])
        self._items = items

    def items(self) -> Any:
        return iter(self._items)


class ReleaseIoTests(unittest.TestCase):
    def test_frozen_file_set_copies_bytes_and_derived_observations(self) -> None:
        source = {"artifact.bin": b"artifact", "metadata.json": b"{}\n"}
        frozen = release_io.FrozenFileSet(
            source,
            "candidate files",
            maximum_file_count=2,
            maximum_file_bytes=16,
            maximum_total_bytes=24,
        )
        source["artifact.bin"] = b"changed"
        self.assertEqual(frozen.names, ("artifact.bin", "metadata.json"))
        self.assertEqual(frozen.files["artifact.bin"], b"artifact")
        self.assertEqual(frozen.total_bytes, 11)
        self.assertEqual(
            frozen.sha256_by_name["artifact.bin"],
            "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c",
        )
        with self.assertRaises(TypeError):
            frozen.files["extra"] = b"no"  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            frozen.label = "changed"  # type: ignore[misc]

    def test_frozen_file_set_is_an_observation_not_an_authority_capability(
        self,
    ) -> None:
        class StructuralLookalike:
            files = {"artifact": b"bytes"}
            names = ("artifact",)

            @property
            def resolved_path(self) -> Any:
                return None

            def revalidate(self, rehash: bool = True) -> None:
                del rehash

            def close(self) -> None:
                return None

        frozen = release_io.FrozenFileSet(
            {"artifact": b"bytes"},
            "observation",
            maximum_file_count=1,
            maximum_file_bytes=8,
            maximum_total_bytes=8,
        )
        self.assertFalse(hasattr(frozen, "readonly_proof"))
        self.assertFalse(hasattr(frozen, "sandbox_permit"))
        with self.assertRaises(TypeError):
            isinstance(frozen, release_io.ExactInputView)
        with self.assertRaises(TypeError):
            isinstance(frozen, release_io.ExactOutputView)
        with self.assertRaises(TypeError):
            isinstance(StructuralLookalike(), release_io.ExactInputView)

    def test_portable_names_are_ascii_and_windows_safe(self) -> None:
        for name in ("artifact", "forge.exe", "metadata-1.json", "a_b+c"):
            with self.subTest(accepted=name):
                self.assertEqual(release_io.require_safe_basename(name, "name"), name)
        for name in (
            "",
            ".",
            "..",
            "../artifact",
            "a/b",
            "a\\b",
            "file:stream",
            "trailing.",
            "trailing ",
            "CON",
            "nul.txt",
            "COM1.log",
            "lpt9",
            "snowman-☃",
            "a" * 256,
        ):
            with self.subTest(rejected=name), self.assertRaises(
                release_io.VerificationError
            ):
                release_io.require_safe_basename(name, "name")

    def test_exact_normalizers_reject_hostile_duplicate_item_streams(self) -> None:
        for names in (("file", "file"), ("File", "file")):
            with self.subTest(input_names=names), self.assertRaises(
                release_io.VerificationError
            ):
                release_io.normalize_exact_file_limits(
                    DuplicateItems([(names[0], 8), (names[1], 8)]),
                    16,
                    "input",
                )
            with self.subTest(output_names=names), self.assertRaises(
                release_io.VerificationError
            ):
                release_io.normalize_exact_output_files(
                    DuplicateItems([(names[0], b"a"), (names[1], b"b")]),
                    "output",
                    maximum_file_count=2,
                    maximum_file_bytes=8,
                    maximum_total_bytes=16,
                )

    def test_exact_normalizers_bound_iteration_and_require_builtin_scalars(
        self,
    ) -> None:
        class IntSubclass(int):
            pass

        class StringSubclass(str):
            pass

        class BytesSubclass(bytes):
            pass

        for invalid_limit in (True, IntSubclass(1)):
            with self.subTest(limit=invalid_limit), self.assertRaises(
                release_io.VerificationError
            ):
                release_io.normalize_exact_file_limits(
                    {"file": invalid_limit}, 8, "input"
                )
        with self.assertRaisesRegex(release_io.VerificationError, "hard cap"):
            release_io.normalize_exact_file_limits(
                {},
                8,
                "input",
                maximum_file_count=release_io.MAX_EXACT_FILE_COUNT + 1,
            )
        with self.assertRaisesRegex(release_io.VerificationError, "hard cap"):
            release_io.normalize_exact_output_files(
                {},
                "output",
                maximum_file_count=release_io.MAX_EXACT_FILE_COUNT + 1,
                maximum_file_bytes=1,
                maximum_total_bytes=1,
            )
        with self.assertRaises(release_io.VerificationError):
            release_io.normalize_exact_file_limits(
                {"first": 1, "second": 1},
                2,
                "input",
                maximum_file_count=1,
            )
        with self.assertRaises(release_io.VerificationError):
            release_io.normalize_exact_output_files(
                {StringSubclass("file"): b"a"},
                "output",
                maximum_file_count=1,
                maximum_file_bytes=1,
                maximum_total_bytes=1,
            )
        with self.assertRaises(release_io.VerificationError):
            release_io.normalize_exact_output_files(
                {"file": BytesSubclass(b"a")},
                "output",
                maximum_file_count=1,
                maximum_file_bytes=1,
                maximum_total_bytes=1,
            )


if __name__ == "__main__":
    unittest.main()
