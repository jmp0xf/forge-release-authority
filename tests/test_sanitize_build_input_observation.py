from __future__ import annotations

import base64
import copy
import json
import ntpath
import os
import tempfile
import unittest
from pathlib import Path

from scripts import sanitize_build_input_observation as sanitizer


SOURCE_COMMIT = "1" * 40
UNIX_TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-musl",
)
WINDOWS_TARGET = "x86_64-pc-windows-msvc"


def _unix_native(value: str) -> dict[str, str]:
    return {
        "encoding": "unix-bytes",
        "raw_base64": base64.b64encode(os.fsencode(value)).decode("ascii"),
    }


def _windows_native(value: str, encoding: str = "windows-wide") -> dict[str, str]:
    return {
        "encoding": encoding,
        "raw_base64": base64.b64encode(value.encode("utf-16-le")).decode("ascii"),
    }


def _extended_windows_local_path(value: str) -> str:
    return "\\\\?\\" + value


def _arguments(target: str, target_directory: str, *, windows: bool) -> list[dict[str, str]]:
    values = [
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
        target,
        "--target-dir",
        target_directory,
    ]
    encoder = _windows_native if windows else _unix_native
    return [encoder(value) for value in values]


def _unix_document(
    *, target: str, cargo: str, working_directory: str, target_directory: str
) -> dict[str, object]:
    return {
        "schema": sanitizer.SOURCE_SCHEMA,
        "purpose": sanitizer.SOURCE_PURPOSE,
        "phase": sanitizer.SOURCE_PHASE,
        "source_commit": {"object_format": "sha1", "oid": SOURCE_COMMIT},
        "target": target,
        "cargo_command": {
            "program": _unix_native(cargo),
            "arguments": _arguments(target, target_directory, windows=False),
            "working_directory": _unix_native(working_directory),
        },
        "windows_msvc_environment": {"status": "not-applicable"},
    }


def _windows_document() -> tuple[dict[str, object], dict[str, str], dict[str, str]]:
    paths = {
        "cargo": r"C:\hostedtoolcache\windows\Rust\cargo.exe",
        "source": r"D:\a\forge\forge",
        "runner_temp": r"D:\a\_temp",
        "build_temp": r"D:\a\_temp\forge-private-build-temp",
        "stage": r"D:\a\forge-stage",
        "cargo_home": r"D:\a\cargo-home",
        "raw": r"D:\a\_temp\forge-private-build-input",
        "isolated_source": r"D:\a\_temp\forge-private-build-temp\forge-source-123\source",
        "target_dir": r"D:\a\_temp\forge-private-build-temp\forge-build-123",
    }
    environment = {
        "GITHUB_WORKSPACE": r"D:\a\forge",
        "ProgramData": r"C:\ProgramData",
        "ProgramFiles": r"C:\Program Files",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
        "RUNNER_TOOL_CACHE": r"C:\hostedtoolcache\windows",
        "RUSTUP_HOME": r"C:\Users\runneradmin\.rustup",
        "SYSTEMROOT": r"C:\Windows",
        "USERPROFILE": r"C:\Users\runneradmin",
    }
    msvc = {
        "path": ";".join(
            (
                r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.44\bin",
                r"C:\Program Files (x86)\Windows Kits\10\bin",
                r"C:\Windows\System32",
                r"D:\a\cargo-home\bin",
            )
        ),
        "lib": ";".join(
            (
                r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.44\lib",
                r"C:\Program Files (x86)\Windows Kits\10\Lib",
            )
        ),
        "include": ";".join(
            (
                r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.44\include",
                r"C:\Program Files (x86)\Windows Kits\10\Include",
            )
        ),
    }
    document: dict[str, object] = {
        "schema": sanitizer.SOURCE_SCHEMA,
        "purpose": sanitizer.SOURCE_PURPOSE,
        "phase": sanitizer.SOURCE_PHASE,
        "source_commit": {"object_format": "sha1", "oid": SOURCE_COMMIT},
        "target": WINDOWS_TARGET,
        "cargo_command": {
            "program": _windows_native(paths["cargo"]),
            "arguments": _arguments(
                WINDOWS_TARGET, paths["target_dir"], windows=True
            ),
            "working_directory": _windows_native(paths["isolated_source"]),
        },
        "windows_msvc_environment": {
            "status": "observed",
            "path": _windows_native(msvc["path"], "windows-utf16le-base64"),
            "lib": _windows_native(msvc["lib"], "windows-utf16le-base64"),
            "include": _windows_native(msvc["include"], "windows-utf16le-base64"),
        },
    }
    return document, paths, environment


def _sanitize_windows(
    document: dict[str, object], *, path_overrides: dict[str, str] | None = None
) -> dict[str, object]:
    _, paths, environment = _windows_document()
    paths.update(path_overrides or {})
    return sanitizer.sanitize_document(
        document,
        target=WINDOWS_TARGET,
        source_commit=SOURCE_COMMIT,
        expected_cargo=paths["cargo"],
        source_root=paths["source"],
        runner_temp=paths["runner_temp"],
        build_temp=paths["build_temp"],
        stage_directory=paths["stage"],
        cargo_home=paths["cargo_home"],
        raw_directory=paths["raw"],
        environment=environment,
    )


class BuildInputSanitizerTests(unittest.TestCase):
    def test_five_targets_produce_only_closed_reported_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = os.fspath(root / "tool" / "cargo")
            source = os.fspath(root / "source")
            runner_temp = os.fspath(root / "runner-temp")
            build_temp = os.fspath(Path(runner_temp) / "forge-private-build-temp")
            stage = os.fspath(root / "stage")
            cargo_home = os.fspath(root / "cargo-home")
            raw = os.fspath(Path(runner_temp) / sanitizer.RAW_DIRECTORY_NAME)
            working_directory = os.fspath(
                Path(build_temp) / "isolated-checkout" / "source"
            )
            target_directory = os.fspath(Path(build_temp) / "target-build")
            for target in UNIX_TARGETS:
                with self.subTest(target=target):
                    summary = sanitizer.sanitize_document(
                        _unix_document(
                            target=target,
                            cargo=cargo,
                            working_directory=working_directory,
                            target_directory=target_directory,
                        ),
                        target=target,
                        source_commit=SOURCE_COMMIT,
                        expected_cargo=cargo,
                        source_root=source,
                        runner_temp=runner_temp,
                        build_temp=build_temp,
                        stage_directory=stage,
                        cargo_home=cargo_home,
                        raw_directory=raw,
                        environment={},
                    )
                    self.assertEqual(summary["schema"], sanitizer.SUMMARY_SCHEMA)
                    self.assertEqual(summary["trust"], sanitizer.SUMMARY_TRUST)
                    self.assertEqual(
                        summary["evidence_status"], sanitizer.SUMMARY_EVIDENCE_STATUS
                    )
                    self.assertEqual(
                        summary["reported_windows_msvc_environment"],
                        {"status": "reported-not-applicable"},
                    )

            windows_document, paths, environment = _windows_document()
            summary = sanitizer.sanitize_document(
                windows_document,
                target=WINDOWS_TARGET,
                source_commit=SOURCE_COMMIT,
                expected_cargo=paths["cargo"],
                source_root=paths["source"],
                runner_temp=paths["runner_temp"],
                build_temp=paths["build_temp"],
                stage_directory=paths["stage"],
                cargo_home=paths["cargo_home"],
                raw_directory=paths["raw"],
                environment=environment,
            )
            windows = summary["reported_windows_msvc_environment"]
            assert isinstance(windows, dict)
            self.assertEqual(windows["status"], "reported-observed")
            self.assertEqual(windows["path"]["entry_count"], 4)
            self.assertEqual(
                windows["path"]["root_classes"],
                ["visual-studio", "windows-sdk", "system", "cargo-home"],
            )

            rendered = json.dumps(summary, sort_keys=True)
            for private_value in (*paths.values(), "runneradmin", "raw_base64"):
                self.assertNotIn(private_value, rendered)

    def test_exact_command_and_source_contract_fail_closed(self) -> None:
        document, paths, _ = _windows_document()
        mutations = (
            ("extra root key", lambda value: value.__setitem__("extra", True)),
            (
                "wrong purpose",
                lambda value: value.__setitem__("purpose", "unknown"),
            ),
            (
                "wrong source",
                lambda value: value["source_commit"].__setitem__("oid", "2" * 40),
            ),
            (
                "wrong argument order",
                lambda value: value["cargo_command"]["arguments"].reverse(),
            ),
            (
                "extra argument",
                lambda value: value["cargo_command"]["arguments"].append(
                    _windows_native("extra")
                ),
            ),
            (
                "working directory outside authority build temp",
                lambda value: value["cargo_command"].__setitem__(
                    "working_directory", _windows_native(r"D:\\outside\\source")
                ),
            ),
            (
                "target directory outside authority build temp",
                lambda value: value["cargo_command"]["arguments"].__setitem__(
                    -1, _windows_native(r"D:\\outside\\target")
                ),
            ),
            (
                "normalized Cargo alias",
                lambda value: value["cargo_command"].__setitem__(
                    "program",
                    _windows_native(
                        ntpath.join(ntpath.dirname(paths["cargo"]), "bin", "..", "cargo.exe")
                    ),
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(document)
                mutate(changed)
                with self.assertRaises(sanitizer.SanitizationError):
                    _sanitize_windows(changed)

        for label, build_temp in (
            ("outside runner temp", r"D:\\outside"),
            ("contains source checkout", paths["source"]),
            ("equals raw namespace", paths["raw"]),
        ):
            with self.subTest(build_temp=label):
                with self.assertRaises(sanitizer.SanitizationError):
                    _sanitize_windows(
                        copy.deepcopy(document),
                        path_overrides={"build_temp": build_temp},
                    )

    def test_json_numbers_are_rejected_without_parser_details(self) -> None:
        for raw in (b'{"unexpected":1}', b'{"unexpected":1.5}', b'{"unexpected":NaN}'):
            with self.subTest(raw=raw):
                with self.assertRaises(sanitizer.SanitizationError) as raised:
                    sanitizer._parse_document(raw)
                self.assertNotIn(raw.decode("ascii"), str(raised.exception))

        huge_integer = b'{"unexpected":' + (b"9" * 5_000) + b"}"
        with self.assertRaises(sanitizer.SanitizationError) as raised:
            sanitizer._parse_document(huge_integer)
        self.assertEqual(
            str(raised.exception), "private observation contains an unexpected JSON number"
        )

    def test_windows_paths_require_drive_absolute_and_do_not_trust_substrings(self) -> None:
        document, _, _ = _windows_document()
        document["cargo_command"]["working_directory"] = _windows_native(
            r"\private-build\source"
        )
        with self.assertRaises(sanitizer.SanitizationError):
            _sanitize_windows(document)

        document, _, _ = _windows_document()
        document["windows_msvc_environment"]["path"] = _windows_native(
            r"C:\evil\Microsoft Visual Studio\bin",
            "windows-utf16le-base64",
        )
        summary = _sanitize_windows(document)
        windows = summary["reported_windows_msvc_environment"]
        assert isinstance(windows, dict)
        self.assertEqual(windows["path"]["root_classes"], ["other-absolute"])

        document, _, _ = _windows_document()
        document["windows_msvc_environment"]["path"] = _windows_native(
            "C:\\", "windows-utf16le-base64"
        )
        summary = _sanitize_windows(document)
        windows = summary["reported_windows_msvc_environment"]
        assert isinstance(windows, dict)
        self.assertEqual(windows["path"]["root_classes"], ["other-absolute"])

        document, _, _ = _windows_document()
        document["windows_msvc_environment"]["path"] = _windows_native(
            ";".join(
                (
                    r"C:\Windows\System32",
                    r"C:\Windows",
                    r"C:\Windows\System32",
                )
            ),
            "windows-utf16le-base64",
        )
        summary = _sanitize_windows(document)
        windows = summary["reported_windows_msvc_environment"]
        assert isinstance(windows, dict)
        self.assertEqual(windows["path"]["root_classes"], ["system"] * 3)

    def test_windows_extended_local_drive_paths_match_plain_authority_roots(self) -> None:
        document, paths, _ = _windows_document()
        document["cargo_command"]["working_directory"] = _windows_native(
            _extended_windows_local_path(paths["isolated_source"])
        )
        document["cargo_command"]["arguments"][-1] = _windows_native(
            _extended_windows_local_path(paths["target_dir"])
        )
        document["windows_msvc_environment"]["path"] = _windows_native(
            ";".join(
                (
                    _extended_windows_local_path(r"C:\Windows\System32"),
                    _extended_windows_local_path(r"D:\a\cargo-home\bin"),
                )
            ),
            "windows-utf16le-base64",
        )

        summary = _sanitize_windows(document)
        windows = summary["reported_windows_msvc_environment"]
        assert isinstance(windows, dict)
        self.assertEqual(windows["path"]["root_classes"], ["system", "cargo-home"])
        self.assertEqual(
            summary["reported_cargo_command"]["working_directory_profile"],
            "absolute-under-authority-build-temp-isolated-source",
        )

    def test_windows_non_local_namespaces_and_drive_relative_paths_are_rejected(self) -> None:
        for path in (
            r"\\server\share\source",
            r"\\.\D:\private-build\source",
            r"\\?\UNC\server\share\source",
            r"D:private-build\source",
        ):
            with self.subTest(path=path):
                document, _, _ = _windows_document()
                document["cargo_command"]["working_directory"] = _windows_native(path)
                with self.assertRaises(sanitizer.SanitizationError):
                    _sanitize_windows(document)

    def test_native_decoding_rejects_noncanonical_nul_odd_and_oversize_values(self) -> None:
        document, _, _ = _windows_document()
        values = (
            "%%%not-base64%%%",
            base64.b64encode(b"x").decode("ascii"),
            base64.b64encode(b"\0\0").decode("ascii"),
            base64.b64encode(b"x" * (sanitizer.MAX_NATIVE_BYTES + 2)).decode(
                "ascii"
            ),
        )
        for raw_base64 in values:
            with self.subTest(size=len(raw_base64)):
                changed = copy.deepcopy(document)
                changed["windows_msvc_environment"]["path"][
                    "raw_base64"
                ] = raw_base64
                with self.assertRaises(sanitizer.SanitizationError):
                    _sanitize_windows(changed)

    def test_error_text_never_repeats_candidate_native_values(self) -> None:
        document, _, _ = _windows_document()
        sentinel = r"C:\private\secret-person\cargo.exe"
        document["cargo_command"]["program"] = _windows_native(sentinel)
        with self.assertRaises(sanitizer.SanitizationError) as raised:
            _sanitize_windows(document)
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertNotIn("secret-person", str(raised.exception))
        self.assertEqual(raised.exception.diagnostic_code, "cargo-program")

        document, _, _ = _windows_document()
        document["cargo_command"]["working_directory"] = _windows_native(
            r"D:\outside\source"
        )
        with self.assertRaises(sanitizer.SanitizationError) as raised:
            _sanitize_windows(document)
        self.assertEqual(raised.exception.diagnostic_code, "cargo-working-directory")

        document, _, _ = _windows_document()
        document["windows_msvc_environment"]["path"] = _windows_native(
            r"relative\tool",
            "windows-utf16le-base64",
        )
        with self.assertRaises(sanitizer.SanitizationError) as raised:
            _sanitize_windows(document)
        self.assertEqual(raised.exception.diagnostic_code, "windows-environment")

        self.assertTrue(
            {"cargo-program", "cargo-working-directory", "windows-environment"}
            <= sanitizer.DIAGNOSTIC_CODES
        )

    def test_consume_removes_raw_on_success_and_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            cargo = os.fspath(root / "cargo")
            source = os.fspath(root / "source")
            stage = os.fspath(root / "stage")
            cargo_home = os.fspath(root / "cargo-home")
            build_temp = os.fspath(runner_temp / "forge-private-build-temp")
            target_directory = os.fspath(Path(build_temp) / "target-build")
            working_directory = os.fspath(
                Path(build_temp) / "isolated-checkout" / "source"
            )

            for valid in (True, False):
                with self.subTest(valid=valid):
                    raw_directory = runner_temp / sanitizer.RAW_DIRECTORY_NAME
                    raw_directory.mkdir(mode=0o700)
                    raw_path = raw_directory / (
                        f"{sanitizer.RAW_FILE_PREFIX}{UNIX_TARGETS[0]}.json"
                    )
                    raw_path.write_bytes(
                        json.dumps(
                            _unix_document(
                                target=UNIX_TARGETS[0],
                                cargo=cargo,
                                working_directory=working_directory,
                                target_directory=target_directory,
                            )
                        ).encode()
                        if valid
                        else b'{"schema":"wrong","schema":"duplicate"}'
                    )
                    if valid:
                        summary = sanitizer.consume_build_input_observation(
                            input_directory=raw_directory,
                            target=UNIX_TARGETS[0],
                            source_commit=SOURCE_COMMIT,
                            expected_cargo=cargo,
                            source_root=source,
                            runner_temp=os.fspath(runner_temp),
                            build_temp=build_temp,
                            stage_directory=stage,
                            cargo_home=cargo_home,
                            environment={},
                        )
                        self.assertEqual(summary["schema"], sanitizer.SUMMARY_SCHEMA)
                    else:
                        with self.assertRaises(sanitizer.SanitizationError):
                            sanitizer.consume_build_input_observation(
                                input_directory=raw_directory,
                                target=UNIX_TARGETS[0],
                                source_commit=SOURCE_COMMIT,
                                expected_cargo=cargo,
                                source_root=source,
                                runner_temp=os.fspath(runner_temp),
                                build_temp=build_temp,
                                stage_directory=stage,
                                cargo_home=cargo_home,
                                environment={},
                            )
                    self.assertFalse(raw_directory.exists())

    @unittest.skipUnless(os.name == "nt", "requires native Windows path semantics")
    def test_windows_consume_removes_raw_and_preserves_only_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            raw_directory = runner_temp / sanitizer.RAW_DIRECTORY_NAME
            raw_directory.mkdir()
            cargo = os.fspath(root / "tool" / "cargo.exe")
            build_temp = runner_temp / "forge-private-build-temp"
            working_directory = os.fspath(
                build_temp / "isolated-checkout" / "source"
            )
            target_directory = os.fspath(build_temp / "target-build")
            document, _, environment = _windows_document()
            document["cargo_command"] = {
                "program": _windows_native(cargo),
                "arguments": _arguments(
                    WINDOWS_TARGET, target_directory, windows=True
                ),
                "working_directory": _windows_native(working_directory),
            }
            raw_path = raw_directory / (
                f"{sanitizer.RAW_FILE_PREFIX}{WINDOWS_TARGET}.json"
            )
            raw_path.write_text(json.dumps(document), encoding="utf-8")

            summary = sanitizer.consume_build_input_observation(
                input_directory=raw_directory,
                target=WINDOWS_TARGET,
                source_commit=SOURCE_COMMIT,
                expected_cargo=cargo,
                source_root=os.fspath(root / "source"),
                runner_temp=os.fspath(runner_temp),
                build_temp=os.fspath(build_temp),
                stage_directory=os.fspath(root / "stage"),
                cargo_home=os.fspath(root / "cargo-home"),
                environment=environment,
            )

            self.assertFalse(raw_directory.exists())
            self.assertEqual(summary["schema"], sanitizer.SUMMARY_SCHEMA)
            self.assertEqual(
                summary["reported_windows_msvc_environment"]["status"],
                "reported-observed",
            )
            rendered = json.dumps(summary, sort_keys=True)
            self.assertNotIn(os.fspath(root), rendered)
            self.assertNotIn("raw_base64", rendered)

    def test_consume_rejects_oversize_and_symlink_without_retaining_raw(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            raw_directory = runner_temp / sanitizer.RAW_DIRECTORY_NAME
            raw_directory.mkdir()
            raw_path = raw_directory / (
                f"{sanitizer.RAW_FILE_PREFIX}{UNIX_TARGETS[0]}.json"
            )
            raw_path.write_bytes(b"x" * (sanitizer.MAX_RAW_BYTES + 1))
            with self.assertRaises(sanitizer.SanitizationError):
                sanitizer.consume_build_input_observation(
                    input_directory=raw_directory,
                    target=UNIX_TARGETS[0],
                    source_commit=SOURCE_COMMIT,
                    expected_cargo=os.fspath(root / "cargo"),
                    source_root=os.fspath(root / "source"),
                    runner_temp=os.fspath(runner_temp),
                    build_temp=os.fspath(
                        runner_temp / "forge-private-build-temp"
                    ),
                    stage_directory=os.fspath(root / "stage"),
                    cargo_home=os.fspath(root / "cargo-home"),
                    environment={},
                )
            self.assertFalse(raw_directory.exists())

            raw_directory.mkdir()
            outside = root / "outside"
            outside.write_text("private", encoding="utf-8")
            raw_path.symlink_to(outside)
            with self.assertRaises(sanitizer.SanitizationError):
                sanitizer.consume_build_input_observation(
                    input_directory=raw_directory,
                    target=UNIX_TARGETS[0],
                    source_commit=SOURCE_COMMIT,
                    expected_cargo=os.fspath(root / "cargo"),
                    source_root=os.fspath(root / "source"),
                    runner_temp=os.fspath(runner_temp),
                    build_temp=os.fspath(
                        runner_temp / "forge-private-build-temp"
                    ),
                    stage_directory=os.fspath(root / "stage"),
                    cargo_home=os.fspath(root / "cargo-home"),
                    environment={},
                )
            self.assertFalse(raw_directory.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "private")

    def test_cleanup_refuses_unexpected_sibling_and_does_not_follow_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            raw_directory = runner_temp / sanitizer.RAW_DIRECTORY_NAME
            raw_directory.mkdir()
            outside = root / "outside"
            outside.write_text("keep", encoding="utf-8")
            (raw_directory / "unexpected").symlink_to(outside)
            with self.assertRaisesRegex(
                sanitizer.SanitizationError, "unexpected entry"
            ):
                sanitizer.cleanup_raw_namespace(
                    raw_directory, runner_temp, UNIX_TARGETS[0]
                )
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_cleanup_removes_fixed_raw_before_reporting_entry_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            raw_directory = runner_temp / sanitizer.RAW_DIRECTORY_NAME
            raw_directory.mkdir()
            raw_path = raw_directory / (
                f"{sanitizer.RAW_FILE_PREFIX}{UNIX_TARGETS[0]}.json"
            )
            raw_path.write_text("private", encoding="utf-8")
            for index in range(5):
                (raw_directory / f"unexpected-{index}").write_text(
                    "keep", encoding="utf-8"
                )

            with self.assertRaisesRegex(
                sanitizer.SanitizationError, "exceeds its entry bound"
            ):
                sanitizer.cleanup_raw_namespace(
                    raw_directory, runner_temp, UNIX_TARGETS[0]
                )

            self.assertFalse(raw_path.exists())
            self.assertTrue(raw_directory.is_dir())
            self.assertEqual(
                sorted(path.name for path in raw_directory.iterdir()),
                [f"unexpected-{index}" for index in range(5)],
            )

    def test_consume_validates_target_before_constructing_a_raw_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary) / "runner-temp"
            runner_temp.mkdir()
            with self.assertRaisesRegex(
                sanitizer.SanitizationError, "outside the five-target canary matrix"
            ):
                sanitizer.consume_build_input_observation(
                    input_directory=runner_temp / sanitizer.RAW_DIRECTORY_NAME,
                    target="../../not-a-target",
                    source_commit=SOURCE_COMMIT,
                    expected_cargo="/cargo",
                    source_root="/source",
                    runner_temp=os.fspath(runner_temp),
                    build_temp=os.fspath(runner_temp / "forge-private-build-temp"),
                    stage_directory="/stage",
                    cargo_home="/cargo-home",
                    environment={},
                )


if __name__ == "__main__":
    unittest.main()
