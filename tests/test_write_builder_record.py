from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import write_builder_record as records

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "contracts" / "release-policy.json"
SOURCE_COMMIT = "a" * 40
AUTHORITY_COMMIT = "b" * 40


class BuilderRecordTests(unittest.TestCase):
    def test_record_is_deterministic_and_binds_exact_assets(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        target = policy["targets"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            outputs = root / "records"
            assets.mkdir()
            outputs.mkdir()
            binary = b"binary bytes"
            sbom = b'{"bomFormat":"CycloneDX"}\n'
            (assets / target["binary"]).write_bytes(binary)
            (assets / target["sbom"]).write_bytes(sbom)

            output = records.write_builder_record(
                POLICY_PATH,
                assets,
                outputs,
                target["triple"],
                SOURCE_COMMIT,
                AUTHORITY_COMMIT,
            )

            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(output.name, target["builderRecord"])
            self.assertEqual(value["target"], target["triple"])
            self.assertEqual(value["runner_label"], target["runnerLabel"])
            self.assertEqual(value["rust_version"], policy["toolchain"]["rust"])
            self.assertEqual(value["source"]["commit"], SOURCE_COMMIT)
            self.assertEqual(value["authority"]["commit"], AUTHORITY_COMMIT)
            self.assertEqual(
                value["binary"],
                {
                    "length": len(binary),
                    "name": target["binary"],
                    "sha256": hashlib.sha256(binary).hexdigest(),
                },
            )
            self.assertEqual(
                value["sbom"],
                {
                    "length": len(sbom),
                    "name": target["sbom"],
                    "sha256": hashlib.sha256(sbom).hexdigest(),
                },
            )
            with self.assertRaises(records.RecordError):
                records.write_builder_record(
                    POLICY_PATH,
                    assets,
                    outputs,
                    target["triple"],
                    SOURCE_COMMIT,
                    AUTHORITY_COMMIT,
                )

    def test_invalid_identity_target_and_policy_fail_closed(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        target = policy["targets"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            outputs = root / "records"
            assets.mkdir()
            outputs.mkdir()
            (assets / target["binary"]).write_bytes(b"binary")
            (assets / target["sbom"]).write_bytes(b"sbom")
            for source_commit, authority_commit, target_triple in (
                ("A" * 40, AUTHORITY_COMMIT, target["triple"]),
                (SOURCE_COMMIT, "short", target["triple"]),
                (SOURCE_COMMIT, AUTHORITY_COMMIT, "unknown-target"),
            ):
                with self.subTest(
                    source_commit=source_commit,
                    authority_commit=authority_commit,
                    target=target_triple,
                ):
                    with self.assertRaises(records.RecordError):
                        records.write_builder_record(
                            POLICY_PATH,
                            assets,
                            outputs,
                            target_triple,
                            source_commit,
                            authority_commit,
                        )

            duplicate_policy = root / "duplicate-policy.json"
            duplicate_policy.write_text(
                '{"schema":"forge.release-authority-policy/v1","schema":"duplicate"}',
                encoding="utf-8",
            )
            with self.assertRaises(records.RecordError):
                records.write_builder_record(
                    duplicate_policy,
                    assets,
                    outputs,
                    target["triple"],
                    SOURCE_COMMIT,
                    AUTHORITY_COMMIT,
                )

    def test_symlink_asset_is_not_recorded(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        target = policy["targets"][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            outputs = root / "records"
            assets.mkdir()
            outputs.mkdir()
            source = root / "outside"
            source.write_bytes(b"binary")
            (assets / target["binary"]).symlink_to(source)
            (assets / target["sbom"]).write_bytes(b"sbom")

            with self.assertRaises(records.RecordError):
                records.write_builder_record(
                    POLICY_PATH,
                    assets,
                    outputs,
                    target["triple"],
                    SOURCE_COMMIT,
                    AUTHORITY_COMMIT,
                )


if __name__ == "__main__":
    unittest.main()
