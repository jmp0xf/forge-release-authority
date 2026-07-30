from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import verify_release as verifier


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "contracts" / "release-policy.json"
FORGE_COMMIT = "a" * 40
AUTHORITY_COMMIT = "b" * 40
LOCK_BYTES = (
    b"version = 4\n\n"
    b"[[package]]\n"
    b'name = "fixture-dependency"\n'
    b'version = "1.0.0"\n'
    b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    + f'checksum = "{"d" * 64}"\n'.encode("ascii")
)
LOCK_DIGEST = hashlib.sha256(LOCK_BYTES).hexdigest()
# Re-run the recorded commands in the Forge checkout at these two input digests,
# join selected packages to release-baseline, then render the projection below.
FORGE_SBOM_GRAPH_DERIVATION_RECEIPT: dict[str, Any] = {
    "projectionSchema": "forge.release-sbom-graph/v1",
    "forgeCommit": "b7a72ffcd099dd86a696e27f61037a41d43fb139",
    "sourceInputs": {
        "Cargo.lock": "2632b36dd2409d528c27f77eac3a4c734d41d85009cc9078b16eadaf4fecee6f",
        "licenses/release-baseline.json": (
            "d979a63fdab612a90da34965e69bf56b3210d02a67b9a2c05a2e88bf9cc75837"
        ),
    },
    "metadataCommand": [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--format-version",
        "1",
        "--filter-platform",
        "<target>",
    ],
    "treeCommand": [
        "cargo",
        "tree",
        "--locked",
        "--offline",
        "-p",
        "forge-cli",
        "--target",
        "<target>",
        "-e",
        "normal,build",
        "--prefix",
        "depth",
        "--format",
        "@@{p}@@",
        "--no-dedupe",
    ],
    "targets": [
        {
            "triple": "x86_64-unknown-linux-musl",
            "componentCount": 86,
            "dependencyEdgeCount": 151,
            "canonicalSha256": (
                "a02a644a2cdc7b46da1b771828cd7fe4b1a76fb2fb58448f7ceec0fdefccdb55"
            ),
        },
        {
            "triple": "aarch64-unknown-linux-musl",
            "componentCount": 85,
            "dependencyEdgeCount": 150,
            "canonicalSha256": (
                "dbd12b827e48d6a61931850e00ac5dcc24b85a05be2986e4df99b5c5ccd4627e"
            ),
        },
        {
            "triple": "x86_64-apple-darwin",
            "componentCount": 86,
            "dependencyEdgeCount": 153,
            "canonicalSha256": (
                "241662b88242609b7c5b6c2d6a02a9114aa26f01d517709b0f00e30efddc7189"
            ),
        },
        {
            "triple": "aarch64-apple-darwin",
            "componentCount": 85,
            "dependencyEdgeCount": 152,
            "canonicalSha256": (
                "d5e37c125fde43d27e8d21736a0793b215a3bb5bc9d9b216c8cc2bdcfffb6469"
            ),
        },
        {
            "triple": "x86_64-pc-windows-msvc",
            "componentCount": 88,
            "dependencyEdgeCount": 152,
            "canonicalSha256": (
                "337ad1adef86fe3def7f4ec02a5cb2f539426a2f6e5a41aaf7eac29d182146f2"
            ),
        },
    ],
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def synthetic_sbom_graph_contract(policy: dict[str, Any]) -> dict[str, Any]:
    """Return the explicit semantic graph contract used only by unit fixtures."""
    root_ref = f"pkg:cargo/forge@{policy['release']['version']}"
    dependency_ref = "urn:forge:cargo:blake3:" + "0" * 64
    root = {
        "bomRef": root_ref,
        "type": "application",
        "name": "forge",
        "version": policy["release"]["version"],
        "source": "workspace",
        "checksum": None,
        "licenseExpression": policy["projectLicenseExpression"],
    }
    dependency = {
        "bomRef": dependency_ref,
        "type": "library",
        "name": "fixture-dependency",
        "version": "1.0.0",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "checksum": "d" * 64,
        "licenseExpression": "MIT",
    }
    projection = {
        "schema": "forge.release-sbom-graph/v1",
        "root": root,
        "components": [dependency],
        "dependencies": [
            {"component": root, "dependsOn": [dependency]},
            {"component": dependency, "dependsOn": []},
        ],
    }
    return {
        "componentCount": 2,
        "dependencyEdgeCount": 1,
        "canonicalSha256": sha256(json_bytes(projection)),
    }


def synthetic_executable(binary_format: str) -> bytes:
    """Build the smallest structure accepted by the independent format parser."""
    if binary_format.startswith("elf64-"):
        data = bytearray(121)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", data, 16, 2)  # ET_EXEC
        machine = 62 if binary_format == "elf64-x86_64-static" else 183
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<I", data, 20, 1)
        struct.pack_into("<Q", data, 24, 0x1000)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 52, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<II", data, 64, 1, 5)  # PT_LOAD, PF_R | PF_X
        struct.pack_into("<Q", data, 72, 120)
        struct.pack_into("<Q", data, 80, 0x1000)
        struct.pack_into("<Q", data, 96, 1)
        struct.pack_into("<Q", data, 104, 1)
        data[120] = 0xC3
        return bytes(data)
    if binary_format.startswith("macho64-"):
        data = bytearray(129)
        data[:4] = b"\xcf\xfa\xed\xfe"
        cpu_type = 0x01000007 if binary_format == "macho64-x86_64" else 0x0100000C
        struct.pack_into("<I", data, 4, cpu_type)
        struct.pack_into("<III", data, 12, 2, 2, 96)  # MH_EXECUTE, two commands
        struct.pack_into("<II", data, 32, 0x19, 72)  # LC_SEGMENT_64
        struct.pack_into("<Q", data, 64, 1)
        struct.pack_into("<QQ", data, 72, 128, 1)
        struct.pack_into("<i", data, 88, 5)  # maximum protection
        struct.pack_into("<i", data, 92, 5)  # VM_PROT_READ | VM_PROT_EXECUTE
        struct.pack_into("<I", data, 96, 0)
        struct.pack_into("<IIQ", data, 104, 0x80000028, 24, 128)  # LC_MAIN
        data[128] = 0xC3
        return bytes(data)
    if binary_format == "pe64-x86_64":
        data = bytearray(241)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x40)
        data[0x40:0x44] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x44, 0x8664)
        struct.pack_into("<H", data, 0x46, 1)
        struct.pack_into("<H", data, 0x54, 112)
        struct.pack_into("<H", data, 0x56, 0x0002)
        struct.pack_into("<H", data, 0x58, 0x20B)
        struct.pack_into("<I", data, 0x68, 0x1000)  # AddressOfEntryPoint
        struct.pack_into("<I", data, 0x90, 0x2000)  # SizeOfImage
        struct.pack_into("<I", data, 0x94, 240)  # SizeOfHeaders
        section_offset = 0x40 + 24 + 112
        struct.pack_into("<II", data, section_offset + 8, 1, 0x1000)
        struct.pack_into("<II", data, section_offset + 16, 1, 240)
        struct.pack_into("<I", data, section_offset + 36, 0x20000020)
        data[240] = 0xC3
        return bytes(data)
    raise AssertionError(f"unsupported fixture format {binary_format}")


def forged_magic_only_header(binary_format: str) -> bytes:
    """Reproduce headers that the earlier shallow parser incorrectly accepted."""
    if binary_format.startswith("elf64-"):
        data = bytearray(64)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into(
            "<H", data, 18, 62 if binary_format == "elf64-x86_64-static" else 183
        )
        struct.pack_into("<H", data, 54, 56)
        return bytes(data)
    if binary_format.startswith("macho64-"):
        data = bytearray(32)
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into(
            "<I",
            data,
            4,
            0x01000007 if binary_format == "macho64-x86_64" else 0x0100000C,
        )
        return bytes(data)
    if binary_format == "pe64-x86_64":
        data = bytearray(96)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", data, 68, 0x8664)
        struct.pack_into("<H", data, 88, 0x20B)
        return bytes(data)
    raise AssertionError(f"unsupported fixture format {binary_format}")


class CandidateFixture:
    """A semantically valid 13-file candidate made from synthetic binaries.

    Minimal structurally valid binaries keep these unit tests portable while
    exercising the same unconditional structure gate as production.
    """

    def __init__(self, root: Path, *, structured_binaries: bool = True) -> None:
        self.root = root
        self.assets = root / "assets"
        self.records = root / "builder-records"
        self.cargo_lock = root / "Cargo.lock"
        self.source_license_notices = root / "source-THIRD-PARTY-LICENSES.txt"
        self.assets.mkdir()
        self.records.mkdir()
        self.cargo_lock.write_bytes(LOCK_BYTES)
        production_policy, _ = verifier.load_policy(POLICY_PATH)
        self.policy = json.loads(json.dumps(production_policy))
        for target in self.policy["targets"]:
            target["sbomGraph"] = synthetic_sbom_graph_contract(self.policy)
        self.policy_path = root / "test-release-policy.json"
        self.policy_path.write_bytes(json_bytes(self.policy))
        self.policy, _ = verifier.load_policy(self.policy_path)
        self.structured_binaries = structured_binaries
        self._write_target_assets()
        notice_bytes = b"Synthetic fixture notice corpus.\n"
        (self.assets / self.policy["release"]["notice"]["name"]).write_bytes(
            notice_bytes
        )
        self.source_license_notices.write_bytes(notice_bytes)
        self.rewrite_manifest_and_checksums()
        self.rewrite_builder_records()

    def _write_target_assets(self) -> None:
        for target in self.policy["targets"]:
            binary = (
                synthetic_executable(target["binaryFormat"])
                if self.structured_binaries
                else f"synthetic binary for {target['triple']}\n".encode("ascii")
            )
            (self.assets / target["binary"]).write_bytes(binary)
            dependency_ref = "urn:forge:cargo:blake3:" + "0" * 64
            bom = {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "bom-ref": dependency_ref,
                        "hashes": [{"alg": "SHA-256", "content": "d" * 64}],
                        "licenses": [{"expression": "MIT"}],
                        "name": "fixture-dependency",
                        "properties": [
                            {
                                "name": "forge:cargo-source",
                                "value": "registry+https://github.com/rust-lang/crates.io-index",
                            }
                        ],
                        "type": "library",
                        "version": "1.0.0",
                    }
                ],
                "dependencies": [
                    {
                        "dependsOn": [dependency_ref],
                        "ref": f"pkg:cargo/forge@{self.policy['release']['version']}",
                    },
                    {"dependsOn": [], "ref": dependency_ref},
                ],
                "metadata": {
                    "component": {
                        "bom-ref": f"pkg:cargo/forge@{self.policy['release']['version']}",
                        "hashes": [{"alg": "SHA-256", "content": sha256(binary)}],
                        "licenses": [
                            {"expression": self.policy["projectLicenseExpression"]}
                        ],
                        "name": "forge",
                        "properties": [
                            {"name": "forge:target-triple", "value": target["triple"]},
                            {"name": "forge:cargo-lock-sha256", "value": LOCK_DIGEST},
                            {"name": "forge:source-commit", "value": FORGE_COMMIT},
                            {"name": "forge:binary-sha256", "value": sha256(binary)},
                            {"name": "forge:binary-length", "value": str(len(binary))},
                        ],
                        "type": "application",
                        "version": self.policy["release"]["version"],
                    }
                },
                "specVersion": "1.6",
                "version": 1,
            }
            (self.assets / target["sbom"]).write_bytes(json_bytes(bom))

    def manifest_value(self) -> dict[str, Any]:
        artifacts = []
        for target in self.policy["targets"]:
            for name, kind in (
                (target["binary"], "binary"),
                (target["sbom"], "cyclonedx-sbom"),
            ):
                data = (self.assets / name).read_bytes()
                artifacts.append(
                    {
                        "kind": kind,
                        "length": len(data),
                        "name": name,
                        "sha256": sha256(data),
                        "target": target["triple"],
                    }
                )
        notice = self.policy["release"]["notice"]
        notice_data = (self.assets / notice["name"]).read_bytes()
        artifacts.append(
            {
                "kind": "license-notices",
                "length": len(notice_data),
                "name": notice["name"],
                "sha256": sha256(notice_data),
                "target": notice["target"],
            }
        )
        artifacts.sort(key=lambda artifact: artifact["name"])
        return {
            "artifacts": artifacts,
            "provenance": {
                "authority_status": "unassigned-external",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signing": "sigstore-keyless-oidc",
                "status": "required-external",
                "subject_set": "exact-finalized-local-assets",
                "subjects": self.policy["release"]["assets"],
            },
            "release": {
                "channel": "release-candidate",
                "distribution": "github-release",
                "status": "local-review-candidate",
                "version": self.policy["release"]["version"],
            },
            "rollback": {
                "previous_release": None,
                "retain_published_releases": 2,
                "status": "first-candidate-no-n-minus-one",
            },
            "schema": self.policy["release"]["manifestSchema"],
        }

    def rewrite_manifest_and_checksums(self) -> None:
        (self.assets / "release-manifest.json").write_bytes(
            json_bytes(self.manifest_value())
        )
        self.rewrite_checksums()

    def rewrite_checksums(self) -> None:
        names = sorted(
            name for name in self.policy["release"]["assets"] if name != "SHA256SUMS"
        )
        text = "".join(
            f"{sha256((self.assets / name).read_bytes())}  {name}\n" for name in names
        )
        (self.assets / "SHA256SUMS").write_text(text, encoding="ascii", newline="")

    def rewrite_builder_records(self) -> None:
        for path in self.records.iterdir():
            path.unlink()
        for target in self.policy["targets"]:
            binary = (self.assets / target["binary"]).read_bytes()
            sbom = (self.assets / target["sbom"]).read_bytes()
            record = {
                "authority": {
                    "commit": AUTHORITY_COMMIT,
                    "owner_id": self.policy["authority"]["ownerId"],
                    "repository_id": self.policy["authority"]["repositoryId"],
                },
                "binary": {
                    "length": len(binary),
                    "name": target["binary"],
                    "sha256": sha256(binary),
                },
                "runner_label": target["runnerLabel"],
                "rust_version": self.policy["toolchain"]["rust"],
                "sbom": {
                    "length": len(sbom),
                    "name": target["sbom"],
                    "sha256": sha256(sbom),
                },
                "schema": self.policy["builderRecords"]["schema"],
                "source": {
                    "commit": FORGE_COMMIT,
                    "owner_id": self.policy["source"]["ownerId"],
                    "repository_id": self.policy["source"]["repositoryId"],
                },
                "target": target["triple"],
            }
            (self.records / target["builderRecord"]).write_bytes(json_bytes(record))

    def verify(self) -> dict[str, Any]:
        return verifier.verify_release(
            self.policy_path,
            self.cargo_lock,
            self.source_license_notices,
            self.assets,
            self.records,
            FORGE_COMMIT,
            AUTHORITY_COMMIT,
        )


class VerifyReleaseTests(unittest.TestCase):
    def fixture(
        self, directory: str, *, structured_binaries: bool = True
    ) -> CandidateFixture:
        return CandidateFixture(
            Path(directory), structured_binaries=structured_binaries
        )

    def test_policy_freezes_identity_release_assets_toolchain_and_runners(self) -> None:
        policy, _ = verifier.load_policy(POLICY_PATH)
        self.assertEqual(
            policy["source"],
            {
                "owner": "jmp0xf",
                "repository": "forge",
                "ownerId": 2247932,
                "repositoryId": 1312750430,
            },
        )
        self.assertEqual(policy["release"]["version"], "0.1.0-rc.2")
        self.assertEqual(policy["release"]["tag"], "v0.1.0-rc.2")
        self.assertEqual(
            policy["release"]["manifestSchema"], "forge.release-manifest/v2"
        )
        self.assertEqual(len(policy["release"]["assets"]), 13)
        self.assertEqual(policy["release"]["artifactCount"], 11)
        self.assertEqual(policy["release"]["checksumLineCount"], 12)
        self.assertIs(policy["release"]["binaryStructureCheckRequired"], True)
        self.assertEqual(policy["release"]["notice"]["target"], "all")
        self.assertEqual(policy["toolchain"]["rust"], "1.96.0")
        self.assertEqual(
            [target["runnerLabel"] for target in policy["targets"]],
            [
                "ubuntu-24.04",
                "ubuntu-24.04-arm",
                "macos-15-intel",
                "macos-15",
                "windows-2025",
            ],
        )
        self.assertEqual(
            policy["authority"],
            {
                "owner": "jmp0xf",
                "repository": "forge-release-authority",
                "ownerId": 2247932,
                "repositoryId": 1317240187,
                "oidcIssuer": "https://token.actions.githubusercontent.com",
                "oidcSubjectPrefix": "repo:jmp0xf@2247932/forge-release-authority@1317240187",
                "environment": "forge-release",
            },
        )
        self.assertEqual(
            [
                (
                    target["triple"],
                    target["sbomGraph"]["componentCount"],
                    target["sbomGraph"]["dependencyEdgeCount"],
                    target["sbomGraph"]["canonicalSha256"],
                )
                for target in policy["targets"]
            ],
            [
                (
                    receipt["triple"],
                    receipt["componentCount"],
                    receipt["dependencyEdgeCount"],
                    receipt["canonicalSha256"],
                )
                for receipt in FORGE_SBOM_GRAPH_DERIVATION_RECEIPT["targets"]
            ],
        )
        self.assertEqual(
            FORGE_SBOM_GRAPH_DERIVATION_RECEIPT["projectionSchema"],
            verifier.SBOM_GRAPH_SCHEMA,
        )
        self.assertRegex(
            FORGE_SBOM_GRAPH_DERIVATION_RECEIPT["forgeCommit"], r"^[0-9a-f]{40}$"
        )
        self.assertEqual(
            policy["limits"],
            {
                "binaryBytes": 67_108_864,
                "cargoLockBytes": 1_048_576,
                "sbomBytes": 2_097_152,
                "noticeBytes": 8_388_608,
                "manifestBytes": 65_536,
                "checksumsBytes": 16_384,
                "builderRecordBytes": 65_536,
                "totalAssetBytes": 201_326_592,
                "totalBuilderRecordBytes": 262_144,
            },
        )

    def test_policy_requires_a_bounded_exact_sbom_graph_contract(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        for name in (
            "missing",
            "zero-count",
            "over-count",
            "zero-edges",
            "over-edges",
            "malformed-digest",
            "missing-total",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                candidate = json.loads(json.dumps(policy))
                if name == "missing":
                    del candidate["targets"][0]["sbomGraph"]
                elif name == "zero-count":
                    candidate["targets"][0]["sbomGraph"]["componentCount"] = 0
                elif name == "over-count":
                    candidate["targets"][0]["sbomGraph"]["componentCount"] = (
                        verifier.MAX_SBOM_COMPONENTS + 1
                    )
                elif name == "zero-edges":
                    candidate["targets"][0]["sbomGraph"]["dependencyEdgeCount"] = 0
                elif name == "over-edges":
                    candidate["targets"][0]["sbomGraph"]["dependencyEdgeCount"] = (
                        verifier.MAX_SBOM_DEPENDENCY_EDGES + 1
                    )
                elif name == "malformed-digest":
                    candidate["targets"][0]["sbomGraph"]["canonicalSha256"] = "A" * 64
                else:
                    del candidate["limits"]["totalAssetBytes"]
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

    def test_secure_posix_capabilities_fail_closed(self) -> None:
        with mock.patch.object(os, "name", "nt"):
            with self.assertRaisesRegex(verifier.VerificationError, "POSIX"):
                verifier._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "O_NOFOLLOW", 0):
            with self.assertRaisesRegex(verifier.VerificationError, "O_NOFOLLOW"):
                verifier._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_dir_fd", set()):
            with self.assertRaisesRegex(verifier.VerificationError, r"open\(dir_fd\)"):
                verifier._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_follow_symlinks", set()):
            with self.assertRaisesRegex(
                verifier.VerificationError, "follow_symlinks=False"
            ):
                verifier._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "supports_fd", set()):
            with self.assertRaisesRegex(verifier.VerificationError, r"scandir\(fd\)"):
                verifier._require_secure_posix_fs_capabilities()
        with mock.patch.object(os, "geteuid", None):
            with self.assertRaisesRegex(verifier.VerificationError, "geteuid"):
                verifier._require_secure_posix_fs_capabilities()

    def test_json_integer_and_directory_enumeration_work_are_bounded(self) -> None:
        with self.assertRaisesRegex(verifier.VerificationError, "integer exceeds"):
            verifier._load_json_bytes(
                b'{"value":' + b"9" * 65 + b"}", "oversized integer fixture"
            )

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
            with self.assertRaisesRegex(verifier.VerificationError, "more than 2"):
                verifier._bounded_directory_names(123, 2, "oversized directory")
        self.assertEqual(entries.count, 3)

    def test_exact_directory_enforces_cumulative_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_bytes(b"aaaaaa")
            (root / "b").write_bytes(b"bbbbbb")
            with self.assertRaisesRegex(
                verifier.VerificationError, "remaining directory total limit"
            ):
                verifier._read_exact_directory(
                    root,
                    ["a", "b"],
                    lambda _name: 6,
                    11,
                    "budget fixture",
                )
            self.assertEqual(
                verifier._read_exact_directory(
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
                        verifier.VerificationError,
                        "remaining directory total limit",
                    ):
                        verifier._read_regular_file_at(
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

                with mock.patch.object(
                    verifier, "_require_secure_posix_fs_capabilities"
                ), mock.patch.object(os, "open", side_effect=swap_directory_open):
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "directory changed before"
                    ):
                        verifier._read_exact_directory(
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

                with mock.patch.object(
                    verifier, "_require_secure_posix_fs_capabilities"
                ), mock.patch.object(os, "open", side_effect=swap_entry_open):
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "changed before it was opened"
                    ):
                        verifier._read_exact_directory(
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
                real_reader = verifier._read_regular_file_at

                def replace_after_read(
                    directory_fd: int,
                    name: str,
                    limit: int,
                    remaining_total: int,
                    label: str,
                ) -> tuple[bytes, verifier.StatIdentity]:
                    result = real_reader(
                        directory_fd, name, limit, remaining_total, label
                    )
                    item.unlink()
                    item.write_bytes(b"replaced")
                    return result

                with mock.patch.object(
                    verifier,
                    "_read_regular_file_at",
                    side_effect=replace_after_read,
                ):
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "changed after it was read"
                    ):
                        verifier._read_exact_directory(
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
                real_reader = verifier._read_regular_file_at

                def mutate_directory_after_read(
                    directory_fd: int,
                    name: str,
                    limit: int,
                    remaining_total: int,
                    label: str,
                ) -> tuple[bytes, verifier.StatIdentity]:
                    result = real_reader(
                        directory_fd, name, limit, remaining_total, label
                    )
                    transient = root / "transient"
                    transient.write_bytes(b"change")
                    transient.unlink()
                    return result

                with mock.patch.object(
                    verifier,
                    "_read_regular_file_at",
                    side_effect=mutate_directory_after_read,
                ):
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "directory changed during"
                    ):
                        verifier._read_exact_directory(
                            root,
                            ["item"],
                            lambda _name: 64,
                            64,
                            "identity fixture",
                        )

    def test_canonical_projection_receipt_binds_refs_fields_and_root_edges(
        self,
    ) -> None:
        policy, _ = verifier.load_policy(POLICY_PATH)
        root_ref = f"pkg:cargo/forge@{policy['release']['version']}"
        dependency_ref = "urn:forge:cargo:blake3:" + "0" * 64
        components = {
            root_ref: verifier._sbom_graph_node(
                root_ref,
                "application",
                "forge",
                policy["release"]["version"],
                "workspace",
                None,
                policy["projectLicenseExpression"],
            ),
            dependency_ref: verifier._sbom_graph_node(
                dependency_ref,
                "library",
                "fixture-dependency",
                "1.0.0",
                "registry+https://github.com/rust-lang/crates.io-index",
                "d" * 64,
                "MIT",
            ),
        }
        graph: dict[str, list[str]] = {root_ref: [dependency_ref], dependency_ref: []}
        self.assertEqual(
            verifier._canonical_sbom_graph_contract(root_ref, components, graph),
            (
                2,
                1,
                synthetic_sbom_graph_contract(policy)["canonicalSha256"],
            ),
        )

        for field, replacement in (
            ("bomRef", "urn:forge:cargo:blake3:" + "1" * 64),
            ("name", "other-dependency"),
            ("version", "2.0.0"),
            ("source", "registry+https://example.invalid/index"),
            ("checksum", "e" * 64),
            ("licenseExpression", "Apache-2.0"),
        ):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(components))
                changed[dependency_ref][field] = replacement
                self.assertNotEqual(
                    verifier._canonical_sbom_graph_contract(root_ref, changed, graph)[
                        2
                    ],
                    synthetic_sbom_graph_contract(policy)["canonicalSha256"],
                )
        disconnected_graph: dict[str, list[str]] = {
            root_ref: [],
            dependency_ref: [],
        }
        self.assertNotEqual(
            verifier._canonical_sbom_graph_contract(
                root_ref, components, disconnected_graph
            )[2],
            synthetic_sbom_graph_contract(policy)["canonicalSha256"],
        )

    def test_happy_path_is_deterministic_and_binds_both_commits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            first = fixture.verify()
            second = fixture.verify()
            expected_subjects = [
                {
                    "digest": {"sha256": sha256((fixture.assets / name).read_bytes())},
                    "length": len((fixture.assets / name).read_bytes()),
                    "name": name,
                }
                for name in fixture.policy["release"]["assets"]
            ]
        self.assertEqual(first, second)
        dependencies = first["buildDefinition"]["resolvedDependencies"]
        self.assertEqual(dependencies[0]["digest"], {"gitCommit": FORGE_COMMIT})
        self.assertEqual(dependencies[1]["digest"], {"gitCommit": AUTHORITY_COMMIT})
        self.assertEqual(
            len(
                first["buildDefinition"]["internalParameters"]["release"][
                    "subjectNames"
                ]
            ),
            13,
        )
        subjects = first["buildDefinition"]["internalParameters"]["release"]["subjects"]
        self.assertEqual(subjects, expected_subjects)
        self.assertEqual(len(first["runDetails"]["byproducts"]), 5)
        self.assertEqual(
            verifier._canonical_json(first), verifier._canonical_json(second)
        )

    def test_sbom_graph_contract_rejects_subset_license_and_edge_drift(self) -> None:
        for mutation in ("subset", "license", "edge"):
            with self.subTest(
                mutation=mutation
            ), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                target = fixture.policy["targets"][0]
                sbom_path = fixture.assets / target["sbom"]
                sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
                root_ref = sbom["metadata"]["component"]["bom-ref"]
                dependency_ref = sbom["components"][0]["bom-ref"]
                if mutation == "subset":
                    sbom["components"] = []
                    sbom["dependencies"] = [{"dependsOn": [], "ref": root_ref}]
                    expected_error = "semantic components"
                elif mutation == "license":
                    sbom["components"][0]["licenses"][0]["expression"] = "Apache-2.0"
                    expected_error = "canonical bom-ref and semantic graph"
                else:
                    dependency = next(
                        item
                        for item in sbom["dependencies"]
                        if item["ref"] == dependency_ref
                    )
                    dependency["dependsOn"] = [root_ref]
                    expected_error = "dependency edges"
                sbom_path.write_bytes(json_bytes(sbom))
                fixture.rewrite_manifest_and_checksums()
                fixture.rewrite_builder_records()
                with self.assertRaisesRegex(verifier.VerificationError, expected_error):
                    fixture.verify()

    def test_sbom_graph_contract_rejects_consistent_bom_ref_relabeling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            target = fixture.policy["targets"][0]
            sbom_path = fixture.assets / target["sbom"]
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            old_ref = sbom["components"][0]["bom-ref"]
            new_ref = "urn:forge:cargo:blake3:" + "1" * 64
            sbom["components"][0]["bom-ref"] = new_ref
            for dependency in sbom["dependencies"]:
                if dependency["ref"] == old_ref:
                    dependency["ref"] = new_ref
                dependency["dependsOn"] = [
                    new_ref if reference == old_ref else reference
                    for reference in dependency["dependsOn"]
                ]
            sbom["dependencies"].sort(key=lambda dependency: dependency["ref"])
            sbom_path.write_bytes(json_bytes(sbom))
            fixture.rewrite_manifest_and_checksums()
            fixture.rewrite_builder_records()
            with self.assertRaisesRegex(
                verifier.VerificationError, "canonical bom-ref and semantic graph"
            ):
                fixture.verify()

    def test_sbom_rejects_dependency_edges_at_the_runtime_complexity_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            target = fixture.policy["targets"][0]
            binary = (fixture.assets / target["binary"]).read_bytes()
            sbom = (fixture.assets / target["sbom"]).read_bytes()
            lock_packages = verifier._parse_trusted_cargo_lock(LOCK_BYTES)
            with mock.patch.object(verifier, "MAX_SBOM_DEPENDENCY_EDGES", 0):
                with self.assertRaisesRegex(
                    verifier.VerificationError, "edge complexity limit"
                ):
                    verifier._validate_sbom(
                        fixture.policy,
                        target,
                        sbom,
                        binary,
                        FORGE_COMMIT,
                        lock_packages,
                    )

    def test_rejects_missing_extra_casefold_collision_symlink_and_nonregular(
        self,
    ) -> None:
        mutations = {
            "missing": lambda fixture: (
                fixture.assets / fixture.policy["targets"][0]["binary"]
            ).unlink(),
            "extra": lambda fixture: (fixture.assets / "unexpected").write_bytes(
                b"extra"
            ),
            "casefold": lambda fixture: (fixture.assets / "sha256sums").write_bytes(
                b"collision"
            ),
            "symlink": self._replace_notice_with_symlink,
        }
        if hasattr(os, "mkfifo"):
            mutations["nonregular"] = self._replace_notice_with_fifo
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                mutation(fixture)
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    @staticmethod
    def _replace_notice_with_symlink(fixture: CandidateFixture) -> None:
        notice = fixture.assets / fixture.policy["release"]["notice"]["name"]
        outside = fixture.root / "outside-notices"
        outside.write_bytes(notice.read_bytes())
        notice.unlink()
        notice.symlink_to(outside)

    @staticmethod
    def _replace_notice_with_fifo(fixture: CandidateFixture) -> None:
        notice = fixture.assets / fixture.policy["release"]["notice"]["name"]
        notice.unlink()
        os.mkfifo(notice)

    def test_rejects_manifest_v1_unknown_fields_and_duplicate_json_keys(self) -> None:
        for mutation_name in ("v1", "unknown", "duplicate"):
            with self.subTest(
                mutation=mutation_name
            ), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                manifest_path = fixture.assets / "release-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if mutation_name == "v1":
                    manifest["schema"] = "forge.release-manifest/v1"
                    manifest_path.write_bytes(json_bytes(manifest))
                elif mutation_name == "unknown":
                    manifest["candidateSaysApproved"] = True
                    manifest_path.write_bytes(json_bytes(manifest))
                else:
                    rendered = json_bytes(manifest)
                    manifest_path.write_bytes(
                        b'{"schema":"forge.release-manifest/v2",' + rendered[1:]
                    )
                fixture.rewrite_checksums()
                with self.assertRaises(verifier.VerificationError):
                    fixture.verify()

    def test_rejects_asset_checksum_sbom_and_builder_record_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            binary = fixture.assets / fixture.policy["targets"][0]["binary"]
            binary.write_bytes(binary.read_bytes() + b"tamper")
            with self.assertRaisesRegex(verifier.VerificationError, "length|sha256"):
                fixture.verify()

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            checksums = fixture.assets / "SHA256SUMS"
            lines = checksums.read_text(encoding="ascii").splitlines()
            lines[0] = "0" * 64 + lines[0][64:]
            checksums.write_text("\n".join(lines) + "\n", encoding="ascii", newline="")
            with self.assertRaisesRegex(verifier.VerificationError, "digest mismatch"):
                fixture.verify()

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            target = fixture.policy["targets"][0]
            sbom_path = fixture.assets / target["sbom"]
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            for prop in sbom["metadata"]["component"]["properties"]:
                if prop["name"] == "forge:source-commit":
                    prop["value"] = "d" * 40
            sbom_path.write_bytes(json_bytes(sbom))
            fixture.rewrite_manifest_and_checksums()
            fixture.rewrite_builder_records()
            with self.assertRaisesRegex(verifier.VerificationError, "source-commit"):
                fixture.verify()

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            target = fixture.policy["targets"][0]
            record_path = fixture.records / target["builderRecord"]
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["runner_label"] = "self-hosted"
            record_path.write_bytes(json_bytes(record))
            with self.assertRaisesRegex(verifier.VerificationError, "runner_label"):
                fixture.verify()

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            fixture.cargo_lock.write_bytes(LOCK_BYTES + b"# changed\n")
            with self.assertRaisesRegex(
                verifier.VerificationError, "trusted source-commit"
            ):
                fixture.verify()

        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            notice = fixture.assets / fixture.policy["release"]["notice"]["name"]
            notice.write_bytes(b"candidate substituted notices\n")
            fixture.rewrite_manifest_and_checksums()
            with self.assertRaisesRegex(
                verifier.VerificationError, "trusted source-commit"
            ):
                fixture.verify()

    def test_public_verifiers_have_no_binary_structure_bypass(self) -> None:
        self.assertNotIn(
            "check_binary_structure",
            inspect.signature(verifier.verify_release).parameters,
        )
        self.assertNotIn(
            "check_binary_structure",
            inspect.signature(verifier._verify_release_with_subjects).parameters,
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory, structured_binaries=False)
            with self.assertRaisesRegex(verifier.VerificationError, "ELF64"):
                fixture.verify()

    def test_binary_parsers_require_bounded_executable_structures_not_magic_only(
        self,
    ) -> None:
        policy, _ = verifier.load_policy(POLICY_PATH)
        for target in policy["targets"]:
            with self.subTest(target=target["triple"]):
                verifier._validate_binary_structure(
                    target, synthetic_executable(target["binaryFormat"])
                )
                with self.assertRaises(verifier.VerificationError):
                    verifier._validate_binary_structure(
                        target, forged_magic_only_header(target["binaryFormat"])
                    )

        elf_target = policy["targets"][0]
        interpreted_elf = bytearray(synthetic_executable(elf_target["binaryFormat"]))
        struct.pack_into("<I", interpreted_elf, 64, 3)  # PT_INTERP
        with self.assertRaisesRegex(
            verifier.VerificationError, "dynamically interpreted"
        ):
            verifier._validate_binary_structure(elf_target, bytes(interpreted_elf))

        dynamically_needed_elf = bytearray(
            synthetic_executable(elf_target["binaryFormat"])
        )
        dynamically_needed_elf.extend(b"\0" * (240 - len(dynamically_needed_elf)))
        struct.pack_into("<H", dynamically_needed_elf, 56, 2)
        struct.pack_into("<Q", dynamically_needed_elf, 72, 200)
        dynamically_needed_elf[200] = 0xC3
        struct.pack_into("<II", dynamically_needed_elf, 120, 2, 4)  # PT_DYNAMIC
        struct.pack_into("<Q", dynamically_needed_elf, 128, 208)
        struct.pack_into("<Q", dynamically_needed_elf, 152, 32)
        struct.pack_into("<Q", dynamically_needed_elf, 160, 32)
        struct.pack_into("<qQ", dynamically_needed_elf, 208, 1, 0)  # DT_NEEDED
        struct.pack_into("<qQ", dynamically_needed_elf, 224, 0, 0)  # DT_NULL
        with self.assertRaisesRegex(verifier.VerificationError, "DT_NEEDED"):
            verifier._validate_binary_structure(
                elf_target, bytes(dynamically_needed_elf)
            )
        bss_entry_elf = bytearray(synthetic_executable(elf_target["binaryFormat"]))
        struct.pack_into("<Q", bss_entry_elf, 24, 0x1001)
        struct.pack_into("<Q", bss_entry_elf, 104, 2)
        with self.assertRaisesRegex(verifier.VerificationError, "entry point"):
            verifier._validate_binary_structure(elf_target, bytes(bss_entry_elf))

        macho_target = policy["targets"][2]
        truncated_commands = bytearray(
            synthetic_executable(macho_target["binaryFormat"])
        )
        struct.pack_into("<I", truncated_commands, 36, 80)
        with self.assertRaisesRegex(
            verifier.VerificationError, "load command|LC_SEGMENT"
        ):
            verifier._validate_binary_structure(macho_target, bytes(truncated_commands))
        missing_main = bytearray(synthetic_executable(macho_target["binaryFormat"]))
        struct.pack_into("<I", missing_main, 104, 0)
        with self.assertRaisesRegex(verifier.VerificationError, "LC_MAIN"):
            verifier._validate_binary_structure(macho_target, bytes(missing_main))
        command_entry = bytearray(synthetic_executable(macho_target["binaryFormat"]))
        struct.pack_into("<Q", command_entry, 112, 32)
        with self.assertRaisesRegex(verifier.VerificationError, "LC_MAIN"):
            verifier._validate_binary_structure(macho_target, bytes(command_entry))
        forbidden_execute = bytearray(
            synthetic_executable(macho_target["binaryFormat"])
        )
        struct.pack_into("<i", forbidden_execute, 88, 1)
        with self.assertRaisesRegex(verifier.VerificationError, "maximum protection"):
            verifier._validate_binary_structure(macho_target, bytes(forbidden_execute))

        pe_target = policy["targets"][4]
        non_executable_section = bytearray(
            synthetic_executable(pe_target["binaryFormat"])
        )
        struct.pack_into("<I", non_executable_section, 236, 0x00000020)
        with self.assertRaisesRegex(
            verifier.VerificationError, "executable PE code section"
        ):
            verifier._validate_binary_structure(
                pe_target, bytes(non_executable_section)
            )
        missing_pe_entry = bytearray(synthetic_executable(pe_target["binaryFormat"]))
        struct.pack_into("<I", missing_pe_entry, 0x68, 0)
        with self.assertRaisesRegex(verifier.VerificationError, "entry point"):
            verifier._validate_binary_structure(pe_target, bytes(missing_pe_entry))
        header_backed_pe = bytearray(synthetic_executable(pe_target["binaryFormat"]))
        struct.pack_into("<I", header_backed_pe, 216, 128)
        with self.assertRaisesRegex(verifier.VerificationError, "PE section"):
            verifier._validate_binary_structure(pe_target, bytes(header_backed_pe))
        undersized_headers = bytearray(synthetic_executable(pe_target["binaryFormat"]))
        struct.pack_into("<I", undersized_headers, 0x94, 239)
        with self.assertRaisesRegex(verifier.VerificationError, "section table"):
            verifier._validate_binary_structure(pe_target, bytes(undersized_headers))
        dll_image = bytearray(synthetic_executable(pe_target["binaryFormat"]))
        struct.pack_into("<H", dll_image, 0x56, 0x2002)
        with self.assertRaisesRegex(verifier.VerificationError, "executable PE32"):
            verifier._validate_binary_structure(pe_target, bytes(dll_image))

    def test_binary_parsers_enforce_conservative_structure_caps(self) -> None:
        self.assertEqual(verifier.MAX_ELF_PROGRAM_HEADERS, 128)
        self.assertEqual(verifier.MAX_ELF_DYNAMIC_TABLE_BYTES, 1_048_576)
        self.assertEqual(verifier.MAX_MACHO_LOAD_COMMANDS, 256)
        self.assertEqual(verifier.MAX_MACHO_LOAD_COMMAND_BYTES, 1_048_576)
        self.assertEqual(verifier.MAX_PE_SECTIONS, 96)
        self.assertEqual(verifier.MAX_SBOM_COMPONENTS, 512)
        self.assertEqual(verifier.MAX_SBOM_DEPENDENCY_EDGES, 4_096)

        policy, _ = verifier.load_policy(POLICY_PATH)
        elf_target = policy["targets"][0]
        excessive_elf_headers = bytearray(
            synthetic_executable(elf_target["binaryFormat"])
        )
        struct.pack_into(
            "<H",
            excessive_elf_headers,
            56,
            verifier.MAX_ELF_PROGRAM_HEADERS + 1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "ELF complexity"):
            verifier._validate_binary_structure(
                elf_target, bytes(excessive_elf_headers)
            )

        dynamic_elf = bytearray(synthetic_executable(elf_target["binaryFormat"]))
        dynamic_elf.extend(b"\0" * (240 - len(dynamic_elf)))
        struct.pack_into("<H", dynamic_elf, 56, 2)
        struct.pack_into("<II", dynamic_elf, 120, 2, 4)  # PT_DYNAMIC
        struct.pack_into("<Q", dynamic_elf, 128, 208)
        struct.pack_into("<Q", dynamic_elf, 152, 32)
        struct.pack_into("<Q", dynamic_elf, 160, 32)
        with mock.patch.object(verifier, "MAX_ELF_DYNAMIC_TABLE_BYTES", 16):
            with self.assertRaisesRegex(
                verifier.VerificationError, "dynamic-table complexity"
            ):
                verifier._validate_binary_structure(elf_target, bytes(dynamic_elf))

        macho_target = policy["targets"][2]
        excessive_macho_commands = bytearray(
            synthetic_executable(macho_target["binaryFormat"])
        )
        struct.pack_into(
            "<I",
            excessive_macho_commands,
            16,
            verifier.MAX_MACHO_LOAD_COMMANDS + 1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "Mach-O.*complexity"):
            verifier._validate_binary_structure(
                macho_target, bytes(excessive_macho_commands)
            )

        pe_target = policy["targets"][4]
        excessive_pe_sections = bytearray(
            synthetic_executable(pe_target["binaryFormat"])
        )
        struct.pack_into(
            "<H",
            excessive_pe_sections,
            0x46,
            verifier.MAX_PE_SECTIONS + 1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "section PE limit"):
            verifier._validate_binary_structure(pe_target, bytes(excessive_pe_sections))

    def test_cli_writes_predicate_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory, structured_binaries=True)
            output_directory = Path(directory) / "outputs"
            output_directory.mkdir(mode=0o700)
            output = output_directory / "predicate.json"
            subject_checksums = output_directory / "subject-checksums.txt"
            arguments = [
                "--policy",
                str(fixture.policy_path),
                "--assets",
                str(fixture.assets),
                "--builder-records",
                str(fixture.records),
                "--cargo-lock",
                str(fixture.cargo_lock),
                "--source-license-notices",
                str(fixture.source_license_notices),
                "--forge-commit",
                FORGE_COMMIT,
                "--authority-commit",
                AUTHORITY_COMMIT,
                "--predicate-out",
                str(output),
                "--subject-checksums-out",
                str(subject_checksums),
            ]
            with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit
            ) as bypass_flag:
                verifier._parse_arguments(arguments + ["--skip-binary-structure"])
            self.assertEqual(bypass_flag.exception.code, 2)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 0)
            predicate = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                predicate["buildDefinition"]["buildType"],
                fixture.policy["provenance"]["buildType"],
            )
            expected_subject_lines = [
                f"{sha256((fixture.assets / name).read_bytes())}  {name}"
                for name in fixture.policy["release"]["assets"]
            ]
            self.assertEqual(
                subject_checksums.read_text(encoding="ascii").splitlines(),
                expected_subject_lines,
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 1)
            output.unlink()
            subject_checksums.unlink()
            output.write_text("occupied\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 1)
            self.assertFalse(subject_checksums.exists())
            output.unlink()
            same_output = Path(directory) / "same-output"
            colliding_outputs = list(arguments)
            colliding_outputs[colliding_outputs.index(str(output))] = str(same_output)
            colliding_outputs[colliding_outputs.index(str(subject_checksums))] = str(
                same_output
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(colliding_outputs), 1)
            self.assertFalse(same_output.exists())
            unrelated = output_directory / "unrelated"
            unrelated.write_text("occupied\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 1)
            self.assertFalse(output.exists())
            self.assertFalse(subject_checksums.exists())
            unrelated.unlink()
            output_directory.chmod(0o755)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 1)
            output_directory.chmod(0o700)
            inside_inputs = list(arguments)
            inside_inputs[inside_inputs.index(str(output))] = str(
                fixture.assets / "predicate.json"
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(inside_inputs), 1)

    def test_cli_binds_actual_input_and_output_directory_inodes(self) -> None:
        with self.subTest("input ancestor changes after pin"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                safe = root / "safe"
                safe.mkdir()
                fixture = self.fixture(str(safe), structured_binaries=True)
                alias = root / "input-alias"
                alias.symlink_to(safe, target_is_directory=True)
                replacement = root / "replacement"
                (replacement / "assets").mkdir(parents=True)
                output_directory = root / "outputs"
                output_directory.mkdir(mode=0o700)
                predicate = output_directory / "predicate.json"
                checksums = output_directory / "subject-checksums.txt"
                arguments = [
                    "--policy",
                    str(fixture.policy_path),
                    "--assets",
                    str(alias / "assets"),
                    "--builder-records",
                    str(fixture.records),
                    "--cargo-lock",
                    str(fixture.cargo_lock),
                    "--source-license-notices",
                    str(fixture.source_license_notices),
                    "--forge-commit",
                    FORGE_COMMIT,
                    "--authority-commit",
                    AUTHORITY_COMMIT,
                    "--predicate-out",
                    str(predicate),
                    "--subject-checksums-out",
                    str(checksums),
                ]
                real_verify = verifier._verify_release_with_pinned_directories

                def swap_input_ancestor(*args: Any, **kwargs: Any) -> Any:
                    alias.unlink()
                    alias.symlink_to(replacement, target_is_directory=True)
                    return real_verify(*args, **kwargs)

                with mock.patch.object(
                    verifier,
                    "_verify_release_with_pinned_directories",
                    side_effect=swap_input_ancestor,
                ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(verifier.main(arguments), 1)
                self.assertFalse(predicate.exists())
                self.assertFalse(checksums.exists())

        with self.subTest("canonical output ancestor changes before secure open"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = root / "inputs"
                (inputs / "leaf").mkdir(parents=True)
                output_ancestor = root / "output"
                (output_ancestor / "leaf").mkdir(parents=True)
                detached = root / "detached-output"
                pinned_input = verifier._pin_directory(inputs, "test input")
                real_open = verifier._open_resolved_directory
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
                        verifier,
                        "_open_resolved_directory",
                        side_effect=swap_before_component_open,
                    ):
                        with self.assertRaises(verifier.VerificationError):
                            verifier._pin_output(
                                output_ancestor / "leaf" / "predicate.json",
                                [pinned_input],
                            )
                finally:
                    verifier._close_pinned_directory(pinned_input)
                self.assertTrue(swapped)
                self.assertFalse((inputs / "leaf" / "predicate.json").exists())

    def test_cli_rechecks_both_created_outputs_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self.fixture(directory, structured_binaries=True)
            output_directory = root / "outputs"
            output_directory.mkdir(mode=0o700)
            predicate = output_directory / "predicate.json"
            checksums = output_directory / "subject-checksums.txt"
            arguments = [
                "--policy",
                str(fixture.policy_path),
                "--assets",
                str(fixture.assets),
                "--builder-records",
                str(fixture.records),
                "--cargo-lock",
                str(fixture.cargo_lock),
                "--source-license-notices",
                str(fixture.source_license_notices),
                "--forge-commit",
                FORGE_COMMIT,
                "--authority-commit",
                AUTHORITY_COMMIT,
                "--predicate-out",
                str(predicate),
                "--subject-checksums-out",
                str(checksums),
            ]
            real_write = verifier._write_create_only
            created: list[verifier._CreatedOutput] = []

            def tamper_first_during_second_write(
                output: verifier._PinnedOutput, data: bytes
            ) -> verifier._CreatedOutput:
                result = real_write(output, data)
                if created:
                    os.lseek(created[0].file_fd, 0, os.SEEK_SET)
                    os.write(created[0].file_fd, b"X")
                    os.fsync(created[0].file_fd)
                created.append(result)
                return result

            with mock.patch.object(
                verifier,
                "_write_create_only",
                side_effect=tamper_first_during_second_write,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments), 1)
            self.assertTrue(predicate.exists())
            self.assertTrue(checksums.read_bytes().startswith(b"X"))

    def test_created_output_growth_is_rejected_before_readback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "outputs"
            output_directory.mkdir(mode=0o700)
            pinned = verifier._pin_output(output_directory / "result", [])
            created = verifier._write_create_only(pinned, b"ok")
            try:
                os.ftruncate(created.file_fd, 32 * 1024 * 1024)
                with mock.patch.object(
                    os,
                    "read",
                    side_effect=AssertionError("readback must remain bounded"),
                ):
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "changed before completion"
                    ):
                        verifier._require_created_outputs_stable([created])
            finally:
                os.close(created.file_fd)
                os.close(pinned.directory_fd)

    def test_cli_pins_output_parents_and_rejects_boundary_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = self.fixture(directory, structured_binaries=True)

            def arguments(predicate: Path, checksums: Path) -> list[str]:
                return [
                    "--policy",
                    str(fixture.policy_path),
                    "--assets",
                    str(fixture.assets),
                    "--builder-records",
                    str(fixture.records),
                    "--cargo-lock",
                    str(fixture.cargo_lock),
                    "--source-license-notices",
                    str(fixture.source_license_notices),
                    "--forge-commit",
                    FORGE_COMMIT,
                    "--authority-commit",
                    AUTHORITY_COMMIT,
                    "--predicate-out",
                    str(predicate),
                    "--subject-checksums-out",
                    str(checksums),
                ]

            descendant = fixture.assets / "nested"
            descendant.mkdir()
            descendant_predicate = descendant / "predicate.json"
            safe_output_directory = root / "safe-outputs"
            safe_output_directory.mkdir(mode=0o700)
            safe_checksums = safe_output_directory / "safe-checksums.txt"
            with mock.patch.object(
                verifier, "_verify_release_with_pinned_directories"
            ) as verify_mock, redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                self.assertEqual(
                    verifier.main(arguments(descendant_predicate, safe_checksums)), 1
                )
            verify_mock.assert_not_called()
            self.assertFalse(descendant_predicate.exists())
            self.assertFalse(safe_checksums.exists())

            casefold_predicate = root / "Qualification.json"
            casefold_checksums = root / "qualification.JSON"
            with mock.patch.object(
                verifier, "_verify_release_with_pinned_directories"
            ) as verify_mock, redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                self.assertEqual(
                    verifier.main(arguments(casefold_predicate, casefold_checksums)), 1
                )
            verify_mock.assert_not_called()
            self.assertFalse(casefold_predicate.exists())
            self.assertFalse(casefold_checksums.exists())

            symlink_parent = root / "output-link"
            symlink_parent.symlink_to(root, target_is_directory=True)
            with mock.patch.object(
                verifier, "_verify_release_with_pinned_directories"
            ) as verify_mock, redirect_stdout(io.StringIO()), redirect_stderr(
                io.StringIO()
            ):
                self.assertEqual(
                    verifier.main(
                        arguments(
                            symlink_parent / "predicate.json",
                            symlink_parent / "checksums.txt",
                        )
                    ),
                    1,
                )
            verify_mock.assert_not_called()
            self.assertFalse((root / "predicate.json").exists())
            self.assertFalse((root / "checksums.txt").exists())

            safe_parent = root / "safe-parent"
            safe_nested = safe_parent / "nested"
            safe_nested.mkdir(parents=True)
            safe_nested.chmod(0o700)
            alias = root / "output-alias"
            alias.symlink_to(safe_parent, target_is_directory=True)
            aliased_predicate = alias / "nested" / "predicate.json"

            def swap_output_ancestor(
                *_args: Any, **_kwargs: Any
            ) -> tuple[dict[str, Any], bytes]:
                alias.unlink()
                alias.symlink_to(fixture.assets, target_is_directory=True)
                return {}, b"synthetic checksums\n"

            with mock.patch.object(
                verifier,
                "_verify_release_with_pinned_directories",
                side_effect=swap_output_ancestor,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(
                    verifier.main(arguments(aliased_predicate, safe_checksums)), 1
                )
            self.assertFalse((safe_nested / aliased_predicate.name).exists())
            self.assertFalse(
                (fixture.assets / "nested" / aliased_predicate.name).exists()
            )
            self.assertFalse(safe_checksums.exists())

            output_directory = root / "outputs"
            detached_directory = root / "detached-outputs"
            output_directory.mkdir(mode=0o700)
            predicate = output_directory / "predicate.json"
            checksums = output_directory / "subject-checksums.txt"

            def swap_output_parent(
                *_args: Any, **_kwargs: Any
            ) -> tuple[dict[str, Any], bytes]:
                output_directory.rename(detached_directory)
                output_directory.symlink_to(fixture.assets, target_is_directory=True)
                return {}, b"synthetic checksums\n"

            with mock.patch.object(
                verifier,
                "_verify_release_with_pinned_directories",
                side_effect=swap_output_parent,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(arguments(predicate, checksums)), 1)
            self.assertFalse((detached_directory / predicate.name).exists())
            self.assertFalse((detached_directory / checksums.name).exists())
            self.assertFalse((fixture.assets / predicate.name).exists())
            self.assertFalse((fixture.assets / checksums.name).exists())


if __name__ == "__main__":
    unittest.main()
