from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import io
import json
import os
import pickle
import stat
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

from scripts import verify_release as verifier


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "contracts" / "release-policy.json"
FORGE_COMMIT = "a" * 40
AUTHORITY_COMMIT = "b" * 40
ACTIONS_ENVIRONMENT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_NAME": "main",
    "GITHUB_REF_PROTECTED": "true",
    "GITHUB_REF_TYPE": "branch",
    "GITHUB_REPOSITORY": "jmp0xf/forge-release-authority",
    "GITHUB_REPOSITORY_ID": "1317240187",
    "GITHUB_REPOSITORY_OWNER": "jmp0xf",
    "GITHUB_REPOSITORY_OWNER_ID": "2247932",
    "GITHUB_SHA": AUTHORITY_COMMIT,
    "GITHUB_WORKFLOW_REF": verifier.AUTHORITY_WORKFLOW_REF,
    "GITHUB_WORKFLOW_SHA": AUTHORITY_COMMIT,
}
EXACT_OUTPUT_TEST_BUDGETS = {
    "maximum_file_count": 4,
    "maximum_file_bytes": 64,
    "maximum_total_bytes": 128,
}
LOCK_BYTES = (
    b"version = 4\n\n"
    b"[[package]]\n"
    b'name = "fixture-dependency"\n'
    b'version = "1.0.0"\n'
    b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    + f'checksum = "{"d" * 64}"\n'.encode("ascii")
)
LOCK_DIGEST = hashlib.sha256(LOCK_BYTES).hexdigest()
NOTICE_BYTES = b"Synthetic fixture notice corpus.\n"
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
        (self.assets / self.policy["release"]["notice"]["name"]).write_bytes(
            NOTICE_BYTES
        )
        self.source_license_notices.write_bytes(NOTICE_BYTES)
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
        return self.verify_with(self.resolved_materials())

    def verify_with(self, materials: verifier._ResolvedMaterials) -> dict[str, Any]:
        predicate, _subject_checksums = verifier._verify_release_with_subjects(
            self.policy_path,
            self.assets,
            self.records,
            FORGE_COMMIT,
            AUTHORITY_COMMIT,
            materials,
        )
        return predicate

    def resolved_materials(self) -> verifier._ResolvedMaterials:
        return verifier._ResolvedMaterials(
            cargo_lock=self.cargo_lock.read_bytes(),
            source_license_notices=self.source_license_notices.read_bytes(),
            authority_policy=self.policy_path.read_bytes(),
            authority_verifier=verifier.AUTHORITY_VERIFIER_PATH.read_bytes(),
        )

    @contextmanager
    def cli_environment(self) -> Iterator[None]:
        with (
            mock.patch.dict(os.environ, ACTIONS_ENVIRONMENT, clear=True),
            mock.patch.object(verifier, "AUTHORITY_POLICY_PATH", self.policy_path),
            mock.patch.object(
                verifier,
                "_resolve_github_materials",
                return_value=self.resolved_materials(),
            ),
        ):
            yield


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
            policy["provenance"],
            {
                "predicateType": verifier.SLSA_PROVENANCE_V1,
                "buildType": verifier.BUILD_TYPE_URI,
                "builderId": verifier.BUILDER_ID_URI,
            },
        )
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

    def test_policy_rejects_provenance_identity_drift(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        for mutation in ("build-type", "builder-id", "legacy-workflow-ref"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                if mutation == "build-type":
                    candidate["provenance"]["buildType"] = (
                        "https://example.invalid/build"
                    )
                elif mutation == "builder-id":
                    candidate["provenance"]["builderId"] = (
                        "https://example.invalid/builder"
                    )
                else:
                    candidate["provenance"]["workflowRef"] = "legacy"
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

    def test_policy_rejects_immutable_repository_identity_drift(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        for section, field in (
            ("source", "owner"),
            ("source", "ownerId"),
            ("source", "repository"),
            ("source", "repositoryId"),
            ("authority", "owner"),
            ("authority", "ownerId"),
            ("authority", "repository"),
            ("authority", "repositoryId"),
        ):
            with (
                self.subTest(section=section, field=field),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                candidate[section][field] = 1 if field.endswith("Id") else "different"
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

    def test_policy_rejects_builder_authority_drift(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        for field in ("oidcIssuer", "oidcSubjectPrefix", "environment"):
            with (
                self.subTest(field=field),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                candidate["authority"][field] = "different"
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

    def test_policy_rejects_builder_target_drift(self) -> None:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        for index in range(len(policy["targets"])):
            other = policy["targets"][(index + 1) % len(policy["targets"])]
            for field in ("runnerLabel", "binaryFormat"):
                with (
                    self.subTest(index=index, field=field),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    candidate = json.loads(json.dumps(policy))
                    candidate["targets"][index][field] = other[field]
                    path = Path(directory) / "policy.json"
                    path.write_bytes(json_bytes(candidate))
                    with self.assertRaises(verifier.VerificationError):
                        verifier.load_policy(path)

            with (
                self.subTest(index=index, field="builderRecord"),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                next_index = (index + 1) % len(candidate["targets"])
                current_record = candidate["targets"][index]["builderRecord"]
                candidate["targets"][index]["builderRecord"] = candidate["targets"][
                    next_index
                ]["builderRecord"]
                candidate["targets"][next_index]["builderRecord"] = current_record
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

            with (
                self.subTest(index=index, field="triple"),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                candidate["targets"][index]["triple"] = "different-target"
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

            with (
                self.subTest(index=index, field="subjectPair"),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                next_index = (index + 1) % len(candidate["targets"])
                for field in ("binary", "sbom"):
                    current_value = candidate["targets"][index][field]
                    candidate["targets"][index][field] = candidate["targets"][
                        next_index
                    ][field]
                    candidate["targets"][next_index][field] = current_value
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

            with (
                self.subTest(index=index, field="subjectNames"),
                tempfile.TemporaryDirectory() as directory,
            ):
                candidate = json.loads(json.dumps(policy))
                target = candidate["targets"][index]
                old_binary = target["binary"]
                old_sbom = target["sbom"]
                target["binary"] = f"renamed-target-{index}"
                target["sbom"] = f"{target['binary']}.cdx.json"
                renames = {old_binary: target["binary"], old_sbom: target["sbom"]}
                candidate["release"]["assets"] = sorted(
                    renames.get(name, name) for name in candidate["release"]["assets"]
                )
                path = Path(directory) / "policy.json"
                path.write_bytes(json_bytes(candidate))
                with self.assertRaises(verifier.VerificationError):
                    verifier.load_policy(path)

        with tempfile.TemporaryDirectory() as directory:
            candidate = json.loads(json.dumps(policy))
            candidate["release"]["notice"]["name"] = "RENAMED-NOTICES.txt"
            candidate["release"]["assets"] = sorted(
                "RENAMED-NOTICES.txt" if name == verifier.NOTICE_NAME else name
                for name in candidate["release"]["assets"]
            )
            path = Path(directory) / "policy.json"
            path.write_bytes(json_bytes(candidate))
            with self.assertRaises(verifier.VerificationError):
                verifier.load_policy(path)

    def test_provenance_identity_uris_resolve_to_versioned_contracts(self) -> None:
        contracts = {
            verifier.BUILD_TYPE_URI: ROOT / "docs" / "build-types" / "qualify-v1.md",
            verifier.BUILDER_ID_URI: (
                ROOT / "docs" / "builders" / "github-actions-protected-v1.md"
            ),
        }
        for uri, path in contracts.items():
            with self.subTest(uri=uri):
                self.assertTrue(path.is_file())
                text = path.read_text(encoding="utf-8")
                self.assertIn(f"Identity: `{uri}`", text)
                self.assertIn("no SLSA Build level", text)

    def test_actions_context_derives_only_protected_main_authority_commit(self) -> None:
        self.assertEqual(
            verifier._authority_commit_from_actions_environment(ACTIONS_ENVIRONMENT),
            AUTHORITY_COMMIT,
        )
        for name in (
            "GITHUB_ACTIONS",
            "GITHUB_EVENT_NAME",
            "GITHUB_REF",
            "GITHUB_REF_NAME",
            "GITHUB_REF_PROTECTED",
            "GITHUB_REF_TYPE",
            "GITHUB_REPOSITORY",
            "GITHUB_REPOSITORY_ID",
            "GITHUB_REPOSITORY_OWNER",
            "GITHUB_REPOSITORY_OWNER_ID",
            "GITHUB_WORKFLOW_REF",
        ):
            with self.subTest(name=name):
                changed = dict(ACTIONS_ENVIRONMENT)
                changed[name] = "unexpected"
                with self.assertRaises(verifier.VerificationError):
                    verifier._authority_commit_from_actions_environment(changed)
        changed = dict(ACTIONS_ENVIRONMENT)
        changed["GITHUB_WORKFLOW_SHA"] = "c" * 40
        with self.assertRaisesRegex(verifier.VerificationError, "workflow commit"):
            verifier._authority_commit_from_actions_environment(changed)

    def test_github_api_reader_rejects_redirects_and_unbounded_responses(self) -> None:
        class Headers:
            def __init__(self, content_type: str, content_length: str | None) -> None:
                self.content_type = content_type
                self.content_length = content_length

            def get_content_type(self) -> str:
                return self.content_type

            def get(self, name: str) -> str | None:
                return self.content_length if name == "Content-Length" else None

        class Response:
            def __init__(
                self,
                data: bytes,
                *,
                url: str = verifier.GITHUB_API_ROOT + "/repositories/1",
                content_type: str = "application/json",
                content_length: str | None = None,
            ) -> None:
                self.data = data
                self.url = url
                self.headers = Headers(content_type, content_length)

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_args: Any) -> None:
                return None

            def getcode(self) -> int:
                return 200

            def geturl(self) -> str:
                return self.url

            def read(self, amount: int) -> bytes:
                return self.data[:amount]

        class Opener:
            def __init__(self, response: Response) -> None:
                self.response = response

            def open(self, _request: Any, *, timeout: int) -> Response:
                self.assert_timeout(timeout)
                return self.response

            @staticmethod
            def assert_timeout(timeout: int) -> None:
                if timeout != verifier.GITHUB_API_TIMEOUT_SECONDS:
                    raise AssertionError(timeout)

        def read(response: Response, limit: int = 64) -> Any:
            with mock.patch.object(
                verifier, "build_opener", return_value=Opener(response)
            ):
                return verifier._github_api_get("/repositories/1", limit, "fixture")

        self.assertEqual(read(Response(b'{"ok":true}')), {"ok": True})
        for mutation, response in (
            (
                "redirect",
                Response(b'{"ok":true}', url="https://example.invalid/redirect"),
            ),
            ("content-type", Response(b"{}", content_type="text/plain")),
            ("declared-size", Response(b"{}", content_length="65")),
            ("huge-declared-size", Response(b"{}", content_length="9" * 100)),
            ("streamed-size", Response(b"{" + b" " * 64 + b"}")),
            ("invalid-json", Response(b"{")),
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(verifier.VerificationError),
            ):
                read(response)
        with (
            mock.patch.dict(
                os.environ, {verifier.GITHUB_API_TOKEN_ENV: "bad\ntoken"}, clear=True
            ),
            self.assertRaises(verifier.VerificationError),
        ):
            verifier._github_api_get("/repositories/1", 64, "fixture")

    def test_repository_materials_are_bound_to_protected_main_git_objects(self) -> None:
        repository_id = 1312750430
        tree_sha = "c" * 40
        legal_tree_sha = "d" * 40
        lock_sha = verifier._git_blob_sha(LOCK_BYTES)
        notice_sha = verifier._git_blob_sha(NOTICE_BYTES)
        prefix = f"/repositories/{repository_id}"
        documents: dict[str, Any] = {
            prefix: {
                "default_branch": "main",
                "full_name": "jmp0xf/forge",
                "id": repository_id,
                "name": "forge",
                "owner": {"id": 2247932, "login": "jmp0xf"},
                "private": False,
                "visibility": "public",
            },
            prefix + "/branches/main": {
                "commit": {"sha": FORGE_COMMIT},
                "name": "main",
                "protected": True,
            },
            prefix + f"/git/commits/{FORGE_COMMIT}": {
                "sha": FORGE_COMMIT,
                "tree": {"sha": tree_sha},
            },
            prefix + f"/git/trees/{tree_sha}": {
                "sha": tree_sha,
                "tree": [
                    {
                        "mode": "100644",
                        "path": "Cargo.lock",
                        "sha": lock_sha,
                        "type": "blob",
                    },
                    {
                        "mode": "040000",
                        "path": "legal",
                        "sha": legal_tree_sha,
                        "type": "tree",
                    },
                ],
                "truncated": False,
            },
            prefix + f"/git/trees/{legal_tree_sha}": {
                "sha": legal_tree_sha,
                "tree": [
                    {
                        "mode": "100644",
                        "path": "THIRD-PARTY-LICENSES.txt",
                        "sha": notice_sha,
                        "type": "blob",
                    }
                ],
                "truncated": False,
            },
            prefix + f"/git/blobs/{lock_sha}": {
                "content": base64.b64encode(LOCK_BYTES).decode("ascii"),
                "encoding": "base64",
                "sha": lock_sha,
                "size": len(LOCK_BYTES),
            },
            prefix + f"/git/blobs/{notice_sha}": {
                "content": base64.b64encode(NOTICE_BYTES).decode("ascii"),
                "encoding": "base64",
                "sha": notice_sha,
                "size": len(NOTICE_BYTES),
            },
        }

        def resolve(candidate: dict[str, Any]) -> dict[str, bytes]:
            def api_get(path: str, _limit: int, _label: str) -> Any:
                if path not in candidate:
                    raise verifier.VerificationError(f"unexpected API path {path}")
                return json.loads(json.dumps(candidate[path]))

            return verifier._resolve_repository_files(
                {
                    "owner": "jmp0xf",
                    "ownerId": 2247932,
                    "repository": "forge",
                    "repositoryId": repository_id,
                },
                FORGE_COMMIT,
                {"Cargo.lock": 1024, "legal/THIRD-PARTY-LICENSES.txt": 1024},
                api_get,
            )

        self.assertEqual(
            resolve(documents),
            {
                "Cargo.lock": LOCK_BYTES,
                "legal/THIRD-PARTY-LICENSES.txt": NOTICE_BYTES,
            },
        )

        def mutate(name: str, candidate: dict[str, Any]) -> None:
            if name == "repository-id":
                candidate[prefix]["id"] = 1
            elif name == "owner-id":
                candidate[prefix]["owner"]["id"] = 1
            elif name == "private-repository":
                candidate[prefix]["private"] = True
                candidate[prefix]["visibility"] = "private"
            elif name == "unprotected-main":
                candidate[prefix + "/branches/main"]["protected"] = False
            elif name == "non-head-commit":
                candidate[prefix + "/branches/main"]["commit"]["sha"] = "e" * 40
            elif name == "commit-sha":
                candidate[prefix + f"/git/commits/{FORGE_COMMIT}"]["sha"] = "e" * 40
            elif name == "tree-sha":
                candidate[prefix + f"/git/trees/{tree_sha}"]["sha"] = "e" * 40
            elif name == "truncated-tree":
                candidate[prefix + f"/git/trees/{tree_sha}"]["truncated"] = True
            elif name == "symlink":
                candidate[prefix + f"/git/trees/{tree_sha}"]["tree"][0]["mode"] = (
                    "120000"
                )
            elif name == "submodule":
                entry = candidate[prefix + f"/git/trees/{tree_sha}"]["tree"][0]
                entry["mode"] = "160000"
                entry["type"] = "commit"
            elif name == "missing-file":
                candidate[prefix + f"/git/trees/{tree_sha}"]["tree"].pop(0)
            elif name == "duplicate-file":
                entries = candidate[prefix + f"/git/trees/{tree_sha}"]["tree"]
                entries.append(json.loads(json.dumps(entries[0])))
            elif name == "blob-sha":
                candidate[prefix + f"/git/blobs/{lock_sha}"]["sha"] = "e" * 40
            elif name == "blob-size":
                candidate[prefix + f"/git/blobs/{lock_sha}"]["size"] = 2048
            elif name == "blob-content":
                candidate[prefix + f"/git/blobs/{lock_sha}"]["content"] = "YQ=="
            else:
                raise AssertionError(name)

        for mutation in (
            "repository-id",
            "owner-id",
            "private-repository",
            "unprotected-main",
            "non-head-commit",
            "commit-sha",
            "tree-sha",
            "truncated-tree",
            "symlink",
            "submodule",
            "missing-file",
            "duplicate-file",
            "blob-sha",
            "blob-size",
            "blob-content",
        ):
            with self.subTest(mutation=mutation):
                candidate = json.loads(json.dumps(documents))
                mutate(mutation, candidate)
                with self.assertRaises(verifier.VerificationError):
                    resolve(candidate)

    def test_authority_materials_match_the_executed_policy_and_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            materials = fixture.resolved_materials()
            for mutation in ("policy", "verifier"):
                with self.subTest(mutation=mutation):
                    changed = verifier._ResolvedMaterials(
                        cargo_lock=materials.cargo_lock,
                        source_license_notices=materials.source_license_notices,
                        authority_policy=(
                            b"{}\n"
                            if mutation == "policy"
                            else materials.authority_policy
                        ),
                        authority_verifier=(
                            b"changed\n"
                            if mutation == "verifier"
                            else materials.authority_verifier
                        ),
                    )
                    with self.assertRaisesRegex(
                        verifier.VerificationError, f"authority {mutation} differs"
                    ):
                        fixture.verify_with(changed)

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
        with mock.patch.object(os, "fchmod", None):
            with self.assertRaisesRegex(verifier.VerificationError, "fchmod"):
                verifier._require_exact_io_capabilities()

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

                with (
                    mock.patch.object(
                        verifier, "_require_secure_posix_fs_capabilities"
                    ),
                    mock.patch.object(os, "open", side_effect=swap_directory_open),
                ):
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

                with (
                    mock.patch.object(
                        verifier, "_require_secure_posix_fs_capabilities"
                    ),
                    mock.patch.object(os, "open", side_effect=swap_entry_open),
                ):
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

    def test_exact_input_is_immutable_stable_and_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "descriptor.json").write_bytes(b'{"schema":"fixture"}\n')
            (root / "payload").write_bytes(b"payload\n")
            limits = {"descriptor.json": 128, "payload": 128}
            with (
                mock.patch.object(
                    verifier,
                    "_resolve_github_materials",
                    side_effect=AssertionError("exact input must stay offline"),
                ),
                mock.patch.object(
                    verifier,
                    "_authority_commit_from_actions_environment",
                    side_effect=AssertionError("exact input must ignore Actions"),
                ),
                mock.patch.object(
                    verifier,
                    "build_opener",
                    side_effect=AssertionError("exact input must not use the network"),
                ),
                verifier.open_exact_input(root, limits, 256, "build input") as opened,
            ):
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
            with verifier.open_exact_input(
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
                with self.assertRaisesRegex(verifier.VerificationError, "closed"):
                    stale.revalidate()
            finally:
                os.close(released_fd)

    def test_exact_input_is_opaque_and_closes_before_releasing_fd(self) -> None:
        with self.assertRaisesRegex(TypeError, "cannot be constructed directly"):
            verifier.ExactInput()
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("ForgedExactInput", (verifier.ExactInput,), {})
        forged = object.__new__(verifier.ExactInput)
        with self.assertRaisesRegex(verifier.VerificationError, "ownership"):
            forged.revalidate()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "item").write_bytes(b"value")
            real_close = verifier._close_pinned_directory
            opened: verifier.ExactInput | None = None

            def require_closed_before_release(
                pinned: verifier._PinnedDirectory,
            ) -> None:
                if opened is not None and pinned is opened._directory:
                    self.assertTrue(opened._closed)
                real_close(pinned)

            with mock.patch.object(
                verifier,
                "_close_pinned_directory",
                side_effect=require_closed_before_release,
            ):
                with verifier.open_exact_input(
                    root, {"item": 16}, 16, "opaque input"
                ) as opened:
                    forged_with_stolen_lifetime = object.__new__(verifier.ExactInput)
                    object.__setattr__(
                        forged_with_stolen_lifetime, "_lifetime", opened._lifetime
                    )
                    with self.assertRaisesRegex(
                        verifier.VerificationError, "ownership"
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
            opened: verifier.ExactInput | None = None
            real_close = verifier._close_pinned_directory

            def interrupt_owned_close(pinned: verifier._PinnedDirectory) -> None:
                nonlocal attempts
                if opened is not None and pinned is opened._directory:
                    attempts += 1
                    raise interruption
                real_close(pinned)

            with self.assertRaises(KeyboardInterrupt) as raised:
                with mock.patch.object(
                    verifier,
                    "_close_pinned_directory",
                    side_effect=interrupt_owned_close,
                ):
                    with verifier.open_exact_input(
                        root, {"item": 16}, 16, "interrupted input"
                    ) as opened:
                        released_fd = opened._directory.directory_fd

            self.assertIs(raised.exception, interruption)
            self.assertEqual(attempts, 1)
            assert opened is not None
            self.assertTrue(opened._closed)
            with self.assertRaisesRegex(verifier.VerificationError, "closed"):
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
            with verifier.open_exact_input(
                input_directory, {"item": 16}, 16, "closed input"
            ) as opened:
                stale = opened
                released_fd = opened._directory.directory_fd

            reopened_fd = os.open(input_directory, os.O_RDONLY | os.O_DIRECTORY)
            if reopened_fd != released_fd:
                os.dup2(reopened_fd, released_fd)
                os.close(reopened_fd)
            created: verifier.ExactOutput | None = None
            try:
                with self.assertRaisesRegex(verifier.VerificationError, "closed"):
                    created = verifier.create_exact_output(
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
                with self.assertRaises(verifier.VerificationError):
                    with verifier.open_exact_input(
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
                with self.assertRaises(verifier.VerificationError):
                    with verifier.open_exact_input(
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
            with self.subTest(mutation_name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "input"
                root.mkdir()
                item = root / "item"
                item.write_bytes(b"same")
                with self.assertRaises(verifier.VerificationError):
                    with verifier.open_exact_input(
                        root, {"item": 16}, 16, "mutable input"
                    ):
                        mutate(item)

    def test_exact_input_rejects_non_exact_and_aliased_files(self) -> None:
        for mutation_name in ("missing", "extra", "casefold", "symlink", "hardlink"):
            with self.subTest(mutation_name), tempfile.TemporaryDirectory() as directory:
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
                with self.assertRaises(verifier.VerificationError):
                    with verifier.open_exact_input(root, limits, 32, "unsafe input"):
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

            with verifier.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                with (
                    mock.patch.object(
                        verifier,
                        "_resolve_github_materials",
                        side_effect=AssertionError("exact output must stay offline"),
                    ),
                    mock.patch.object(
                        verifier,
                        "_authority_commit_from_actions_environment",
                        side_effect=AssertionError("exact output must ignore Actions"),
                    ),
                    mock.patch.object(
                        verifier,
                        "build_opener",
                        side_effect=AssertionError(
                            "exact output must not use the network"
                        ),
                    ),
                    mock.patch.object(os, "fsync", side_effect=track_fsync),
                ):
                    output = verifier.create_exact_output(
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
            verifier.ExactOutput()
        with self.assertRaisesRegex(TypeError, "cannot be subclassed"):
            type("ForgedExactOutput", (verifier.ExactOutput,), {})
        forged = object.__new__(verifier.ExactOutput)
        with self.assertRaisesRegex(verifier.VerificationError, "ownership"):
            forged.close()

        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = verifier.create_exact_output(
                output_directory,
                {"result": b"result"},
                [],
                "opaque output",
                **EXACT_OUTPUT_TEST_BUDGETS,
            )
            forged_with_stolen_lifetime = object.__new__(verifier.ExactOutput)
            object.__setattr__(
                forged_with_stolen_lifetime, "_lifetime", output._lifetime
            )
            with self.assertRaisesRegex(verifier.VerificationError, "ownership"):
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
            real_close = verifier._close_fd

            def require_closed_before_release(file_fd: int) -> None:
                self.assertTrue(output._closed)
                real_close(file_fd)

            with mock.patch.object(
                verifier, "_close_fd", side_effect=require_closed_before_release
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
                with self.assertRaisesRegex(verifier.VerificationError, "closed"):
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
            output = verifier.create_exact_output(
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
            real_close = verifier._close_fd
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
            with mock.patch.object(verifier, "_close_fd", side_effect=track_close):
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
            output = verifier.create_exact_output(
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
                verifier._ExactIoLifetime.close_with
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
                    == str(verifier.AUTHORITY_VERIFIER_PATH)
                    and frame.f_lineno == cleanup_line
                ):
                    armed = False
                    raise interruption
                return interrupt_before_cleanup

            previous_trace = sys.gettrace()
            try:
                sys.settrace(interrupt_before_cleanup)
                with (
                    mock.patch.object(verifier, "_close_fd") as first_attempt,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    output.close()
            finally:
                sys.settrace(previous_trace)

            self.assertIs(raised.exception, interruption)
            first_attempt.assert_not_called()
            self.assertFalse(output._closed)
            attempted: list[int] = []
            real_close = verifier._close_fd

            def track_close(file_fd: int) -> None:
                attempted.append(file_fd)
                real_close(file_fd)

            with mock.patch.object(verifier, "_close_fd", side_effect=track_close):
                output.close()
            self.assertEqual(attempted, list(owned_fds))

    def test_exact_output_interrupt_after_cleanup_is_not_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = verifier.create_exact_output(
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
                verifier._ExactIoLifetime.close_with
            )
            final_closed_line = start_line + next(
                index
                for index, line in enumerate(source)
                if line.strip() == "self._state = _EXACT_IO_CLOSED"
            )
            interruption = KeyboardInterrupt("synthetic post-cleanup interruption")
            armed = True
            attempted: list[int] = []
            real_close = verifier._close_fd

            def interrupt_before_final_closed(
                frame: Any, event: str, _argument: Any
            ) -> Any:
                nonlocal armed
                if (
                    armed
                    and event == "line"
                    and frame.f_code.co_filename
                    == str(verifier.AUTHORITY_VERIFIER_PATH)
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
                    mock.patch.object(verifier, "_close_fd", side_effect=track_close),
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
            with mock.patch.object(verifier, "_close_fd") as retried:
                output.close()
            retried.assert_not_called()

    def test_exact_output_reentrant_close_is_rejected_while_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_directory = Path(directory) / "output"
            output_directory.mkdir(mode=0o700)
            output_directory.chmod(0o700)
            output = verifier.create_exact_output(
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
            close_errors: list[verifier.VerificationError] = []
            owned_close_attempts: list[int] = []
            attempted = False
            real_components = verifier._path_component_identities
            real_close = verifier._close_fd

            def attempt_reentrant_close(*args: Any, **kwargs: Any) -> Any:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    try:
                        output.close()
                    except verifier.VerificationError as error:
                        close_errors.append(error)
                return real_components(*args, **kwargs)

            def track_owned_close(file_fd: int) -> None:
                if file_fd in owned_fds:
                    owned_close_attempts.append(file_fd)
                real_close(file_fd)

            with (
                mock.patch.object(
                    verifier,
                    "_path_component_identities",
                    side_effect=attempt_reentrant_close,
                ),
                mock.patch.object(verifier, "_close_fd", side_effect=track_owned_close),
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
            output = verifier.create_exact_output(
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
            real_close = verifier._close_fd

            def interrupt_first_close(file_fd: int) -> None:
                attempted.append(file_fd)
                if len(attempted) == 1:
                    raise interruption
                real_close(file_fd)

            with (
                mock.patch.object(
                    verifier, "_close_fd", side_effect=interrupt_first_close
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                output.close()

            self.assertIs(raised.exception, interruption)
            self.assertEqual(attempted, list(owned_fds))
            with mock.patch.object(verifier, "_close_fd") as retried:
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
            captured: list[verifier.ExactOutput] = []

            def capture_then_reject(output: verifier.ExactOutput) -> None:
                captured.append(output)
                raise verifier.VerificationError("synthetic final rejection")

            with (
                mock.patch.object(
                    verifier.ExactOutput,
                    "revalidate",
                    autospec=True,
                    side_effect=capture_then_reject,
                ),
                self.assertRaisesRegex(
                    verifier.VerificationError, "synthetic final rejection"
                ),
            ):
                verifier.create_exact_output(
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
                with self.assertRaisesRegex(verifier.VerificationError, "closed"):
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
            captured: list[verifier.ExactOutput] = []
            attempted: list[int] = []
            armed = False
            interruption = KeyboardInterrupt("synthetic failed-create interruption")
            real_close = verifier._close_fd

            def capture_then_reject(output: verifier.ExactOutput) -> None:
                nonlocal armed
                captured.append(output)
                armed = True
                raise verifier.VerificationError("synthetic final rejection")

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
                    verifier.ExactOutput,
                    "revalidate",
                    autospec=True,
                    side_effect=capture_then_reject,
                ),
                mock.patch.object(
                    verifier, "_close_fd", side_effect=interrupt_first_cleanup
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                verifier.create_exact_output(
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
            with self.assertRaisesRegex(verifier.VerificationError, "closed"):
                stale.revalidate()
            with mock.patch.object(verifier, "_close_fd") as retried:
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
            with verifier.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                occupied = parent / "occupied"
                occupied.mkdir(mode=0o700)
                occupied.chmod(0o700)
                (occupied / "existing").write_bytes(b"occupied")
                with self.assertRaises(verifier.VerificationError):
                    verifier.create_exact_output(
                        occupied,
                        {"result": b"result"},
                        [opened],
                        "occupied output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

                with self.assertRaises(verifier.VerificationError):
                    verifier.create_exact_output(
                        input_directory,
                        {"result": b"result"},
                        [opened],
                        "overlapping output",
                        **EXACT_OUTPUT_TEST_BUDGETS,
                    )

                casefold = parent / "casefold"
                casefold.mkdir(mode=0o700)
                casefold.chmod(0o700)
                with self.assertRaises(verifier.VerificationError):
                    verifier.create_exact_output(
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
                with self.assertRaises(verifier.VerificationError):
                    verifier.create_exact_output(
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
            real_revalidate = verifier.ExactInput.revalidate

            def replace_output_after_input_check(
                opened: verifier.ExactInput, rehash: bool = True
            ) -> None:
                nonlocal calls
                real_revalidate(opened, rehash=rehash)
                calls += 1
                if calls == 2:
                    output = output_directory / "result"
                    output.rename(output_directory / "detached-result")
                    output.write_bytes(b"replacement")
                    output.chmod(0o600)

            with verifier.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                with (
                    mock.patch.object(
                        verifier.ExactInput,
                        "revalidate",
                        autospec=True,
                        side_effect=replace_output_after_input_check,
                    ),
                    self.assertRaises(verifier.VerificationError),
                ):
                    verifier.create_exact_output(
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
            real_sha256 = verifier._sha256
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

            created: verifier.ExactOutput | None = None
            try:
                with (
                    mock.patch.object(
                        verifier, "_sha256", side_effect=replace_during_final_hash
                    ),
                    self.assertRaises(verifier.VerificationError),
                ):
                    created = verifier.create_exact_output(
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
                    verifier.VerificationError, "synthetic interrupted write.*retained"
                ),
            ):
                verifier.create_exact_output(
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
            output = verifier.create_exact_output(
                boundary,
                {"one": b"1234", "two": b"5678"},
                [],
                "budget boundary",
                maximum_file_count=2,
                maximum_file_bytes=4,
                maximum_total_bytes=8,
            )
            output.close()
            self.assertEqual(sorted(path.name for path in boundary.iterdir()), ["one", "two"])

            cases = (
                (
                    "count",
                    {"one": b"1", "two": b"2", "three": b"3"},
                    {"maximum_file_count": 2, "maximum_file_bytes": 4, "maximum_total_bytes": 8},
                ),
                (
                    "file",
                    {"one": b"12345"},
                    {"maximum_file_count": 2, "maximum_file_bytes": 4, "maximum_total_bytes": 8},
                ),
                (
                    "total",
                    {"one": b"1234", "two": b"56789"},
                    {"maximum_file_count": 2, "maximum_file_bytes": 5, "maximum_total_bytes": 8},
                ),
            )
            for name, files, budgets in cases:
                with self.subTest(name=name):
                    target = parent / name
                    target.mkdir(mode=0o700)
                    target.chmod(0o700)
                    with self.assertRaises(verifier.VerificationError):
                        verifier.create_exact_output(
                            target, files, [], f"{name} budget output", **budgets
                        )
                    self.assertEqual(list(target.iterdir()), [])

            missing = parent / "missing-budget"
            missing.mkdir(mode=0o700)
            missing.chmod(0o700)
            with self.assertRaises(TypeError):
                verifier.create_exact_output(
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
            real_revalidate = verifier.ExactInput.revalidate

            def grow_output_after_input_check(
                opened: verifier.ExactInput, rehash: bool = True
            ) -> None:
                nonlocal calls
                real_revalidate(opened, rehash=rehash)
                calls += 1
                if calls == 2:
                    with (output_directory / "result").open("ab") as output:
                        output.write(b"5")

            with verifier.open_exact_input(
                input_directory, {"source": 16}, 16, "source input"
            ) as opened:
                with (
                    mock.patch.object(
                        verifier.ExactInput,
                        "revalidate",
                        autospec=True,
                        side_effect=grow_output_after_input_check,
                    ),
                    self.assertRaisesRegex(
                        verifier.VerificationError, "4-byte total output limit"
                    ),
                ):
                    verifier.create_exact_output(
                        output_directory,
                        {"result": b"1234"},
                        [opened],
                        "growing output",
                        maximum_file_count=1,
                        maximum_file_bytes=8,
                        maximum_total_bytes=4,
                    )
            self.assertEqual((output_directory / "result").read_bytes(), b"12345")

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
            expected_policy_digest = sha256(fixture.policy_path.read_bytes())
            expected_byproducts = [
                {
                    "digest": {
                        "sha256": sha256(
                            (fixture.records / target["builderRecord"]).read_bytes()
                        )
                    },
                    "name": target["builderRecord"],
                }
                for target in sorted(
                    fixture.policy["targets"], key=lambda item: item["builderRecord"]
                )
            ]
        self.assertEqual(first, second)
        self.assertEqual(set(first), {"buildDefinition", "runDetails"})
        build_definition = first["buildDefinition"]
        self.assertEqual(
            set(build_definition),
            {
                "buildType",
                "externalParameters",
                "internalParameters",
                "resolvedDependencies",
            },
        )
        self.assertEqual(build_definition["buildType"], verifier.BUILD_TYPE_URI)
        self.assertEqual(
            build_definition["externalParameters"], {"sourceCommit": FORGE_COMMIT}
        )
        dependencies = first["buildDefinition"]["resolvedDependencies"]
        self.assertEqual(len(dependencies), 4)
        dependencies_by_uri = {
            dependency["uri"]: dependency for dependency in dependencies
        }
        self.assertEqual(
            dependencies_by_uri[
                f"git+https://github.com/jmp0xf/forge.git@{FORGE_COMMIT}"
            ],
            {
                "uri": f"git+https://github.com/jmp0xf/forge.git@{FORGE_COMMIT}",
                "digest": {"gitCommit": FORGE_COMMIT},
            },
        )
        self.assertEqual(
            dependencies_by_uri[
                "git+https://github.com/jmp0xf/forge-release-authority.git@"
                + AUTHORITY_COMMIT
            ],
            {
                "uri": (
                    "git+https://github.com/jmp0xf/forge-release-authority.git@"
                    + AUTHORITY_COMMIT
                ),
                "digest": {"gitCommit": AUTHORITY_COMMIT},
            },
        )
        cargo_uri = f"https://github.com/jmp0xf/forge/blob/{FORGE_COMMIT}/Cargo.lock"
        notices_uri = (
            "https://github.com/jmp0xf/forge/blob/"
            f"{FORGE_COMMIT}/THIRD-PARTY-LICENSES.txt"
        )
        self.assertEqual(
            dependencies_by_uri[cargo_uri],
            {
                "name": "Cargo.lock",
                "uri": cargo_uri,
                "digest": {"sha256": sha256(LOCK_BYTES)},
            },
        )
        self.assertEqual(
            dependencies_by_uri[notices_uri],
            {
                "name": "THIRD-PARTY-LICENSES.txt",
                "uri": notices_uri,
                "digest": {"sha256": sha256(NOTICE_BYTES)},
            },
        )
        internal = build_definition["internalParameters"]
        self.assertEqual(
            set(internal), {"authority", "authorityCommit", "policySha256", "release"}
        )
        self.assertEqual(
            internal["authority"],
            {
                "environment": "forge-release",
                "oidcIssuer": "https://token.actions.githubusercontent.com",
                "oidcSubjectPrefix": (
                    "repo:jmp0xf@2247932/forge-release-authority@1317240187"
                ),
                "ownerId": 2247932,
                "repositoryId": 1317240187,
            },
        )
        self.assertEqual(internal["authorityCommit"], AUTHORITY_COMMIT)
        self.assertEqual(internal["policySha256"], expected_policy_digest)
        release = internal["release"]
        self.assertEqual(set(release), {"subjectNames", "tag", "targets", "version"})
        self.assertEqual(release["subjectNames"], fixture.policy["release"]["assets"])
        self.assertEqual(release["tag"], "v0.1.0-rc.2")
        self.assertEqual(
            release["targets"],
            [target["triple"] for target in fixture.policy["targets"]],
        )
        self.assertEqual(release["version"], "0.1.0-rc.2")
        self.assertNotIn("subjects", release)
        self.assertEqual(
            set(first["runDetails"]), {"builder", "byproducts", "metadata"}
        )
        self.assertEqual(
            first["runDetails"]["builder"], {"id": verifier.BUILDER_ID_URI}
        )
        self.assertEqual(first["runDetails"]["metadata"], {})
        self.assertEqual(first["runDetails"]["byproducts"], expected_byproducts)
        self.assertEqual(
            verifier._canonical_json(first), verifier._canonical_json(second)
        )

    def test_sbom_graph_contract_rejects_subset_license_and_edge_drift(self) -> None:
        for mutation in ("subset", "license", "edge"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
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
            with (
                self.subTest(mutation=mutation_name),
                tempfile.TemporaryDirectory() as directory,
            ):
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
                "--assets",
                str(fixture.assets),
                "--builder-records",
                str(fixture.records),
                "--forge-commit",
                FORGE_COMMIT,
                "--predicate-out",
                str(output),
                "--subject-checksums-out",
                str(subject_checksums),
            ]
            with (
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as bypass_flag,
            ):
                verifier._parse_arguments(arguments + ["--skip-binary-structure"])
            self.assertEqual(bypass_flag.exception.code, 2)
            for removed_option in (
                "--policy",
                "--cargo-lock",
                "--source-license-notices",
                "--authority-commit",
            ):
                with (
                    self.subTest(removed_option=removed_option),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as removed,
                ):
                    verifier._parse_arguments(arguments + [removed_option, "untrusted"])
                self.assertEqual(removed.exception.code, 2)
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
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
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(arguments), 1)
            output.unlink()
            subject_checksums.unlink()
            output.write_text("occupied\n", encoding="utf-8")
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(arguments), 1)
            self.assertFalse(subject_checksums.exists())
            output.unlink()
            same_output = Path(directory) / "same-output"
            colliding_outputs = list(arguments)
            colliding_outputs[colliding_outputs.index(str(output))] = str(same_output)
            colliding_outputs[colliding_outputs.index(str(subject_checksums))] = str(
                same_output
            )
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(colliding_outputs), 1)
            self.assertFalse(same_output.exists())
            unrelated = output_directory / "unrelated"
            unrelated.write_text("occupied\n", encoding="utf-8")
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(arguments), 1)
            self.assertFalse(output.exists())
            self.assertFalse(subject_checksums.exists())
            unrelated.unlink()
            output_directory.chmod(0o755)
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(arguments), 1)
            output_directory.chmod(0o700)
            inside_inputs = list(arguments)
            inside_inputs[inside_inputs.index(str(output))] = str(
                fixture.assets / "predicate.json"
            )
            with (
                fixture.cli_environment(),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
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
                    "--assets",
                    str(alias / "assets"),
                    "--builder-records",
                    str(fixture.records),
                    "--forge-commit",
                    FORGE_COMMIT,
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

                with (
                    fixture.cli_environment(),
                    mock.patch.object(
                        verifier,
                        "_verify_release_with_pinned_directories",
                        side_effect=swap_input_ancestor,
                    ),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                ):
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
                "--assets",
                str(fixture.assets),
                "--builder-records",
                str(fixture.records),
                "--forge-commit",
                FORGE_COMMIT,
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

            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier,
                    "_write_create_only",
                    side_effect=tamper_first_during_second_write,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
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
                    "--assets",
                    str(fixture.assets),
                    "--builder-records",
                    str(fixture.records),
                    "--forge-commit",
                    FORGE_COMMIT,
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
            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier, "_verify_release_with_pinned_directories"
                ) as verify_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    verifier.main(arguments(descendant_predicate, safe_checksums)), 1
                )
            verify_mock.assert_not_called()
            self.assertFalse(descendant_predicate.exists())
            self.assertFalse(safe_checksums.exists())

            casefold_predicate = root / "Qualification.json"
            casefold_checksums = root / "qualification.JSON"
            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier, "_verify_release_with_pinned_directories"
                ) as verify_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(
                    verifier.main(arguments(casefold_predicate, casefold_checksums)), 1
                )
            verify_mock.assert_not_called()
            self.assertFalse(casefold_predicate.exists())
            self.assertFalse(casefold_checksums.exists())

            symlink_parent = root / "output-link"
            symlink_parent.symlink_to(root, target_is_directory=True)
            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier, "_verify_release_with_pinned_directories"
                ) as verify_mock,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
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

            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier,
                    "_verify_release_with_pinned_directories",
                    side_effect=swap_output_ancestor,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
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

            with (
                fixture.cli_environment(),
                mock.patch.object(
                    verifier,
                    "_verify_release_with_pinned_directories",
                    side_effect=swap_output_parent,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verifier.main(arguments(predicate, checksums)), 1)
            self.assertFalse((detached_directory / predicate.name).exists())
            self.assertFalse((detached_directory / checksums.name).exists())
            self.assertFalse((fixture.assets / predicate.name).exists())
            self.assertFalse((fixture.assets / checksums.name).exists())


if __name__ == "__main__":
    unittest.main()
