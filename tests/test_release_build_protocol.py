from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, cast

from scripts import release_build_protocol as protocol


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "release-build"
SOURCE_COMMIT = "a" * 40
BINARY_SHA256 = "c" * 64
SOURCE_ROOT = "/authority/source"
SOURCE_INVENTORY = (
    "Cargo.toml",
    "crates/forge-cli/Cargo.toml",
    "crates/forge-cli/src/main.rs",
)
DEPENDENCY_ROOT = "/authority/cargo/registry/src"
DEPENDENCY_PATHS = (
    "build-helper-1.2.3/Cargo.toml",
    "build-helper-1.2.3/src/lib.rs",
    "serde-1.0.229/Cargo.toml",
    "serde-1.0.229/src/lib.rs",
    "test-only-4.5.6/Cargo.toml",
    "test-only-4.5.6/src/lib.rs",
)
DEPENDENCY_INVENTORY = {
    path: hashlib.sha256(path.encode("utf-8")).hexdigest() for path in DEPENDENCY_PATHS
}
TARGET_ROOT = "/authority/target"
FIXTURE_GRAPH_SHA256 = (
    "9de4910711a62ab01a543f4a0f12016efd3d093b056cec3a0bdff14e2e296613"
)


class ReleaseBuildProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (ROOT / "contracts" / "release-policy.json").read_text()
        )
        cls.synthetic_graph_policy = copy.deepcopy(cls.policy)
        cls.synthetic_graph_policy["targets"][0]["sbomGraph"] = {
            "componentCount": 3,
            "dependencyEdgeCount": 2,
            "canonicalSha256": FIXTURE_GRAPH_SHA256,
        }
        cls.plan_bytes = (FIXTURES / "release-build-plan.json").read_bytes()
        cls.lock_bytes = (FIXTURES / "Cargo.lock").read_bytes()
        cls.metadata_bytes = (FIXTURES / "metadata.json").read_bytes()
        cls.tree_bytes = (FIXTURES / "tree.txt").read_bytes()
        cls.build_messages_bytes = (FIXTURES / "build-messages.jsonl").read_bytes()
        cls.descriptor_bytes = (
            FIXTURES / "release-build-apply-descriptor.json"
        ).read_bytes()
        cls.consumer_descriptor_bytes = (
            FIXTURES / "forge-consumer-release-build-apply-descriptor.json"
        ).read_bytes()

    def accepted_plan(
        self,
        plan_bytes: bytes | None = None,
        policy: dict[str, Any] | None = None,
        source_commit: str = SOURCE_COMMIT,
        lock_bytes: bytes | None = None,
        rust_toolchain: str = protocol.RELEASE_RUST_TOOLCHAIN,
        source_root: str = SOURCE_ROOT,
        source_inventory: tuple[str, ...] = SOURCE_INVENTORY,
        dependency_root: str = DEPENDENCY_ROOT,
        dependency_inventory: dict[str, str] | None = None,
        target_root: str = TARGET_ROOT,
    ) -> protocol.AcceptedReleaseBuildPlan:
        return protocol.accept_release_build_plan(
            self.plan_bytes if plan_bytes is None else plan_bytes,
            self.policy if policy is None else policy,
            source_commit,
            self.lock_bytes if lock_bytes is None else lock_bytes,
            rust_toolchain,
            source_root,
            source_inventory,
            dependency_root,
            DEPENDENCY_INVENTORY
            if dependency_inventory is None
            else dependency_inventory,
            target_root,
        )

    def mutate_plan(self, mutate: Callable[[dict[str, Any]], None]) -> bytes:
        document = json.loads(self.plan_bytes)
        mutate(document)
        return protocol.canonical_json(document)

    def mutate_build_messages(
        self, mutate: Callable[[list[dict[str, Any]]], None]
    ) -> bytes:
        messages = [
            json.loads(line)
            for line in self.build_messages_bytes.decode("utf-8").splitlines()
        ]
        mutate(messages)
        return (
            "\n".join(
                json.dumps(message, separators=(",", ":")) for message in messages
            )
            + "\n"
        ).encode("utf-8")

    def descriptor(
        self,
        *,
        plan: protocol.AcceptedReleaseBuildPlan | None = None,
        metadata: bytes | None = None,
        tree: bytes | None = None,
        build_messages: bytes | None = None,
        lock: bytes | None = None,
        length: int = 120,
        digest: str = BINARY_SHA256,
        captured: protocol.CapturedReleaseBinary | None = None,
    ) -> bytes:
        accepted = (
            self.accepted_plan(policy=self.synthetic_graph_policy)
            if plan is None
            else plan
        )
        captured_metadata = self.metadata_bytes if metadata is None else metadata
        captured_tree = self.tree_bytes if tree is None else tree
        captured_messages = (
            self.build_messages_bytes if build_messages is None else build_messages
        )
        if captured is None:
            artifact = protocol.resolve_release_binary_artifact(
                accepted,
                captured_metadata,
                captured_tree,
                captured_messages,
            )
            captured = protocol.bind_captured_release_binary(
                accepted, artifact, length, digest
            )
        return protocol.build_release_build_apply_descriptor(
            accepted,
            captured_metadata,
            captured_tree,
            captured_messages,
            self.lock_bytes if lock is None else lock,
            captured,
        )

    def assert_plan_rejected(
        self, plan_bytes: bytes, message: str, **kwargs: Any
    ) -> None:
        with self.assertRaisesRegex(protocol.ProtocolError, message):
            self.accepted_plan(plan_bytes=plan_bytes, **kwargs)

    def test_accepts_golden_plan_and_closes_execution_semantics(self) -> None:
        accepted = self.accepted_plan()
        self.assertEqual(
            accepted.plan_sha256, hashlib.sha256(self.plan_bytes).hexdigest()
        )
        self.assertEqual(accepted.source_commit, SOURCE_COMMIT)
        self.assertEqual(
            accepted.cargo_lock_sha256, hashlib.sha256(self.lock_bytes).hexdigest()
        )
        self.assertEqual(accepted.execution.target, "x86_64-unknown-linux-musl")
        self.assertEqual(accepted.execution.rust_toolchain, "1.96.0")
        self.assertEqual(accepted.source_root, SOURCE_ROOT)
        self.assertEqual(accepted.source_inventory, frozenset(SOURCE_INVENTORY))
        self.assertEqual(accepted.dependency_root, DEPENDENCY_ROOT)
        self.assertEqual(
            accepted.dependency_inventory,
            tuple(sorted(DEPENDENCY_INVENTORY.items())),
        )
        self.assertEqual(accepted.target_root, TARGET_ROOT)
        self.assertRegex(
            accepted.authority_context_sha256,
            r"\A[0-9a-f]{64}\Z",
        )
        self.assertEqual(
            accepted.execution.source_inventory_sha256,
            accepted.source_inventory_sha256,
        )
        self.assertEqual(
            accepted.execution.dependency_inventory_sha256,
            accepted.dependency_inventory_sha256,
        )
        self.assertEqual(accepted.execution.profile, "release")
        self.assertEqual(accepted.execution.features, ())
        self.assertEqual(
            accepted.execution.environment_overrides,
            (("CARGO_TARGET_DIR", TARGET_ROOT),),
        )
        self.assertEqual(
            accepted.execution.cargo_build_arguments("/authority/target"),
            (
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
                "x86_64-unknown-linux-musl",
                "--target-dir",
                "/authority/target",
            ),
        )
        self.assertEqual(
            accepted.execution.cargo_metadata_arguments(),
            (
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--filter-platform",
                "x86_64-unknown-linux-musl",
            ),
        )
        self.assertNotIn("--features", accepted.execution.cargo_tree_arguments())
        with self.assertRaisesRegex(protocol.ProtocolError, "absolute path"):
            accepted.execution.cargo_build_arguments("relative-target")

    def test_public_validator_rechecks_and_preserves_the_exact_plan(self) -> None:
        accepted = self.accepted_plan()
        self.assertIs(protocol.require_accepted_release_build_plan(accepted), accepted)

        for value in (
            object(),
            replace(accepted, plan_sha256="f" * 64),
            replace(accepted, source_root="/authority/other-source"),
        ):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.require_accepted_release_build_plan(value)

        class AcceptedPlanSubclass(protocol.AcceptedReleaseBuildPlan):
            pass

        fields = {
            name: getattr(accepted, name) for name in accepted.__dataclass_fields__
        }
        with self.assertRaisesRegex(protocol.ProtocolError, "exact accepted"):
            protocol.require_accepted_release_build_plan(AcceptedPlanSubclass(**fields))

    def test_accepts_exactly_the_five_policy_targets(self) -> None:
        for target in self.policy["targets"]:
            with self.subTest(target=target["triple"]):
                plan_bytes = self.mutate_plan(
                    lambda document, target=target: (
                        document.__setitem__("target", target["triple"]),
                        document["outputs"].__setitem__("binary", target["binary"]),
                        document["outputs"].__setitem__("sbom", target["sbom"]),
                    )
                )
                accepted = self.accepted_plan(plan_bytes=plan_bytes)
                self.assertEqual(accepted.execution.target, target["triple"])
                self.assertEqual(accepted.binary_name, target["binary"])
                self.assertEqual(accepted.sbom_name, target["sbom"])

    def test_plan_rejects_unknown_duplicate_reordered_and_oversized_json(self) -> None:
        unknown = self.mutate_plan(
            lambda document: document.__setitem__("future", True)
        )
        self.assert_plan_rejected(unknown, "fields differ from protocol")
        for name, value in (
            ("features", ["future"]),
            ("environment", {"RUSTFLAGS": "x"}),
        ):
            with self.subTest(name=name):
                candidate = self.mutate_plan(
                    lambda document, name=name, value=value: document.__setitem__(
                        name, value
                    )
                )
                self.assert_plan_rejected(candidate, "fields differ from protocol")

        duplicate = self.plan_bytes.replace(
            b'{\n  "schema":',
            b'{\n  "schema": "forge.release-build-plan/v1",\n  "schema":',
            1,
        )
        self.assert_plan_rejected(duplicate, "duplicate key 'schema'")

        document = json.loads(self.plan_bytes)
        reordered = {"purpose": document["purpose"], "schema": document["schema"]}
        reordered.update(
            (key, value)
            for key, value in document.items()
            if key not in {"purpose", "schema"}
        )
        self.assert_plan_rejected(
            protocol.canonical_json(reordered), "canonical protocol order"
        )
        self.assert_plan_rejected(
            b" " * (protocol.MAX_PLAN_BYTES + 1),
            "1..=16384 bytes",
        )

    def test_plan_rejects_wrong_schema_version_semantics_and_output(self) -> None:
        cases = {
            "schema": ("schema", "forge.release-build-plan/v2"),
            "purpose": ("purpose", "unknown"),
            "profile": ("profile", "dev"),
            "dependency": ("dependency_resolution", "unlocked"),
            "network": ("network", "online"),
            "binary": ("binary", "other"),
        }
        for name, (field, value) in cases.items():
            with self.subTest(name=name):
                candidate = self.mutate_plan(
                    lambda document, field=field, value=value: document.__setitem__(
                        field, value
                    )
                )
                self.assert_plan_rejected(candidate, "frozen protocol value")

        wrong_output = self.mutate_plan(
            lambda document: document["outputs"].__setitem__("binary", "other")
        )
        self.assert_plan_rejected(wrong_output, "outputs.binary")

        policy = copy.deepcopy(self.policy)
        policy["release"]["version"] = "0.1.0"
        with self.assertRaisesRegex(protocol.ProtocolError, "release.version"):
            self.accepted_plan(policy=policy)

    def test_plan_rejects_wrong_source_target_lock_and_policy_source(self) -> None:
        with self.assertRaisesRegex(protocol.ProtocolError, "source_commit.oid"):
            self.accepted_plan(source_commit="b" * 40)
        with self.assertRaisesRegex(
            protocol.ProtocolError, "full lowercase Git object ID"
        ):
            self.accepted_plan(source_commit="not-an-object")

        unknown_target = self.mutate_plan(
            lambda document: document.__setitem__("target", "future-target")
        )
        self.assert_plan_rejected(unknown_target, "frozen policy target")

        wrong_lock = self.mutate_plan(
            lambda document: document.__setitem__("cargo_lock_sha256", "0" * 64)
        )
        self.assert_plan_rejected(wrong_lock, "cargo_lock_sha256")

        policy = copy.deepcopy(self.policy)
        policy["source"]["repository"] = "not-forge"
        with self.assertRaisesRegex(protocol.ProtocolError, "policy.source.repository"):
            self.accepted_plan(policy=policy)

    def test_policy_rejects_unknown_fields_at_every_existing_object_level(self) -> None:
        mutations: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            ("root", lambda value: value.__setitem__("future", True)),
            ("source", lambda value: value["source"].__setitem__("future", True)),
            (
                "authority",
                lambda value: value["authority"].__setitem__("future", True),
            ),
            (
                "release",
                lambda value: value["release"].__setitem__("future", True),
            ),
            (
                "notice",
                lambda value: value["release"]["notice"].__setitem__("future", True),
            ),
            (
                "toolchain",
                lambda value: value["toolchain"].__setitem__("future", True),
            ),
            (
                "target",
                lambda value: value["targets"][0].__setitem__("future", True),
            ),
            (
                "sbomGraph",
                lambda value: value["targets"][0]["sbomGraph"].__setitem__(
                    "future", True
                ),
            ),
            (
                "builderRecords",
                lambda value: value["builderRecords"].__setitem__("future", True),
            ),
            (
                "provenance",
                lambda value: value["provenance"].__setitem__("future", True),
            ),
            (
                "limits",
                lambda value: value["limits"].__setitem__("future", True),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(level=label):
                policy = copy.deepcopy(self.policy)
                mutate(policy)
                with self.assertRaisesRegex(protocol.ProtocolError, "fields differ"):
                    self.accepted_plan(policy=policy)

    def test_plan_binds_trusted_toolchain_source_root_and_inventory(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["toolchain"]["rust"] = "1.96.1"
        with self.assertRaisesRegex(protocol.ProtocolError, "policy.toolchain.rust"):
            self.accepted_plan(policy=policy)
        with self.assertRaisesRegex(protocol.ProtocolError, "expected Rust toolchain"):
            self.accepted_plan(rust_toolchain="1.96.1")
        with self.assertRaisesRegex(protocol.ProtocolError, "not canonical"):
            self.accepted_plan(source_root="/authority/source/")
        with self.assertRaisesRegex(protocol.ProtocolError, "unsafe path segment"):
            self.accepted_plan(source_root="/authority/../outside")
        with self.assertRaisesRegex(
            protocol.ProtocolError, "omits workspace Cargo.toml"
        ):
            self.accepted_plan(source_inventory=("crates/forge-cli/Cargo.toml",))
        with self.assertRaisesRegex(
            protocol.ProtocolError, "non-canonical relative path"
        ):
            self.accepted_plan(
                source_inventory=("Cargo.toml", "crates/../outside/Cargo.toml")
            )

    def test_plan_binds_disjoint_dependency_root_and_frozen_inventory(self) -> None:
        accepted = self.accepted_plan(
            dependency_inventory=dict(reversed(tuple(DEPENDENCY_INVENTORY.items())))
        )
        baseline = self.accepted_plan()
        self.assertEqual(
            accepted.dependency_inventory,
            baseline.dependency_inventory,
        )
        self.assertEqual(
            accepted.dependency_inventory_sha256,
            baseline.dependency_inventory_sha256,
        )
        for kwargs in (
            {"dependency_root": SOURCE_ROOT},
            {"dependency_root": SOURCE_ROOT + "/vendor"},
            {"target_root": SOURCE_ROOT + "/target"},
            {
                "source_root": r"D:\Authority\Source",
                "dependency_root": r"d:\authority\source\registry",
            },
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(protocol.ProtocolError, "roots overlap"):
                    self.accepted_plan(**kwargs)
        with self.assertRaisesRegex(protocol.ProtocolError, "count exceeds bounds"):
            self.accepted_plan(dependency_inventory={})
        with self.assertRaisesRegex(protocol.ProtocolError, "lowercase SHA-256"):
            self.accepted_plan(
                dependency_inventory={"serde-1.0.229/Cargo.toml": "A" * 64}
            )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "non-canonical relative path"
        ):
            self.accepted_plan(
                dependency_inventory={"serde-1.0.229/../Cargo.toml": "a" * 64}
            )

    def test_plan_accepts_reviewed_registry_path_characters(self) -> None:
        paths = (
            "toml-1.1.3+spec-1.1.0/Cargo.toml",
            "schemars-1.2.1/snapshots/skip.rs~skip_struct_field.json",
        )
        inventory = {
            **DEPENDENCY_INVENTORY,
            **{path: "a" * 64 for path in paths},
        }

        accepted = self.accepted_plan(dependency_inventory=inventory)

        for path in paths:
            self.assertIn((path, "a" * 64), accepted.dependency_inventory)

    def test_plan_bounds_inventory_total_utf8_bytes(self) -> None:
        original = protocol.MAX_INVENTORY_UTF8_BYTES
        try:
            protocol.MAX_INVENTORY_UTF8_BYTES = 12
            with self.assertRaisesRegex(protocol.ProtocolError, "UTF-8 byte budget"):
                self.accepted_plan(source_inventory=("Cargo.toml", "a/b"))
            protocol.MAX_INVENTORY_UTF8_BYTES = 64
            with self.assertRaisesRegex(protocol.ProtocolError, "UTF-8 byte budget"):
                self.accepted_plan(dependency_inventory={"a": "0" * 64})
        finally:
            protocol.MAX_INVENTORY_UTF8_BYTES = original

    def test_plan_accepts_canonical_sha256_git_identity(self) -> None:
        source_commit = "d" * 64
        plan_bytes = self.mutate_plan(
            lambda document: document["source_commit"].update(
                {"object_format": "sha256", "oid": source_commit}
            )
        )
        accepted = self.accepted_plan(
            plan_bytes=plan_bytes, source_commit=source_commit
        )
        self.assertEqual(accepted.source_commit, source_commit)

    def test_plan_rejects_lock_bounds_and_noncanonical_lock(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["limits"]["cargoLockBytes"] = len(self.lock_bytes) - 1
        with self.assertRaisesRegex(protocol.ProtocolError, "Cargo.lock must contain"):
            self.accepted_plan(policy=policy)
        with self.assertRaisesRegex(protocol.ProtocolError, "LF-terminated"):
            self.accepted_plan(lock_bytes=self.lock_bytes.replace(b"\n", b"\r\n"))

    def test_descriptor_matches_checked_in_golden_exactly(self) -> None:
        self.assertEqual(self.descriptor(), self.descriptor_bytes)
        document = json.loads(self.descriptor_bytes)
        self.assertEqual(document["schema"], protocol.APPLY_DESCRIPTOR_SCHEMA)
        self.assertEqual(
            document["plan_sha256"], hashlib.sha256(self.plan_bytes).hexdigest()
        )
        self.assertEqual(
            [package["key"] for package in document["sbom_graph"]["packages"]],
            sorted(package["key"] for package in document["sbom_graph"]["packages"]),
        )
        self.assertEqual(
            [row["package"] for row in document["sbom_graph"]["dependencies"]],
            sorted(row["package"] for row in document["sbom_graph"]["dependencies"]),
        )

    def test_descriptor_is_deterministic_and_excludes_paths(self) -> None:
        first = self.descriptor()
        second = self.descriptor()
        self.assertEqual(first, second)
        text = first.decode("utf-8")
        self.assertNotIn("/authority/", text)
        self.assertNotIn("file://", text)
        self.assertNotIn("test-only", text)
        self.assertTrue(text.endswith("\n"))

    def test_descriptor_rejects_binary_fact_bounds(self) -> None:
        for length in (0, self.policy["limits"]["binaryBytes"] + 1, True):
            with self.subTest(length=length):
                with self.assertRaisesRegex(protocol.ProtocolError, "binary length"):
                    self.descriptor(length=length)
        with self.assertRaisesRegex(protocol.ProtocolError, "lowercase SHA-256"):
            self.descriptor(digest="C" * 64)

    def test_descriptor_rejects_changed_or_malformed_capture_inputs(self) -> None:
        with self.assertRaisesRegex(protocol.ProtocolError, "no longer matches"):
            self.descriptor(lock=self.lock_bytes + b"\n")
        duplicate_metadata = self.metadata_bytes.replace(
            b'{\n  "packages":',
            b'{\n  "packages": [],\n  "packages":',
            1,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "duplicate key 'packages'"):
            self.descriptor(metadata=duplicate_metadata)
        with self.assertRaisesRegex(
            protocol.ProtocolError, "Cargo metadata must contain"
        ):
            self.descriptor(metadata=b"x" * (protocol.MAX_METADATA_BYTES + 1))
        with self.assertRaisesRegex(protocol.ProtocolError, "Cargo tree must contain"):
            self.descriptor(tree=b"x" * (protocol.MAX_TREE_BYTES + 1))
        with self.assertRaisesRegex(protocol.ProtocolError, "depth discontinuity"):
            self.descriptor(tree=self.tree_bytes.replace(b"1@@serde", b"2@@serde"))
        with self.assertRaisesRegex(protocol.ProtocolError, "Cargo.lock must contain"):
            self.descriptor(lock=cast(bytes, "not-bytes"))
        oversized_lock = b"x" * (self.policy["limits"]["cargoLockBytes"] + 1)
        with self.assertRaisesRegex(protocol.ProtocolError, "Cargo.lock must contain"):
            self.descriptor(lock=oversized_lock)

    def test_descriptor_binds_metadata_to_trusted_source_inventory(self) -> None:
        outside_root = json.loads(self.metadata_bytes)
        outside_root["workspace_root"] = "/outside/unbound"
        with self.assertRaisesRegex(protocol.ProtocolError, "workspace_root"):
            self.descriptor(metadata=protocol.canonical_json(outside_root))

        outside_manifest = json.loads(self.metadata_bytes)
        outside_manifest["packages"][0]["manifest_path"] = "/outside/unbound/Cargo.toml"
        with self.assertRaisesRegex(protocol.ProtocolError, "escapes"):
            self.descriptor(metadata=protocol.canonical_json(outside_manifest))

        unbound_manifest = json.loads(self.metadata_bytes)
        unbound_manifest["packages"][0]["manifest_path"] = (
            "/authority/source/unbound/Cargo.toml"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "unbound"):
            self.descriptor(metadata=protocol.canonical_json(unbound_manifest))

        outside_id = json.loads(self.metadata_bytes)
        outside_id["packages"][0]["id"] = "path+file:///outside/unbound#0.1.0-rc.2"
        outside_id["workspace_members"] = [outside_id["packages"][0]["id"]]
        outside_id["workspace_default_members"] = [outside_id["packages"][0]["id"]]
        with self.assertRaisesRegex(protocol.ProtocolError, "workspace package ID"):
            self.descriptor(metadata=protocol.canonical_json(outside_id))

        plan = self.accepted_plan(
            policy=self.synthetic_graph_policy,
            source_inventory=("Cargo.toml", "crates/forge-cli/src/main.rs"),
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "unbound"):
            self.descriptor(plan=plan)

    def test_descriptor_binds_every_registry_path_to_verified_dependency_files(
        self,
    ) -> None:
        source_replacement = json.loads(self.metadata_bytes)
        source_replacement["packages"][1]["manifest_path"] = (
            "/authority/source/vendor/serde-1.0.229/Cargo.toml"
        )
        source_replacement["packages"][1]["targets"][0]["src_path"] = (
            "/authority/source/vendor/serde-1.0.229/src/lib.rs"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "dependency root"):
            self.descriptor(metadata=protocol.canonical_json(source_replacement))

        unbound = json.loads(self.metadata_bytes)
        unbound["packages"][1]["targets"][0]["src_path"] = (
            DEPENDENCY_ROOT + "/serde-1.0.229/src/replaced.rs"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "dependency inventory"):
            self.descriptor(metadata=protocol.canonical_json(unbound))

        cross_package = json.loads(self.metadata_bytes)
        cross_package["packages"][1]["targets"][0]["src_path"] = (
            DEPENDENCY_ROOT + "/build-helper-1.2.3/src/lib.rs"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "package directory"):
            self.descriptor(metadata=protocol.canonical_json(cross_package))

        unsupported_source = json.loads(self.metadata_bytes)
        unsupported_source["packages"][3]["source"] = (
            "registry+https://private.invalid/index"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "outside protocol"):
            self.descriptor(metadata=protocol.canonical_json(unsupported_source))

        missing_manifest_inventory = dict(DEPENDENCY_INVENTORY)
        del missing_manifest_inventory["serde-1.0.229/Cargo.toml"]
        plan = self.accepted_plan(
            policy=self.synthetic_graph_policy,
            dependency_inventory=missing_manifest_inventory,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "dependency inventory"):
            self.descriptor(plan=plan)

    def test_descriptor_rejects_registry_manifest_identity_substitution(self) -> None:
        replacement_paths = {
            "replacement/not-serde/Cargo.toml": "1" * 64,
            "replacement/not-serde/src/lib.rs": "2" * 64,
        }
        inventory = {**DEPENDENCY_INVENTORY, **replacement_paths}
        plan = self.accepted_plan(
            policy=self.synthetic_graph_policy,
            dependency_inventory=inventory,
        )
        metadata = json.loads(self.metadata_bytes)
        metadata["packages"][1]["manifest_path"] = (
            DEPENDENCY_ROOT + "/replacement/not-serde/Cargo.toml"
        )
        metadata["packages"][1]["targets"][0]["src_path"] = (
            DEPENDENCY_ROOT + "/replacement/not-serde/src/lib.rs"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "manifest directory"):
            self.descriptor(plan=plan, metadata=protocol.canonical_json(metadata))

    def test_descriptor_source_binding_supports_canonical_windows_paths(self) -> None:
        windows_root = r"D:\authority\source"
        metadata = json.loads(self.metadata_bytes)
        metadata["workspace_root"] = windows_root
        root_package = metadata["packages"][0]
        root_package["id"] = (
            "path+file:///D:/authority/source/crates/forge-cli#0.1.0-rc.2"
        )
        root_package["manifest_path"] = windows_root + r"\crates\forge-cli\Cargo.toml"
        root_package["targets"][0]["src_path"] = (
            windows_root + r"\crates\forge-cli\src\main.rs"
        )
        metadata["workspace_members"] = [root_package["id"]]
        metadata["workspace_default_members"] = [root_package["id"]]

        tree = self.tree_bytes.replace(
            b"/authority/source/crates/forge-cli",
            (windows_root + r"\crates\forge-cli").encode("utf-8"),
        )
        message_lines = self.build_messages_bytes.decode("utf-8").splitlines()
        messages = [json.loads(line) for line in message_lines]
        messages[2]["package_id"] = root_package["id"]
        messages[2]["manifest_path"] = root_package["manifest_path"]
        messages[2]["target"]["src_path"] = root_package["targets"][0]["src_path"]
        build_messages = (
            "\n".join(
                json.dumps(message, separators=(",", ":")) for message in messages
            )
            + "\n"
        ).encode("utf-8")
        plan = self.accepted_plan(
            policy=self.synthetic_graph_policy,
            source_root=windows_root,
        )
        self.assertEqual(
            self.descriptor(
                plan=plan,
                metadata=protocol.canonical_json(metadata),
                tree=tree,
                build_messages=build_messages,
            ),
            self.descriptor_bytes,
        )

    def test_descriptor_requires_exact_compiler_artifact_closure(self) -> None:
        lines = self.build_messages_bytes.decode("utf-8").splitlines()
        missing = ("\n".join(lines[1:]) + "\n").encode("utf-8")
        with self.assertRaisesRegex(protocol.ProtocolError, "closure differs"):
            self.descriptor(build_messages=missing)

        metadata = json.loads(self.metadata_bytes)
        extra_package = metadata["packages"][3]
        extra = json.dumps(
            {
                "reason": "compiler-artifact",
                "package_id": extra_package["id"],
                "target": extra_package["targets"][0],
            },
            separators=(",", ":"),
        )
        extra_messages = ("\n".join([*lines[:-1], extra, lines[-1]]) + "\n").encode(
            "utf-8"
        )
        with self.assertRaisesRegex(
            protocol.ProtocolError, "outside the selected graph"
        ):
            self.descriptor(build_messages=extra_messages)

        duplicate = ("\n".join([lines[0], *lines]) + "\n").encode("utf-8")
        with self.assertRaisesRegex(
            protocol.ProtocolError, "repeats a compiler-artifact"
        ):
            self.descriptor(build_messages=duplicate)

        wrong_target = json.loads(lines[0])
        wrong_target["target"]["name"] = "wrong-target"
        wrong_target_messages = (
            "\n".join(
                [
                    json.dumps(wrong_target, separators=(",", ":")),
                    *lines[1:],
                ]
            )
            + "\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(protocol.ProtocolError, "target differs"):
            self.descriptor(build_messages=wrong_target_messages)

        wrong_root_metadata = json.loads(self.metadata_bytes)
        wrong_root_metadata["packages"][0]["targets"][0]["name"] = "not-forge"
        wrong_root_lines = list(lines)
        wrong_root_message = json.loads(wrong_root_lines[2])
        wrong_root_message["target"]["name"] = "not-forge"
        wrong_root_lines[2] = json.dumps(wrong_root_message, separators=(",", ":"))
        with self.assertRaisesRegex(protocol.ProtocolError, "wrong root target"):
            self.descriptor(
                metadata=protocol.canonical_json(wrong_root_metadata),
                build_messages=("\n".join(wrong_root_lines) + "\n").encode("utf-8"),
            )

    def test_resolves_one_pinned_root_artifact_binding(self) -> None:
        plan = self.accepted_plan(policy=self.synthetic_graph_policy)
        artifact = protocol.resolve_release_binary_artifact(
            plan,
            self.metadata_bytes,
            self.tree_bytes,
            self.build_messages_bytes,
        )
        self.assertEqual(artifact.target_root, TARGET_ROOT)
        self.assertEqual(
            artifact.authority_context_sha256,
            plan.authority_context_sha256,
        )
        self.assertEqual(
            artifact.relative_path,
            "x86_64-unknown-linux-musl/release/forge",
        )
        self.assertEqual(
            artifact.metadata_sha256,
            hashlib.sha256(self.metadata_bytes).hexdigest(),
        )
        self.assertRegex(artifact.identity_sha256, r"\A[0-9a-f]{64}\Z")
        with self.assertRaisesRegex(protocol.ProtocolError, "does not match"):
            plan.execution.cargo_build_arguments("/authority/other-target")

    def test_all_public_consumers_reject_forged_accepted_plan_fields(self) -> None:
        plan = self.accepted_plan(policy=self.synthetic_graph_policy)
        artifact = protocol.resolve_release_binary_artifact(
            plan,
            self.metadata_bytes,
            self.tree_bytes,
            self.build_messages_bytes,
        )
        captured = protocol.bind_captured_release_binary(
            plan, artifact, 120, BINARY_SHA256
        )
        dependency_inventory = list(plan.dependency_inventory)
        dependency_inventory[0] = (
            dependency_inventory[0][0],
            "e" * 64,
        )
        forged_plans = (
            ("plan SHA", replace(plan, plan_sha256="e" * 64)),
            ("source commit", replace(plan, source_commit="b" * 40)),
            ("Cargo.lock SHA", replace(plan, cargo_lock_sha256="e" * 64)),
            ("source root", replace(plan, source_root="/authority/forged-source")),
            ("target root", replace(plan, target_root="/authority/forged-target")),
            (
                "source inventory",
                replace(
                    plan,
                    source_inventory=plan.source_inventory | frozenset({"forged.txt"}),
                ),
            ),
            (
                "dependency inventory",
                replace(plan, dependency_inventory=tuple(dependency_inventory)),
            ),
            (
                "source inventory digest",
                replace(plan, source_inventory_sha256="e" * 64),
            ),
            (
                "dependency inventory digest",
                replace(plan, dependency_inventory_sha256="e" * 64),
            ),
            (
                "execution target",
                replace(
                    plan,
                    execution=replace(
                        plan.execution, target="aarch64-unknown-linux-musl"
                    ),
                ),
            ),
            (
                "execution root",
                replace(
                    plan,
                    execution=replace(
                        plan.execution, target_root="/authority/forged-target"
                    ),
                ),
            ),
            (
                "execution toolchain",
                replace(
                    plan,
                    execution=replace(plan.execution, rust_toolchain="1.96.1"),
                ),
            ),
            (
                "execution profile",
                replace(plan, execution=replace(plan.execution, profile="dev")),
            ),
            (
                "execution network",
                replace(plan, execution=replace(plan.execution, network="online")),
            ),
            (
                "execution features",
                replace(
                    plan,
                    execution=replace(plan.execution, features=("future",)),
                ),
            ),
            (
                "execution environment",
                replace(
                    plan,
                    execution=replace(plan.execution, environment_overrides=()),
                ),
            ),
            (
                "SBOM graph",
                replace(
                    plan,
                    sbom_graph=replace(
                        plan.sbom_graph,
                        component_count=plan.sbom_graph.component_count + 1,
                    ),
                ),
            ),
            ("binary limit", replace(plan, binary_limit=plan.binary_limit - 1)),
            (
                "license",
                replace(plan, project_license_expression="LicenseRef-forged"),
            ),
            (
                "canonical plan",
                replace(plan, canonical_bytes=plan.canonical_bytes + b" "),
            ),
            (
                "context digest",
                replace(plan, authority_context_sha256="e" * 64),
            ),
        )
        consumers: tuple[
            tuple[str, Callable[[protocol.AcceptedReleaseBuildPlan], object]], ...
        ] = (
            (
                "resolve",
                lambda value: protocol.resolve_release_binary_artifact(
                    value,
                    self.metadata_bytes,
                    self.tree_bytes,
                    self.build_messages_bytes,
                ),
            ),
            (
                "bind",
                lambda value: protocol.bind_captured_release_binary(
                    value, artifact, 120, BINARY_SHA256
                ),
            ),
            (
                "build",
                lambda value: protocol.build_release_build_apply_descriptor(
                    value,
                    self.metadata_bytes,
                    self.tree_bytes,
                    self.build_messages_bytes,
                    self.lock_bytes,
                    captured,
                ),
            ),
        )
        for field, forged in forged_plans:
            for consumer, consume in consumers:
                with self.subTest(field=field, consumer=consumer):
                    with self.assertRaises(protocol.ProtocolError):
                        consume(forged)

    def test_rejects_hand_constructed_and_subclassed_accepted_plans(self) -> None:
        plan = self.accepted_plan(policy=self.synthetic_graph_policy)
        fields = {name: getattr(plan, name) for name in plan.__dataclass_fields__}
        fields["cargo_lock_limit"] = plan.cargo_lock_limit - 1
        constructed = protocol.AcceptedReleaseBuildPlan(**fields)
        with self.assertRaises(protocol.ProtocolError):
            protocol.resolve_release_binary_artifact(
                constructed,
                self.metadata_bytes,
                self.tree_bytes,
                self.build_messages_bytes,
            )

        class AcceptedPlanSubclass(protocol.AcceptedReleaseBuildPlan):
            pass

        exact_fields = {name: getattr(plan, name) for name in plan.__dataclass_fields__}
        subclassed = AcceptedPlanSubclass(**exact_fields)
        with self.assertRaisesRegex(protocol.ProtocolError, "exact accepted"):
            protocol.resolve_release_binary_artifact(
                subclassed,
                self.metadata_bytes,
                self.tree_bytes,
                self.build_messages_bytes,
            )

    def test_bind_rejects_malformed_artifact_binding_fields(self) -> None:
        plan = self.accepted_plan(policy=self.synthetic_graph_policy)
        artifact = protocol.resolve_release_binary_artifact(
            plan,
            self.metadata_bytes,
            self.tree_bytes,
            self.build_messages_bytes,
        )
        for field, forged in (
            ("context", replace(artifact, authority_context_sha256="e" * 64)),
            ("plan", replace(artifact, plan_sha256="e" * 64)),
            ("root", replace(artifact, target_root="/authority/other-target")),
            ("path", replace(artifact, relative_path="../forge")),
            ("metadata", replace(artifact, metadata_sha256="X" * 64)),
            ("tree", replace(artifact, tree_sha256="not-a-digest")),
            ("messages", replace(artifact, build_messages_sha256="F" * 64)),
            ("identity", replace(artifact, identity_sha256="invalid")),
        ):
            with self.subTest(field=field):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.bind_captured_release_binary(
                        plan, forged, 120, BINARY_SHA256
                    )

    def test_resolves_canonical_windows_target_artifact_path(self) -> None:
        target = self.policy["targets"][-1]
        plan_document = json.loads(self.plan_bytes)
        plan_document["target"] = target["triple"]
        plan_document["outputs"] = {
            "binary": target["binary"],
            "sbom": target["sbom"],
        }
        policy = copy.deepcopy(self.policy)
        policy["targets"][-1]["sbomGraph"] = {
            "componentCount": 3,
            "dependencyEdgeCount": 2,
            "canonicalSha256": FIXTURE_GRAPH_SHA256,
        }
        windows_target_root = r"D:\authority\target"
        plan = self.accepted_plan(
            plan_bytes=protocol.canonical_json(plan_document),
            policy=policy,
            target_root=windows_target_root,
        )
        metadata = json.loads(self.metadata_bytes)
        metadata["target_directory"] = windows_target_root
        messages = [
            json.loads(line)
            for line in self.build_messages_bytes.decode("utf-8").splitlines()
        ]
        for message in messages[:-1]:
            relative_filenames = [
                value.removeprefix(TARGET_ROOT + "/").replace(
                    "x86_64-unknown-linux-musl", target["triple"], 1
                )
                for value in message["filenames"]
            ]
            message["filenames"] = [
                windows_target_root + "\\" + value.replace("/", "\\")
                for value in relative_filenames
            ]
            if message["executable"] is not None:
                message["filenames"] = [
                    windows_target_root
                    + "\\"
                    + target["triple"]
                    + r"\release\forge.exe"
                ]
                message["executable"] = message["filenames"][0]
        build_messages = (
            "\n".join(
                json.dumps(message, separators=(",", ":")) for message in messages
            )
            + "\n"
        ).encode("utf-8")
        artifact = protocol.resolve_release_binary_artifact(
            plan,
            protocol.canonical_json(metadata),
            self.tree_bytes,
            build_messages,
        )
        self.assertEqual(
            artifact.relative_path,
            "x86_64-pc-windows-msvc/release/forge.exe",
        )

    def test_root_artifact_rejects_unknown_escaping_and_repeated_paths(self) -> None:
        root_path = TARGET_ROOT + "/x86_64-unknown-linux-musl/release/forge"
        cases: tuple[tuple[str, Callable[[list[dict[str, Any]]], None], str], ...] = (
            (
                "escape",
                lambda messages: (
                    messages[2].__setitem__("filenames", ["/outside/forge"]),
                    messages[2].__setitem__("executable", "/outside/forge"),
                ),
                "target root",
            ),
            (
                "unknown",
                lambda messages: (
                    messages[2].__setitem__(
                        "filenames", [TARGET_ROOT + "/release/other"]
                    ),
                    messages[2].__setitem__(
                        "executable", TARGET_ROOT + "/release/other"
                    ),
                ),
                "frozen target output",
            ),
            (
                "missing executable",
                lambda messages: messages[2].__setitem__("executable", None),
                "omits its executable",
            ),
            (
                "detached executable",
                lambda messages: messages[2].__setitem__(
                    "filenames", [root_path + ".replacement"]
                ),
                "absent from filenames",
            ),
            (
                "repeated path",
                lambda messages: messages[1].__setitem__(
                    "filenames", messages[0]["filenames"]
                ),
                "repeats an output path",
            ),
            (
                "missing path set",
                lambda messages: messages[2].pop("filenames"),
                "must be an array",
            ),
            (
                "manifest replacement",
                lambda messages: messages[2].__setitem__(
                    "manifest_path", "/authority/source/Cargo.toml"
                ),
                "manifest_path",
            ),
        )
        for label, mutate, message in cases:
            with self.subTest(case=label):
                build_messages = self.mutate_build_messages(mutate)
                with self.assertRaisesRegex(protocol.ProtocolError, message):
                    self.descriptor(build_messages=build_messages)

        duplicate_root = self.mutate_build_messages(
            lambda messages: messages.insert(3, copy.deepcopy(messages[2]))
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "repeats"):
            self.descriptor(build_messages=duplicate_root)

    def test_descriptor_rejects_detached_binary_capture_binding(self) -> None:
        plan = self.accepted_plan(policy=self.synthetic_graph_policy)
        artifact = protocol.resolve_release_binary_artifact(
            plan,
            self.metadata_bytes,
            self.tree_bytes,
            self.build_messages_bytes,
        )
        captured = protocol.bind_captured_release_binary(
            plan, artifact, 120, BINARY_SHA256
        )
        changed_messages = self.mutate_build_messages(
            lambda messages: messages[2].__setitem__("fresh", False)
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "artifact binding"):
            self.descriptor(
                plan=plan,
                build_messages=changed_messages,
                captured=captured,
            )

        changed_inventory = dict(DEPENDENCY_INVENTORY)
        changed_inventory["serde-1.0.229/Cargo.toml"] = "f" * 64
        changed_plan = self.accepted_plan(
            policy=self.synthetic_graph_policy,
            dependency_inventory=changed_inventory,
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "Authority context"):
            protocol.bind_captured_release_binary(
                changed_plan,
                artifact,
                120,
                BINARY_SHA256,
            )

    def test_descriptor_requires_exact_policy_sbom_graph(self) -> None:
        with self.assertRaisesRegex(
            protocol.ProtocolError, "differs from Authority policy"
        ):
            self.descriptor(plan=self.accepted_plan())
        for field, value in (
            ("componentCount", 4),
            ("dependencyEdgeCount", 3),
            ("canonicalSha256", "f" * 64),
        ):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.synthetic_graph_policy)
                policy["targets"][0]["sbomGraph"][field] = value
                plan = self.accepted_plan(policy=policy)
                with self.assertRaisesRegex(
                    protocol.ProtocolError, "differs from Authority policy"
                ):
                    self.descriptor(plan=plan)

    def test_descriptor_rejects_non_policy_source_and_unreviewed_license(self) -> None:
        private_source = "registry+https://private.invalid/index"
        lock = self.lock_bytes.replace(
            protocol.CRATES_IO_SOURCE.encode(), private_source.encode()
        )
        plan_document = json.loads(self.plan_bytes)
        plan_document["cargo_lock_sha256"] = hashlib.sha256(lock).hexdigest()
        plan = self.accepted_plan(
            plan_bytes=protocol.canonical_json(plan_document),
            policy=self.synthetic_graph_policy,
            lock_bytes=lock,
        )
        metadata = self.metadata_bytes.replace(
            protocol.CRATES_IO_SOURCE.encode(), private_source.encode()
        )
        build_messages = self.build_messages_bytes.replace(
            protocol.CRATES_IO_SOURCE.encode(), private_source.encode()
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "source is outside"):
            self.descriptor(
                plan=plan,
                metadata=metadata,
                build_messages=build_messages,
                lock=lock,
            )

        metadata_document = json.loads(self.metadata_bytes)
        metadata_document["packages"][1]["license"] = "LicenseRef-future"
        with self.assertRaisesRegex(protocol.ProtocolError, "unreviewed license"):
            self.descriptor(metadata=protocol.canonical_json(metadata_document))

    def test_descriptor_rejects_graph_ambiguity_and_cycles(self) -> None:
        metadata_document = json.loads(self.metadata_bytes)
        duplicate = copy.deepcopy(metadata_document["packages"][1])
        duplicate["id"] = "registry+duplicate#serde@1.0.229"
        metadata_document["packages"].append(duplicate)
        with self.assertRaisesRegex(
            protocol.ProtocolError, "repeats a crates.io package directory"
        ):
            self.descriptor(metadata=protocol.canonical_json(metadata_document))

        cycle_tree = (
            self.tree_bytes
            + b"2@@forge-cli v0.1.0-rc.2 (/authority/source/crates/forge-cli)@@\n"
        )
        with self.assertRaisesRegex(protocol.ProtocolError, "root has an incoming"):
            self.descriptor(tree=cycle_tree)

    def test_blake3_package_reference_vectors_are_frozen(self) -> None:
        self.assertEqual(
            protocol._blake3_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        self.assertEqual(
            protocol._blake3_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        )
        self.assertEqual(
            protocol._blake3_hex(b"a" * 65),
            "f345679d9055e53939e92c04ff4f6c9d824b849810d4b598f54baa23336cde99",
        )
        self.assertEqual(
            protocol._blake3_hex(b"x" * 300),
            "296a7bce08325b75b90d23204fd50b75f618d9d6c807cd1dfaaf3a4169fa8a23",
        )

    def test_descriptor_matches_protected_forge_consumer_golden(self) -> None:
        """Match Forge's xtask/tests/golden consumer fixture without executing Forge."""
        self.assertEqual(
            hashlib.sha256(self.consumer_descriptor_bytes).hexdigest(),
            "6f41a10eca4fb6bd51e1be93d7225c61d19a739476889402c90a642dd3836ad9",
        )
        consumer = json.loads(self.consumer_descriptor_bytes)
        authority = json.loads(self.descriptor_bytes)
        consumer["plan_sha256"] = authority["plan_sha256"]
        consumer["binary"]["sha256"] = authority["binary"]["sha256"]
        consumer["sbom_graph"]["packages"][0]["source"]["crate_archive_sha256"] = (
            authority["sbom_graph"]["packages"][0]["source"]["crate_archive_sha256"]
        )
        self.assertEqual(protocol.canonical_json(consumer), self.descriptor_bytes)

    def test_module_has_no_process_network_path_or_file_capability(self) -> None:
        source = (ROOT / "scripts" / "release_build_protocol.py").read_text()
        tree = ast.parse(source)
        imports: set[str] = set()
        forbidden_calls: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"open", "exec", "eval", "compile", "__import__"}:
                    forbidden_calls.append(node.func.id)
        self.assertEqual(
            imports,
            {
                "__future__",
                "dataclasses",
                "hashlib",
                "json",
                "re",
                "struct",
                "tomllib",
                "typing",
            },
        )
        self.assertEqual(forbidden_calls, [])
        for token in ("subprocess", "urllib", "socket", "pathlib", "requests"):
            self.assertNotIn(token, imports)


if __name__ == "__main__":
    unittest.main()
