from __future__ import annotations

import json
import re
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUALIFY_WORKFLOW = ROOT / ".github" / "workflows" / "qualify.yml"
VERIFY_WORKFLOW = ROOT / ".github" / "workflows" / "verify.yml"
WRITER_PATH = ROOT / "scripts" / "write_canary_observation.py"
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
POLICY_PATH = ROOT / "contracts" / "release-policy.json"
README_PATH = ROOT / "README.md"
BUILD_TYPE_PATH = ROOT / "docs" / "build-types" / "qualify-v1.md"
BUILDER_PATH = ROOT / "docs" / "builders" / "github-actions-protected-v1.md"
ALLOWED_ACTIONS = {
    "actions/attest": "508db95dd578ae2727ebd6217d5ba78e4fbda05d",
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
}
ACTION_LINE = re.compile(
    r"^\s*uses:\s+([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]+)(?:\s+#.*)?$"
)
JOB_HEADER = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$", re.MULTILINE)


def _job_blocks(workflow: str) -> dict[str, str]:
    jobs = workflow[workflow.index("jobs:\n") + len("jobs:\n") :]
    headers = list(JOB_HEADER.finditer(jobs))
    blocks: dict[str, str] = {}
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(jobs)
        blocks[header.group(1)] = jobs[header.start() : end]
    return blocks


def _step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {name!r}")
    start = workflow.index(marker)
    end = workflow.find("\n      - name:", start + len(marker))
    return workflow[start:] if end == -1 else workflow[start:end]


class QualifyWorkflowTests(unittest.TestCase):
    def test_external_actions_are_the_complete_allowlist_at_full_commits(self) -> None:
        seen: set[str] = set()
        for workflow_path in sorted(WORKFLOW_DIRECTORY.glob("*.yml")):
            for line_number, line in enumerate(
                workflow_path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "uses:" not in line:
                    continue
                match = ACTION_LINE.fullmatch(line)
                self.assertIsNotNone(
                    match,
                    f"{workflow_path.name}:{line_number} is not a full-SHA action reference",
                )
                assert match is not None
                action, reference = match.groups()
                self.assertIn(action, ALLOWED_ACTIONS)
                self.assertEqual(reference, ALLOWED_ACTIONS[action])
                self.assertEqual(len(reference), 40)
                seen.add(action)
        self.assertEqual(seen, set(ALLOWED_ACTIONS))

    def test_verify_workflow_has_required_windows_observation_gate(self) -> None:
        qualify = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        verify = VERIFY_WORKFLOW.read_text(encoding="utf-8")
        windows = _job_blocks(verify)["windows-observation"]
        qualification_python_versions = set(
            re.findall(r'^\s+python-version: "([^"]+)"$', qualify, re.MULTILINE)
        )

        self.assertEqual(qualification_python_versions, {"3.14.6"})
        self.assertEqual(windows.count("    name: Windows observation\n"), 1)
        self.assertEqual(windows.count("    runs-on: windows-2025\n"), 1)
        self.assertEqual(windows.count('          python-version: "3.14.6"\n'), 1)
        self.assertEqual(windows.count("          check-latest: false\n"), 1)
        self.assertNotIn("continue-on-error", windows)
        self.assertNotIn("\n    if:", windows)
        self.assertNotIn("\n    needs:", windows)
        self.assertIn(
            "test_hash_budget_hashes_real_executable_suffix",
            windows,
        )
        self.assertIn(
            "test_hash_budget_accepts_windows_path_and_descriptor_projections",
            windows,
        )
        self.assertIn("test_hash_budget_rejects_same_view_metadata_changes", windows)
        self.assertIn(
            "test_cross_view_snapshot_rejects_unknown_or_different_objects",
            windows,
        )
        self.assertIn(
            "test_windows_consume_removes_raw_and_preserves_only_summary", windows
        )
        self.assertNotIn("test_consume_removes_raw_on_success_and_malformed_input", windows)
        self.assertIn(
            "test_cleanup_removes_fixed_raw_before_reporting_entry_overflow",
            windows,
        )
        self.assertIn(
            "test_windows_paths_require_drive_absolute_and_do_not_trust_substrings",
            windows,
        )

    def test_only_protected_job_has_signing_permissions(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        header = workflow[: workflow.index("jobs:\n")]
        self.assertIn("workflow_dispatch:\n", header)
        self.assertIn("permissions: {}\n", header)
        self.assertNotIn("pull_request:", header)
        self.assertNotIn("push:", header)
        self.assertNotIn("${{ secrets", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("overwrite: true", workflow)
        self.assertEqual(workflow.count("overwrite: false"), 6)
        expected_retention = {
            "Upload canary runner observation": 30,
            "Upload exact finalized assets": 30,
            "Upload exact builder records": 30,
            "Upload deterministic qualification preview": 30,
            "Upload qualified release assets": 90,
            "Upload qualification evidence": 90,
        }
        for step_name, days in expected_retention.items():
            upload = _step_block(workflow, step_name)
            self.assertIn("uses: actions/upload-artifact@", upload, step_name)
            self.assertEqual(upload.count(f"retention-days: {days}"), 1, step_name)
            self.assertEqual(upload.count("overwrite: false"), 1, step_name)

        jobs = _job_blocks(workflow)
        self.assertEqual(
            set(jobs),
            {
                "preflight",
                "native-build",
                "finalize",
                "independent-qualify",
                "protected-attest",
            },
        )
        for name, block in jobs.items():
            if name == "protected-attest":
                continue
            self.assertNotIn("id-token:", block, name)
            self.assertNotIn("attestations:", block, name)
            self.assertNotIn("environment:", block, name)

        protected = jobs["protected-attest"]
        self.assertEqual(protected.count("environment: forge-release"), 1)
        self.assertEqual(protected.count("id-token: write"), 1)
        self.assertEqual(protected.count("attestations: write"), 1)
        self.assertIn("needs: independent-qualify", protected)
        self.assertIn("python scripts/verify_release.py", protected)
        self.assertIn("push-to-registry: false", protected)
        self.assertIn("create-storage-record: false", protected)
        self.assertNotIn("repository: jmp0xf/forge", protected)
        self.assertNotIn("working-directory: forge", protected)
        self.assertNotIn("cargo ", protected.lower())
        self.assertNotIn("xtask", protected.lower())

    def test_stage_a_dispatch_is_canary_only_and_fails_closed(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        header = workflow[: workflow.index("jobs:\n")]
        input_names = re.findall(
            r"^      ([A-Za-z][A-Za-z0-9]*):\s*$", header, re.MULTILINE
        )
        self.assertEqual(input_names, ["sourceCommit", "mode"])
        self.assertIn(
            "      mode:\n"
            "        description: Inactive release-authority diagnostic mode\n"
            "        required: true\n"
            "        type: choice\n"
            "        options:\n"
            "          - canary\n",
            header,
        )
        self.assertNotIn("default:", header)
        self.assertNotIn("qualification", header.lower())
        self.assertIn("run-name: Canary Forge", header)
        self.assertIn("group: forge-v0.1.0-rc.2-canary", header)

        jobs = _job_blocks(workflow)
        preflight = jobs["preflight"]
        native = jobs["native-build"]
        self.assertEqual(preflight.count("DISPATCH_MODE: ${{ inputs.mode }}"), 1)
        self.assertEqual(
            preflight.count('if os.environ["DISPATCH_MODE"] != "canary":'), 1
        )
        self.assertEqual(
            len(
                re.findall(
                    r"^    if: \$\{\{ inputs\.mode == 'canary' \}\}$",
                    native,
                    re.MULTILINE,
                )
            ),
            1,
        )

    def test_private_build_input_is_consumed_at_first_authority_boundary(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        native = _job_blocks(workflow)["native-build"]
        unix_create = _step_block(native, "Create fresh native directories")
        windows_create = _step_block(
            native, "Create fresh native directories on Windows"
        )
        unix_build = _step_block(native, "Check, test, and observe native candidate")
        windows_build = _step_block(
            native, "Check, test, and observe native candidate on Windows"
        )

        self.assertNotIn("${{ runner.temp }}", native)
        for block in (unix_create, unix_build):
            self.assertEqual(
                block.count(
                    'BUILD_INPUT_DIR="$RUNNER_TEMP/forge-private-build-input"'
                ),
                1,
            )
            self.assertEqual(
                block.count('BUILD_TEMP="$RUNNER_TEMP/forge-private-build-temp"'),
                1,
            )
        for block in (windows_create, windows_build):
            self.assertEqual(block.count("forge-private-build-input"), 1)
            self.assertEqual(block.count("forge-private-build-temp"), 1)
            self.assertIn("$env:RUNNER_TEMP", block)
        for block in (unix_create, windows_create):
            self.assertIn("refusing existing native directory", block)

        for platform, block, writer in (
            ("unix", unix_build, "scripts/write_canary_observation.py"),
            ("windows", windows_build, r"scripts\write_canary_observation.py"),
        ):
            self.assertEqual(block.count("--build-input-observation-dir"), 2, platform)
            self.assertEqual(block.count("--build-temp"), 1, platform)
            self.assertEqual(block.count("--expected-cargo"), 1, platform)
            self.assertEqual(block.count("--runner-temp"), 2, platform)
            release_index = block.index("release-build")
            writer_index = block.index(writer)
            version_index = block.index("version", writer_index)
            self.assertLess(release_index, writer_index, platform)
            self.assertLess(writer_index, version_index, platform)
            between = block[release_index:writer_index]
            self.assertNotIn("write_builder_record", between, platform)
            self.assertNotIn("Copy-Item", between, platform)
            self.assertNotIn("chmod", between, platform)

        self.assertLess(
            unix_build.index("trap cleanup_private_build_input EXIT"),
            unix_build.index("release-build"),
        )
        self.assertIn("--cleanup-only", unix_build)
        self.assertLess(windows_build.index("try {"), windows_build.index("release-build"))
        self.assertGreater(windows_build.index("finally {"), windows_build.index("release-build"))
        self.assertIn("--cleanup-only", windows_build)

        writer_source = WRITER_PATH.read_text(encoding="utf-8")
        writer_main = writer_source[writer_source.index("def main(") :]
        consume_index = writer_main.index("consume_build_input_observation(")
        build_index = writer_main.index("observation = build_observation(")
        write_index = writer_main.index("output = write_observation(")
        self.assertLess(consume_index, build_index)
        self.assertLess(build_index, write_index)

        upload_names = (
            "Upload canary runner observation",
            "Upload exact finalized assets",
            "Upload exact builder records",
            "Upload deterministic qualification preview",
            "Upload qualified release assets",
            "Upload qualification evidence",
        )
        for name in upload_names:
            upload = _step_block(workflow, name)
            self.assertNotIn("BUILD_INPUT_DIR", upload, name)
            self.assertNotIn("forge-private-build-input", upload, name)
            self.assertNotIn("release-build-input-observation-", upload, name)

    def test_stage_a_qualification_path_is_statically_unreachable(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        jobs = _job_blocks(workflow)
        for name in ("finalize", "independent-qualify", "protected-attest"):
            self.assertEqual(jobs[name].count("    if: ${{ false }}\n"), 1, name)

        native = jobs["native-build"]
        canary_upload = _step_block(workflow, "Upload canary runner observation")
        self.assertEqual(
            canary_upload.count("        if: ${{ inputs.mode == 'canary' }}\n"), 1
        )
        self.assertNotIn("Upload fixed native handoff", workflow)
        self.assertNotIn("write_builder_record.py", native)
        self.assertNotIn("HANDOFF_DIR", native)
        self.assertNotIn("always()", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertEqual(workflow.count("uses: actions/attest@"), 1)
        self.assertIn("uses: actions/attest@", jobs["protected-attest"])

    def test_stage_a_documentation_preserves_the_canary_evidence_boundary(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        build_type = BUILD_TYPE_PATH.read_text(encoding="utf-8")
        builder = BUILDER_PATH.read_text(encoding="utf-8")

        self.assertIn("`mode=canary`", readme)
        self.assertIn("literal-false condition", readme)
        self.assertIn("never uploaded, cached, hashed into evidence", readme)
        self.assertIn("same runner user", readme)

        self.assertIn('"mode":"canary"', build_type)
        self.assertIn("Stage A cannot create a v1 predicate", build_type)
        self.assertIn("raw hash are never uploaded", build_type)
        self.assertIn("separately reviewed v2", build_type)

        self.assertIn("mechanically unreachable in Stage A", builder)
        self.assertIn("`candidate-controlled-self-report`", builder)
        self.assertIn("`excluded-from-release-evidence`", builder)
        self.assertIn("persistent self-hosted runner", builder)

    def test_native_matrix_and_embedded_python_match_reviewed_contracts(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        native = _job_blocks(workflow)["native-build"]
        self.assertEqual(native.count("          - runner:"), len(policy["targets"]))
        for target in policy["targets"]:
            fragment = textwrap.dedent(
                f"""\
                - runner: {target["runnerLabel"]}
                  target: {target["triple"]}
                  binary: {target["binary"]}
                  sbom: {target["sbom"]}
                """
            )
            self.assertIn(textwrap.indent(fragment, "          ").rstrip(), native)

        python_blocks = re.findall(
            r"python - <<'PY'\n(.*?)^\s*PY$",
            workflow,
            re.MULTILINE | re.DOTALL,
        )
        self.assertGreater(len(python_blocks), 0)
        for index, block in enumerate(python_blocks, start=1):
            compile(textwrap.dedent(block), f"qualify.yml Python block {index}", "exec")

    def test_native_jobs_install_complete_toolchain_and_keep_source_gates(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        native = _job_blocks(workflow)["native-build"]
        unix_install = _step_block(native, "Install exact Rust toolchain")
        windows_install = _step_block(
            native, "Install exact Rust toolchain on Windows"
        )
        unix_build = _step_block(native, "Check, test, and observe native candidate")
        windows_build = _step_block(
            native, "Check, test, and observe native candidate on Windows"
        )

        rust_version = policy["toolchain"]["rust"]
        self.assertEqual(workflow.count(f"  RUSTUP_TOOLCHAIN: {rust_version}\n"), 1)
        self.assertLess(
            native.index("      - name: Install exact Rust toolchain\n"),
            native.index("      - name: Check, test, and observe native candidate\n"),
        )
        self.assertLess(
            native.index("      - name: Install exact Rust toolchain on Windows\n"),
            native.index(
                "      - name: Check, test, and observe native candidate on Windows\n"
            ),
        )

        for block in (unix_install, windows_install):
            self.assertEqual(block.count("--component clippy"), 1)
            self.assertEqual(block.count("--component rustfmt"), 1)
            self.assertEqual(block.count("cargo clippy --version"), 1)
            self.assertEqual(block.count("cargo fmt --version"), 1)

        expected_tests = {
            "unix": (
                unix_build,
                'cargo test --locked --offline --workspace --target "$TARGET" '
                "--no-fail-fast",
            ),
            "windows": (
                windows_build,
                "cargo test --locked --offline --workspace --target $env:TARGET "
                "--no-fail-fast",
            ),
        }
        for platform, (block, test_command) in expected_tests.items():
            self.assertEqual(block.count("cargo fmt --all -- --check"), 1, platform)
            self.assertLess(
                block.index("cargo fmt --all -- --check"),
                block.index("cargo fetch --locked"),
                platform,
            )
            self.assertEqual(block.count(test_command), 1, platform)
            self.assertNotIn("--test-threads", block, platform)

    def test_canary_observations_are_native_only_and_outside_provenance(self) -> None:
        workflow = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        jobs = _job_blocks(workflow)
        native = jobs["native-build"]
        unix_build = _step_block(workflow, "Check, test, and observe native candidate")
        windows_build = _step_block(
            workflow, "Check, test, and observe native candidate on Windows"
        )
        upload = _step_block(workflow, "Upload canary runner observation")

        script = "scripts/write_canary_observation.py"
        windows_script = r"scripts\write_canary_observation.py"
        self.assertEqual(workflow.count(script), 1)
        self.assertEqual(workflow.count(windows_script), 1)
        self.assertIn(script, unix_build)
        self.assertIn(windows_script, windows_build)
        unix_observation_start = unix_build.index(script)
        unix_observation = unix_build[
            unix_observation_start : unix_build.index(
                "          trap - EXIT", unix_observation_start
            )
        ]
        windows_observation_start = windows_build.index(windows_script)
        windows_observation = windows_build[
            windows_observation_start : windows_build.index(
                "$observationStatus = $LASTEXITCODE",
                windows_observation_start,
            )
        ]
        for argument in (
            "--authority-commit",
            "--binary",
            "--build-input-observation-dir",
            "--build-temp",
            "--cargo-home",
            "--expected-cargo",
            "--output-dir",
            "--runner-temp",
            "--source-commit",
            "--source-root",
            "--target",
        ):
            self.assertEqual(unix_observation.count(argument), 1, argument)
            self.assertEqual(windows_observation.count(argument), 1, argument)

        self.assertIn("name: canary-observation-${{ matrix.target }}", upload)
        self.assertIn(
            "path: ${{ github.workspace }}/canary-observation/"
            "runner-observation-${{ matrix.target }}.json",
            upload,
        )
        self.assertEqual(upload.count("retention-days: 30"), 1)
        self.assertEqual(upload.count("overwrite: false"), 1)
        self.assertIn("contents: read", native)
        self.assertNotIn("id-token:", native)
        self.assertNotIn("attestations:", native)
        self.assertNotIn("environment:", native)

        for job_name in ("finalize", "independent-qualify", "protected-attest"):
            self.assertNotIn("canary-observation", jobs[job_name], job_name)
            self.assertNotIn("runner-observation", jobs[job_name], job_name)
            self.assertNotIn(script, jobs[job_name], job_name)
            self.assertNotIn(windows_script, jobs[job_name], job_name)
        self.assertEqual(workflow.count("name: canary-observation-"), 1)
        self.assertEqual(workflow.count("runner-observation-${{ matrix.target }}.json"), 1)
        self.assertNotIn("Upload fixed native handoff", workflow)
        self.assertNotIn("write_builder_record.py", native)
        self.assertNotIn("HANDOFF_DIR", native)


if __name__ == "__main__":
    unittest.main()
