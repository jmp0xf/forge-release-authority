from __future__ import annotations

import json
import re
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUALIFY_WORKFLOW = ROOT / ".github" / "workflows" / "qualify.yml"
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
POLICY_PATH = ROOT / "contracts" / "release-policy.json"
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
        self.assertEqual(workflow.count("retention-days: 30"), 4)

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
                  record: {target["builderRecord"]}
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


if __name__ == "__main__":
    unittest.main()
