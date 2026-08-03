from __future__ import annotations

import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "linux-sandbox-observer.yml"
QUALIFY_WORKFLOW = ROOT / ".github" / "workflows" / "qualify.yml"


def _step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    if workflow.count(marker) != 1:
        raise AssertionError(f"expected exactly one workflow step named {name!r}")
    start = workflow.index(marker)
    end = workflow.find("\n      - name:", start + len(marker))
    return workflow[start:] if end == -1 else workflow[start:end]


def _heredoc(block: str, marker: str) -> str:
    opener = f"<<'{marker}'\n"
    if block.count(opener) != 1:
        raise AssertionError(f"expected exactly one {marker!r} heredoc")
    start = block.index(opener) + len(opener)
    end = block.index(f"\n          {marker}", start)
    return textwrap.dedent(block[start:end])


class LinuxSandboxObserverWorkflowTests(unittest.TestCase):
    workflow: str
    header: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.header = cls.workflow[: cls.workflow.index("jobs:\n")]

    def test_is_a_fresh_manual_authority_only_observer(self) -> None:
        self.assertEqual(self.header.count("  workflow_dispatch:\n"), 1)
        for forbidden in ("pull_request:", "push:", "schedule:", "inputs:"):
            self.assertNotIn(forbidden, self.header)
        self.assertIn("permissions: {}\n", self.header)
        self.assertIn("group: linux-sandbox-observer\n", self.header)
        self.assertIn("cancel-in-progress: false\n", self.header)
        self.assertEqual(self.workflow.count("    permissions:\n"), 1)
        self.assertEqual(self.workflow.count("      contents: read\n"), 1)
        self.assertEqual(self.workflow.count("    timeout-minutes: 10\n"), 1)
        self.assertEqual(self.workflow.count("      fail-fast: false\n"), 1)
        self.assertEqual(self.workflow.count("          - runner: ubuntu-24.04\n"), 1)
        self.assertEqual(
            self.workflow.count("          - runner: ubuntu-24.04-arm\n"), 1
        )
        self.assertEqual(self.workflow.count("            machine: x86_64\n"), 1)
        self.assertEqual(self.workflow.count("            machine: aarch64\n"), 1)

        checkout = _step_block(self.workflow, "Check out authority")
        self.assertIn(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            checkout,
        )
        for expected in (
            "ref: ${{ github.sha }}",
            "path: authority",
            "persist-credentials: false",
            "show-progress: false",
        ):
            self.assertEqual(checkout.count(expected), 1, expected)

    def test_context_guard_binds_protected_main_and_clean_checkout(self) -> None:
        guard = _step_block(self.workflow, "Bind protected authority context")
        source = _heredoc(guard, "CONTEXT_PY")
        compile(source, "linux-sandbox-observer-context", "exec")

        expected_context = {
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
            "GITHUB_RUN_ATTEMPT": "1",
        }
        for name, value in expected_context.items():
            self.assertIn(f'"{name}": "{value}"', source, name)
        self.assertIn("linux-sandbox-observer.yml@refs/heads/main", source)
        self.assertIn('os.environ.get("GITHUB_WORKFLOW_SHA", "")', source)
        self.assertIn("workflow_commit != authority_commit", source)
        self.assertIn('git("rev-parse", "--verify", "HEAD")', source)
        self.assertIn(
            'git("status", "--porcelain=v1", "--untracked-files=all")', source
        )
        self.assertNotIn("print(", source)

    def test_root_observer_has_closed_inputs_output_and_results(self) -> None:
        step = _step_block(self.workflow, "Observe fixed Linux cgroup case")
        source = _heredoc(step, "OBSERVER_PY")
        compile(source, "linux-sandbox-observer-root", "exec")

        for expected in (
            "/usr/bin/sudo --non-interactive -- /usr/bin/true",
            "/usr/bin/sudo --non-interactive --",
            "/usr/bin/env -i",
            "LC_ALL=C",
            "PATH=/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "/usr/bin/python3 - 2>/dev/null",
        ):
            self.assertIn(expected, step, expected)
        self.assertEqual(source.count("observer._observe_linux_sandbox_case()"), 1)
        self.assertIn("os.umask(0o077)", source)
        self.assertIn("print(result.name, flush=True)", source)
        for name, code in (
            ("CASE_OBSERVED", 0),
            ("UNAVAILABLE", 2),
            ("UNKNOWN", 3),
            ("CLEANUP_UNCONFIRMED", 4),
        ):
            self.assertIn(f"observer._Observation.{name}: {code}", source)
            self.assertIn(f"{code}:{name})", step)
        self.assertEqual(
            step.count("linux sandbox observer: CLEANUP_UNCONFIRMED"), 2
        )
        self.assertNotIn("continue-on-error", step)

    def test_observer_cannot_reach_candidate_or_release_authority(self) -> None:
        qualify = QUALIFY_WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("release_sandbox_linux", qualify)
        self.assertNotIn("linux-sandbox-observer", qualify)

        for forbidden in (
            "jmp0xf/forge\n",
            "sourceCommit",
            "cargo ",
            "xtask",
            "secrets.",
            "id-token:",
            "attestations:",
            "environment:",
            "actions/cache",
            "actions/upload-artifact",
            "actions/download-artifact",
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "GITHUB_PATH",
            "GITHUB_STATE",
            "GITHUB_STEP_SUMMARY",
            "continue-on-error",
            "always()",
        ):
            self.assertNotIn(forbidden, self.workflow, forbidden)


if __name__ == "__main__":
    unittest.main()
