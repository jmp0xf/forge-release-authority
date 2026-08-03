from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Iterator

from scripts import release_sandbox as sandbox


def _canonical_for_attack(value: Any) -> bytes:
    """Render mutations canonically without using the validator under test."""
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)


class ReleaseSandboxContractTests(unittest.TestCase):
    def test_phase_policies_freeze_process_and_denial_boundaries(self) -> None:
        expected_processes = {
            sandbox.Phase.BOOTSTRAP: {
                "child_policy": "fixed-toolchain-descendants-only",
                "descendant_executables": ["authority-resolved-fixed-toolchain"],
                "launcher": "authority-direct",
                "root_executable": "authority-resolved-fixed-cargo",
            },
            sandbox.Phase.PLAN: {
                "child_policy": "fixed-git-descendants-only",
                "descendant_executables": ["fixed-git"],
                "launcher": "authority-direct",
                "root_executable": "same-bootstrap-pinned-xtask",
            },
            sandbox.Phase.EXECUTE: {
                "child_policy": "fixed-toolchain-tree-only",
                "descendant_executables": ["fixed-toolchain"],
                "launcher": "authority-direct",
                "root_executable": "fixed-cargo",
            },
            sandbox.Phase.APPLY: {
                "child_policy": "zero-child",
                "descendant_executables": [],
                "launcher": "authority-direct",
                "root_executable": "same-bootstrap-pinned-xtask",
            },
        }
        expected_write_scopes = {
            sandbox.Phase.BOOTSTRAP: "fresh-bootstrap-target-only",
            sandbox.Phase.PLAN: "declared-plan-output-only",
            sandbox.Phase.EXECUTE: "declared-build-and-stage-roots-only",
            sandbox.Phase.APPLY: "declared-apply-root-only",
        }

        for phase in sandbox.Phase:
            with self.subTest(phase=phase.value):
                policy = sandbox.phase_policy(phase)
                self.assertEqual(policy["schema"], sandbox.PHASE_POLICY_SCHEMA)
                self.assertEqual(policy["phase"], phase.value)
                self.assertEqual(policy["process"], expected_processes[phase])
                self.assertEqual(policy["network"], "denied")
                self.assertEqual(policy["fallback"], "denied")
                self.assertEqual(
                    policy["command_channels"],
                    {"authority": "denied", "github": "denied"},
                )
                self.assertEqual(
                    policy["environment"],
                    {
                        "mode": "fixed-allowlist-only",
                        "proxy_variables": "denied",
                        "secret_variables": "denied",
                    },
                )
                self.assertEqual(
                    policy["filesystem"],
                    {
                        "outside_declared_write_roots": "denied",
                        "read_roots": {
                            "dependency_cache": "authority-verified-read-only",
                            "source": "authority-pinned-read-only",
                            "toolchain": "authority-pinned-read-only",
                        },
                        "write_scope": expected_write_scopes[phase],
                    },
                )
                rendered = sandbox.render_phase_policy(phase)
                self.assertEqual(
                    sandbox.parse_phase_policy(rendered, expected_phase=phase), policy
                )
                self.assertEqual(sandbox.validate_phase_policy(policy), phase)

        first = sandbox.phase_policy(sandbox.Phase.PLAN)
        first["process"]["descendant_executables"].append("mutated")
        self.assertEqual(
            sandbox.phase_policy(sandbox.Phase.PLAN)["process"][
                "descendant_executables"
            ],
            ["fixed-git"],
        )
        self.assertEqual(
            sandbox.phase_policy(sandbox.Phase.PLAN)["process"]["root_executable"],
            sandbox.phase_policy(sandbox.Phase.APPLY)["process"]["root_executable"],
        )

    def test_capability_observation_is_unavailable_non_proof_and_fail_closed(
        self,
    ) -> None:
        for phase in sandbox.Phase:
            for unavailable_reason in sandbox.BackendUnavailableReason:
                with self.subTest(phase=phase.value, reason=unavailable_reason.value):
                    document = sandbox.unavailable_capability_observation(
                        phase, unavailable_reason
                    )
                    self.assertEqual(
                        document["schema"], sandbox.CAPABILITY_OBSERVATION_SCHEMA
                    )
                    self.assertEqual(document["trust"], "candidate-controlled")
                    self.assertEqual(
                        document["evidence_status"],
                        "excluded-from-release-evidence",
                    )
                    self.assertEqual(document["backend"]["status"], "unavailable")
                    self.assertEqual(
                        document["capabilities"], {"status": "unavailable"}
                    )
                    rendered = sandbox.render_capability_observation(
                        phase, unavailable_reason
                    )
                    self.assertEqual(
                        sandbox.parse_capability_observation(
                            rendered, expected_phase=phase
                        ),
                        document,
                    )
                    decision = sandbox.assess_capability_observation(
                        document, expected_phase=phase
                    )
                    self.assertFalse(decision.allowed)
                    self.assertEqual(
                        decision.reason, sandbox.DecisionReason.BACKEND_UNAVAILABLE
                    )
                    with self.assertRaisesRegex(
                        sandbox.SandboxUnavailableError, "^backend-unavailable$"
                    ):
                        sandbox.require_sandbox(document, expected_phase=phase)

        self.assertEqual(
            {reason.value for reason in sandbox.DecisionReason},
            {"backend-unavailable", "invalid-observation", "phase-mismatch"},
        )

    def test_strict_json_rejects_duplicate_unknown_and_noncanonical_inputs(
        self,
    ) -> None:
        document = sandbox.unavailable_capability_observation("plan")
        canonical = sandbox.render_capability_observation("plan")
        duplicate = canonical.replace(b'{"backend":', b'{"phase":"plan","backend":', 1)
        unknown = copy.deepcopy(document)
        unknown["extra"] = "denied"
        pretty = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("ascii")
        without_newline = canonical.removesuffix(b"\n")

        for name, raw in (
            ("duplicate", duplicate),
            ("unknown", _canonical_for_attack(unknown)),
            ("pretty", pretty),
            ("without-newline", without_newline),
            ("invalid-utf8", b"\xff"),
            ("number", b'{"value":1}\n'),
            ("oversize", b" " * (sandbox.MAX_CANONICAL_JSON_BYTES + 1)),
        ):
            with self.subTest(name=name):
                with self.assertRaises(sandbox.SandboxContractError):
                    sandbox.parse_capability_observation(raw)

        with self.assertRaises(sandbox.SandboxContractError):
            sandbox.render_canonical_json({"number": 1})
        with self.assertRaises(sandbox.SandboxContractError):
            sandbox.render_canonical_json({"float": 1.0})

    def test_wrong_phase_unknown_status_and_unknown_reason_fail_closed(self) -> None:
        plan = sandbox.unavailable_capability_observation("plan")
        with self.assertRaises(sandbox.SandboxContractError):
            sandbox.parse_capability_observation(
                _canonical_for_attack(plan), expected_phase="execute"
            )

        wrong_status = copy.deepcopy(plan)
        wrong_status["backend"]["status"] = "available"
        wrong_capability = copy.deepcopy(plan)
        wrong_capability["capabilities"]["status"] = "enforced"
        wrong_reason = copy.deepcopy(plan)
        wrong_reason["backend"]["reason"] = "backend-secret-detail"
        for name, mutation in (
            ("backend-status", wrong_status),
            ("capability-status", wrong_capability),
            ("backend-reason", wrong_reason),
        ):
            with self.subTest(name=name):
                with self.assertRaises(sandbox.SandboxContractError) as raised:
                    sandbox.parse_capability_observation(
                        _canonical_for_attack(mutation)
                    )
                self.assertNotIn("backend-secret-detail", str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)
                decision = sandbox.assess_capability_observation(
                    mutation, expected_phase="plan"
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason, sandbox.DecisionReason.INVALID_OBSERVATION
                )

        decision = sandbox.assess_capability_observation(
            sandbox.unavailable_capability_observation("apply"),
            expected_phase="plan",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sandbox.DecisionReason.PHASE_MISMATCH)

        with self.assertRaises(sandbox.SandboxContractError) as invalid_utf8:
            sandbox.parse_canonical_json(b"\xffprivate")
        self.assertIsNone(invalid_utf8.exception.__cause__)

        class DeceptiveDictionary(dict[str, Any]):
            def __eq__(self, _other: object) -> bool:
                return True

        deceptive = DeceptiveDictionary(sandbox.phase_policy("plan"))
        with self.assertRaises(sandbox.SandboxContractError):
            sandbox.validate_phase_policy(deceptive)
        decision = sandbox.assess_capability_observation(
            DeceptiveDictionary(plan), expected_phase="plan"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, sandbox.DecisionReason.INVALID_OBSERVATION)

    def test_policy_expansion_attacks_are_rejected_even_when_canonical(self) -> None:
        attacks: list[tuple[str, dict[str, Any], sandbox.Phase]] = []

        extra_executable = sandbox.phase_policy("plan")
        extra_executable["process"]["descendant_executables"].append("fixed-shell")
        attacks.append(("executable", extra_executable, sandbox.Phase.PLAN))

        extra_environment = sandbox.phase_policy("execute")
        extra_environment["environment"]["extra_variables"] = "allowed"
        attacks.append(("environment", extra_environment, sandbox.Phase.EXECUTE))

        network = sandbox.phase_policy("execute")
        network["network"] = "loopback-only"
        attacks.append(("network", network, sandbox.Phase.EXECUTE))

        apply_child = sandbox.phase_policy("apply")
        apply_child["process"]["descendant_executables"] = ["fixed-git"]
        apply_child["process"]["child_policy"] = "fixed-git-descendants-only"
        attacks.append(("child", apply_child, sandbox.Phase.APPLY))

        command_channel = sandbox.phase_policy("plan")
        command_channel["command_channels"]["github"] = "allowed"
        attacks.append(("command-channel", command_channel, sandbox.Phase.PLAN))

        write_escape = sandbox.phase_policy("apply")
        write_escape["filesystem"]["outside_declared_write_roots"] = "allowed"
        attacks.append(("write-boundary", write_escape, sandbox.Phase.APPLY))

        fallback = sandbox.phase_policy("execute")
        fallback["fallback"] = "best-effort"
        attacks.append(("fallback", fallback, sandbox.Phase.EXECUTE))

        unknown = sandbox.phase_policy("plan")
        unknown["optional"] = "denied"
        attacks.append(("unknown", unknown, sandbox.Phase.PLAN))

        for name, mutation, phase in attacks:
            with self.subTest(name=name):
                with self.assertRaises(sandbox.SandboxContractError):
                    sandbox.parse_phase_policy(
                        _canonical_for_attack(mutation), expected_phase=phase
                    )

        with self.assertRaises(sandbox.SandboxContractError):
            sandbox.parse_phase_policy(
                sandbox.render_phase_policy("execute"), expected_phase="plan"
            )

    def test_contract_output_has_no_raw_values_digests_or_positive_claim_terms(
        self,
    ) -> None:
        observations = [
            sandbox.unavailable_capability_observation(phase) for phase in sandbox.Phase
        ]
        policies = [sandbox.phase_policy(phase) for phase in sandbox.Phase]

        for observation in observations:
            self.assertFalse(
                {"path", "environment", "digest", "sha256", "raw"} & set(observation)
            )
            values = list(_string_values(observation))
            self.assertFalse(any("\\" in value for value in values))
            self.assertFalse(
                any(
                    value in {"PATH", "HOME", "GITHUB_TOKEN", "HTTPS_PROXY"}
                    for value in values
                )
            )
            self.assertFalse(
                any(
                    len(value) == 64
                    and all(character in "0123456789abcdef" for character in value)
                    for value in values
                )
            )

        for document in [*observations, *policies]:
            rendered = sandbox.render_canonical_json(document).decode("ascii").lower()
            for forbidden in (
                "qualification",
                "qualified",
                "proof",
                "proven",
                "attestation",
            ):
                self.assertNotIn(forbidden, rendered)

        for observation in observations:
            self.assertEqual(
                [key for key in observation if "evidence" in key],
                ["evidence_status"],
            )
            self.assertEqual(
                [value for value in _string_values(observation) if "evidence" in value],
                ["excluded-from-release-evidence"],
            )

        policy_values = [value for item in policies for value in _string_values(item)]
        self.assertFalse(any("evidence" in value for value in policy_values))


if __name__ == "__main__":
    unittest.main()
