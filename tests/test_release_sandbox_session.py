from __future__ import annotations

import copy
import unittest
from typing import Any

from scripts import release_sandbox as sandbox


class LegacyFakeBackend(sandbox.AuthoritySandboxBackend):
    """Exercise lifecycle plumbing only, never sandbox enforcement evidence."""

    def __init__(self) -> None:
        self.open_count = 0
        self.received_phase: sandbox.Phase | None = None
        self.received_policy: dict[str, Any] | None = None

    def _open_session(
        self, *, phase: sandbox.Phase, policy: dict[str, Any]
    ) -> sandbox.SandboxSession:
        self.open_count += 1
        self.received_phase = phase
        self.received_policy = policy
        return self._new_session(
            phase=phase,
            policy=policy,
            cleanup=lambda: sandbox.CleanupStatus.CONFIRMED,
        )


class ReleaseSandboxSessionBindingTests(unittest.TestCase):
    def test_v1_binding_preserves_exact_policy_identity(self) -> None:
        for phase in sandbox.Phase:
            with self.subTest(phase=phase.value):
                policy = sandbox.phase_policy(phase)
                binding = sandbox.bind_phase_policy(policy)

                self.assertIs(type(binding), sandbox.PhasePolicyBinding)
                self.assertEqual(binding.schema, sandbox.PHASE_POLICY_SCHEMA)
                self.assertIs(binding.phase, phase)
                self.assertEqual(
                    binding.canonical_bytes,
                    sandbox.render_phase_policy(phase),
                )
                self.assertEqual(
                    sandbox.parse_phase_policy(
                        binding.canonical_bytes,
                        expected_phase=phase,
                    ),
                    policy,
                )

    def test_legacy_hook_and_factory_remain_compatible(self) -> None:
        backend = LegacyFakeBackend()
        policy = sandbox.phase_policy(sandbox.Phase.PLAN)

        session = backend.open_session(phase=sandbox.Phase.PLAN, policy=policy)

        self.assertEqual(backend.open_count, 1)
        self.assertIs(backend.received_phase, sandbox.Phase.PLAN)
        self.assertEqual(backend.received_policy, policy)
        self.assertIsNot(backend.received_policy, policy)
        session.require_policy(copy.deepcopy(policy))
        self.assertIs(session.close(), sandbox.CleanupStatus.CONFIRMED)

    def test_base_dispatcher_cannot_be_overridden(self) -> None:
        class DispatcherOverrideBackend(LegacyFakeBackend):
            def __init__(self) -> None:
                super().__init__()
                self.dispatch_override_count = 0

            def _open_bound_session(  # type: ignore[misc]
                self,
                *,
                binding: sandbox.PhasePolicyBinding,
            ) -> sandbox.SandboxSession:
                del binding
                self.dispatch_override_count += 1
                raise AssertionError("the base-owned dispatcher must not be replaced")

        backend = DispatcherOverrideBackend()
        session = backend.open_session(
            phase=sandbox.Phase.BOOTSTRAP,
            policy=sandbox.phase_policy(sandbox.Phase.BOOTSTRAP),
        )

        self.assertEqual(backend.dispatch_override_count, 0)
        self.assertEqual(backend.open_count, 1)
        self.assertIs(session.close(), sandbox.CleanupStatus.CONFIRMED)

    def test_invalid_binding_values_fail_closed(self) -> None:
        backend = LegacyFakeBackend()
        valid = sandbox.bind_phase_policy(sandbox.phase_policy(sandbox.Phase.PLAN))

        class DerivedBinding(sandbox.PhasePolicyBinding):
            pass

        wrong_schema = sandbox.PhasePolicyBinding(
            schema="forge.release-sandbox-phase-policy/v2",
            phase=valid.phase,
            canonical_bytes=valid.canonical_bytes,
        )
        wrong_phase = sandbox.PhasePolicyBinding(
            schema=valid.schema,
            phase=sandbox.Phase.APPLY,
            canonical_bytes=valid.canonical_bytes,
        )
        wrong_bytes = sandbox.PhasePolicyBinding(
            schema=valid.schema,
            phase=valid.phase,
            canonical_bytes=sandbox.render_phase_policy(sandbox.Phase.APPLY),
        )
        derived = DerivedBinding(
            schema=valid.schema,
            phase=valid.phase,
            canonical_bytes=valid.canonical_bytes,
        )
        mutated = sandbox.bind_phase_policy(sandbox.phase_policy(sandbox.Phase.PLAN))
        object.__setattr__(mutated, "canonical_bytes", b"{}\n")

        for name, binding in (
            ("unknown-schema", wrong_schema),
            ("wrong-phase", wrong_phase),
            ("wrong-bytes", wrong_bytes),
            ("subclass", derived),
            ("mutated", mutated),
        ):
            with self.subTest(name=name):
                with self.assertRaises(sandbox.SandboxContractError):
                    backend._new_bound_session(
                        binding=binding,
                        cleanup=lambda: sandbox.CleanupStatus.CONFIRMED,
                    )

    def test_session_rebuilds_binding_before_retaining_it(self) -> None:
        backend = LegacyFakeBackend()
        policy = sandbox.phase_policy(sandbox.Phase.PLAN)
        binding = sandbox.bind_phase_policy(policy)
        session = backend._new_bound_session(
            binding=binding,
            cleanup=lambda: sandbox.CleanupStatus.CONFIRMED,
        )

        object.__setattr__(binding, "canonical_bytes", b"{}\n")

        session.require_policy(policy)
        self.assertIs(session.close(), sandbox.CleanupStatus.CONFIRMED)

    def test_unknown_policy_schema_is_rejected_before_backend_open(self) -> None:
        backend = LegacyFakeBackend()
        policy = sandbox.phase_policy(sandbox.Phase.PLAN)
        policy["schema"] = "forge.release-sandbox-phase-policy/v2"

        with self.assertRaises(sandbox.SandboxContractError):
            backend.open_session(phase=sandbox.Phase.PLAN, policy=policy)

        self.assertEqual(backend.open_count, 0)

    def test_mutating_nested_policy_cannot_confuse_binding_phase(self) -> None:
        backend = LegacyFakeBackend()
        policy = sandbox.phase_policy(sandbox.Phase.PLAN)

        class MutatingProcess(dict[str, Any]):
            def __eq__(self, other: object) -> bool:
                policy.clear()
                policy.update(sandbox.phase_policy(sandbox.Phase.APPLY))
                return super().__eq__(other)

        policy["process"] = MutatingProcess(policy["process"])

        with self.assertRaises(sandbox.SandboxContractError):
            backend.open_session(phase=sandbox.Phase.PLAN, policy=policy)

        self.assertEqual(policy["phase"], sandbox.Phase.PLAN.value)
        self.assertEqual(backend.open_count, 0)

    def test_wrong_returned_binding_is_closed_and_rejected(self) -> None:
        cleanup_events: list[str] = []

        def cleanup() -> sandbox.CleanupStatus:
            cleanup_events.append("closed")
            return sandbox.CleanupStatus.CONFIRMED

        class WrongBindingBackend(sandbox.AuthoritySandboxBackend):
            def _open_session(
                self, *, phase: sandbox.Phase, policy: dict[str, Any]
            ) -> sandbox.SandboxSession:
                del phase, policy
                return self._new_bound_session(
                    binding=sandbox.bind_phase_policy(
                        sandbox.phase_policy(sandbox.Phase.PLAN)
                    ),
                    cleanup=cleanup,
                )

        backend = WrongBindingBackend()
        with self.assertRaisesRegex(
            sandbox.SandboxContractError,
            "^sandbox backend returned an invalid session$",
        ):
            backend.open_session(
                phase=sandbox.Phase.APPLY,
                policy=sandbox.phase_policy(sandbox.Phase.APPLY),
            )
        self.assertEqual(cleanup_events, ["closed"])

    def test_preissued_permit_is_closed_and_rejected(self) -> None:
        cleanup_events: list[str] = []

        class PreissuedPermitBackend(sandbox.AuthoritySandboxBackend):
            def __init__(self) -> None:
                self.stolen_permit: sandbox.SandboxPermit | None = None

            def _open_session(
                self, *, phase: sandbox.Phase, policy: dict[str, Any]
            ) -> sandbox.SandboxSession:
                def cleanup() -> sandbox.CleanupStatus:
                    cleanup_events.append("closed")
                    return sandbox.CleanupStatus.CONFIRMED

                session = self._new_session(
                    phase=phase,
                    policy=policy,
                    cleanup=cleanup,
                )
                self.stolen_permit = session.issue_permit()
                return session

        backend = PreissuedPermitBackend()
        with self.assertRaisesRegex(
            sandbox.SandboxContractError,
            "^sandbox backend returned an invalid session$",
        ):
            backend.open_session(
                phase=sandbox.Phase.EXECUTE,
                policy=sandbox.phase_policy(sandbox.Phase.EXECUTE),
            )

        self.assertEqual(cleanup_events, ["closed"])
        self.assertIsNotNone(backend.stolen_permit)
        assert backend.stolen_permit is not None
        with self.assertRaises(sandbox.SandboxContractError):
            backend.stolen_permit.require_active(sandbox.Phase.EXECUTE)

    def test_unavailable_backend_behavior_is_unchanged(self) -> None:
        backend = sandbox.UnavailableSandboxBackend()
        for phase in sandbox.Phase:
            with self.subTest(phase=phase.value):
                with self.assertRaisesRegex(
                    sandbox.SandboxUnavailableError,
                    "^backend-unavailable$",
                ):
                    backend.open_session(
                        phase=phase, policy=sandbox.phase_policy(phase)
                    )


if __name__ == "__main__":
    unittest.main()
