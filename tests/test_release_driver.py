from __future__ import annotations

import contextlib
import copy
import dataclasses
import inspect
import io
import pickle
import unittest
from typing import Any

from scripts import release_driver as driver
from scripts import release_sandbox as sandbox


class FakeBackend(sandbox.AuthoritySandboxBackend):
    def __init__(
        self,
        events: list[str],
        *,
        fail_open: sandbox.Phase | None = None,
        cleanup_unknown: sandbox.Phase | None = None,
        cleanup_error: sandbox.Phase | None = None,
    ) -> None:
        self.events = events
        self.fail_open = fail_open
        self.cleanup_unknown = cleanup_unknown
        self.cleanup_error = cleanup_error
        self.policies: dict[sandbox.Phase, dict[str, Any]] = {}

    def _open_session(
        self, *, phase: sandbox.Phase, policy: dict[str, Any]
    ) -> sandbox.SandboxSession:
        self.events.append(f"open:{phase.value}")
        if phase is self.fail_open:
            raise sandbox.SandboxUnavailableError("fake open failure")
        self.policies[phase] = policy

        def cleanup() -> sandbox.CleanupStatus:
            self.events.append(f"close:{phase.value}")
            if phase is self.cleanup_error:
                raise RuntimeError("fake cleanup failure")
            if phase is self.cleanup_unknown:
                return sandbox.CleanupStatus.UNKNOWN
            return sandbox.CleanupStatus.CONFIRMED

        return self._new_session(phase=phase, policy=policy, cleanup=cleanup)


class FakeOperations:
    def __init__(self, events: list[str], *, fail_operation: str | None = None) -> None:
        self.events = events
        self.fail_operation = fail_operation
        self.permits: list[sandbox.SandboxPermit] = []
        self.pinned_xtask = object()
        self.accepted_plan = object()
        self.execution_capture = object()
        self.apply_capture = object()
        self.plan_xtask: object | None = None
        self.apply_xtask: object | None = None

    def _enter(
        self, name: str, phase: sandbox.Phase, permit: sandbox.SandboxPermit
    ) -> None:
        permit.require_active(phase)
        self.permits.append(permit)
        self.events.append(f"operation:{name}")
        if name == self.fail_operation:
            raise RuntimeError("fake operation failure")

    def bootstrap(self, permit: sandbox.SandboxPermit) -> object:
        self._enter("bootstrap", sandbox.Phase.BOOTSTRAP, permit)
        return self.pinned_xtask

    def plan(self, permit: sandbox.SandboxPermit, pinned_xtask: object) -> object:
        self._enter("plan", sandbox.Phase.PLAN, permit)
        self.plan_xtask = pinned_xtask
        return self.accepted_plan

    def execute(self, permit: sandbox.SandboxPermit, accepted_plan: object) -> object:
        self._enter("execute", sandbox.Phase.EXECUTE, permit)
        if accepted_plan is not self.accepted_plan:
            raise RuntimeError("accepted plan identity changed")
        return self.execution_capture

    def apply(
        self,
        permit: sandbox.SandboxPermit,
        pinned_xtask: object,
        accepted_plan: object,
        execution_capture: object,
    ) -> object:
        self._enter("apply", sandbox.Phase.APPLY, permit)
        self.apply_xtask = pinned_xtask
        if (
            accepted_plan is not self.accepted_plan
            or execution_capture is not self.execution_capture
        ):
            raise RuntimeError("apply input identity changed")
        return self.apply_capture

    def verify_target(self, apply_capture: object) -> None:
        self.events.append("operation:verify-target")
        if self.fail_operation == "verify-target":
            raise RuntimeError("fake verification failure")
        if apply_capture is not self.apply_capture:
            raise RuntimeError("apply capture identity changed")


class ReentrantOperations(FakeOperations):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.canary: driver.CanaryDriver | None = None

    def bootstrap(self, permit: sandbox.SandboxPermit) -> object:
        pinned_xtask = super().bootstrap(permit)
        if self.canary is None:
            raise RuntimeError("reentrant test driver is absent")
        try:
            self.canary.run()
        except driver.DriverDiscardedError:
            # An Authority callback must not be able to hide re-entry and let
            # the outer invocation continue to a report.
            pass
        return pinned_xtask


class ReleaseDriverTests(unittest.TestCase):
    def test_canary_runs_closed_sequence_with_live_phase_permits(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        operations = FakeOperations(events)
        canary = driver.CanaryDriver(backend=backend, operations=operations)

        report = canary.run()

        self.assertEqual(
            events,
            [
                "open:bootstrap",
                "operation:bootstrap",
                "close:bootstrap",
                "open:plan",
                "operation:plan",
                "close:plan",
                "open:execute",
                "operation:execute",
                "close:execute",
                "open:apply",
                "operation:apply",
                "close:apply",
                "operation:verify-target",
            ],
        )
        self.assertEqual(set(backend.policies), set(sandbox.Phase))
        for phase, policy in backend.policies.items():
            self.assertEqual(policy, sandbox.phase_policy(phase))
        self.assertIs(operations.plan_xtask, operations.pinned_xtask)
        self.assertIs(operations.apply_xtask, operations.pinned_xtask)
        self.assertEqual(
            [permit.phase for permit in operations.permits],
            [
                sandbox.Phase.BOOTSTRAP,
                sandbox.Phase.PLAN,
                sandbox.Phase.EXECUTE,
                sandbox.Phase.APPLY,
            ],
        )
        for permit in operations.permits:
            with self.assertRaises(sandbox.SandboxContractError):
                permit.require_active(permit.phase)

        expected_report = driver.CanaryReport()
        self.assertEqual(report, expected_report)
        self.assertEqual(canary.report, expected_report)
        self.assertEqual(canary.state, driver.DriverState.CANARY_REPORTED)
        self.assertIs(canary.report, report)
        self.assertFalse(report.builder_record_written)
        self.assertEqual(report.evidence_status, "excluded-from-release-evidence")
        self.assertFalse(report.handoff_written)
        self.assertEqual(report.purpose, "inactive-canary-diagnostic-only")
        self.assertFalse(report.qualification_eligible)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            setattr(report, "qualification_eligible", True)

    def test_permits_are_live_session_bound_and_never_created_from_json(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        plan_policy = sandbox.phase_policy(sandbox.Phase.PLAN)
        first = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=plan_policy
        )
        second = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=plan_policy
        )
        first_permit = first.issue_permit()
        second_permit = second.issue_permit()

        first.require_permit(first_permit, expected_phase=sandbox.Phase.PLAN)
        second.require_permit(second_permit, expected_phase=sandbox.Phase.PLAN)
        with self.assertRaises(sandbox.SandboxContractError):
            second.require_permit(first_permit, expected_phase=sandbox.Phase.PLAN)
        with self.assertRaises(sandbox.SandboxContractError):
            first.require_permit(first_permit, expected_phase=sandbox.Phase.APPLY)

        for name, capability in (
            ("session", first),
            ("permit", first_permit),
        ):
            with self.subTest(name=name, operation="copy"):
                with self.assertRaises(TypeError):
                    copy.copy(capability)
            with self.subTest(name=name, operation="deepcopy"):
                with self.assertRaises(TypeError):
                    copy.deepcopy(capability)
            with self.subTest(name=name, operation="pickle"):
                with self.assertRaises(TypeError):
                    pickle.dumps(capability)

        self.assertIs(first.close(), sandbox.CleanupStatus.CONFIRMED)
        self.assertIs(second.close(), sandbox.CleanupStatus.CONFIRMED)
        with self.assertRaises(sandbox.SandboxContractError):
            first_permit.require_active(sandbox.Phase.PLAN)

        observation = sandbox.unavailable_capability_observation(
            sandbox.Phase.BOOTSTRAP
        )
        with self.assertRaises(TypeError):
            driver.CanaryDriver(
                backend=observation,  # type: ignore[arg-type]
                operations=FakeOperations([]),
            )
        with self.assertRaises(sandbox.SandboxUnavailableError):
            sandbox.require_sandbox(observation, expected_phase=sandbox.Phase.BOOTSTRAP)

    def test_callback_reentry_irreversibly_discards_without_a_report(self) -> None:
        events: list[str] = []
        operations = ReentrantOperations(events)
        canary = driver.CanaryDriver(backend=FakeBackend(events), operations=operations)
        operations.canary = canary

        with self.assertRaisesRegex(
            driver.DriverDiscardedError, "^release canary discarded$"
        ):
            canary.run()

        self.assertEqual(canary.state, driver.DriverState.DISCARDED)
        self.assertIsNone(canary.report)
        self.assertEqual(
            events,
            [
                "open:bootstrap",
                "operation:bootstrap",
                "close:bootstrap",
            ],
        )

    def test_every_operation_failure_discards_without_a_report(self) -> None:
        for failure in (
            "bootstrap",
            "plan",
            "execute",
            "apply",
            "verify-target",
        ):
            with self.subTest(failure=failure):
                events: list[str] = []
                canary = driver.CanaryDriver(
                    backend=FakeBackend(events),
                    operations=FakeOperations(events, fail_operation=failure),
                )
                with self.assertRaisesRegex(
                    driver.DriverDiscardedError, "^release canary discarded$"
                ):
                    canary.run()
                self.assertEqual(canary.state, driver.DriverState.DISCARDED)
                self.assertIsNone(canary.report)
                self.assertNotIn("canary-reported", events)

    def test_every_phase_open_failure_discards_without_a_report(self) -> None:
        for phase in sandbox.Phase:
            with self.subTest(phase=phase.value):
                events: list[str] = []
                canary = driver.CanaryDriver(
                    backend=FakeBackend(events, fail_open=phase),
                    operations=FakeOperations(events),
                )
                with self.assertRaises(driver.DriverDiscardedError):
                    canary.run()
                self.assertEqual(canary.state, driver.DriverState.DISCARDED)
                self.assertIsNone(canary.report)
                self.assertNotIn("operation:verify-target", events)

    def test_cleanup_unknown_or_error_discards_every_phase(self) -> None:
        for failure_kind in ("unknown", "error"):
            for phase in sandbox.Phase:
                with self.subTest(failure_kind=failure_kind, phase=phase.value):
                    events: list[str] = []
                    backend = FakeBackend(
                        events,
                        cleanup_unknown=(phase if failure_kind == "unknown" else None),
                        cleanup_error=(phase if failure_kind == "error" else None),
                    )
                    canary = driver.CanaryDriver(
                        backend=backend, operations=FakeOperations(events)
                    )
                    with self.assertRaises(driver.DriverDiscardedError):
                        canary.run()
                    self.assertEqual(canary.state, driver.DriverState.DISCARDED)
                    self.assertIsNone(canary.report)
                    self.assertNotIn("operation:verify-target", events)

    def test_real_backend_is_unavailable_and_cli_has_no_other_mode(self) -> None:
        events: list[str] = []
        canary = driver.CanaryDriver(
            backend=sandbox.UnavailableSandboxBackend(),
            operations=FakeOperations(events),
        )
        with self.assertRaises(driver.DriverDiscardedError):
            canary.run()
        self.assertEqual(canary.state, driver.DriverState.DISCARDED)
        self.assertIsNone(canary.report)
        self.assertEqual(events, [])

        self.assertNotIn("mode", inspect.signature(driver.run_canary).parameters)
        stderr = io.StringIO()
        stdout = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            self.assertEqual(driver.main([]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "release canary discarded\n")

        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                driver.main(["--qualification"])

    def test_state_graph_and_module_exclude_release_success_writers(self) -> None:
        self.assertEqual(
            [state.value for state in driver.DriverState],
            [
                "bound",
                "bootstrapped",
                "plan-accepted",
                "execution-captured",
                "apply-captured",
                "canary-target-checked",
                "canary-reported",
                "discarded",
            ],
        )
        source = inspect.getsource(driver)
        self.assertNotIn("write_builder_record", source)
        self.assertNotIn("write_handoff", source)
        self.assertNotIn("SUCCESS_RECORDED", source)
        self.assertNotIn("HANDOFF_SEALED", source)


if __name__ == "__main__":
    unittest.main()
