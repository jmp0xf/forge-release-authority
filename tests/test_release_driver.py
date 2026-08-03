from __future__ import annotations

import contextlib
import copy
import dataclasses
import inspect
import io
import pickle
import threading
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
        fail_execute: sandbox.Phase | None = None,
        cleanup_unknown: sandbox.Phase | None = None,
        cleanup_error: sandbox.Phase | None = None,
        cleanup_reentry: sandbox.Phase | None = None,
    ) -> None:
        self.events = events
        self.fail_open = fail_open
        self.fail_execute = fail_execute
        self.cleanup_unknown = cleanup_unknown
        self.cleanup_error = cleanup_error
        self.cleanup_reentry = cleanup_reentry
        self.policies: dict[sandbox.Phase, dict[str, Any]] = {}
        self.sessions: dict[sandbox.Phase, sandbox.SandboxSession] = {}

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
            if phase is self.cleanup_reentry:
                nested = self.sessions[phase].close()
                self.events.append(f"nested-close:{phase.value}:{nested.value}")
            if phase is self.cleanup_unknown:
                return sandbox.CleanupStatus.UNKNOWN
            return sandbox.CleanupStatus.CONFIRMED

        session = self._new_session(phase=phase, policy=policy, cleanup=cleanup)
        self.sessions[phase] = session
        return session

    def invocation(self, phase: sandbox.Phase) -> sandbox.SandboxInvocation[object]:
        def execute() -> object:
            self.events.append(f"execute:{phase.value}")
            if phase is self.fail_execute:
                raise RuntimeError("fake execution failure")
            return object()

        return self._new_invocation(
            session=self.sessions[phase], phase=phase, executor=execute
        )


class FakeOperations:
    def __init__(
        self,
        events: list[str],
        backend: FakeBackend,
        *,
        fail_operation: str | None = None,
    ) -> None:
        self.events = events
        self.backend = backend
        self.fail_operation = fail_operation
        self.permits: list[sandbox.SandboxPermit] = []
        self.pinned_xtask = object()
        self.accepted_plan = object()
        self.execution_capture = object()
        self.apply_capture = object()
        self.plan_xtask: sandbox.SandboxPhaseCapture[object] | None = None
        self.apply_xtask: sandbox.SandboxPhaseCapture[object] | None = None

    def _enter(
        self, name: str, phase: sandbox.Phase, permit: sandbox.SandboxPermit
    ) -> None:
        permit.require_active(phase)
        self.permits.append(permit)
        self.events.append(f"operation:{name}")
        if name == self.fail_operation:
            raise RuntimeError("fake operation failure")

    def _capture(
        self,
        name: str,
        phase: sandbox.Phase,
        permit: sandbox.SandboxPermit,
        value: object,
    ) -> sandbox.SandboxProvisionalCapture[object]:
        self._enter(name, phase, permit)
        execution = permit.execute(self.backend.invocation(phase))
        return permit.capture(execution, value)

    def bootstrap(
        self, permit: sandbox.SandboxPermit
    ) -> sandbox.SandboxProvisionalCapture[object]:
        return self._capture(
            "bootstrap", sandbox.Phase.BOOTSTRAP, permit, self.pinned_xtask
        )

    def plan(
        self,
        permit: sandbox.SandboxPermit,
        pinned_xtask: sandbox.SandboxPhaseCapture[object],
    ) -> sandbox.SandboxProvisionalCapture[object]:
        self.plan_xtask = pinned_xtask
        if pinned_xtask.value is not self.pinned_xtask:
            raise RuntimeError("pinned xtask identity changed")
        return self._capture("plan", sandbox.Phase.PLAN, permit, self.accepted_plan)

    def execute(
        self,
        permit: sandbox.SandboxPermit,
        accepted_plan: sandbox.SandboxPhaseCapture[object],
    ) -> sandbox.SandboxProvisionalCapture[object]:
        if accepted_plan.value is not self.accepted_plan:
            raise RuntimeError("accepted plan identity changed")
        return self._capture(
            "execute", sandbox.Phase.EXECUTE, permit, self.execution_capture
        )

    def apply(
        self,
        permit: sandbox.SandboxPermit,
        pinned_xtask: sandbox.SandboxPhaseCapture[object],
        accepted_plan: sandbox.SandboxPhaseCapture[object],
        execution_capture: sandbox.SandboxPhaseCapture[object],
    ) -> sandbox.SandboxProvisionalCapture[object]:
        self.apply_xtask = pinned_xtask
        if (
            pinned_xtask.value is not self.pinned_xtask
            or accepted_plan.value is not self.accepted_plan
            or execution_capture.value is not self.execution_capture
        ):
            raise RuntimeError("apply input identity changed")
        return self._capture("apply", sandbox.Phase.APPLY, permit, self.apply_capture)

    def verify_target(self, apply_capture: sandbox.SandboxPhaseCapture[object]) -> None:
        self.events.append("operation:verify-target")
        if self.fail_operation == "verify-target":
            raise RuntimeError("fake verification failure")
        if apply_capture.value is not self.apply_capture:
            raise RuntimeError("apply capture identity changed")


class ReentrantOperations(FakeOperations):
    def __init__(self, events: list[str], backend: FakeBackend) -> None:
        super().__init__(events, backend)
        self.canary: driver.CanaryDriver | None = None

    def bootstrap(
        self, permit: sandbox.SandboxPermit
    ) -> sandbox.SandboxProvisionalCapture[object]:
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


class BypassOperations(FakeOperations):
    def bootstrap(
        self, permit: sandbox.SandboxPermit
    ) -> sandbox.SandboxProvisionalCapture[object]:
        self._enter("bootstrap", sandbox.Phase.BOOTSTRAP, permit)
        return object()  # type: ignore[return-value]


class ReleaseDriverTests(unittest.TestCase):
    def test_canary_runs_closed_sequence_with_live_phase_permits(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        operations = FakeOperations(events, backend)
        canary = driver.CanaryDriver(backend=backend, operations=operations)

        report = canary.run()

        self.assertEqual(
            events,
            [
                "open:bootstrap",
                "operation:bootstrap",
                "execute:bootstrap",
                "close:bootstrap",
                "open:plan",
                "operation:plan",
                "execute:plan",
                "close:plan",
                "open:execute",
                "operation:execute",
                "execute:execute",
                "close:execute",
                "open:apply",
                "operation:apply",
                "execute:apply",
                "close:apply",
                "operation:verify-target",
            ],
        )
        self.assertEqual(set(backend.policies), set(sandbox.Phase))
        for phase, policy in backend.policies.items():
            self.assertEqual(policy, sandbox.phase_policy(phase))
        self.assertIsNotNone(operations.plan_xtask)
        self.assertIsNotNone(operations.apply_xtask)
        assert operations.plan_xtask is not None
        assert operations.apply_xtask is not None
        self.assertIs(operations.plan_xtask.value, operations.pinned_xtask)
        self.assertIs(operations.apply_xtask.value, operations.pinned_xtask)
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
                operations=FakeOperations([], FakeBackend([])),
            )
        with self.assertRaises(sandbox.SandboxUnavailableError):
            sandbox.require_sandbox(observation, expected_phase=sandbox.Phase.BOOTSTRAP)

    def test_execution_and_capture_are_one_shot_backend_phase_capabilities(
        self,
    ) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        other_backend = FakeBackend(events)
        policy = sandbox.phase_policy(sandbox.Phase.PLAN)

        bound = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        bound_invocation = backend.invocation(sandbox.Phase.PLAN)
        cross_session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        with self.assertRaises(sandbox.SandboxContractError):
            cross_session.issue_permit().execute(bound_invocation)
        self.assertIs(cross_session.close(), sandbox.CleanupStatus.UNKNOWN)
        self.assertIs(bound.close(), sandbox.CleanupStatus.CONFIRMED)

        session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        permit = session.issue_permit()
        invocation = backend.invocation(sandbox.Phase.PLAN)
        result = permit.execute(invocation)
        captured_value = object()
        provisional = permit.capture(result, captured_value)
        capture = session.close_and_seal(provisional, expected_phase=sandbox.Phase.PLAN)
        self.assertIs(capture.value, captured_value)
        self.assertIs(capture.phase, sandbox.Phase.PLAN)
        with self.assertRaises(sandbox.SandboxContractError):
            session.require_policy(policy)

        second = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        second_permit = second.issue_permit()
        second_result = second_permit.execute(backend.invocation(sandbox.Phase.PLAN))
        second_permit.capture(second_result, object())
        with self.assertRaises(sandbox.SandboxContractError):
            second_permit.capture(second_result, object())
        with self.assertRaises(sandbox.SandboxUnavailableError):
            second.close_and_seal(provisional, expected_phase=sandbox.Phase.PLAN)

        apply_policy = sandbox.phase_policy(sandbox.Phase.APPLY)
        apply_session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.APPLY, policy=apply_policy
        )
        apply_invocation = backend.invocation(sandbox.Phase.APPLY)
        wrong_phase = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        with self.assertRaises(sandbox.SandboxContractError):
            wrong_phase.issue_permit().execute(apply_invocation)
        self.assertIs(wrong_phase.close(), sandbox.CleanupStatus.UNKNOWN)
        self.assertIs(apply_session.close(), sandbox.CleanupStatus.CONFIRMED)

        other_session = sandbox.AuthoritySandboxBackend.open_session(
            other_backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        other_invocation = other_backend.invocation(sandbox.Phase.PLAN)
        wrong_backend = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=sandbox.Phase.PLAN, policy=policy
        )
        with self.assertRaises(sandbox.SandboxContractError):
            wrong_backend.issue_permit().execute(other_invocation)
        self.assertIs(wrong_backend.close(), sandbox.CleanupStatus.UNKNOWN)
        self.assertIs(other_session.close(), sandbox.CleanupStatus.CONFIRMED)

        for name, capability in (
            ("invocation", invocation),
            ("result", result),
            ("provisional", provisional),
            ("capture", capture),
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

        with self.assertRaises(sandbox.SandboxContractError):
            permit.execute(invocation)

    def test_swallowed_execution_reentry_permanently_poisons_session(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        phase = sandbox.Phase.BOOTSTRAP
        session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=phase, policy=sandbox.phase_policy(phase)
        )
        permit = session.issue_permit()
        invocation: sandbox.SandboxInvocation[object]

        def reentrant_executor() -> object:
            try:
                permit.execute(invocation)
            except sandbox.SandboxContractError:
                pass
            return object()

        invocation = backend._new_invocation(
            session=session,
            phase=phase,
            executor=reentrant_executor,
        )
        with self.assertRaises(sandbox.SandboxContractError):
            permit.execute(invocation)
        self.assertIs(session.close(), sandbox.CleanupStatus.UNKNOWN)

    def test_concurrent_execution_attempts_poison_both_results(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        phase = sandbox.Phase.EXECUTE
        session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=phase, policy=sandbox.phase_policy(phase)
        )
        permit = session.issue_permit()
        started = threading.Event()
        release = threading.Event()
        failures: list[type[BaseException]] = []

        def blocking_executor() -> object:
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test executor was not released")
            return object()

        invocation = backend._new_invocation(
            session=session,
            phase=phase,
            executor=blocking_executor,
        )

        def run_invocation() -> None:
            try:
                permit.execute(invocation)
            except BaseException as error:
                failures.append(type(error))

        first = threading.Thread(target=run_invocation)
        first.start()
        self.assertTrue(started.wait(timeout=5))
        second = threading.Thread(target=run_invocation)
        second.start()
        second.join(timeout=5)
        release.set()
        first.join(timeout=5)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(
            failures,
            [sandbox.SandboxContractError, sandbox.SandboxContractError],
        )
        self.assertIs(session.close(), sandbox.CleanupStatus.UNKNOWN)

    def test_swallowed_cleanup_reentry_forces_unknown(self) -> None:
        events: list[str] = []
        phase = sandbox.Phase.APPLY
        backend = FakeBackend(events, cleanup_reentry=phase)
        session = sandbox.AuthoritySandboxBackend.open_session(
            backend, phase=phase, policy=sandbox.phase_policy(phase)
        )

        self.assertIs(session.close(), sandbox.CleanupStatus.UNKNOWN)
        self.assertIn("nested-close:apply:unknown", events)

    def test_concurrent_close_cannot_race_cleanup_confirmed_seal(self) -> None:
        phase = sandbox.Phase.PLAN
        policy = sandbox.phase_policy(phase)
        backend = FakeBackend([])
        cleanup_started = threading.Event()
        cleanup_release = threading.Event()

        def cleanup() -> sandbox.CleanupStatus:
            cleanup_started.set()
            if not cleanup_release.wait(timeout=5):
                raise RuntimeError("test cleanup was not released")
            return sandbox.CleanupStatus.CONFIRMED

        session = backend._new_session(
            phase=phase,
            policy=policy,
            cleanup=cleanup,
        )
        permit = session.issue_permit()
        invocation = backend._new_invocation(
            session=session,
            phase=phase,
            executor=object,
        )
        result = permit.execute(invocation)
        provisional = permit.capture(result, object())
        failures: list[type[BaseException]] = []

        def seal() -> None:
            try:
                session.close_and_seal(provisional, expected_phase=phase)
            except BaseException as error:
                failures.append(type(error))

        sealing = threading.Thread(target=seal)
        sealing.start()
        self.assertTrue(cleanup_started.wait(timeout=5))
        self.assertIs(session.close(), sandbox.CleanupStatus.UNKNOWN)
        cleanup_release.set()
        sealing.join(timeout=5)

        self.assertFalse(sealing.is_alive())
        self.assertEqual(failures, [sandbox.SandboxUnavailableError])

    def test_backend_post_open_validation_failure_always_closes_session(self) -> None:
        events: list[str] = []

        class WrongPhaseBackend(sandbox.AuthoritySandboxBackend):
            def _open_session(
                self, *, phase: sandbox.Phase, policy: dict[str, Any]
            ) -> sandbox.SandboxSession:
                del phase, policy

                def cleanup() -> sandbox.CleanupStatus:
                    events.append("close:wrong-phase")
                    return sandbox.CleanupStatus.CONFIRMED

                return self._new_session(
                    phase=sandbox.Phase.PLAN,
                    policy=sandbox.phase_policy(sandbox.Phase.PLAN),
                    cleanup=cleanup,
                )

        backend = WrongPhaseBackend()
        with self.assertRaisesRegex(
            sandbox.SandboxContractError,
            "^sandbox backend returned an invalid session$",
        ):
            sandbox.AuthoritySandboxBackend.open_session(
                backend,
                phase=sandbox.Phase.APPLY,
                policy=sandbox.phase_policy(sandbox.Phase.APPLY),
            )
        self.assertEqual(events, ["close:wrong-phase"])

    def test_operation_cannot_advance_without_backend_execution_capture(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        canary = driver.CanaryDriver(
            backend=backend,
            operations=BypassOperations(events, backend),
        )

        with self.assertRaises(driver.DriverDiscardedError):
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

    def test_callback_reentry_irreversibly_discards_without_a_report(self) -> None:
        events: list[str] = []
        backend = FakeBackend(events)
        operations = ReentrantOperations(events, backend)
        canary = driver.CanaryDriver(backend=backend, operations=operations)
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
                "execute:bootstrap",
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
                backend = FakeBackend(events)
                canary = driver.CanaryDriver(
                    backend=backend,
                    operations=FakeOperations(events, backend, fail_operation=failure),
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
                backend = FakeBackend(events, fail_open=phase)
                canary = driver.CanaryDriver(
                    backend=backend,
                    operations=FakeOperations(events, backend),
                )
                with self.assertRaises(driver.DriverDiscardedError):
                    canary.run()
                self.assertEqual(canary.state, driver.DriverState.DISCARDED)
                self.assertIsNone(canary.report)
                self.assertNotIn("operation:verify-target", events)

    def test_every_phase_execution_failure_discards_without_a_report(self) -> None:
        for phase in sandbox.Phase:
            with self.subTest(phase=phase.value):
                events: list[str] = []
                backend = FakeBackend(events, fail_execute=phase)
                canary = driver.CanaryDriver(
                    backend=backend,
                    operations=FakeOperations(events, backend),
                )
                with self.assertRaises(driver.DriverDiscardedError):
                    canary.run()
                self.assertEqual(canary.state, driver.DriverState.DISCARDED)
                self.assertIsNone(canary.report)
                self.assertIn(f"execute:{phase.value}", events)
                self.assertIn(f"close:{phase.value}", events)
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
                        backend=backend, operations=FakeOperations(events, backend)
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
            operations=FakeOperations(events, FakeBackend(events)),
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
