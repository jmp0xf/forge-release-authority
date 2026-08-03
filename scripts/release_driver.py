#!/usr/bin/env python3
"""Run the fail-closed, canary-only Authority release driver kernel.

This module deliberately has no real process or platform backend yet.  It
coordinates live sandbox sessions supplied by Authority code, threads the same
bootstrap-pinned xtask through PLAN and APPLY, and can terminate only in a
diagnostic canary report or a discarded state.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Literal, Protocol, Sequence, TypeVar, cast

if __package__:
    from . import release_sandbox as sandbox
else:
    import release_sandbox as sandbox  # type: ignore[import-not-found,no-redef]


CANARY_PURPOSE: Literal["inactive-canary-diagnostic-only"] = (
    "inactive-canary-diagnostic-only"
)
CANARY_EVIDENCE_STATUS: Literal["excluded-from-release-evidence"] = (
    "excluded-from-release-evidence"
)


class DriverError(RuntimeError):
    """The canary driver could not complete its closed state machine."""


class DriverDiscardedError(DriverError):
    """The current invocation is irreversibly discarded."""


class DriverStateError(DriverError):
    """A caller attempted a transition outside the closed state graph."""


class DriverState(str, Enum):
    BOUND = "bound"
    BOOTSTRAPPED = "bootstrapped"
    PLAN_ACCEPTED = "plan-accepted"
    EXECUTION_CAPTURED = "execution-captured"
    APPLY_CAPTURED = "apply-captured"
    CANARY_TARGET_CHECKED = "canary-target-checked"
    CANARY_REPORTED = "canary-reported"
    DISCARDED = "discarded"


_NEXT_STATE = {
    DriverState.BOUND: DriverState.BOOTSTRAPPED,
    DriverState.BOOTSTRAPPED: DriverState.PLAN_ACCEPTED,
    DriverState.PLAN_ACCEPTED: DriverState.EXECUTION_CAPTURED,
    DriverState.EXECUTION_CAPTURED: DriverState.APPLY_CAPTURED,
    DriverState.APPLY_CAPTURED: DriverState.CANARY_TARGET_CHECKED,
    DriverState.CANARY_TARGET_CHECKED: DriverState.CANARY_REPORTED,
}


class CanaryOperations(Protocol):
    """Authority-owned operations invoked by the platform-neutral kernel."""

    def bootstrap(self, permit: sandbox.SandboxPermit) -> object: ...

    def plan(self, permit: sandbox.SandboxPermit, pinned_xtask: object) -> object: ...

    def execute(
        self, permit: sandbox.SandboxPermit, accepted_plan: object
    ) -> object: ...

    def apply(
        self,
        permit: sandbox.SandboxPermit,
        pinned_xtask: object,
        accepted_plan: object,
        execution_capture: object,
    ) -> object: ...

    def verify_target(self, apply_capture: object) -> None: ...


_Result = TypeVar("_Result")
_MISSING = object()


@dataclass(frozen=True, slots=True)
class CanaryReport:
    """A nominal, immutable diagnostic result that can never authorize release."""

    builder_record_written: Literal[False] = field(default=False, init=False)
    evidence_status: Literal["excluded-from-release-evidence"] = field(
        default=CANARY_EVIDENCE_STATUS, init=False
    )
    handoff_written: Literal[False] = field(default=False, init=False)
    purpose: Literal["inactive-canary-diagnostic-only"] = field(
        default=CANARY_PURPOSE, init=False
    )
    qualification_eligible: Literal[False] = field(default=False, init=False)


class CanaryDriver:
    """One-shot, irreversible canary state machine."""

    def __init__(
        self,
        *,
        backend: sandbox.AuthoritySandboxBackend,
        operations: CanaryOperations,
    ) -> None:
        if not isinstance(backend, sandbox.AuthoritySandboxBackend):
            raise TypeError("canary backend must be Authority-owned")
        self._backend = backend
        self._operations = operations
        self._report: CanaryReport | None = None
        self._running = False
        self._state = DriverState.BOUND

    @property
    def state(self) -> DriverState:
        return self._state

    @property
    def report(self) -> CanaryReport | None:
        return self._report

    def _transition(self, expected: DriverState, target: DriverState) -> None:
        if self._state is not expected or _NEXT_STATE.get(expected) is not target:
            raise DriverStateError("canary state transition is outside the graph")
        self._state = target

    def _discard(self) -> None:
        self._report = None
        self._state = DriverState.DISCARDED

    def _run_phase(
        self,
        phase: sandbox.Phase,
        operation: Callable[[sandbox.SandboxPermit], _Result],
    ) -> _Result:
        policy = sandbox.phase_policy(phase)
        session: sandbox.SandboxSession | None = None
        result: object = _MISSING
        operation_failed = False
        try:
            # Calling the base implementation prevents an injected adapter from
            # replacing the validation wrapper around its protected hook.
            session = sandbox.AuthoritySandboxBackend.open_session(
                self._backend, phase=phase, policy=policy
            )
            permit = session.issue_permit()
            result = operation(permit)
            session.require_permit(permit, expected_phase=phase)
        except BaseException:
            operation_failed = True

        cleanup_status = sandbox.CleanupStatus.UNKNOWN
        if session is not None:
            try:
                cleanup_status = session.close()
            except BaseException:
                cleanup_status = sandbox.CleanupStatus.UNKNOWN

        if (
            operation_failed
            or cleanup_status is not sandbox.CleanupStatus.CONFIRMED
            or result is _MISSING
        ):
            raise DriverDiscardedError("canary phase failed")
        return cast(_Result, result)

    def run(self) -> CanaryReport:
        """Run exactly one diagnostic canary; no qualification mode exists."""
        if self._running:
            self._discard()
            raise DriverDiscardedError("release canary discarded")
        if self._state is not DriverState.BOUND:
            raise DriverStateError("canary driver is one-shot")
        self._running = True
        try:
            pinned_xtask = self._run_phase(
                sandbox.Phase.BOOTSTRAP, self._operations.bootstrap
            )
            self._transition(DriverState.BOUND, DriverState.BOOTSTRAPPED)

            accepted_plan = self._run_phase(
                sandbox.Phase.PLAN,
                lambda permit: self._operations.plan(permit, pinned_xtask),
            )
            self._transition(DriverState.BOOTSTRAPPED, DriverState.PLAN_ACCEPTED)

            execution_capture = self._run_phase(
                sandbox.Phase.EXECUTE,
                lambda permit: self._operations.execute(permit, accepted_plan),
            )
            self._transition(DriverState.PLAN_ACCEPTED, DriverState.EXECUTION_CAPTURED)

            apply_capture = self._run_phase(
                sandbox.Phase.APPLY,
                lambda permit: self._operations.apply(
                    permit,
                    pinned_xtask,
                    accepted_plan,
                    execution_capture,
                ),
            )
            self._transition(DriverState.EXECUTION_CAPTURED, DriverState.APPLY_CAPTURED)

            self._operations.verify_target(apply_capture)
            self._transition(
                DriverState.APPLY_CAPTURED, DriverState.CANARY_TARGET_CHECKED
            )

            report = CanaryReport()
            self._transition(
                DriverState.CANARY_TARGET_CHECKED, DriverState.CANARY_REPORTED
            )
            self._report = report
            return report
        except BaseException:
            self._discard()
            raise DriverDiscardedError("release canary discarded") from None
        finally:
            self._running = False


def run_canary(
    *,
    backend: sandbox.AuthoritySandboxBackend,
    operations: CanaryOperations,
) -> CanaryReport:
    """Authority API for the sole supported mode: a non-proof canary."""
    return CanaryDriver(backend=backend, operations=operations).run()


class _UnavailableOperations:
    def bootstrap(self, permit: sandbox.SandboxPermit) -> object:
        del permit
        raise DriverDiscardedError("canary operations unavailable")

    def plan(self, permit: sandbox.SandboxPermit, pinned_xtask: object) -> object:
        del permit, pinned_xtask
        raise DriverDiscardedError("canary operations unavailable")

    def execute(self, permit: sandbox.SandboxPermit, accepted_plan: object) -> object:
        del permit, accepted_plan
        raise DriverDiscardedError("canary operations unavailable")

    def apply(
        self,
        permit: sandbox.SandboxPermit,
        pinned_xtask: object,
        accepted_plan: object,
        execution_capture: object,
    ) -> object:
        del permit, pinned_xtask, accepted_plan, execution_capture
        raise DriverDiscardedError("canary operations unavailable")

    def verify_target(self, apply_capture: object) -> None:
        del apply_capture
        raise DriverDiscardedError("canary operations unavailable")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the inactive Authority release canary kernel"
    )
    parser.parse_args(argv)
    try:
        run_canary(
            backend=sandbox.UnavailableSandboxBackend(),
            operations=_UnavailableOperations(),
        )
    except DriverDiscardedError:
        print("release canary discarded", file=sys.stderr)
        return 1
    raise AssertionError("unavailable backend unexpectedly completed")


if __name__ == "__main__":
    raise SystemExit(main())
