#!/usr/bin/env python3
"""Define the platform-neutral release sandbox contract.

This module deliberately does not implement an operating-system sandbox.  It
defines the fixed phase policies that a future backend must enforce and a
bounded, candidate-controlled observation for the current no-backend state.
Such an observation is policy input only and is excluded from release
evidence.  It can never authorize a phase by itself.
"""

from __future__ import annotations

import copy
import json
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import (
    Any,
    Callable,
    Generic,
    NoReturn,
    Sequence,
    SupportsIndex,
    TypeVar,
    cast,
    final,
)


PHASE_POLICY_SCHEMA = "forge.release-sandbox-phase-policy/v1"
CAPABILITY_OBSERVATION_SCHEMA = "forge.release-sandbox-capability-observation/v1"
OBSERVATION_TRUST = "candidate-controlled"
OBSERVATION_EVIDENCE_STATUS = "excluded-from-release-evidence"
OBSERVATION_USE = "policy-input-only"
MAX_CANONICAL_JSON_BYTES = 16 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_ITEMS = 64
MAX_JSON_STRING_CHARACTERS = 512


class SandboxContractError(ValueError):
    """A document or requested phase is outside the closed sandbox contract."""


class SandboxUnavailableError(RuntimeError):
    """The requested phase has no usable sandbox backend."""


class Phase(str, Enum):
    BOOTSTRAP = "bootstrap"
    PLAN = "plan"
    EXECUTE = "execute"
    APPLY = "apply"


class BackendUnavailableReason(str, Enum):
    CONTRACT_ONLY = "contract-only-no-os-backend"
    PLATFORM_UNSUPPORTED = "platform-backend-unsupported"
    INITIALIZATION_FAILED = "backend-initialization-failed"
    OBSERVATION_FAILED = "backend-observation-failed"


class DecisionReason(str, Enum):
    BACKEND_UNAVAILABLE = "backend-unavailable"
    INVALID_OBSERVATION = "invalid-observation"
    PHASE_MISMATCH = "phase-mismatch"


@dataclass(frozen=True)
class SandboxDecision:
    """One closed, non-authorizing sandbox decision."""

    allowed: bool
    phase: Phase
    reason: DecisionReason


_PHASE_PROCESS_POLICIES: dict[Phase, dict[str, Any]] = {
    Phase.BOOTSTRAP: {
        "child_policy": "fixed-toolchain-descendants-only",
        "descendant_executables": ["authority-resolved-fixed-toolchain"],
        "launcher": "authority-direct",
        "root_executable": "authority-resolved-fixed-cargo",
    },
    Phase.PLAN: {
        "child_policy": "fixed-git-descendants-only",
        "descendant_executables": ["fixed-git"],
        "launcher": "authority-direct",
        "root_executable": "same-bootstrap-pinned-xtask",
    },
    Phase.EXECUTE: {
        "child_policy": "fixed-toolchain-tree-only",
        "descendant_executables": ["fixed-toolchain"],
        "launcher": "authority-direct",
        "root_executable": "fixed-cargo",
    },
    Phase.APPLY: {
        "child_policy": "zero-child",
        "descendant_executables": [],
        "launcher": "authority-direct",
        "root_executable": "same-bootstrap-pinned-xtask",
    },
}

_PHASE_WRITE_SCOPES = {
    Phase.BOOTSTRAP: "fresh-bootstrap-target-only",
    Phase.PLAN: "declared-plan-output-only",
    Phase.EXECUTE: "declared-build-and-stage-roots-only",
    Phase.APPLY: "declared-apply-root-only",
}


def _coerce_phase(value: Phase | str) -> Phase:
    if isinstance(value, Phase):
        return value
    if not isinstance(value, str):
        raise SandboxContractError("sandbox phase is outside the closed enum")
    try:
        return Phase(value)
    except ValueError:
        raise SandboxContractError("sandbox phase is outside the closed enum") from None


def _coerce_unavailable_reason(
    value: BackendUnavailableReason | str,
) -> BackendUnavailableReason:
    if isinstance(value, BackendUnavailableReason):
        return value
    if not isinstance(value, str):
        raise SandboxContractError("sandbox backend reason is outside the closed enum")
    try:
        return BackendUnavailableReason(value)
    except ValueError:
        raise SandboxContractError(
            "sandbox backend reason is outside the closed enum"
        ) from None


def phase_policy(phase: Phase | str) -> dict[str, Any]:
    """Return a fresh copy of the fixed policy for one release phase."""
    selected = _coerce_phase(phase)
    policy = {
        "backend_requirement": "platform-sandbox-required",
        "command_channels": {
            "authority": "denied",
            "github": "denied",
        },
        "environment": {
            "mode": "fixed-allowlist-only",
            "proxy_variables": "denied",
            "secret_variables": "denied",
        },
        "fallback": "denied",
        "filesystem": {
            "outside_declared_write_roots": "denied",
            "read_roots": {
                "dependency_cache": "authority-verified-read-only",
                "source": "authority-pinned-read-only",
                "toolchain": "authority-pinned-read-only",
            },
            "write_scope": _PHASE_WRITE_SCOPES[selected],
        },
        "network": "denied",
        "phase": selected.value,
        "process": _PHASE_PROCESS_POLICIES[selected],
        "schema": PHASE_POLICY_SCHEMA,
    }
    return copy.deepcopy(policy)


def unavailable_capability_observation(
    phase: Phase | str,
    reason: BackendUnavailableReason | str = BackendUnavailableReason.CONTRACT_ONLY,
) -> dict[str, Any]:
    """Report only that no sandbox capability was observed.

    The returned vocabulary is deliberately too small to carry paths,
    environment values, executable names supplied by a caller, or digests.
    """
    selected = _coerce_phase(phase)
    selected_reason = _coerce_unavailable_reason(reason)
    return {
        "backend": {
            "reason": selected_reason.value,
            "status": "unavailable",
        },
        "capabilities": {"status": "unavailable"},
        "evidence_status": OBSERVATION_EVIDENCE_STATUS,
        "phase": selected.value,
        "schema": CAPABILITY_OBSERVATION_SCHEMA,
        "trust": OBSERVATION_TRUST,
        "use": OBSERVATION_USE,
    }


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SandboxContractError("sandbox JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_number(_value: str) -> None:
    raise SandboxContractError("sandbox JSON contains a forbidden number")


def _validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise SandboxContractError("sandbox JSON exceeds its depth bound")
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        if len(value) > MAX_JSON_STRING_CHARACTERS:
            raise SandboxContractError("sandbox JSON string exceeds its bound")
        return
    if type(value) is list:
        if len(value) > MAX_JSON_ITEMS:
            raise SandboxContractError("sandbox JSON array exceeds its bound")
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_JSON_ITEMS:
            raise SandboxContractError("sandbox JSON object exceeds its bound")
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > MAX_JSON_STRING_CHARACTERS:
                raise SandboxContractError("sandbox JSON object key is invalid")
            _validate_json_value(item, depth + 1)
        return
    raise SandboxContractError("sandbox JSON contains a forbidden value type")


def render_canonical_json(value: Any) -> bytes:
    """Render bounded Forge canonical JSON with one trailing newline.

    Numbers are intentionally excluded from this contract.  Typed parsers below
    must still be used to enforce document fields and closed vocabularies.
    """
    _validate_json_value(value)
    try:
        rendered = (
            json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError):
        raise SandboxContractError("sandbox JSON cannot be rendered") from None
    if len(rendered) > MAX_CANONICAL_JSON_BYTES:
        raise SandboxContractError("sandbox JSON exceeds its byte bound")
    return rendered


def parse_canonical_json(raw: bytes) -> Any:
    """Parse only the exact bounded representation produced by the renderer."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_CANONICAL_JSON_BYTES:
        raise SandboxContractError("sandbox JSON is outside its byte bound")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_number,
            parse_float=_reject_json_number,
            parse_int=_reject_json_number,
        )
    except SandboxContractError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise SandboxContractError("sandbox JSON is not strict JSON") from None
    _validate_json_value(value)
    if render_canonical_json(value) != raw:
        raise SandboxContractError("sandbox JSON is not canonical")
    return value


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise SandboxContractError(f"{label} has an unexpected structure")
    return cast(dict[str, Any], value)


def _require_literal(value: Any, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise SandboxContractError(f"{label} is outside the closed enum")
    return value


def validate_phase_policy(value: Any) -> Phase:
    """Validate an in-memory phase policy against the immutable contract."""
    policy = _require_exact_keys(
        value,
        {
            "backend_requirement",
            "command_channels",
            "environment",
            "fallback",
            "filesystem",
            "network",
            "phase",
            "process",
            "schema",
        },
        "sandbox phase policy",
    )
    _require_literal(policy["schema"], PHASE_POLICY_SCHEMA, "sandbox policy schema")
    selected = _coerce_phase(policy["phase"])
    if policy != phase_policy(selected):
        raise SandboxContractError(
            "sandbox phase policy differs from the fixed contract"
        )
    return selected


def render_phase_policy(phase: Phase | str) -> bytes:
    return render_canonical_json(phase_policy(phase))


def parse_phase_policy(
    raw: bytes, *, expected_phase: Phase | str | None = None
) -> dict[str, Any]:
    value = parse_canonical_json(raw)
    selected = validate_phase_policy(value)
    if expected_phase is not None and selected is not _coerce_phase(expected_phase):
        raise SandboxContractError("sandbox phase policy has the wrong phase")
    return cast(dict[str, Any], value)


def validate_capability_observation(
    value: Any,
) -> tuple[Phase, BackendUnavailableReason]:
    """Validate the v1 no-backend capability observation."""
    observation = _require_exact_keys(
        value,
        {
            "backend",
            "capabilities",
            "evidence_status",
            "phase",
            "schema",
            "trust",
            "use",
        },
        "sandbox capability observation",
    )
    _require_literal(
        observation["schema"],
        CAPABILITY_OBSERVATION_SCHEMA,
        "sandbox capability schema",
    )
    _require_literal(
        observation["trust"], OBSERVATION_TRUST, "sandbox observation trust"
    )
    _require_literal(
        observation["evidence_status"],
        OBSERVATION_EVIDENCE_STATUS,
        "sandbox observation evidence status",
    )
    _require_literal(observation["use"], OBSERVATION_USE, "sandbox observation use")
    selected = _coerce_phase(observation["phase"])
    backend = _require_exact_keys(
        observation["backend"], {"reason", "status"}, "sandbox backend"
    )
    _require_literal(backend["status"], "unavailable", "sandbox backend status")
    reason = _coerce_unavailable_reason(backend["reason"])
    capabilities = _require_exact_keys(
        observation["capabilities"], {"status"}, "sandbox capabilities"
    )
    _require_literal(capabilities["status"], "unavailable", "sandbox capability status")
    return selected, reason


def render_capability_observation(
    phase: Phase | str,
    reason: BackendUnavailableReason | str = BackendUnavailableReason.CONTRACT_ONLY,
) -> bytes:
    return render_canonical_json(unavailable_capability_observation(phase, reason))


def parse_capability_observation(
    raw: bytes, *, expected_phase: Phase | str | None = None
) -> dict[str, Any]:
    value = parse_canonical_json(raw)
    selected, _reason = validate_capability_observation(value)
    if expected_phase is not None and selected is not _coerce_phase(expected_phase):
        raise SandboxContractError("sandbox capability observation has the wrong phase")
    return cast(dict[str, Any], value)


def assess_capability_observation(
    value: Any, *, expected_phase: Phase | str
) -> SandboxDecision:
    """Fail closed because v1 has no successful backend state."""
    selected = _coerce_phase(expected_phase)
    try:
        observed_phase, _reason = validate_capability_observation(value)
    except SandboxContractError:
        return SandboxDecision(False, selected, DecisionReason.INVALID_OBSERVATION)
    if observed_phase is not selected:
        return SandboxDecision(False, selected, DecisionReason.PHASE_MISMATCH)
    return SandboxDecision(False, selected, DecisionReason.BACKEND_UNAVAILABLE)


def require_sandbox(value: Any, *, expected_phase: Phase | str) -> None:
    """Reject candidate-controlled observations regardless of their contents.

    A usable capability is a live :class:`SandboxSession` created by an
    Authority-owned backend.  There is intentionally no JSON-to-session path.
    """
    decision = assess_capability_observation(value, expected_phase=expected_phase)
    raise SandboxUnavailableError(decision.reason.value)


class CleanupStatus(str, Enum):
    """The only cleanup result that permits a driver transition."""

    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


_ExecutionValue = TypeVar("_ExecutionValue")
_ExecutionValueCo = TypeVar("_ExecutionValueCo", covariant=True)
_CaptureValue = TypeVar("_CaptureValue")
_CaptureValueCo = TypeVar("_CaptureValueCo", covariant=True)

_INVOCATION_IDLE = object()
_INVOCATION_EXECUTING = object()
_INVOCATION_EXECUTED = object()
_INVOCATION_POISONED = object()
_SESSION_IDLE = object()
_SESSION_EXECUTING = object()
_SESSION_EXECUTED = object()
_SESSION_CAPTURED = object()
_SESSION_CLOSED = object()
_SESSION_SEALED = object()


class SandboxInvocation(Generic[_ExecutionValueCo]):
    """One backend-owned, phase-bound request to execute an exact child.

    The executable, argv, environment, namespaces, resource limits, and capture
    boundaries are closed over by the backend callback rather than supplied by
    a caller.  A real backend must raise unless the complete OS boundary and
    process result satisfy its contract.
    """

    __slots__ = ("__executor", "__lock", "__phase", "__session", "__state")

    def __init__(
        self,
        constructor_key: object,
        session: SandboxSession,
        phase: Phase,
        executor: Callable[[], _ExecutionValueCo],
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox invocations are backend-issued only")
        self.__executor: Callable[[], _ExecutionValueCo] | None = executor
        self.__lock = threading.RLock()
        self.__phase = phase
        self.__session = session
        self.__state = _INVOCATION_IDLE

    @property
    def phase(self) -> Phase:
        return self.__phase

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox invocations cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox invocations cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox invocations cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox invocations cannot be serialized")

    def _execute_once(
        self, *, session: SandboxSession, expected_phase: Phase
    ) -> _ExecutionValueCo:
        with self.__lock:
            if (
                self.__session is not session
                or self.__phase is not expected_phase
                or self.__state is not _INVOCATION_IDLE
            ):
                self.__state = _INVOCATION_POISONED
                self.__executor = None
                raise SandboxContractError(
                    "sandbox invocation is not active for this session phase"
                )
            executor = self.__executor
            if executor is None:
                self.__state = _INVOCATION_POISONED
                raise SandboxContractError("sandbox invocation has no executor")
            self.__state = _INVOCATION_EXECUTING
        try:
            value = executor()
        except BaseException:
            with self.__lock:
                self.__state = _INVOCATION_POISONED
                self.__executor = None
            raise
        with self.__lock:
            if self.__state is not _INVOCATION_EXECUTING:
                self.__state = _INVOCATION_POISONED
                self.__executor = None
                raise SandboxContractError("sandbox invocation was re-entered")
            self.__state = _INVOCATION_EXECUTED
            self.__executor = None
        return value


class SandboxExecutionResult(Generic[_ExecutionValueCo]):
    """Opaque result of one invocation while its issuing session remains live."""

    __slots__ = ("__phase", "__session", "__value")

    def __init__(
        self,
        constructor_key: object,
        phase: Phase,
        session: SandboxSession,
        value: _ExecutionValueCo,
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox results are session-issued only")
        self.__phase = phase
        self.__session = session
        self.__value = value

    @property
    def phase(self) -> Phase:
        return self.__phase

    @property
    def value(self) -> _ExecutionValueCo:
        return self.__value

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox results cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox results cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox results cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox results cannot be serialized")

    def _was_issued_by(self, session: SandboxSession) -> bool:
        return self.__session is session


class SandboxProvisionalCapture(Generic[_CaptureValueCo]):
    """Authority-TCB parsing associated with a completed sandbox invocation.

    This object is not usable across phases and is not semantic validation or
    sandbox proof.  Only confirmed backend cleanup can seal it into a
    :class:`SandboxPhaseCapture`.
    """

    __slots__ = ("__phase", "__result", "__session", "__value")

    def __init__(
        self,
        constructor_key: object,
        phase: Phase,
        session: SandboxSession,
        result: SandboxExecutionResult[object],
        value: _CaptureValueCo,
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError(
                "sandbox provisional captures are session-issued only"
            )
        self.__phase = phase
        self.__result = result
        self.__session = session
        self.__value = value

    @property
    def phase(self) -> Phase:
        return self.__phase

    @property
    def value(self) -> _CaptureValueCo:
        return self.__value

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox provisional captures cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox provisional captures cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox provisional captures cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox provisional captures cannot be serialized")

    def _was_issued_by(
        self,
        session: SandboxSession,
        result: SandboxExecutionResult[object],
    ) -> bool:
        return self.__session is session and self.__result is result


class SandboxPhaseCapture(Generic[_CaptureValueCo]):
    """A phase value sealed only after affirmative backend cleanup.

    The Authority parser remains responsible for returning an exact immutable
    semantic type and revalidating it at every consumer.  Sealing proves only
    this session's invocation-and-cleanup lifecycle, never value correctness.
    """

    __slots__ = ("__phase", "__value")

    def __init__(
        self,
        constructor_key: object,
        phase: Phase,
        provisional: SandboxProvisionalCapture[_CaptureValueCo],
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox phase captures are session-issued only")
        self.__phase = phase
        self.__value = provisional.value

    @property
    def phase(self) -> Phase:
        return self.__phase

    @property
    def value(self) -> _CaptureValueCo:
        return self.__value

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox phase captures cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox phase captures cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox phase captures cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox phase captures cannot be serialized")


class SandboxPermit:
    """Opaque, live authority to invoke one operation in one sandbox session."""

    __slots__ = ("__phase", "__session")

    def __init__(
        self, constructor_key: object, phase: Phase, session: SandboxSession
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox permits are backend-issued only")
        self.__phase = phase
        self.__session = session

    @property
    def phase(self) -> Phase:
        return self.__phase

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox permits cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox permits cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox permits cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox permits cannot be serialized")

    def _was_issued_by(self, session: SandboxSession) -> bool:
        return self.__session is session

    def require_active(self, expected_phase: Phase | str) -> None:
        """Fail unless this permit still belongs to its active issuing session."""
        self.__session.require_permit(self, expected_phase=expected_phase)

    def execute(
        self, invocation: SandboxInvocation[_ExecutionValue]
    ) -> SandboxExecutionResult[_ExecutionValue]:
        """Consume the issuing backend's exact invocation once."""
        return self.__session.execute(self, invocation)

    def capture(
        self,
        result: SandboxExecutionResult[object],
        value: _CaptureValue,
    ) -> SandboxProvisionalCapture[_CaptureValue]:
        """Associate one Authority-parsed value with the completed invocation."""
        return self.__session.capture(self, result, value)


class SandboxSession:
    """One non-serializable Authority backend capability.

    The session binds the exact immutable phase policy, issues one permit, and
    invalidates that permit before cleanup starts.  A candidate observation is
    merely a dictionary and cannot satisfy this live-object contract.
    """

    __slots__ = (
        "__cleanup",
        "__execution_result",
        "__lock",
        "__owner",
        "__permit",
        "__phase",
        "__poisoned",
        "__policy_bytes",
        "__provisional",
        "__state",
    )

    def __init__(
        self,
        constructor_key: object,
        owner: AuthoritySandboxBackend,
        phase: Phase,
        policy: dict[str, Any],
        cleanup: Callable[[], CleanupStatus],
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox sessions are backend-issued only")
        selected = validate_phase_policy(policy)
        if selected is not phase:
            raise SandboxContractError("sandbox session has the wrong phase policy")
        self.__cleanup: Callable[[], CleanupStatus] | None = cleanup
        self.__execution_result: SandboxExecutionResult[object] | None = None
        self.__lock = threading.RLock()
        self.__owner = owner
        self.__permit: SandboxPermit | None = None
        self.__phase = phase
        self.__poisoned = False
        self.__policy_bytes = render_phase_policy(phase)
        self.__provisional: SandboxProvisionalCapture[object] | None = None
        self.__state = _SESSION_IDLE

    @property
    def phase(self) -> Phase:
        return self.__phase

    def __copy__(self) -> NoReturn:
        raise TypeError("sandbox sessions cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        del memo
        raise TypeError("sandbox sessions cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("sandbox sessions cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("sandbox sessions cannot be serialized")

    def require_policy(self, policy: dict[str, Any]) -> None:
        """Check that this live capability enforces the requested fixed policy."""
        with self.__lock:
            if (
                self.__state
                not in (
                    _SESSION_IDLE,
                    _SESSION_EXECUTING,
                    _SESSION_EXECUTED,
                    _SESSION_CAPTURED,
                )
                or self.__poisoned
                or render_canonical_json(policy) != self.__policy_bytes
            ):
                raise SandboxContractError("sandbox session policy is not active")
            if validate_phase_policy(policy) is not self.__phase:
                raise SandboxContractError("sandbox session has the wrong phase")

    def issue_permit(self) -> SandboxPermit:
        with self.__lock:
            if (
                self.__state is not _SESSION_IDLE
                or self.__poisoned
                or self.__permit is not None
            ):
                raise SandboxContractError("sandbox session cannot issue a permit")
            permit = SandboxPermit(_SESSION_CONSTRUCTOR_KEY, self.__phase, self)
            self.__permit = permit
            return permit

    def _permit_is_active(self, permit: SandboxPermit, expected_phase: Phase) -> bool:
        return (
            self.__state is not _SESSION_CLOSED
            and not self.__poisoned
            and type(permit) is SandboxPermit
            and permit is self.__permit
            and permit._was_issued_by(self)
            and expected_phase is self.__phase
        )

    def _poison(self) -> None:
        self.__poisoned = True

    def require_permit(
        self, permit: SandboxPermit, *, expected_phase: Phase | str
    ) -> None:
        selected = _coerce_phase(expected_phase)
        with self.__lock:
            if not self._permit_is_active(permit, selected):
                raise SandboxContractError(
                    "sandbox permit is not active for this session"
                )

    def execute(
        self,
        permit: SandboxPermit,
        invocation: SandboxInvocation[_ExecutionValue],
    ) -> SandboxExecutionResult[_ExecutionValue]:
        """Run one backend-issued invocation and bind its result to this session."""
        with self.__lock:
            if (
                not self._permit_is_active(permit, self.__phase)
                or self.__state is not _SESSION_IDLE
                or type(invocation) is not SandboxInvocation
            ):
                self._poison()
                raise SandboxContractError("sandbox session execution is invalid")
            self.__state = _SESSION_EXECUTING
        try:
            value = invocation._execute_once(session=self, expected_phase=self.__phase)
        except BaseException:
            with self.__lock:
                self._poison()
            raise
        with self.__lock:
            if self.__state is not _SESSION_EXECUTING or self.__poisoned:
                self._poison()
                raise SandboxContractError("sandbox session execution was re-entered")
            result = SandboxExecutionResult(
                _SESSION_CONSTRUCTOR_KEY, self.__phase, self, value
            )
            self.__execution_result = cast(SandboxExecutionResult[object], result)
            self.__state = _SESSION_EXECUTED
            return result

    def capture(
        self,
        permit: SandboxPermit,
        result: SandboxExecutionResult[object],
        value: _CaptureValue,
    ) -> SandboxProvisionalCapture[_CaptureValue]:
        """Create the sole provisional capture after this session's execution."""
        with self.__lock:
            if (
                not self._permit_is_active(permit, self.__phase)
                or self.__state is not _SESSION_EXECUTED
                or type(result) is not SandboxExecutionResult
                or result is not self.__execution_result
                or not result._was_issued_by(self)
            ):
                self._poison()
                raise SandboxContractError(
                    "sandbox result is not active for this session"
                )
            provisional = SandboxProvisionalCapture(
                _SESSION_CONSTRUCTOR_KEY,
                self.__phase,
                self,
                result,
                value,
            )
            self.__provisional = cast(SandboxProvisionalCapture[object], provisional)
            self.__state = _SESSION_CAPTURED
            return provisional

    def _begin_close(
        self,
        provisional: SandboxProvisionalCapture[object] | None,
        expected_phase: Phase | None,
    ) -> bool:
        with self.__lock:
            if self.__state is _SESSION_SEALED:
                return False
            if self.__state is _SESSION_CLOSED:
                self._poison()
                return False
            if provisional is not None:
                result = self.__execution_result
                if (
                    expected_phase is not self.__phase
                    or self.__state is not _SESSION_CAPTURED
                    or result is None
                    or type(provisional) is not SandboxProvisionalCapture
                    or provisional is not self.__provisional
                    or not provisional._was_issued_by(self, result)
                ):
                    self._poison()
            self.__state = _SESSION_CLOSED
            self.__permit = None
            return True

    def _finish_cleanup(self) -> CleanupStatus:
        status = CleanupStatus.UNKNOWN
        try:
            with self.__lock:
                cleanup = self.__cleanup
                self.__cleanup = None
            if cleanup is None:
                raise SandboxUnavailableError("sandbox-cleanup-unknown")
            observed = cleanup()
            with self.__lock:
                if not self.__poisoned and observed is CleanupStatus.CONFIRMED:
                    status = CleanupStatus.CONFIRMED
        except BaseException:
            with self.__lock:
                self._poison()
            raise SandboxUnavailableError("sandbox-cleanup-unknown") from None
        finally:
            with self.__lock:
                self.__execution_result = None
                self.__provisional = None
        return status

    def close(self) -> CleanupStatus:
        """Invalidate the permit, then require an affirmative backend cleanup."""
        if not self._begin_close(None, None):
            return CleanupStatus.UNKNOWN
        return self._finish_cleanup()

    def close_and_seal(
        self,
        provisional: SandboxProvisionalCapture[_CaptureValue],
        *,
        expected_phase: Phase | str,
    ) -> SandboxPhaseCapture[_CaptureValue]:
        """Close successfully before creating a value usable by another phase."""
        selected = _coerce_phase(expected_phase)
        if not self._begin_close(
            cast(SandboxProvisionalCapture[object], provisional), selected
        ):
            raise SandboxUnavailableError("sandbox-cleanup-unknown")
        if self._finish_cleanup() is not CleanupStatus.CONFIRMED:
            raise SandboxUnavailableError("sandbox-cleanup-unknown")
        with self.__lock:
            if self.__state is not _SESSION_CLOSED or self.__poisoned:
                raise SandboxUnavailableError("sandbox-cleanup-unknown")
            sealed = SandboxPhaseCapture(
                _SESSION_CONSTRUCTOR_KEY, self.__phase, provisional
            )
            self.__state = _SESSION_SEALED
            return sealed

    def _is_owned_by(
        self, owner: AuthoritySandboxBackend, expected_phase: Phase
    ) -> bool:
        with self.__lock:
            return (
                self.__owner is owner
                and self.__phase is expected_phase
                and self.__state is _SESSION_IDLE
                and not self.__poisoned
            )


_SESSION_CONSTRUCTOR_KEY = object()


class AuthoritySandboxBackend(ABC):
    """Authority-owned adapter boundary for live platform sandbox sessions.

    The driver, adapter, and this Python interpreter are all Authority TCB.
    Python-private constructors do not isolate hostile same-process code; a
    real backend must execute candidate code only in its OS-sandboxed child.
    """

    @final
    def open_session(
        self, *, phase: Phase | str, policy: dict[str, Any]
    ) -> SandboxSession:
        selected = _coerce_phase(phase)
        if validate_phase_policy(policy) is not selected:
            raise SandboxContractError("sandbox backend received the wrong policy")
        session = self._open_session(phase=selected, policy=copy.deepcopy(policy))
        if type(session) is not SandboxSession:
            raise SandboxContractError("sandbox backend did not return a live session")
        try:
            if not session._is_owned_by(self, selected):
                raise SandboxContractError("sandbox backend returned a foreign session")
            session.require_policy(policy)
        except BaseException:
            try:
                session.close()
            except BaseException:
                pass
            raise SandboxContractError(
                "sandbox backend returned an invalid session"
            ) from None
        return session

    @abstractmethod
    def _open_session(self, *, phase: Phase, policy: dict[str, Any]) -> SandboxSession:
        """Establish an OS session or reclaim every partial resource and raise."""

    @final
    def _new_session(
        self,
        *,
        phase: Phase,
        policy: dict[str, Any],
        cleanup: Callable[[], CleanupStatus],
    ) -> SandboxSession:
        """Wrap a backend's live OS capability for the Authority driver."""
        return SandboxSession(_SESSION_CONSTRUCTOR_KEY, self, phase, policy, cleanup)

    @final
    def _new_invocation(
        self,
        *,
        session: SandboxSession,
        phase: Phase,
        executor: Callable[[], _ExecutionValue],
    ) -> SandboxInvocation[_ExecutionValue]:
        """Bind one exact, backend-owned child execution to a release phase."""
        if type(session) is not SandboxSession or not session._is_owned_by(self, phase):
            raise SandboxContractError(
                "sandbox invocation requires this backend's live session"
            )
        return SandboxInvocation(_SESSION_CONSTRUCTOR_KEY, session, phase, executor)


class UnavailableSandboxBackend(AuthoritySandboxBackend):
    """Current real backend: qualification remains impossible and fails closed."""

    def _open_session(self, *, phase: Phase, policy: dict[str, Any]) -> SandboxSession:
        del phase, policy
        raise SandboxUnavailableError("backend-unavailable")
