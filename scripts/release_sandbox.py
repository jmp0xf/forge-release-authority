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
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, NoReturn, Sequence, SupportsIndex, cast, final


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


class SandboxSession:
    """One non-serializable Authority backend capability.

    The session binds the exact immutable phase policy, issues one permit, and
    invalidates that permit before cleanup starts.  A candidate observation is
    merely a dictionary and cannot satisfy this live-object contract.
    """

    __slots__ = (
        "__active",
        "__cleanup",
        "__permit",
        "__phase",
        "__policy_bytes",
    )

    def __init__(
        self,
        constructor_key: object,
        phase: Phase,
        policy: dict[str, Any],
        cleanup: Callable[[], CleanupStatus],
    ) -> None:
        if constructor_key is not _SESSION_CONSTRUCTOR_KEY:
            raise SandboxContractError("sandbox sessions are backend-issued only")
        selected = validate_phase_policy(policy)
        if selected is not phase:
            raise SandboxContractError("sandbox session has the wrong phase policy")
        self.__active = True
        self.__cleanup = cleanup
        self.__permit: SandboxPermit | None = None
        self.__phase = phase
        self.__policy_bytes = render_phase_policy(phase)

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
        if not self.__active or render_canonical_json(policy) != self.__policy_bytes:
            raise SandboxContractError("sandbox session policy is not active")
        if validate_phase_policy(policy) is not self.__phase:
            raise SandboxContractError("sandbox session has the wrong phase")

    def issue_permit(self) -> SandboxPermit:
        if not self.__active or self.__permit is not None:
            raise SandboxContractError("sandbox session cannot issue a permit")
        permit = SandboxPermit(_SESSION_CONSTRUCTOR_KEY, self.__phase, self)
        self.__permit = permit
        return permit

    def require_permit(
        self, permit: SandboxPermit, *, expected_phase: Phase | str
    ) -> None:
        selected = _coerce_phase(expected_phase)
        if (
            not self.__active
            or type(permit) is not SandboxPermit
            or permit is not self.__permit
            or not permit._was_issued_by(self)
            or selected is not self.__phase
        ):
            raise SandboxContractError("sandbox permit is not active for this session")

    def close(self) -> CleanupStatus:
        """Invalidate the permit, then require an affirmative backend cleanup."""
        if not self.__active:
            return CleanupStatus.UNKNOWN
        self.__active = False
        self.__permit = None
        try:
            status = self.__cleanup()
        except BaseException:
            raise SandboxUnavailableError("sandbox-cleanup-unknown") from None
        if status is not CleanupStatus.CONFIRMED:
            return CleanupStatus.UNKNOWN
        return CleanupStatus.CONFIRMED


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
        session.require_policy(policy)
        return session

    @abstractmethod
    def _open_session(self, *, phase: Phase, policy: dict[str, Any]) -> SandboxSession:
        """Establish an OS-enforced session or raise without fallback."""

    @final
    def _new_session(
        self,
        *,
        phase: Phase,
        policy: dict[str, Any],
        cleanup: Callable[[], CleanupStatus],
    ) -> SandboxSession:
        """Wrap a backend's live OS capability for the Authority driver."""
        return SandboxSession(_SESSION_CONSTRUCTOR_KEY, phase, policy, cleanup)


class UnavailableSandboxBackend(AuthoritySandboxBackend):
    """Current real backend: qualification remains impossible and fails closed."""

    def _open_session(self, *, phase: Phase, policy: dict[str, Any]) -> SandboxSession:
        del phase, policy
        raise SandboxUnavailableError("backend-unavailable")
