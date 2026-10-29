from datetime import datetime, timezone


TERMINAL_STATES = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}
FORWARD_STATES = [
    "CREATED", "VALIDATING", "STATIC_ANALYSIS", "RE_ANALYSIS", "NORMALIZING",
    "DETECTION", "AI_ANALYSIS", "REPORTING", "COMPLETED",
]
ALLOWED_TRANSITIONS = {
    state: {next_state, "PARTIAL", "FAILED", "CANCELLED"} - {state}
    for state, next_state in zip(FORWARD_STATES, FORWARD_STATES[1:])
}
ALLOWED_TRANSITIONS["COMPLETED"] = set()
ALLOWED_TRANSITIONS["PARTIAL"] = set()
ALLOWED_TRANSITIONS["FAILED"] = set()
ALLOWED_TRANSITIONS["CANCELLED"] = set()


class InvalidStateTransition(ValueError):
    pass


def transition_analysis(analysis, new_state: str, progress: int | None = None) -> None:
    if new_state not in ALLOWED_TRANSITIONS.get(analysis.status, set()):
        raise InvalidStateTransition(f"Invalid analysis transition: {analysis.status} -> {new_state}")
    if progress is not None:
        if progress < analysis.progress or progress > 100:
            raise InvalidStateTransition("Analysis progress must be monotonic and at most 100")
        analysis.progress = progress
    analysis.status = new_state
    analysis.stage = new_state
    analysis.heartbeat_at = datetime.now(timezone.utc)
    if new_state in TERMINAL_STATES:
        analysis.completed_at = datetime.now(timezone.utc)
