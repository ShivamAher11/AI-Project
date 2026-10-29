from types import SimpleNamespace

import pytest

from app.state_machine import InvalidStateTransition, transition_analysis


def test_forward_transition_and_terminal_partial_are_allowed():
    analysis = SimpleNamespace(status="CREATED", stage="CREATED", progress=0, heartbeat_at=None, completed_at=None)
    transition_analysis(analysis, "VALIDATING", 5)
    transition_analysis(analysis, "STATIC_ANALYSIS", 15)
    transition_analysis(analysis, "PARTIAL", 95)
    assert analysis.status == "PARTIAL"
    assert analysis.stage == "PARTIAL"
    assert analysis.progress == 95
    assert analysis.completed_at is not None


def test_invalid_transition_and_regressing_progress_are_rejected():
    analysis = SimpleNamespace(status="CREATED", stage="CREATED", progress=0, heartbeat_at=None, completed_at=None)
    with pytest.raises(InvalidStateTransition):
        transition_analysis(analysis, "STATIC_ANALYSIS", 15)
    transition_analysis(analysis, "VALIDATING", 5)
    with pytest.raises(InvalidStateTransition):
        transition_analysis(analysis, "STATIC_ANALYSIS", 4)
