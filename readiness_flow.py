"""
CRA Readiness Assessment — Quiz Flow Controller
Manages session state and delegates rendering to readiness_ui.py.
"""

import streamlit as st

from readiness_scorer import calculate_score
from readiness_ui import display_welcome_screen, display_question, display_results

# Unique key prefix so multiple quiz instances don't collide
_STATE_PREFIX = "readiness_quiz"


def _state_key() -> str:
    """Return the session-state key for this quiz instance."""
    return _STATE_PREFIX


def initialize_quiz_state() -> str:
    """
    Ensure quiz state exists in session_state.
    Returns the state key.
    """
    key = _state_key()
    if key not in st.session_state:
        st.session_state[key] = {
            "phase": "welcome",   # welcome | quiz | results
            "current_q": 0,
            "answers": {},        # {qid: points}
            "score_result": None,
            "lead_submitted": False,
            "lead_name": "",
        }
    return key


def run_quiz_flow() -> None:
    """
    Main entry point — call this once from pages/0_Readiness_Check.py.
    Dispatches to the correct UI phase.
    """
    key = initialize_quiz_state()
    s = st.session_state[key]
    phase = s.get("phase", "welcome")

    if phase == "welcome":
        display_welcome_screen(key)

    elif phase == "quiz":
        display_question(key)

    elif phase == "results":
        # Calculate score once and cache
        if not s.get("score_result"):
            s["score_result"] = calculate_score(s["answers"])
        display_results(key)

    else:
        # Fallback — reset to welcome
        s["phase"] = "welcome"
        st.rerun()


def handle_navigation(key: str) -> None:
    """
    (Utility) Manually advance or retreat the quiz.
    Useful for testing or admin overrides.
    """
    s = st.session_state.get(key, {})
    phase = s.get("phase")
    if phase == "welcome":
        s["phase"] = "quiz"
        s["current_q"] = 0
    elif phase == "quiz":
        from readiness_questions import QUESTIONS
        idx = s.get("current_q", 0)
        if idx < len(QUESTIONS) - 1:
            s["current_q"] = idx + 1
        else:
            s["phase"] = "results"
    st.rerun()
