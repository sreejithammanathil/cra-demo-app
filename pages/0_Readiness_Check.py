"""
CRA Readiness Assessment — Streamlit Page
Appears as the first entry in the sidebar (prefix 0_).
"""

import streamlit as st

from utils import inject_css, sidebar_current_run, sidebar_home_button
from readiness_flow import run_quiz_flow

st.set_page_config(
    page_title="CRA Readiness Assessment",
    page_icon="🛡️",
    layout="wide",
)

# ── Session defaults ──────────────────────────────────────────────────────
if "lang" not in st.session_state:
    st.session_state.lang = "en"

inject_css()

# ── Sidebar ───────────────────────────────────────────────────────────────
ja_nav = st.session_state.lang == "ja"

with st.sidebar:
    sidebar_current_run()
    st.markdown("---")
    st.markdown("##### " + ("ナビゲーション" if ja_nav else "Navigation"))
    st.page_link("app.py",                label="🏠 " + ("ダッシュボード" if ja_nav else "Dashboard"))
    st.page_link("pages/1_Detection.py",  label="🔍 " + ("Act 1 — 検出" if ja_nav else "Act 1 — Detection"))
    st.page_link("pages/2_Decision.py",   label="⚖️ " + ("Act 2 — 判定" if ja_nav else "Act 2 — Decision"))
    st.page_link("pages/3_Reporting.py",  label="📡 " + ("Act 3 — 報告" if ja_nav else "Act 3 — Reporting"))
    st.page_link("pages/4_Compliance.py", label="📋 " + ("コンプライアンス" if ja_nav else "Compliance"))
    st.markdown("---")
    sidebar_home_button()

# ── Language toggle ───────────────────────────────────────────────────────
lc1, lc2, _ = st.columns([1, 1, 6])
with lc1:
    if st.button("🇺🇸 English", use_container_width=True,
                 type="primary" if st.session_state.lang == "en" else "secondary"):
        st.session_state.lang = "en"
        st.rerun()
with lc2:
    if st.button("🇯🇵 日本語", use_container_width=True,
                 type="primary" if st.session_state.lang == "ja" else "secondary"):
        st.session_state.lang = "ja"
        st.rerun()

st.markdown("---")

# ── Quiz flow ─────────────────────────────────────────────────────────────
run_quiz_flow()

# ── Footer ────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    "border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    "EU Cyber Resilience Act 2024/2847 · Assessment for illustrative purposes only · "
    "© 2025 Geoglyph K.K. · All rights reserved"
    "</div>",
    unsafe_allow_html=True,
)
