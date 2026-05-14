"""
History & Scenario Reference — CRA Decision Traceability System
"""

import streamlit as st
import pandas as pd

from mock_data import CVE_SCENARIOS, PRODUCTS, DECISION_RULES
from translations import t, SCENARIO_JA

st.set_page_config(
    page_title="History & Scenarios — CRA System",
    page_icon="📚",
    layout="wide"
)

# Inherit language from session state (shared across pages)
if "lang" not in st.session_state:
    st.session_state.lang = "en"

# ---- Language toggle (mirrored here so user can switch on this page too) ----
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

st.title(f"📚 {t('hist_title')}")
st.markdown(t("hist_subtitle"))
st.markdown("---")

# ============= SCENARIO CARDS =============

st.subheader(t("hist_scenarios"))

card_styles = {
    "scenario_a": ("border-left:5px solid #ff4b4b; background:#fff5f5;", "outcome_report"),
    "scenario_b": ("border-left:5px solid #21c354; background:#f0fff4;", "outcome_not_report"),
    "scenario_c": ("border-left:5px solid #ffa500; background:#fff8ec;", "outcome_conflict"),
    "scenario_d": ("border-left:5px solid #7c3aed; background:#f5f3ff;", "outcome_human"),
}

cols = st.columns(4)
for col, (key, (style, outcome_key)) in zip(cols, card_styles.items()):
    s = CVE_SCENARIOS[key]
    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
    name_label = t(f"scenario_{key}_name")
    outcome_label = t(outcome_key)
    human_badge = " &nbsp;<span style='background:#ede9fe;color:#5b21b6;padding:2px 8px;border-radius:10px;font-size:0.7rem'>👤</span>" if s.get("human_review_required") else ""

    with col:
        st.markdown(f"""
        <div style="border-radius:10px; padding:14px 16px; margin-bottom:6px; {style}">
            <div style="font-weight:700; font-size:0.95rem">{name_label}{human_badge}</div>
        </div>
        """, unsafe_allow_html=True)

        st.caption(f"`{s['cve_id']}` | {severity_icon} {s['severity']} · CVSS **{s['cvss_score']}**")
        st.caption(f"{t('outcome_label')} **{outcome_label}**")

        # Decision reason (translated if Japanese)
        reason = (SCENARIO_JA.get(key, {}).get("decision_reason") if st.session_state.lang == "ja"
                  else s.get("decision_reason", ""))
        if isinstance(reason, str) and reason:
            with st.expander(t("hist_why")):
                st.caption(reason)

st.markdown("---")

# ============= SESSION RUN HISTORY =============

st.subheader(t("hist_run_header"))

runs = st.session_state.get("runs_log", [])

if not runs:
    st.info(t("hist_no_runs"))
else:
    run_df = pd.DataFrame([
        {
            t("hist_time"): r["ts"],
            t("hist_scenario"): r["scenario"],
            t("hist_product"): r["product"],
            t("hist_decision"): r["decision"],
        }
        for r in reversed(runs)
    ])

    decision_col = t("hist_decision")

    def color_decision(val):
        colors = {"REPORT": "#fff5f5", "NOT_REPORT": "#f0fff4", "CONFLICT": "#fff8ec", "ESCALATED": "#fdf4ff"}
        return f"background-color: {colors.get(val, '')}"

    st.dataframe(
        run_df.style.map(color_decision, subset=[decision_col]),
        use_container_width=True, hide_index=True
    )

    st.markdown(t("hist_summary"))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(t("hist_total"), len(runs))
    c2.metric(t("hist_report"), sum(1 for r in runs if r["decision"] == "REPORT"))
    c3.metric(t("hist_not_report"), sum(1 for r in runs if r["decision"] == "NOT_REPORT"))
    c4.metric(t("hist_human"), sum(1 for r in runs if r["decision"] in ("CONFLICT", "ESCALATED")))

st.markdown("---")

# ============= DECISION RULES =============

st.subheader(t("hist_rules"))
rules_df = pd.DataFrame([
    {
        t("hist_rule_id"): r["rule_id"],
        t("hist_rule_name"): r["name"],
        t("hist_rule_condition"): r["condition"],
        t("hist_rule_action"): r["action"],
        t("hist_rule_auto"): t("hist_rule_yes") if r["auto_decidable"] else t("hist_rule_no"),
        t("hist_rule_conf"): f"{r['confidence_boost']:.0%}",
    }
    for r in DECISION_RULES
])
st.dataframe(rules_df, use_container_width=True, hide_index=True)

st.markdown("---")

# ============= PRODUCTS IN SCOPE =============

st.subheader(t("hist_products"))
for pname, p in PRODUCTS.items():
    with st.expander(f"**{pname}** — {p['type']} (v{p['version']})"):
        st.caption(p["description"])
        comp_df = pd.DataFrame([
            {
                t("hist_comp"): c["name"],
                t("hist_version"): c["version"],
                t("hist_vendor"): c["vendor"],
                t("hist_type"): c["type"].capitalize(),
            }
            for c in p["sbom"]["components"]
        ])
        st.dataframe(comp_df, use_container_width=True, hide_index=True)

# ============= FOOTER =============

st.markdown("---")
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    f"{t('legal_declaration')}</div>",
    unsafe_allow_html=True
)
