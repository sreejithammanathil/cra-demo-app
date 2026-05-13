"""
History & Scenario Reference — CRA Decision Traceability System
"""

import streamlit as st
import pandas as pd
from datetime import datetime

from mock_data import CVE_SCENARIOS, PRODUCTS, DECISION_RULES

st.set_page_config(
    page_title="History & Scenarios — CRA System",
    page_icon="📚",
    layout="wide"
)

st.title("📚 Scenario Reference & Run History")
st.markdown("**Overview of all demo scenarios, decision rules, and decisions made this session.**")
st.markdown("---")

# ============= SCENARIO REFERENCE CARDS =============

st.subheader("🗂️ Demo Scenarios")

card_styles = {
    "scenario_a": ("border-left: 5px solid #ff4b4b; background:#fff5f5;", "🔴 REPORT"),
    "scenario_b": ("border-left: 5px solid #21c354; background:#f0fff4;", "🟢 NOT_REPORT"),
    "scenario_c": ("border-left: 5px solid #ffa500; background:#fff8ec;", "🟠 CONFLICT"),
    "scenario_d": ("border-left: 5px solid #7c3aed; background:#f5f3ff;", "👤 HUMAN DECISION"),
}

cols = st.columns(4)
for col, (key, (style, outcome)) in zip(cols, card_styles.items()):
    s = CVE_SCENARIOS[key]
    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
    human_tag = " &nbsp;<span style='background:#ede9fe;color:#5b21b6;padding:2px 8px;border-radius:10px;font-size:0.7rem'>Human</span>" if s.get("human_review_required") else ""
    name_short = s["name"].split(":")[0].split("—")[0].strip()
    subtitle = (s["name"].split("—", 1)[1].strip() if "—" in s["name"]
                else s["name"].split(":", 1)[1].strip() if ":" in s["name"] else "")

    with col:
        st.markdown(f"""
        <div style="border-radius:10px; padding:14px 16px; margin-bottom:6px; {style}">
            <div style="font-weight:700; font-size:1rem">{name_short}{human_tag}</div>
            <div style="font-size:0.82rem; margin-top:4px; color:#444">{subtitle}</div>
        </div>
        """, unsafe_allow_html=True)

        st.caption(f"`{s['cve_id']}` | {severity_icon} {s['severity']} · CVSS **{s['cvss_score']}**")
        st.caption(f"Outcome: **{outcome}**")

        reason = s.get("decision_reason", "")
        if isinstance(reason, str) and reason:
            with st.expander("Why?"):
                st.caption(reason)

st.markdown("---")

# ============= SESSION RUN HISTORY =============

st.subheader("🕓 Session Run History")

runs = st.session_state.get("runs_log", [])

if not runs:
    st.info("No scenarios have been run yet in this session. Go to the **Pipeline** page and run a scenario.")
else:
    decision_icon = {"REPORT": "🔴", "NOT_REPORT": "🟢", "CONFLICT": "🟠", "ESCALATED": "⚠️"}

    run_df = pd.DataFrame([
        {
            "Time": r["ts"],
            "Scenario": r["scenario"],
            "Product": r["product"],
            "Decision": r["decision"],
        }
        for r in reversed(runs)
    ])

    # Styled dataframe
    def color_decision(val):
        colors = {"REPORT": "#fff5f5", "NOT_REPORT": "#f0fff4", "CONFLICT": "#fff8ec", "ESCALATED": "#fdf4ff"}
        return f"background-color: {colors.get(val, '')}"

    st.dataframe(
        run_df.style.applymap(color_decision, subset=["Decision"]),
        use_container_width=True,
        hide_index=True
    )

    # Summary stats
    st.markdown("**Session Summary**")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Runs", len(runs))
    c2.metric("REPORT", sum(1 for r in runs if r["decision"] == "REPORT"))
    c3.metric("NOT_REPORT", sum(1 for r in runs if r["decision"] == "NOT_REPORT"))
    c4.metric("Human / Escalated", sum(1 for r in runs if r["decision"] in ("CONFLICT", "ESCALATED")))

st.markdown("---")

# ============= DECISION RULES REFERENCE =============

st.subheader("📏 Decision Rules Engine")
rules_df = pd.DataFrame([
    {
        "ID": r["rule_id"],
        "Rule Name": r["name"],
        "Condition": r["condition"],
        "Action": r["action"],
        "Auto-decide": "✅ Yes" if r["auto_decidable"] else "❌ Human needed",
        "Confidence": f"{r['confidence_boost']:.0%}"
    }
    for r in DECISION_RULES
])
st.dataframe(rules_df, use_container_width=True, hide_index=True)

st.markdown("---")

# ============= PRODUCTS IN SCOPE =============

st.subheader("🏭 J-TEC Products in Scope")
for pname, p in PRODUCTS.items():
    with st.expander(f"**{pname}** — {p['type']} (v{p['version']})"):
        st.caption(p["description"])
        comp_df = pd.DataFrame([
            {"Component": c["name"], "Version": c["version"], "Vendor": c["vendor"], "Type": c["type"].capitalize()}
            for c in p["sbom"]["components"]
        ])
        st.dataframe(comp_df, use_container_width=True, hide_index=True)
