"""
CRA Decision Traceability System - Live Demo
Streamlit Application for Geoglyph Inc.

Demonstrates the complete 6-stage vulnerability decision pipeline:
1. CVE Ingestion → 2. SBOM Matching → 3. Conflict Detection →
4. Decision Proposal → 5. Human Review → 6. ENISA Reporting
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import json

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from decision_engine import DecisionEngine
from enisa_reporter import (
    generate_enisa_submission_json,
    generate_compliance_artifact_html,
    generate_html_download_link
)

# ============= PAGE CONFIG =============

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============= CUSTOM CSS =============

st.markdown("""
<style>
    /* Decision badge colors */
    .badge-report {
        background: #ff4b4b; color: white;
        padding: 6px 18px; border-radius: 20px;
        font-weight: bold; font-size: 1.1rem; display: inline-block;
    }
    .badge-not-report {
        background: #21c354; color: white;
        padding: 6px 18px; border-radius: 20px;
        font-weight: bold; font-size: 1.1rem; display: inline-block;
    }
    .badge-conflict {
        background: #ffa500; color: white;
        padding: 6px 18px; border-radius: 20px;
        font-weight: bold; font-size: 1.1rem; display: inline-block;
    }

    /* Pipeline stepper */
    .stepper-wrap {
        display: flex; justify-content: space-between;
        align-items: center; margin: 1rem 0 1.5rem 0;
    }
    .step-item {
        display: flex; flex-direction: column;
        align-items: center; flex: 1; position: relative;
    }
    .step-item:not(:last-child)::after {
        content: "";
        position: absolute; top: 18px; left: 60%; width: 80%;
        height: 3px; background: #e0e0e0; z-index: 0;
    }
    .step-item.done:not(:last-child)::after { background: #21c354; }
    .step-circle {
        width: 38px; height: 38px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-weight: bold; font-size: 1rem; z-index: 1;
        background: #e0e0e0; color: #888;
    }
    .step-circle.done { background: #21c354; color: white; }
    .step-label {
        font-size: 0.72rem; margin-top: 4px;
        text-align: center; color: #555; max-width: 80px;
    }
    .step-label.done { color: #21c354; font-weight: 600; }

    /* Scenario card */
    .scenario-card {
        border-radius: 10px; padding: 14px 18px; margin-bottom: 8px;
        border-left: 5px solid;
    }
    .card-report   { border-color: #ff4b4b; background: #fff5f5; }
    .card-not      { border-color: #21c354; background: #f0fff4; }
    .card-conflict { border-color: #ffa500; background: #fff8ec; }

    /* Audit trail badge */
    .audit-badge {
        display: inline-block; padding: 2px 10px;
        border-radius: 12px; font-size: 0.75rem; font-weight: 600;
    }
    .audit-stage { background: #dbeafe; color: #1d4ed8; }
    .audit-decision { background: #dcfce7; color: #166534; }
    .audit-conflict { background: #fef9c3; color: #854d0e; }

    /* Section divider */
    .section-title {
        font-size: 1.15rem; font-weight: 700;
        border-bottom: 2px solid #f0f0f0; padding-bottom: 4px;
        margin-bottom: 12px;
    }
</style>
""", unsafe_allow_html=True)

# ============= SESSION STATE =============

if "engine" not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS,
        cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES,
        thresholds=THRESHOLDS
    )

if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = None

if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None

if "runs_log" not in st.session_state:
    st.session_state.runs_log = []

# For the interactive human-review flow (Scenario D)
if "pipeline_phase" not in st.session_state:
    st.session_state.pipeline_phase = "idle"   # idle | awaiting_human | complete

if "pre_review" not in st.session_state:
    st.session_state.pre_review = None   # stores stages 1-4 results for scenario_d

# ============= HELPER FUNCTIONS =============

def run_stages_1_to_4(scenario_key, product_name):
    """Run stages 1-4 and return intermediate results (used for Scenario D pause)."""
    engine = st.session_state.engine
    engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]
    cve_id = scenario["cve_id"]

    with st.spinner("⏳ Stage 1: Ingesting CVE from NVD..."):
        cve = engine.ingest_cve(cve_id, scenario_key)
        st.success(f"✅ Stage 1: CVE {cve_id} ingested")

    with st.spinner("⏳ Stage 2: Matching against SBOM..."):
        sbom_match = engine.match_sbom(cve, product_name)
        st.success(f"✅ Stage 2: {sbom_match['match_reason']}")

    with st.spinner("⏳ Stage 3: Detecting conflicts..."):
        conflict_info = engine.detect_conflicts(cve, sbom_match, scenario_key)
        if conflict_info["conflict_detected"]:
            st.warning(f"⚠️ Stage 3: Conflict ({conflict_info['conflict_type']})")
        else:
            st.success("✅ Stage 3: No conflicts")

    with st.spinner("⏳ Stage 4: Applying decision rules..."):
        decision_proposal = engine.propose_decision(cve, sbom_match, conflict_info, scenario_key)
        st.success(f"✅ Stage 4: Decision proposed ({decision_proposal['decision_type']}) — confidence {decision_proposal['confidence_score']:.0%}")

    return {
        "scenario_key": scenario_key,
        "scenario_name": scenario["name"],
        "product_name": product_name,
        "cve": cve,
        "sbom_match": sbom_match,
        "conflict_info": conflict_info,
        "decision_proposal": decision_proposal,
        "partial_audit_trail": engine.get_audit_trail()
    }


def complete_pipeline(pre, reviewer_name, reviewer_action, override_decision, notes):
    """Complete stages 5-6 after human review (Scenario D)."""
    engine = st.session_state.engine
    scenario = CVE_SCENARIOS[pre["scenario_key"]]

    review_result = engine.human_review(pre["decision_proposal"], reviewer_action)
    review_result["reviewer"] = reviewer_name or "Compliance Officer"
    review_result["justification"] = notes or review_result["justification"]
    if override_decision:
        review_result["final_decision_type"] = override_decision

    enisa_result = engine.enisa_submit(review_result, pre["cve"], pre["product_name"])

    results = {**pre,
               "review_result": review_result,
               "enisa_result": enisa_result,
               "audit_trail": engine.get_audit_trail()}

    st.session_state.runs_log.append({
        "scenario": pre["scenario_name"].split(":")[0],
        "decision": review_result["final_decision_type"],
        "product": pre["product_name"],
        "ts": datetime.now().strftime("%H:%M:%S")
    })
    return results


def run_pipeline(scenario_key, product_name):
    """Full auto pipeline (scenarios A/B/C)."""
    engine = st.session_state.engine
    engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]
    cve_id = scenario["cve_id"]

    with st.spinner("⏳ Stage 1: Ingesting CVE from NVD..."):
        cve = engine.ingest_cve(cve_id, scenario_key)
        st.success(f"✅ Stage 1: CVE {cve_id} ingested")

    with st.spinner("⏳ Stage 2: Matching against SBOM..."):
        sbom_match = engine.match_sbom(cve, product_name)
        st.success(f"✅ Stage 2: {sbom_match['match_reason']}")

    with st.spinner("⏳ Stage 3: Detecting conflicts..."):
        conflict_info = engine.detect_conflicts(cve, sbom_match, scenario_key)
        if conflict_info["conflict_detected"]:
            st.warning(f"⚠️ Stage 3: Conflict detected ({conflict_info['conflict_type']})")
        else:
            st.success("✅ Stage 3: No conflicts")

    with st.spinner("⏳ Stage 4: Applying decision rules..."):
        decision_proposal = engine.propose_decision(cve, sbom_match, conflict_info, scenario_key)
        st.success(f"✅ Stage 4: Decision proposed ({decision_proposal['decision_type']})")

    with st.spinner("⏳ Stage 5: Human review..."):
        review_result = engine.human_review(decision_proposal, "APPROVE")
        st.success("✅ Stage 5: Approved by Compliance Officer")

    with st.spinner("⏳ Stage 6: ENISA submission..."):
        enisa_result = engine.enisa_submit(review_result, cve, product_name)
        st.success(f"✅ Stage 6: {enisa_result['status']}")

    results = {
        "scenario_key": scenario_key,
        "scenario_name": scenario["name"],
        "product_name": product_name,
        "cve": cve,
        "sbom_match": sbom_match,
        "conflict_info": conflict_info,
        "decision_proposal": decision_proposal,
        "review_result": review_result,
        "enisa_result": enisa_result,
        "audit_trail": engine.get_audit_trail()
    }

    st.session_state.runs_log.append({
        "scenario": scenario["name"].split(":")[0],
        "decision": review_result["final_decision_type"],
        "product": product_name,
        "ts": datetime.now().strftime("%H:%M:%S")
    })
    return results


def decision_badge(decision_type):
    cls = {
        "REPORT": "badge-report",
        "NOT_REPORT": "badge-not-report",
        "CONFLICT": "badge-conflict"
    }.get(decision_type, "badge-conflict")
    return f'<span class="{cls}">{decision_type}</span>'


def pipeline_stepper(completed=6):
    stages = ["CVE\nIngest", "SBOM\nMatch", "Conflict\nDetect", "Decision\nRules", "Human\nReview", "ENISA\nReport"]
    items = ""
    for i, label in enumerate(stages, 1):
        done = "done" if i <= completed else ""
        icon = "✓" if i <= completed else str(i)
        items += f"""
        <div class="step-item {done}">
          <div class="step-circle {done}">{icon}</div>
          <div class="step-label {done}">{label.replace(chr(10), '<br>')}</div>
        </div>"""
    st.markdown(f'<div class="stepper-wrap">{items}</div>', unsafe_allow_html=True)


def cvss_gauge(score):
    color = "#ff4b4b" if score >= 8.5 else "#ffa500" if score >= 7.0 else "#ffd700" if score >= 5.0 else "#21c354"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "CVSS Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 10], "tickwidth": 1},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 4], "color": "#d4edda"},
                {"range": [4, 7], "color": "#fff3cd"},
                {"range": [7, 8.5], "color": "#ffe0b2"},
                {"range": [8.5, 10], "color": "#f8d7da"},
            ],
            "threshold": {"line": {"color": "black", "width": 3}, "thickness": 0.75, "value": score}
        }
    ))
    fig.update_layout(height=220, margin=dict(t=40, b=10, l=20, r=20))
    return fig


def sbom_table(product_name, matching_component, match_found):
    product = PRODUCTS.get(product_name, {})
    components = product.get("sbom", {}).get("components", [])
    rows = []
    for c in components:
        is_vuln = match_found and c["name"].lower() in (matching_component or "").lower()
        rows.append({
            "Component": c["name"],
            "Version": c["version"],
            "Vendor": c["vendor"],
            "Type": c["type"].capitalize(),
            "Status": "🔴 VULNERABLE" if is_vuln else "🟢 Safe"
        })
    return pd.DataFrame(rows)


def rule_confidence_chart(rules_fired):
    names = [r["rule"] for r in rules_fired]
    triggered = [r["triggered"] for r in rules_fired]
    colors = ["#21c354" if t else "#e0e0e0" for t in triggered]
    fig = px.bar(
        x=names, y=[1] * len(names),
        color=triggered,
        color_discrete_map={True: "#21c354", False: "#e0e0e0"},
        labels={"x": "Rule", "y": ""},
        title="Decision Rules — Triggered / Not Triggered"
    )
    fig.update_layout(height=220, showlegend=False, margin=dict(t=40, b=60, l=20, r=20),
                      yaxis_visible=False)
    fig.update_xaxes(tickangle=-20)
    return fig


# ============= MAIN HEADER =============

st.title("🔐 CRA Decision Traceability System")
st.markdown("**EU Cyber Resilience Act (2024/2847) — Live Demo for J-TEC Co., Ltd.**")
st.markdown("---")

# ============= SIDEBAR =============

with st.sidebar:
    st.header("📋 Demo Scenarios")

    scenarios = {k: CVE_SCENARIOS[k]["name"] for k in CVE_SCENARIOS}
    selected_scenario = st.selectbox(
        "Choose Scenario:",
        options=list(scenarios.keys()),
        format_func=lambda x: scenarios[x],
        key="scenario_selector"
    )

    # Scenario preview
    s = CVE_SCENARIOS[selected_scenario]
    exp_decision = s.get("expected_decision", "—")
    severity_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
    human_flag = "👤 **Human review required**" if s.get("human_review_required") else ""
    st.markdown(f"""
    > **CVE:** `{s['cve_id']}`
    > **Severity:** {severity_color} {s['severity']} (CVSS {s['cvss_score']})
    > **Expected:** `{exp_decision}`
    {human_flag}
    """)

    st.markdown("---")

    st.header("🏭 J-TEC Product")
    product_names = list(PRODUCTS.keys())
    default_idx = {"scenario_a": 1, "scenario_b": 0, "scenario_c": 2, "scenario_d": 2}.get(selected_scenario, 0)
    selected_product = st.selectbox("Product:", product_names, index=default_idx)

    # Product SBOM quick view
    prod = PRODUCTS[selected_product]
    with st.expander(f"📦 SBOM ({len(prod['sbom']['components'])} components)"):
        for c in prod["sbom"]["components"]:
            st.caption(f"• {c['name']} v{c['version']} ({c['vendor']})")

    st.markdown("---")

    run_btn = st.button("🚀 RUN DEMO PIPELINE", use_container_width=True, type="primary")
    if run_btn:
        # Reset any previous human-review state
        st.session_state.pipeline_phase = "idle"
        st.session_state.pre_review = None
        st.session_state.pipeline_results = None

        if CVE_SCENARIOS[selected_scenario].get("human_review_required"):
            st.session_state.pre_review = run_stages_1_to_4(selected_scenario, selected_product)
            st.session_state.pipeline_phase = "awaiting_human"
            st.session_state.current_scenario = selected_scenario
        else:
            st.session_state.pipeline_results = run_pipeline(selected_scenario, selected_product)
            st.session_state.pipeline_phase = "complete"
            st.session_state.current_scenario = selected_scenario

    # Session stats
    if st.session_state.runs_log:
        st.markdown("---")
        st.header("📊 Session Stats")
        log = st.session_state.runs_log
        st.metric("Scenarios Run", len(log))
        decisions = [r["decision"] for r in log]
        report_count = decisions.count("REPORT")
        st.metric("REPORT decisions", report_count)
        st.metric("NOT_REPORT decisions", decisions.count("NOT_REPORT"))

        with st.expander("Run history"):
            for r in reversed(log):
                st.caption(f"`{r['ts']}` {r['scenario']} → **{r['decision']}**")

# ============= MAIN CONTENT =============

# ============= INTERACTIVE HUMAN REVIEW (Scenario D) =============

if st.session_state.pipeline_phase == "awaiting_human" and st.session_state.pre_review:
    pre = st.session_state.pre_review
    proposal = pre["decision_proposal"]

    st.warning("⏸️ **Pipeline paused at Stage 5 — Compliance Officer review required**")

    # Progress stepper — stopped at stage 4
    st.markdown("#### Pipeline Stages")
    pipeline_stepper(completed=4)
    st.markdown("---")

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("CVE", pre["cve"]["cve_id"])
    col2.metric("CVSS Score", pre["cve"]["cvss_score"])
    col3.metric("Severity", pre["cve"]["severity"])
    col4.metric("System Confidence", f"{proposal['confidence_score']:.0%}", delta="⚠️ Below 80% threshold")

    # Evidence panel
    st.markdown("---")
    st.subheader("📋 Evidence for Review")
    ev_col, gauge_col = st.columns([2, 1])

    with ev_col:
        with st.container(border=True):
            st.markdown("**Why the system cannot auto-decide:**")
            for rule in proposal["rules_fired"]:
                if rule["triggered"]:
                    st.markdown(f"- **{rule['rule']}**")
                    st.caption(rule["reasoning"])

        st.markdown("**Evidence Sources:**")
        for ev in pre["conflict_info"]["evidence_summary"]:
            st.markdown(f"- {ev}")

    with gauge_col:
        st.plotly_chart(cvss_gauge(pre["cve"]["cvss_score"]), use_container_width=True)

    # SBOM table
    match = pre["sbom_match"]
    st.markdown("**SBOM Component Analysis:**")
    df = sbom_table(pre["product_name"], match.get("matching_component"), match["match_found"])
    st.dataframe(
        df.style.apply(
            lambda row: ["background-color: #fff5f5" if "VULNERABLE" in str(row["Status"]) else "" for _ in row],
            axis=1
        ),
        use_container_width=True,
        hide_index=True
    )

    # ---- Human review form ----
    st.markdown("---")
    st.subheader("👤 Stage 5: Compliance Officer Review")
    st.markdown(
        "The automated system has flagged this case for human review. "
        "Review the evidence above and submit your decision below."
    )

    with st.form("human_review_form"):
        reviewer_name = st.text_input("Reviewer Name / ID", placeholder="e.g. Tanaka-san, CO-042")

        st.markdown("**Your Assessment:**")
        notes = st.text_area(
            "Justification / Notes",
            placeholder=(
                "e.g. Reviewed VEX statement and SBOM match. "
                "The firewall mitigation is adequate for our deployment context — NOT_REPORT. "
                "OR: Internal network exposure is unacceptable — REPORT to ENISA."
            ),
            height=110
        )

        st.markdown("**Select Decision:**")
        decision_col1, decision_col2, decision_col3 = st.columns(3)
        with decision_col1:
            approve_report = st.form_submit_button(
                "🔴 APPROVE — REPORT to ENISA",
                use_container_width=True,
                type="primary"
            )
        with decision_col2:
            approve_not_report = st.form_submit_button(
                "🟢 APPROVE — NOT_REPORT",
                use_container_width=True
            )
        with decision_col3:
            escalate = st.form_submit_button(
                "⚠️ ESCALATE for Further Review",
                use_container_width=True
            )

    if approve_report or approve_not_report or escalate:
        if not reviewer_name.strip():
            st.error("Please enter your name / reviewer ID before submitting.")
        elif not notes.strip():
            st.error("Please enter a justification before submitting.")
        else:
            if approve_report:
                action, override = "APPROVE", "REPORT"
                label = "REPORT"
            elif approve_not_report:
                action, override = "APPROVE", "NOT_REPORT"
                label = "NOT_REPORT"
            else:
                action, override = "APPROVE", "CONFLICT"
                label = "ESCALATED"

            with st.spinner("⏳ Stage 5 & 6: Completing pipeline..."):
                results = complete_pipeline(pre, reviewer_name, action, override, notes)

            st.session_state.pipeline_results = results
            st.session_state.pipeline_phase = "complete"
            st.success(f"✅ Decision recorded: **{label}** by {reviewer_name}. Pipeline complete.")
            st.rerun()

if st.session_state.pipeline_results:
    results = st.session_state.pipeline_results

    # ---- Decision banner ----
    final = results["review_result"]["final_decision_type"]
    badge_html = decision_badge(final)
    st.markdown(f"### Final Decision: {badge_html}", unsafe_allow_html=True)

    # ---- Top metrics ----
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Scenario", results["scenario_name"].split(":")[0])
    with col2:
        st.metric("Product", results["product_name"])
    with col3:
        st.metric("CVE", results["cve"]["cve_id"])
    with col4:
        st.metric("CVSS Score", results["cve"]["cvss_score"])
    with col5:
        st.metric("Severity", results["cve"]["severity"])

    st.markdown("---")

    # ---- Pipeline stepper ----
    st.markdown("#### Pipeline Stages")
    pipeline_stepper(completed=6)

    st.markdown("---")

    # ---- Tabs ----
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "1️⃣ CVE Ingestion",
        "2️⃣ SBOM Match",
        "3️⃣ Conflict Detection",
        "4️⃣ Decision Rules",
        "5️⃣ Human Review",
        "6️⃣ ENISA Report",
        "📋 Compliance Artifacts"
    ])

    # ========== TAB 1: CVE INGESTION ==========
    with tab1:
        st.subheader("Stage 1: CVE Ingestion from NVD")
        col1, col2 = st.columns([1, 2])
        with col1:
            st.plotly_chart(cvss_gauge(results["cve"]["cvss_score"]), use_container_width=True)
        with col2:
            st.markdown("**Description**")
            st.info(results["cve"]["description"])
            c1, c2, c3 = st.columns(3)
            c1.metric("CVE ID", results["cve"]["cve_id"])
            c2.metric("Severity", results["cve"]["severity"])
            c3.metric("Exploit Available", "YES ⚠️" if results["cve"]["exploit_available"] else "NO ✅")
            st.markdown(
                f"**Affected Version Range:** `{results['cve']['affected_versions']['range_start']}` "
                f"→ `{results['cve']['affected_versions']['range_end']}`"
            )

    # ========== TAB 2: SBOM MATCHING ==========
    with tab2:
        st.subheader("Stage 2: SBOM Matching")
        match = results["sbom_match"]

        col1, col2, col3 = st.columns(3)
        col1.metric("Product", match["product_name"])
        col2.metric("Match Confidence", f"{match['match_confidence']:.0%}")
        col3.metric("Component Found", "YES 🔴" if match["matching_component"] else "NO 🟢")

        if match["match_found"]:
            st.error(f"🔴 **VULNERABLE** — {match['match_reason']}")
        else:
            st.success(f"🟢 **NOT VULNERABLE** — {match['match_reason']}")

        st.markdown("**Full SBOM Component Analysis**")
        df = sbom_table(results["product_name"], match.get("matching_component"), match["match_found"])
        st.dataframe(
            df.style.apply(
                lambda row: ["background-color: #fff5f5" if "VULNERABLE" in str(row["Status"]) else "" for _ in row],
                axis=1
            ),
            use_container_width=True,
            hide_index=True
        )

    # ========== TAB 3: CONFLICT DETECTION ==========
    with tab3:
        st.subheader("Stage 3: Conflict Detection")
        conflict = results["conflict_info"]

        if conflict["conflict_detected"]:
            st.warning(f"⚠️ **Conflict Detected:** {conflict['conflict_type']}")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Evidence Sources in Conflict**")
                for ev in conflict["evidence_summary"]:
                    st.markdown(f"- {ev}")
            with c2:
                if conflict.get("vex_available"):
                    st.info("📄 **VEX Document Available**\nVendor-provided statement present and reviewed.")
        else:
            st.success("✅ No conflicts detected — all evidence sources agree")
            for ev in conflict["evidence_summary"]:
                st.markdown(f"- {ev}")

        with st.expander("🔍 Raw conflict data"):
            st.json(conflict)

    # ========== TAB 4: DECISION RULES ==========
    with tab4:
        st.subheader("Stage 4: Decision Rules Engine")
        decision = results["decision_proposal"]

        col1, col2, col3 = st.columns(3)
        col1.metric("Proposed Decision", decision["decision_type"])
        col2.metric("Confidence Score", f"{decision['confidence_score']:.0%}")
        col3.metric("Auto-Decidable", "YES ✅" if decision["auto_decidable"] else "NO — Human needed")

        col_chart, col_rules = st.columns([1, 1])

        with col_chart:
            st.plotly_chart(rule_confidence_chart(decision["rules_fired"]), use_container_width=True)

        with col_rules:
            st.markdown("**Rules Evaluation**")
            for rule in decision["rules_fired"]:
                status = "✅ TRIGGERED" if rule["triggered"] else "⬜ Not triggered"
                with st.container(border=True):
                    st.markdown(f"**{rule['rule']}** — {status}")
                    st.caption(rule["reasoning"])

        st.markdown("**Evidence Weighting**")
        weighting = decision["evidence_weighting"]
        ew_df = pd.DataFrame({
            "Evidence Source": ["SBOM Matching", "CVE Data (NVD)", "VEX Statement"],
            "Confidence": [
                weighting["sbom_confidence"],
                weighting["cve_data_confidence"],
                weighting["vex_confidence"]
            ]
        })
        fig_ew = px.bar(
            ew_df, x="Evidence Source", y="Confidence",
            color="Confidence", color_continuous_scale=["#f8d7da", "#fff3cd", "#d4edda"],
            range_y=[0, 1], text_auto=".0%", title="Evidence Confidence Weighting"
        )
        fig_ew.update_layout(height=220, margin=dict(t=40, b=20, l=20, r=20), showlegend=False)
        fig_ew.update_yaxes(tickformat=".0%")
        st.plotly_chart(fig_ew, use_container_width=True)

    # ========== TAB 5: HUMAN REVIEW ==========
    with tab5:
        st.subheader("Stage 5: Human Review Queue")
        review = results["review_result"]

        col1, col2, col3 = st.columns(3)
        col1.metric("Reviewer", review["reviewer"])
        col2.metric("Action", review["action"])
        col3.metric("Decision ID", review["decision_id"][:12] + "…")

        st.markdown("**Review Justification**")
        st.info(review["justification"])

        st.markdown("**Final Decision**")
        st.markdown(decision_badge(review["final_decision_type"]), unsafe_allow_html=True)

    # ========== TAB 6: ENISA REPORTING ==========
    with tab6:
        st.subheader("Stage 6: ENISA Reporting")
        enisa = results["enisa_result"]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Status", enisa["status"])
            st.metric("Submitted to ENISA", "YES ✅" if enisa["submitted"] else "NO — Not required")
        with col2:
            if enisa["submitted"]:
                st.success(f"✅ **ENISA Reference:** `{enisa['enisa_reference_id']}`")
                st.caption(f"Submitted: {enisa['submission_timestamp']}")
                st.markdown("**24-hour SLA clock started from submission timestamp.**")
            else:
                st.info("No ENISA submission required for this decision type.")

        with st.expander("📄 ENISA submission payload preview"):
            enisa_json = generate_enisa_submission_json(
                decision=results["review_result"],
                cve=results["cve"],
                product_name=results["product_name"],
                sbom_match=results["sbom_match"],
                submission_id=results["enisa_result"]["submission_id"]
            )
            st.json(enisa_json)

    # ========== TAB 7: COMPLIANCE ARTIFACTS ==========
    with tab7:
        st.subheader("Compliance Artifacts — Download for Regulatory Audit")

        html_report = generate_compliance_artifact_html(
            decision_id=results["review_result"]["decision_id"],
            cve=results["cve"],
            product_name=results["product_name"],
            sbom_match=results["sbom_match"],
            decision=results["review_result"],
            audit_trail=results["audit_trail"]
        )
        enisa_json = generate_enisa_submission_json(
            decision=results["review_result"],
            cve=results["cve"],
            product_name=results["product_name"],
            sbom_match=results["sbom_match"],
            submission_id=results["enisa_result"]["submission_id"]
        )

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**📄 HTML Compliance Report**")
            st.caption("Full audit artifact with decision trail, evidence, and ENISA payload.")
            st.download_button(
                label="📥 Download HTML Report",
                data=html_report,
                file_name=f"CRA-Compliance-{results['cve']['cve_id']}.html",
                mime="text/html",
                use_container_width=True
            )
        with col2:
            st.markdown("**📋 ENISA JSON Payload**")
            st.caption("Machine-readable report formatted for ENISA submission API.")
            st.download_button(
                label="📋 Download ENISA JSON",
                data=json.dumps(enisa_json, indent=2),
                file_name=f"ENISA-{results['cve']['cve_id']}.json",
                mime="application/json",
                use_container_width=True
            )

    # ============= AUDIT TRAIL =============

    st.markdown("---")
    st.header("📋 Complete Audit Trail")
    st.caption("End-to-end traceability — every decision step timestamped and logged.")

    audit_df = pd.DataFrame(results["audit_trail"])
    if not audit_df.empty:
        audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"])
        for _, row in audit_df.iterrows():
            action = str(row.get("action", ""))
            badge_cls = "audit-stage" if "Stage" in action else "audit-decision" if "Decision" in action else "audit-conflict"
            details = str(row.get("details", ""))
            ts = row["timestamp"].strftime("%H:%M:%S")
            st.markdown(
                f'`{ts}` &nbsp; <span class="audit-badge {badge_cls}">{action}</span> &nbsp; {details}',
                unsafe_allow_html=True
            )

else:
    # ============= LANDING PAGE =============

    st.markdown("### 👈 Select a scenario and click **RUN DEMO PIPELINE** to begin")
    st.markdown("---")

    scenario_meta = [
        ("scenario_a", "card-report",    "🔴 REPORT"),
        ("scenario_b", "card-not",       "🟢 NOT_REPORT"),
        ("scenario_c", "card-conflict",  "🟠 CONFLICT"),
        ("scenario_d", "card-conflict",  "👤 HUMAN DECISION"),
    ]

    col1, col2, col3, col4 = st.columns(4)
    for col, (key, cls, outcome) in zip([col1, col2, col3, col4], scenario_meta):
        s = CVE_SCENARIOS[key]
        human_tag = " 👤" if s.get("human_review_required") else ""
        with col:
            st.markdown(f"""
            <div class="scenario-card {cls}">
                <strong>{s['name'].split(':')[0]}{human_tag}</strong><br>
                <span style="font-size:0.85rem">{s['name'].split('—', 1)[1].strip() if '—' in s['name'] else (s['name'].split(':', 1)[1].strip() if ':' in s['name'] else '')}</span>
            </div>
            """, unsafe_allow_html=True)
            st.caption(f"CVE: `{s['cve_id']}` | CVSS: **{s['cvss_score']}** ({s['severity']})")
            st.caption(f"Outcome: **{outcome}**")
            st.caption(s.get("decision_reason", "")[:120] + "…" if len(s.get("decision_reason","")) > 120 else s.get("decision_reason",""))

    st.markdown("---")
    st.markdown("### 📏 Decision Rules (Active)")
    rules_df = pd.DataFrame([
        {"ID": r["rule_id"], "Rule": r["name"], "Action": r["action"],
         "Auto-decide": "✅" if r["auto_decidable"] else "❌ Human needed"}
        for r in DECISION_RULES
    ])
    st.dataframe(rules_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### 🏭 J-TEC Products in Scope")
    prod_rows = []
    for pname, p in PRODUCTS.items():
        prod_rows.append({
            "Product": pname,
            "Type": p["type"],
            "Version": p["version"],
            "SBOM Components": len(p["sbom"]["components"])
        })
    st.dataframe(pd.DataFrame(prod_rows), use_container_width=True, hide_index=True)

# ============= FOOTER =============

st.markdown("---")
st.markdown("""
<div style='text-align: center; font-size: 12px; color: gray;'>
    🔐 <strong>CRA Decision Traceability System</strong> — Geoglyph Inc. &nbsp;|&nbsp;
    Demo for J-TEC Co., Ltd. &nbsp;|&nbsp; EU Cyber Resilience Act (2024/2847)
</div>
""", unsafe_allow_html=True)
