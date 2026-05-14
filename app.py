"""
CRA Decision Traceability System - Live Demo
Streamlit Application for Geoglyph Inc.
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
)
from translations import t, scenario_name, SCENARIO_JA

# ============= PAGE CONFIG =============

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============= LANGUAGE INIT =============

if "lang" not in st.session_state:
    st.session_state.lang = "en"

# ============= CUSTOM CSS =============

st.markdown("""
<style>
    .badge-report    { background:#ff4b4b; color:white; padding:6px 18px; border-radius:20px; font-weight:bold; font-size:1.1rem; display:inline-block; }
    .badge-not-report{ background:#21c354; color:white; padding:6px 18px; border-radius:20px; font-weight:bold; font-size:1.1rem; display:inline-block; }
    .badge-conflict  { background:#ffa500; color:white; padding:6px 18px; border-radius:20px; font-weight:bold; font-size:1.1rem; display:inline-block; }
    .stepper-wrap { display:flex; justify-content:space-between; align-items:center; margin:1rem 0 1.5rem 0; }
    .step-item { display:flex; flex-direction:column; align-items:center; flex:1; position:relative; }
    .step-item:not(:last-child)::after { content:""; position:absolute; top:18px; left:60%; width:80%; height:3px; background:#e0e0e0; z-index:0; }
    .step-item.done:not(:last-child)::after { background:#21c354; }
    .step-circle { width:38px; height:38px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:1rem; z-index:1; background:#e0e0e0; color:#888; }
    .step-circle.done { background:#21c354; color:white; }
    .step-label { font-size:0.72rem; margin-top:4px; text-align:center; color:#555; max-width:80px; }
    .step-label.done { color:#21c354; font-weight:600; }
    .audit-badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:0.75rem; font-weight:600; }
    .audit-stage { background:#dbeafe; color:#1d4ed8; }
    .audit-decision { background:#dcfce7; color:#166534; }
    .audit-conflict { background:#fef9c3; color:#854d0e; }
    .lang-toggle { display:flex; gap:6px; margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)

# ============= SESSION STATE =============

if "engine" not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS, cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES, thresholds=THRESHOLDS
    )
if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = None
if "pipeline_results" not in st.session_state:
    st.session_state.pipeline_results = None
if "runs_log" not in st.session_state:
    st.session_state.runs_log = []
if "pipeline_phase" not in st.session_state:
    st.session_state.pipeline_phase = "idle"
if "pre_review" not in st.session_state:
    st.session_state.pre_review = None

# ============= HELPERS =============

def decision_badge(decision_type):
    cls = {"REPORT": "badge-report", "NOT_REPORT": "badge-not-report"}.get(decision_type, "badge-conflict")
    return f'<span class="{cls}">{decision_type}</span>'


def pipeline_stepper(completed=6):
    labels = [t("step_ingest"), t("step_sbom"), t("step_conflict"),
              t("step_rules"), t("step_review"), t("step_enisa")]
    items = ""
    for i, label in enumerate(labels, 1):
        done = "done" if i <= completed else ""
        icon = "✓" if i <= completed else str(i)
        items += f'<div class="step-item {done}"><div class="step-circle {done}">{icon}</div><div class="step-label {done}">{label.replace(chr(10), "<br>")}</div></div>'
    st.markdown(f'<div class="stepper-wrap">{items}</div>', unsafe_allow_html=True)


def cvss_gauge(score):
    color = "#ff4b4b" if score >= 8.5 else "#ffa500" if score >= 7.0 else "#ffd700" if score >= 5.0 else "#21c354"
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "CVSS Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 10]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 4],   "color": "#d4edda"},
                {"range": [4, 7],   "color": "#fff3cd"},
                {"range": [7, 8.5], "color": "#ffe0b2"},
                {"range": [8.5, 10],"color": "#f8d7da"},
            ],
            "threshold": {"line": {"color": "black", "width": 3}, "thickness": 0.75, "value": score}
        }
    ))
    fig.update_layout(height=220, margin=dict(t=40, b=10, l=20, r=20))
    return fig


def sbom_table(product_name, matching_component, match_found):
    product = PRODUCTS.get(product_name, {})
    rows = []
    for c in product.get("sbom", {}).get("components", []):
        is_vuln = match_found and c["name"].lower() in (matching_component or "").lower()
        rows.append({
            t("t2_col_component"): c["name"],
            t("t2_col_version"): c["version"],
            t("t2_col_vendor"): c["vendor"],
            t("t2_col_type"): c["type"].capitalize(),
            t("t2_col_status"): t("t2_vulnerable") if is_vuln else t("t2_safe_status"),
        })
    return pd.DataFrame(rows)


def rule_confidence_chart(rules_fired):
    names = [r["rule"] for r in rules_fired]
    triggered = [r["triggered"] for r in rules_fired]
    fig = px.bar(
        x=names, y=[1] * len(names),
        color=triggered,
        color_discrete_map={True: "#21c354", False: "#e0e0e0"},
        title="Decision Rules — Triggered / Not Triggered"
    )
    fig.update_layout(height=220, showlegend=False, margin=dict(t=40, b=60, l=20, r=20), yaxis_visible=False)
    fig.update_xaxes(tickangle=-20)
    return fig


def cve_description(scenario_key):
    if st.session_state.lang == "ja":
        return SCENARIO_JA.get(scenario_key, {}).get("cve_description",
               CVE_SCENARIOS[scenario_key]["cve_description"])
    return CVE_SCENARIOS[scenario_key]["cve_description"]


# ============= PIPELINE FUNCTIONS =============

def run_stages_1_to_4(scenario_key, product_name):
    engine = st.session_state.engine
    engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]
    cve_id = scenario["cve_id"]

    with st.spinner(t("spin1")):
        cve = engine.ingest_cve(cve_id, scenario_key)
        st.success(t("spin1_ok", cve_id=cve_id))
    with st.spinner(t("spin2")):
        sbom_match = engine.match_sbom(cve, product_name)
        st.success(t("spin2_ok", reason=sbom_match["match_reason"]))
    with st.spinner(t("spin3")):
        conflict_info = engine.detect_conflicts(cve, sbom_match, scenario_key)
        if conflict_info["conflict_detected"]:
            st.warning(t("spin3_conflict", type=conflict_info["conflict_type"]))
        else:
            st.success(t("spin3_ok"))
    with st.spinner(t("spin4")):
        decision_proposal = engine.propose_decision(cve, sbom_match, conflict_info, scenario_key)
        st.success(t("spin4_ok", decision=decision_proposal["decision_type"],
                     conf=f"{decision_proposal['confidence_score']:.0%}"))

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
    engine = st.session_state.engine
    review_result = engine.human_review(pre["decision_proposal"], reviewer_action)
    review_result["reviewer"] = reviewer_name or "Compliance Officer"
    review_result["justification"] = notes or review_result["justification"]
    if override_decision:
        review_result["final_decision_type"] = override_decision
    enisa_result = engine.enisa_submit(review_result, pre["cve"], pre["product_name"])
    results = {**pre, "review_result": review_result, "enisa_result": enisa_result,
               "audit_trail": engine.get_audit_trail()}
    st.session_state.runs_log.append({
        "scenario": pre["scenario_name"].split(":")[0].split("：")[0],
        "decision": review_result["final_decision_type"],
        "product": pre["product_name"],
        "ts": datetime.now().strftime("%H:%M:%S")
    })
    return results


def run_pipeline(scenario_key, product_name):
    engine = st.session_state.engine
    engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]
    cve_id = scenario["cve_id"]

    with st.spinner(t("spin1")):
        cve = engine.ingest_cve(cve_id, scenario_key)
        st.success(t("spin1_ok", cve_id=cve_id))
    with st.spinner(t("spin2")):
        sbom_match = engine.match_sbom(cve, product_name)
        st.success(t("spin2_ok", reason=sbom_match["match_reason"]))
    with st.spinner(t("spin3")):
        conflict_info = engine.detect_conflicts(cve, sbom_match, scenario_key)
        if conflict_info["conflict_detected"]:
            st.warning(t("spin3_conflict", type=conflict_info["conflict_type"]))
        else:
            st.success(t("spin3_ok"))
    with st.spinner(t("spin4")):
        decision_proposal = engine.propose_decision(cve, sbom_match, conflict_info, scenario_key)
        st.success(t("spin4_ok", decision=decision_proposal["decision_type"],
                     conf=f"{decision_proposal['confidence_score']:.0%}"))
    with st.spinner(t("spin5")):
        review_result = engine.human_review(decision_proposal, "APPROVE")
        st.success(t("spin5_ok"))
    with st.spinner(t("spin6")):
        enisa_result = engine.enisa_submit(review_result, cve, product_name)
        st.success(t("spin6_ok", status=enisa_result["status"]))

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
        "scenario": scenario["name"].split(":")[0].split("：")[0],
        "decision": review_result["final_decision_type"],
        "product": product_name,
        "ts": datetime.now().strftime("%H:%M:%S")
    })
    return results


# ============= MAIN HEADER =============

st.title(f"🔐 {t('app_title')}")
st.markdown(f"**{t('app_subtitle')}**")
st.markdown("---")

# ============= SIDEBAR =============

with st.sidebar:

    # ---- Language toggle ----
    lang_col1, lang_col2 = st.columns(2)
    with lang_col1:
        if st.button("🇺🇸 English", use_container_width=True,
                     type="primary" if st.session_state.lang == "en" else "secondary"):
            st.session_state.lang = "en"
            st.rerun()
    with lang_col2:
        if st.button("🇯🇵 日本語", use_container_width=True,
                     type="primary" if st.session_state.lang == "ja" else "secondary"):
            st.session_state.lang = "ja"
            st.rerun()

    st.markdown("---")
    st.header(t("sidebar_scenarios"))

    scenario_keys = list(CVE_SCENARIOS.keys())
    selected_scenario = st.selectbox(
        t("sidebar_choose"),
        options=scenario_keys,
        format_func=lambda k: t(f"scenario_{k}_name"),
        key="scenario_selector"
    )

    s = CVE_SCENARIOS[selected_scenario]
    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
    human_flag = t("sidebar_human_flag") if s.get("human_review_required") else ""
    st.markdown(f"""
    > **CVE:** `{s['cve_id']}`
    > **{t('metric_severity')}:** {severity_icon} {s['severity']} (CVSS {s['cvss_score']})
    {human_flag}
    """)

    st.markdown("---")
    st.header(t("sidebar_product_header"))
    product_names = list(PRODUCTS.keys())
    default_idx = {"scenario_a": 1, "scenario_b": 0, "scenario_c": 2, "scenario_d": 2}.get(selected_scenario, 0)
    selected_product = st.selectbox(t("sidebar_product_label"), product_names, index=default_idx)

    prod = PRODUCTS[selected_product]
    n = len(prod["sbom"]["components"])
    with st.expander(t("sidebar_sbom_expander", n=n)):
        for c in prod["sbom"]["components"]:
            st.caption(f"• {c['name']} v{c['version']} ({c['vendor']})")

    st.markdown("---")

    run_btn = st.button(t("sidebar_run_btn"), use_container_width=True, type="primary")
    if run_btn:
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
        st.header(t("sidebar_stats_header"))
        log = st.session_state.runs_log
        decisions = [r["decision"] for r in log]
        st.metric(t("sidebar_stats_runs"), len(log))
        st.metric(t("sidebar_stats_report"), decisions.count("REPORT"))
        st.metric(t("sidebar_stats_not_report"), decisions.count("NOT_REPORT"))
        with st.expander(t("sidebar_run_history")):
            for r in reversed(log):
                st.caption(f"`{r['ts']}` {r['scenario']} → **{r['decision']}**")

# ============= HUMAN REVIEW PANEL (Scenario D) =============

if st.session_state.pipeline_phase == "awaiting_human" and st.session_state.pre_review:
    pre = st.session_state.pre_review
    proposal = pre["decision_proposal"]

    st.warning(t("hr_paused"))
    st.markdown(t("section_pipeline"))
    pipeline_stepper(completed=4)
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric(t("metric_cve"), pre["cve"]["cve_id"])
    col2.metric(t("metric_cvss"), pre["cve"]["cvss_score"])
    col3.metric(t("metric_severity"), pre["cve"]["severity"])
    col4.metric(t("metric_confidence"), f"{proposal['confidence_score']:.0%}", delta=t("hr_below_threshold"))

    st.markdown("---")
    st.subheader(t("hr_evidence"))
    ev_col, gauge_col = st.columns([2, 1])

    with ev_col:
        with st.container(border=True):
            st.markdown(t("hr_why"))
            for rule in proposal["rules_fired"]:
                if rule["triggered"]:
                    st.markdown(f"- **{rule['rule']}**")
                    st.caption(rule["reasoning"])
        st.markdown(t("hr_evidence_sources"))
        for ev in pre["conflict_info"]["evidence_summary"]:
            st.markdown(f"- {ev}")

    with gauge_col:
        st.plotly_chart(cvss_gauge(pre["cve"]["cvss_score"]), use_container_width=True)

    match = pre["sbom_match"]
    st.markdown(t("hr_sbom_analysis"))
    df = sbom_table(pre["product_name"], match.get("matching_component"), match["match_found"])
    st.dataframe(
        df.style.apply(
            lambda row: ["background-color:#fff5f5" if t("t2_vulnerable") in str(row.iloc[-1]) else "" for _ in row],
            axis=1
        ),
        use_container_width=True, hide_index=True
    )

    st.markdown("---")
    st.subheader(t("hr_stage5"))
    st.markdown(t("hr_intro"))

    with st.form("human_review_form"):
        reviewer_name = st.text_input(t("hr_reviewer_label"), placeholder=t("hr_reviewer_placeholder"))
        st.markdown(t("hr_assessment"))
        notes = st.text_area(t("hr_notes_label"), placeholder=t("hr_notes_placeholder"), height=110)
        st.markdown(t("hr_select_decision"))
        dc1, dc2, dc3 = st.columns(3)
        with dc1:
            approve_report = st.form_submit_button(t("hr_btn_report"), use_container_width=True, type="primary")
        with dc2:
            approve_not_report = st.form_submit_button(t("hr_btn_not_report"), use_container_width=True)
        with dc3:
            escalate = st.form_submit_button(t("hr_btn_escalate"), use_container_width=True)

    if approve_report or approve_not_report or escalate:
        if not reviewer_name.strip():
            st.error(t("hr_err_name"))
        elif not notes.strip():
            st.error(t("hr_err_notes"))
        else:
            if approve_report:
                action, override, label = "APPROVE", "REPORT", "REPORT"
            elif approve_not_report:
                action, override, label = "APPROVE", "NOT_REPORT", "NOT_REPORT"
            else:
                action, override, label = "APPROVE", "CONFLICT", "ESCALATED"

            with st.spinner(t("hr_completing")):
                results = complete_pipeline(pre, reviewer_name, action, override, notes)

            st.session_state.pipeline_results = results
            st.session_state.pipeline_phase = "complete"
            st.success(t("hr_done", label=label, name=reviewer_name))
            st.rerun()

# ============= MAIN RESULTS =============

if st.session_state.pipeline_results:
    results = st.session_state.pipeline_results

    final = results["review_result"]["final_decision_type"]
    st.markdown(f"{t('section_decision_banner')} {decision_badge(final)}", unsafe_allow_html=True)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric(t("metric_scenario"), results["scenario_name"].split(":")[0].split("：")[0])
    col2.metric(t("metric_product"), results["product_name"])
    col3.metric(t("metric_cve"), results["cve"]["cve_id"])
    col4.metric(t("metric_cvss"), results["cve"]["cvss_score"])
    col5.metric(t("metric_severity"), results["cve"]["severity"])

    st.markdown("---")
    st.markdown(t("section_pipeline"))
    pipeline_stepper(completed=6)
    st.markdown("---")

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        t("tab_ingest"), t("tab_sbom"), t("tab_conflict"), t("tab_rules"),
        t("tab_review"), t("tab_enisa"), t("tab_artifacts")
    ])

    # ---- Tab 1: CVE Ingestion ----
    with tab1:
        st.subheader(t("t1_header"))
        col1, col2 = st.columns([1, 2])
        with col1:
            st.plotly_chart(cvss_gauge(results["cve"]["cvss_score"]), use_container_width=True)
        with col2:
            st.markdown(t("t1_description"))
            desc = cve_description(results["scenario_key"])
            st.info(desc)
            c1, c2, c3 = st.columns(3)
            c1.metric(t("metric_cve"), results["cve"]["cve_id"])
            c2.metric(t("metric_severity"), results["cve"]["severity"])
            c3.metric(t("metric_exploit"),
                      ("YES ⚠️" if results["cve"]["exploit_available"] else "NO ✅")
                      if st.session_state.lang == "en" else
                      ("あり ⚠️" if results["cve"]["exploit_available"] else "なし ✅"))
            st.markdown(
                f"{t('t1_affected_range')} `{results['cve']['affected_versions']['range_start']}` "
                f"→ `{results['cve']['affected_versions']['range_end']}`"
            )

    # ---- Tab 2: SBOM ----
    with tab2:
        st.subheader(t("t2_header"))
        match = results["sbom_match"]
        col1, col2, col3 = st.columns(3)
        col1.metric(t("metric_product"), match["product_name"])
        col2.metric(t("metric_match_confidence"), f"{match['match_confidence']:.0%}")
        col3.metric(t("metric_component_found"),
                    ("YES 🔴" if match["matching_component"] else "NO 🟢")
                    if st.session_state.lang == "en" else
                    ("あり 🔴" if match["matching_component"] else "なし 🟢"))

        if match["match_found"]:
            st.error(t("t2_vuln", reason=match["match_reason"]))
        else:
            st.success(t("t2_safe", reason=match["match_reason"]))

        st.markdown(t("t2_sbom_table"))
        df = sbom_table(results["product_name"], match.get("matching_component"), match["match_found"])
        st.dataframe(
            df.style.apply(
                lambda row: ["background-color:#fff5f5" if t("t2_vulnerable") in str(row.iloc[-1]) else "" for _ in row],
                axis=1
            ),
            use_container_width=True, hide_index=True
        )

    # ---- Tab 3: Conflict ----
    with tab3:
        st.subheader(t("t3_header"))
        conflict = results["conflict_info"]
        if conflict["conflict_detected"]:
            st.warning(t("t3_conflict", type=conflict["conflict_type"]))
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(t("t3_evidence"))
                for ev in conflict["evidence_summary"]:
                    st.markdown(f"- {ev}")
            with c2:
                if conflict.get("vex_available"):
                    st.info(t("t3_vex"))
        else:
            st.success(t("t3_no_conflict"))
            for ev in conflict["evidence_summary"]:
                st.markdown(f"- {ev}")
        with st.expander(t("t3_raw")):
            st.json(conflict)

    # ---- Tab 4: Rules ----
    with tab4:
        st.subheader(t("t4_header"))
        decision = results["decision_proposal"]
        col1, col2, col3 = st.columns(3)
        col1.metric(t("metric_proposed"), decision["decision_type"])
        col2.metric(t("metric_match_confidence"), f"{decision['confidence_score']:.0%}")
        col3.metric(t("metric_auto_decidable"),
                    t("t4_yes_auto") if decision["auto_decidable"] else t("t4_no_auto"))

        col_chart, col_rules = st.columns([1, 1])
        with col_chart:
            st.plotly_chart(rule_confidence_chart(decision["rules_fired"]), use_container_width=True)
        with col_rules:
            st.markdown(t("t4_rules_eval"))
            for rule in decision["rules_fired"]:
                status = t("t4_triggered") if rule["triggered"] else t("t4_not_triggered")
                with st.container(border=True):
                    st.markdown(f"**{rule['rule']}** — {status}")
                    st.caption(rule["reasoning"])

        st.markdown(t("t4_evidence_weight"))
        weighting = decision["evidence_weighting"]
        ew_df = pd.DataFrame({
            t("t4_ev_sbom"): [weighting["sbom_confidence"]],
            t("t4_ev_nvd"):  [weighting["cve_data_confidence"]],
            t("t4_ev_vex"):  [weighting["vex_confidence"]],
        }).T.reset_index()
        ew_df.columns = ["Source", "Confidence"]
        fig_ew = px.bar(ew_df, x="Source", y="Confidence",
                        color="Confidence", color_continuous_scale=["#f8d7da", "#fff3cd", "#d4edda"],
                        range_y=[0, 1], text_auto=".0%", title=t("t4_evidence_weight"))
        fig_ew.update_layout(height=220, margin=dict(t=40, b=20, l=20, r=20), showlegend=False)
        fig_ew.update_yaxes(tickformat=".0%")
        st.plotly_chart(fig_ew, use_container_width=True)

    # ---- Tab 5: Human Review ----
    with tab5:
        st.subheader(t("t5_header"))
        review = results["review_result"]
        col1, col2, col3 = st.columns(3)
        col1.metric(t("metric_reviewer"), review["reviewer"])
        col2.metric(t("metric_action"), review["action"])
        col3.metric(t("metric_decision_id"), review["decision_id"][:12] + "…")
        st.markdown(t("t5_justification"))
        st.info(review["justification"])
        st.markdown(t("t5_final"))
        st.markdown(decision_badge(review["final_decision_type"]), unsafe_allow_html=True)

    # ---- Tab 6: ENISA ----
    with tab6:
        st.subheader(t("t6_header"))
        enisa = results["enisa_result"]
        col1, col2 = st.columns(2)
        with col1:
            st.metric(t("metric_status"), enisa["status"])
            submitted_label = ("YES ✅" if enisa["submitted"] else "NO — Not required") if st.session_state.lang == "en" else ("あり ✅" if enisa["submitted"] else "なし — 不要")
            st.metric(t("metric_submitted"), submitted_label)
        with col2:
            if enisa["submitted"]:
                st.success(t("t6_ref", ref=enisa["enisa_reference_id"]))
                st.caption(t("t6_submitted_at", ts=enisa["submission_timestamp"]))
                st.markdown(t("t6_sla"))
            else:
                st.info(t("t6_no_submit"))
        with st.expander(t("t6_payload_preview")):
            enisa_json = generate_enisa_submission_json(
                decision=results["review_result"], cve=results["cve"],
                product_name=results["product_name"], sbom_match=results["sbom_match"],
                submission_id=results["enisa_result"]["submission_id"]
            )
            st.json(enisa_json)

    # ---- Tab 7: Artifacts ----
    with tab7:
        st.subheader(t("t7_header"))
        html_report = generate_compliance_artifact_html(
            decision_id=results["review_result"]["decision_id"],
            cve=results["cve"], product_name=results["product_name"],
            sbom_match=results["sbom_match"], decision=results["review_result"],
            audit_trail=results["audit_trail"]
        )
        enisa_json = generate_enisa_submission_json(
            decision=results["review_result"], cve=results["cve"],
            product_name=results["product_name"], sbom_match=results["sbom_match"],
            submission_id=results["enisa_result"]["submission_id"]
        )
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(t("t7_html_title"))
            st.caption(t("t7_html_caption"))
            st.download_button(label=t("t7_html_btn"), data=html_report,
                               file_name=f"CRA-Compliance-{results['cve']['cve_id']}.html",
                               mime="text/html", use_container_width=True)
        with col2:
            st.markdown(t("t7_json_title"))
            st.caption(t("t7_json_caption"))
            st.download_button(label=t("t7_json_btn"), data=json.dumps(enisa_json, indent=2),
                               file_name=f"ENISA-{results['cve']['cve_id']}.json",
                               mime="application/json", use_container_width=True)

    # ---- Audit Trail ----
    st.markdown("---")
    st.header(t("section_audit"))
    st.caption(t("section_audit_caption"))

    audit_df = pd.DataFrame(results["audit_trail"])
    if not audit_df.empty:
        audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"])
        for _, row in audit_df.iterrows():
            action = str(row.get("action", ""))
            badge_cls = "audit-stage" if "Stage" in action or "CVE" in action or "SBOM" in action else \
                        "audit-decision" if "DECISION" in action else "audit-conflict"
            ts = row["timestamp"].strftime("%H:%M:%S")
            st.markdown(
                f'`{ts}` &nbsp; <span class="audit-badge {badge_cls}">{action}</span> &nbsp; {row.get("details","")}',
                unsafe_allow_html=True
            )

else:
    if st.session_state.pipeline_phase != "awaiting_human":
        st.info(t("landing_prompt"))
        st.markdown(t("landing_hint"))

# ============= FOOTER =============

st.markdown("---")
st.markdown(f"<div style='text-align:center;font-size:12px;color:gray;'>🔐 {t('footer')}</div>",
            unsafe_allow_html=True)
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    f"{t('legal_declaration')}</div>",
    unsafe_allow_html=True
)
