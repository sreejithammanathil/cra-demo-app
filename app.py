"""
CRA Decision Traceability System — Executive Dashboard + Pipeline Runner
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
from collections import Counter

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from decision_engine import DecisionEngine
from enisa_reporter import generate_enisa_submission_json, generate_compliance_artifact_html
from translations import t, SCENARIO_JA

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---- shared session state ----
if "lang"             not in st.session_state: st.session_state.lang             = "en"
if "runs_log"         not in st.session_state: st.session_state.runs_log         = []
if "pipeline_results" not in st.session_state: st.session_state.pipeline_results = None
if "pipeline_phase"   not in st.session_state: st.session_state.pipeline_phase   = "idle"
if "pre_review"       not in st.session_state: st.session_state.pre_review       = None
if "engine" not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS, cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES, thresholds=THRESHOLDS
    )

ja = st.session_state.lang == "ja"

# ============= CSS =============
st.markdown("""
<style>
.ready-pill{display:inline-flex;align-items:center;gap:6px;background:#dcfce7;color:#166534;border:1px solid #bbf7d0;border-radius:20px;padding:5px 14px;font-size:0.82rem;font-weight:600}
.ready-dot{width:8px;height:8px;border-radius:50%;background:#21c354}
.badge-report    {background:#ff4b4b;color:white;padding:6px 18px;border-radius:20px;font-weight:bold;font-size:1.1rem;display:inline-block}
.badge-not-report{background:#21c354;color:white;padding:6px 18px;border-radius:20px;font-weight:bold;font-size:1.1rem;display:inline-block}
.badge-conflict  {background:#ffa500;color:white;padding:6px 18px;border-radius:20px;font-weight:bold;font-size:1.1rem;display:inline-block}
.stepper-wrap{display:flex;justify-content:space-between;align-items:center;margin:1rem 0 1.5rem 0}
.step-item{display:flex;flex-direction:column;align-items:center;flex:1;position:relative}
.step-item:not(:last-child)::after{content:"";position:absolute;top:18px;left:60%;width:80%;height:3px;background:#e0e0e0;z-index:0}
.step-item.done:not(:last-child)::after{background:#21c354}
.step-circle{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:1rem;z-index:1;background:#e0e0e0;color:#888}
.step-circle.done{background:#21c354;color:white}
.step-label{font-size:0.72rem;margin-top:4px;text-align:center;color:#555;max-width:80px}
.step-label.done{color:#21c354;font-weight:600}
.audit-badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.75rem;font-weight:600}
.audit-stage{background:#dbeafe;color:#1d4ed8}
.audit-decision{background:#dcfce7;color:#166534}
.audit-conflict{background:#fef9c3;color:#854d0e}
</style>
""", unsafe_allow_html=True)

# ============= HELPERS =============

def decision_badge(d):
    cls = {"REPORT":"badge-report","NOT_REPORT":"badge-not-report"}.get(d,"badge-conflict")
    return f'<span class="{cls}">{d}</span>'

def pipeline_stepper(completed=6):
    labels=[t("step_ingest"),t("step_sbom"),t("step_conflict"),t("step_rules"),t("step_review"),t("step_enisa")]
    items=""
    for i,lbl in enumerate(labels,1):
        done="done" if i<=completed else ""
        icon="✓" if i<=completed else str(i)
        items+=f'<div class="step-item {done}"><div class="step-circle {done}">{icon}</div><div class="step-label {done}">{lbl.replace(chr(10),"<br>")}</div></div>'
    st.markdown(f'<div class="stepper-wrap">{items}</div>',unsafe_allow_html=True)

def cvss_gauge(score):
    color="#ff4b4b" if score>=8.5 else "#ffa500" if score>=7.0 else "#ffd700" if score>=5.0 else "#21c354"
    fig=go.Figure(go.Indicator(
        mode="gauge+number",value=score,domain={"x":[0,1],"y":[0,1]},
        title={"text":"CVSS Score","font":{"size":16}},
        gauge={"axis":{"range":[0,10]},"bar":{"color":color},
               "steps":[{"range":[0,4],"color":"#d4edda"},{"range":[4,7],"color":"#fff3cd"},
                        {"range":[7,8.5],"color":"#ffe0b2"},{"range":[8.5,10],"color":"#f8d7da"}],
               "threshold":{"line":{"color":"black","width":3},"thickness":0.75,"value":score}}
    ))
    fig.update_layout(height=220,margin=dict(t=40,b=10,l=20,r=20))
    return fig

def sbom_table(product_name, matching_component, match_found):
    rows=[]
    for c in PRODUCTS.get(product_name,{}).get("sbom",{}).get("components",[]):
        is_vuln=match_found and c["name"].lower() in (matching_component or "").lower()
        rows.append({t("t2_col_component"):c["name"],t("t2_col_version"):c["version"],
                     t("t2_col_vendor"):c["vendor"],t("t2_col_type"):c["type"].capitalize(),
                     t("t2_col_status"):t("t2_vulnerable") if is_vuln else t("t2_safe_status")})
    return pd.DataFrame(rows)

def rule_confidence_chart(rules_fired):
    names=[r["rule"] for r in rules_fired]; triggered=[r["triggered"] for r in rules_fired]
    fig=px.bar(x=names,y=[1]*len(names),color=triggered,
               color_discrete_map={True:"#21c354",False:"#e0e0e0"},
               title="Decision Rules — Triggered / Not Triggered")
    fig.update_layout(height=220,showlegend=False,margin=dict(t=40,b=60,l=20,r=20),yaxis_visible=False)
    fig.update_xaxes(tickangle=-20)
    return fig

def cve_desc(scenario_key):
    if st.session_state.lang=="ja":
        return SCENARIO_JA.get(scenario_key,{}).get("cve_description",CVE_SCENARIOS[scenario_key]["cve_description"])
    return CVE_SCENARIOS[scenario_key]["cve_description"]

# ============= PIPELINE FUNCTIONS =============

def run_stages_1_to_4(scenario_key, product_name):
    engine=st.session_state.engine; engine.reset_audit_trail()
    scenario=CVE_SCENARIOS[scenario_key]; cve_id=scenario["cve_id"]
    with st.spinner(t("spin1")):
        cve=engine.ingest_cve(cve_id,scenario_key); st.success(t("spin1_ok",cve_id=cve_id))
    with st.spinner(t("spin2")):
        sbom_match=engine.match_sbom(cve,product_name); st.success(t("spin2_ok",reason=sbom_match["match_reason"]))
    with st.spinner(t("spin3")):
        conflict_info=engine.detect_conflicts(cve,sbom_match,scenario_key)
        st.warning(t("spin3_conflict",type=conflict_info["conflict_type"])) if conflict_info["conflict_detected"] else st.success(t("spin3_ok"))
    with st.spinner(t("spin4")):
        decision_proposal=engine.propose_decision(cve,sbom_match,conflict_info,scenario_key)
        st.success(t("spin4_ok",decision=decision_proposal["decision_type"],conf=f"{decision_proposal['confidence_score']:.0%}"))
    return {"scenario_key":scenario_key,"scenario_name":scenario["name"],"product_name":product_name,
            "cve":cve,"sbom_match":sbom_match,"conflict_info":conflict_info,
            "decision_proposal":decision_proposal,"partial_audit_trail":engine.get_audit_trail()}

def complete_pipeline(pre, reviewer_name, reviewer_action, override_decision, notes):
    engine=st.session_state.engine
    review_result=engine.human_review(pre["decision_proposal"],reviewer_action)
    review_result["reviewer"]=reviewer_name or "Compliance Officer"
    review_result["justification"]=notes or review_result["justification"]
    if override_decision: review_result["final_decision_type"]=override_decision
    enisa_result=engine.enisa_submit(review_result,pre["cve"],pre["product_name"])
    results={**pre,"review_result":review_result,"enisa_result":enisa_result,"audit_trail":engine.get_audit_trail()}
    st.session_state.runs_log.append({"scenario":pre["scenario_name"].split(":")[0].split("：")[0],
        "decision":review_result["final_decision_type"],"product":pre["product_name"],
        "ts":datetime.now().strftime("%H:%M:%S")})
    return results

def run_pipeline(scenario_key, product_name):
    engine=st.session_state.engine; engine.reset_audit_trail()
    scenario=CVE_SCENARIOS[scenario_key]; cve_id=scenario["cve_id"]
    with st.spinner(t("spin1")):
        cve=engine.ingest_cve(cve_id,scenario_key); st.success(t("spin1_ok",cve_id=cve_id))
    with st.spinner(t("spin2")):
        sbom_match=engine.match_sbom(cve,product_name); st.success(t("spin2_ok",reason=sbom_match["match_reason"]))
    with st.spinner(t("spin3")):
        conflict_info=engine.detect_conflicts(cve,sbom_match,scenario_key)
        st.warning(t("spin3_conflict",type=conflict_info["conflict_type"])) if conflict_info["conflict_detected"] else st.success(t("spin3_ok"))
    with st.spinner(t("spin4")):
        decision_proposal=engine.propose_decision(cve,sbom_match,conflict_info,scenario_key)
        st.success(t("spin4_ok",decision=decision_proposal["decision_type"],conf=f"{decision_proposal['confidence_score']:.0%}"))
    with st.spinner(t("spin5")):
        review_result=engine.human_review(decision_proposal,"APPROVE"); st.success(t("spin5_ok"))
    with st.spinner(t("spin6")):
        enisa_result=engine.enisa_submit(review_result,cve,product_name); st.success(t("spin6_ok",status=enisa_result["status"]))
    results={"scenario_key":scenario_key,"scenario_name":scenario["name"],"product_name":product_name,
             "cve":cve,"sbom_match":sbom_match,"conflict_info":conflict_info,"decision_proposal":decision_proposal,
             "review_result":review_result,"enisa_result":enisa_result,"audit_trail":engine.get_audit_trail()}
    st.session_state.runs_log.append({"scenario":scenario["name"].split(":")[0].split("：")[0],
        "decision":review_result["final_decision_type"],"product":product_name,"ts":datetime.now().strftime("%H:%M:%S")})
    return results

# ============= SIDEBAR =============

with st.sidebar:
    # Language toggle
    lc1, lc2 = st.columns(2)
    with lc1:
        if st.button("🇺🇸 EN", use_container_width=True,
                     type="primary" if not ja else "secondary"):
            st.session_state.lang = "en"; st.rerun()
    with lc2:
        if st.button("🇯🇵 JP", use_container_width=True,
                     type="primary" if ja else "secondary"):
            st.session_state.lang = "ja"; st.rerun()

    st.markdown("---")
    st.header(t("sidebar_scenarios"))

    selected_scenario = st.selectbox(
        t("sidebar_choose"),
        options=list(CVE_SCENARIOS.keys()),
        format_func=lambda k: t(f"scenario_{k}_name"),
        key="scenario_selector"
    )

    s = CVE_SCENARIOS[selected_scenario]
    sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(s["severity"],"⚪")
    human_flag = t("sidebar_human_flag") if s.get("human_review_required") else ""
    st.markdown(f"> **CVE:** `{s['cve_id']}`\n> **{t('metric_severity')}:** {sev_icon} {s['severity']} (CVSS {s['cvss_score']})\n{human_flag}")

    _sideinfo = {
        "scenario_a": ("Tests: critical exploit present → auto REPORT", "テスト: 重大エクスプロイト → 自動報告"),
        "scenario_b": ("Tests: component absent in SBOM → NOT REPORT", "テスト: SBOMに未存在 → 報告不要"),
        "scenario_c": ("Tests: VEX conflict → human escalation", "テスト: VEX矛盾 → 人的エスカレーション"),
        "scenario_d": ("Tests: ambiguous medium CVE → you decide", "テスト: 曖昧な中程度CVE → あなたが判断"),
    }
    en_note, ja_note = _sideinfo.get(selected_scenario, ("", ""))
    st.caption("ℹ️ " + (ja_note if ja else en_note))

    st.markdown("---")
    st.header(t("sidebar_product_header"))
    product_names = list(PRODUCTS.keys())
    default_idx = {"scenario_a":1,"scenario_b":0,"scenario_c":2,"scenario_d":2}.get(selected_scenario,0)
    selected_product = st.selectbox(t("sidebar_product_label"), product_names, index=default_idx)

    prod = PRODUCTS[selected_product]
    with st.expander(t("sidebar_sbom_expander", n=len(prod["sbom"]["components"]))):
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
        else:
            st.session_state.pipeline_results = run_pipeline(selected_scenario, selected_product)
            st.session_state.pipeline_phase = "complete"

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

    st.markdown("---")

    # Home button — visible only when a pipeline is active
    if st.session_state.pipeline_phase != "idle":
        if st.button("🏠 " + ("ダッシュボードへ戻る" if ja else "Back to Dashboard"),
                     use_container_width=True, type="secondary"):
            st.session_state.pipeline_phase = "idle"
            st.session_state.pipeline_results = None
            st.session_state.pre_review = None
            st.rerun()
        st.markdown("---")

    # Page navigation links
    st.page_link("pages/1_History.py", label="📚 " + ("履歴" if ja else "History"), use_container_width=True)
    st.page_link("pages/2_Scenarios.py", label="📖 " + ("解説" if ja else "Scenarios"), use_container_width=True)

# ============= MAIN AREA =============

# ---- Header ----
st.title(f"🔐 {t('app_title')}")
st.markdown(f"**{t('app_subtitle')}**")
st.markdown("---")

# If pipeline results or human review are active, show those FIRST
if st.session_state.pipeline_phase == "awaiting_human" and st.session_state.pre_review:
    pre = st.session_state.pre_review
    proposal = pre["decision_proposal"]

    st.warning(t("hr_paused"))
    st.markdown(t("section_pipeline")); pipeline_stepper(completed=4); st.markdown("---")

    col1,col2,col3,col4=st.columns(4)
    col1.metric(t("metric_cve"),pre["cve"]["cve_id"]); col2.metric(t("metric_cvss"),pre["cve"]["cvss_score"])
    col3.metric(t("metric_severity"),pre["cve"]["severity"])
    col4.metric(t("metric_confidence"),f"{proposal['confidence_score']:.0%}",delta=t("hr_below_threshold"))

    st.markdown("---"); st.subheader(t("hr_evidence"))
    ev_col,gauge_col=st.columns([2,1])
    with ev_col:
        with st.container(border=True):
            st.markdown(t("hr_why"))
            for rule in proposal["rules_fired"]:
                if rule["triggered"]: st.markdown(f"- **{rule['rule']}**"); st.caption(rule["reasoning"])
        st.markdown(t("hr_evidence_sources"))
        for ev in pre["conflict_info"]["evidence_summary"]: st.markdown(f"- {ev}")
    with gauge_col:
        st.plotly_chart(cvss_gauge(pre["cve"]["cvss_score"]),use_container_width=True)

    match=pre["sbom_match"]; st.markdown(t("hr_sbom_analysis"))
    df=sbom_table(pre["product_name"],match.get("matching_component"),match["match_found"])
    st.dataframe(df.style.map(lambda v:"background-color:#fff5f5" if t("t2_vulnerable") in str(v) else "",subset=[t("t2_col_status")]),use_container_width=True,hide_index=True)

    st.markdown("---"); st.subheader(t("hr_stage5")); st.markdown(t("hr_intro"))
    with st.form("human_review_form"):
        reviewer_name=st.text_input(t("hr_reviewer_label"),placeholder=t("hr_reviewer_placeholder"))
        st.markdown(t("hr_assessment"))
        notes=st.text_area(t("hr_notes_label"),placeholder=t("hr_notes_placeholder"),height=110)
        st.markdown(t("hr_select_decision"))
        dc1,dc2,dc3=st.columns(3)
        with dc1: approve_report=st.form_submit_button(t("hr_btn_report"),use_container_width=True,type="primary")
        with dc2: approve_not_report=st.form_submit_button(t("hr_btn_not_report"),use_container_width=True)
        with dc3: escalate=st.form_submit_button(t("hr_btn_escalate"),use_container_width=True)
    if approve_report or approve_not_report or escalate:
        if not reviewer_name.strip(): st.error(t("hr_err_name"))
        elif not notes.strip(): st.error(t("hr_err_notes"))
        else:
            if approve_report: action,override,label="APPROVE","REPORT","REPORT"
            elif approve_not_report: action,override,label="APPROVE","NOT_REPORT","NOT_REPORT"
            else: action,override,label="APPROVE","CONFLICT","ESCALATED"
            with st.spinner(t("hr_completing")):
                results=complete_pipeline(pre,reviewer_name,action,override,notes)
            st.session_state.pipeline_results=results; st.session_state.pipeline_phase="complete"
            st.success(t("hr_done",label=label,name=reviewer_name)); st.rerun()

elif st.session_state.pipeline_results:
    results = st.session_state.pipeline_results
    final = results["review_result"]["final_decision_type"]
    st.markdown(f"{t('section_decision_banner')} {decision_badge(final)}", unsafe_allow_html=True)

    col1,col2,col3,col4,col5=st.columns(5)
    col1.metric(t("metric_scenario"),results["scenario_name"].split(":")[0].split("：")[0])
    col2.metric(t("metric_product"),results["product_name"])
    col3.metric(t("metric_cve"),results["cve"]["cve_id"])
    col4.metric(t("metric_cvss"),results["cve"]["cvss_score"])
    col5.metric(t("metric_severity"),results["cve"]["severity"])

    st.markdown("---"); st.markdown(t("section_pipeline")); pipeline_stepper(completed=6); st.markdown("---")

    tab1,tab2,tab3,tab4,tab5,tab6,tab7=st.tabs([t("tab_ingest"),t("tab_sbom"),t("tab_conflict"),t("tab_rules"),t("tab_review"),t("tab_enisa"),t("tab_artifacts")])

    with tab1:
        st.subheader(t("t1_header"))
        c1,c2=st.columns([1,2])
        with c1: st.plotly_chart(cvss_gauge(results["cve"]["cvss_score"]),use_container_width=True)
        with c2:
            st.markdown(t("t1_description")); st.info(cve_desc(results["scenario_key"]))
            a,b,c=st.columns(3)
            a.metric(t("metric_cve"),results["cve"]["cve_id"]); b.metric(t("metric_severity"),results["cve"]["severity"])
            c.metric(t("metric_exploit"),("YES ⚠️" if results["cve"]["exploit_available"] else "NO ✅") if not ja else ("あり ⚠️" if results["cve"]["exploit_available"] else "なし ✅"))
            st.markdown(f"{t('t1_affected_range')} `{results['cve']['affected_versions']['range_start']}` → `{results['cve']['affected_versions']['range_end']}`")

    with tab2:
        st.subheader(t("t2_header")); match=results["sbom_match"]
        a,b,c=st.columns(3)
        a.metric(t("metric_product"),match["product_name"]); b.metric(t("metric_match_confidence"),f"{match['match_confidence']:.0%}")
        c.metric(t("metric_component_found"),("YES 🔴" if match["matching_component"] else "NO 🟢") if not ja else ("あり 🔴" if match["matching_component"] else "なし 🟢"))
        st.error(t("t2_vuln",reason=match["match_reason"])) if match["match_found"] else st.success(t("t2_safe",reason=match["match_reason"]))
        st.markdown(t("t2_sbom_table"))
        df=sbom_table(results["product_name"],match.get("matching_component"),match["match_found"])
        st.dataframe(df.style.map(lambda v:"background-color:#fff5f5" if t("t2_vulnerable") in str(v) else "",subset=[t("t2_col_status")]),use_container_width=True,hide_index=True)

    with tab3:
        st.subheader(t("t3_header")); conflict=results["conflict_info"]
        if conflict["conflict_detected"]:
            st.warning(t("t3_conflict",type=conflict["conflict_type"]))
            c1,c2=st.columns(2)
            with c1: st.markdown(t("t3_evidence")); [st.markdown(f"- {ev}") for ev in conflict["evidence_summary"]]
            with c2:
                if conflict.get("vex_available"): st.info(t("t3_vex"))
        else:
            st.success(t("t3_no_conflict")); [st.markdown(f"- {ev}") for ev in conflict["evidence_summary"]]
        with st.expander(t("t3_raw")): st.json(conflict)

    with tab4:
        st.subheader(t("t4_header")); decision=results["decision_proposal"]
        a,b,c=st.columns(3)
        a.metric(t("metric_proposed"),decision["decision_type"]); b.metric(t("metric_match_confidence"),f"{decision['confidence_score']:.0%}")
        c.metric(t("metric_auto_decidable"),t("t4_yes_auto") if decision["auto_decidable"] else t("t4_no_auto"))
        cc,cr=st.columns([1,1])
        with cc: st.plotly_chart(rule_confidence_chart(decision["rules_fired"]),use_container_width=True)
        with cr:
            st.markdown(t("t4_rules_eval"))
            for rule in decision["rules_fired"]:
                with st.container(border=True):
                    st.markdown(f"**{rule['rule']}** — {t('t4_triggered') if rule['triggered'] else t('t4_not_triggered')}")
                    st.caption(rule["reasoning"])
        weighting=decision["evidence_weighting"]
        ew_df=pd.DataFrame({t("t4_ev_sbom"):[weighting["sbom_confidence"]],t("t4_ev_nvd"):[weighting["cve_data_confidence"]],t("t4_ev_vex"):[weighting["vex_confidence"]]}).T.reset_index()
        ew_df.columns=["Source","Confidence"]
        fig_ew=px.bar(ew_df,x="Source",y="Confidence",color="Confidence",color_continuous_scale=["#f8d7da","#fff3cd","#d4edda"],range_y=[0,1],text_auto=".0%")
        fig_ew.update_layout(height=220,margin=dict(t=40,b=20,l=20,r=20),showlegend=False); fig_ew.update_yaxes(tickformat=".0%")
        st.plotly_chart(fig_ew,use_container_width=True)

    with tab5:
        st.subheader(t("t5_header")); review=results["review_result"]
        a,b,c=st.columns(3)
        a.metric(t("metric_reviewer"),review["reviewer"]); b.metric(t("metric_action"),review["action"]); c.metric(t("metric_decision_id"),review["decision_id"][:12]+"…")
        st.markdown(t("t5_justification")); st.info(review["justification"])
        st.markdown(t("t5_final")); st.markdown(decision_badge(review["final_decision_type"]),unsafe_allow_html=True)

    with tab6:
        st.subheader(t("t6_header")); enisa=results["enisa_result"]
        c1,c2=st.columns(2)
        with c1:
            st.metric(t("metric_status"),enisa["status"])
            st.metric(t("metric_submitted"),("YES ✅" if enisa["submitted"] else "NO") if not ja else ("あり ✅" if enisa["submitted"] else "なし"))
        with c2:
            if enisa["submitted"]:
                st.success(t("t6_ref",ref=enisa["enisa_reference_id"])); st.caption(t("t6_submitted_at",ts=enisa["submission_timestamp"])); st.markdown(t("t6_sla"))
            else: st.info(t("t6_no_submit"))
        with st.expander(t("t6_payload_preview")):
            st.json(generate_enisa_submission_json(decision=results["review_result"],cve=results["cve"],product_name=results["product_name"],sbom_match=results["sbom_match"],submission_id=results["enisa_result"]["submission_id"]))

    with tab7:
        st.subheader(t("t7_header"))
        html_report=generate_compliance_artifact_html(decision_id=results["review_result"]["decision_id"],cve=results["cve"],product_name=results["product_name"],sbom_match=results["sbom_match"],decision=results["review_result"],audit_trail=results["audit_trail"])
        enisa_json=generate_enisa_submission_json(decision=results["review_result"],cve=results["cve"],product_name=results["product_name"],sbom_match=results["sbom_match"],submission_id=results["enisa_result"]["submission_id"])
        c1,c2=st.columns(2)
        with c1:
            st.markdown(t("t7_html_title")); st.caption(t("t7_html_caption"))
            st.download_button(t("t7_html_btn"),html_report,f"CRA-{results['cve']['cve_id']}.html","text/html",use_container_width=True)
        with c2:
            st.markdown(t("t7_json_title")); st.caption(t("t7_json_caption"))
            st.download_button(t("t7_json_btn"),json.dumps(enisa_json,indent=2),f"ENISA-{results['cve']['cve_id']}.json","application/json",use_container_width=True)

    st.markdown("---"); st.header(t("section_audit")); st.caption(t("section_audit_caption"))
    audit_df=pd.DataFrame(results["audit_trail"])
    if not audit_df.empty:
        audit_df["timestamp"]=pd.to_datetime(audit_df["timestamp"])
        for _,row in audit_df.iterrows():
            action=str(row.get("action",""))
            badge_cls="audit-stage" if any(k in action for k in ["CVE","SBOM","Stage"]) else "audit-decision" if "DECISION" in action else "audit-conflict"
            st.markdown(f'`{row["timestamp"].strftime("%H:%M:%S")}` &nbsp; <span class="audit-badge {badge_cls}">{action}</span> &nbsp; {row.get("details","")}',unsafe_allow_html=True)

    st.markdown("---")

# ---- Scenario Quick Reference (shown when no pipeline active) ----
if st.session_state.pipeline_phase == "idle":
    _SCEN_INFO = {
        "scenario_a": {
            "color": "#ff4b4b", "bg": "#fff5f5", "icon": "🔴",
            "en": {
                "title": "Scenario A — REPORT Required",
                "condition": "CVSS 9.8 CRITICAL · Exploit available · Component matched in SBOM",
                "what": "A critical known-exploited vulnerability is found in an active product component. All reporting thresholds are exceeded.",
                "outcome": "Automatic REPORT to ENISA within 24h (Article 14 obligation triggered)",
            },
            "ja": {
                "title": "シナリオ A — 報告義務あり",
                "condition": "CVSS 9.8 クリティカル · エクスプロイトあり · SBOMコンポーネント一致",
                "what": "既知の悪用済み重大脆弱性が製品コンポーネントで検出。報告閾値をすべて超過。",
                "outcome": "24時間以内にENISAへ自動報告（第14条義務発動）",
            },
        },
        "scenario_b": {
            "color": "#21c354", "bg": "#f0fff4", "icon": "🟢",
            "en": {
                "title": "Scenario B — NOT REPORT",
                "condition": "CVSS 7.5 HIGH · No exploit · Component NOT in SBOM",
                "what": "A high-severity CVE is found but the affected component is not present in this product's SBOM. No actual exposure.",
                "outcome": "No reporting required — vulnerability does not affect this product",
            },
            "ja": {
                "title": "シナリオ B — 報告不要",
                "condition": "CVSS 7.5 HIGH · エクスプロイトなし · SBOMに該当コンポーネントなし",
                "what": "高深刻度CVEが存在するが、対象コンポーネントはこの製品のSBOMに含まれない。実際の影響なし。",
                "outcome": "報告不要 — この製品に対して脆弱性の影響なし",
            },
        },
        "scenario_c": {
            "color": "#ffa500", "bg": "#fff8ec", "icon": "🟠",
            "en": {
                "title": "Scenario C — Conflicting Evidence",
                "condition": "CVSS 8.1 HIGH · VEX 'not_affected' claim · But component matched",
                "what": "A VEX statement claims the product is not affected, but SBOM matching shows the component is present. Conflicting signals.",
                "outcome": "Conflict flagged → Human review escalation (confidence too low for auto-decision)",
            },
            "ja": {
                "title": "シナリオ C — 証拠の矛盾",
                "condition": "CVSS 8.1 HIGH · VEX「影響なし」 · SBOMコンポーネント一致",
                "what": "VEXは影響なしと主張するが、SBOMマッチングでコンポーネントが存在することが判明。シグナルが矛盾。",
                "outcome": "矛盾検出 → 人的レビューへエスカレーション",
            },
        },
        "scenario_d": {
            "color": "#7c3aed", "bg": "#f5f3ff", "icon": "👤",
            "en": {
                "title": "Scenario D — Human Decision Required",
                "condition": "CVSS 6.8 MEDIUM · No exploit · Partial VEX mitigation only",
                "what": "Ambiguous case: moderate CVSS, no active exploit, VEX shows partial firewall mitigation but component is present. Rule R6 fires.",
                "outcome": "Human review panel activates — you make the compliance decision",
            },
            "ja": {
                "title": "シナリオ D — 人的判断が必要",
                "condition": "CVSS 6.8 MEDIUM · エクスプロイトなし · VEX部分的緩和のみ",
                "what": "曖昧なケース：中程度のCVSS、悪用なし、VEXはFW緩和を示すがコンポーネントは存在。ルールR6が発動。",
                "outcome": "人的レビューパネルが起動 — あなたがコンプライアンス判断を行う",
            },
        },
    }

    with st.expander("📖 " + ("シナリオ早見表 — 実行前にご確認ください" if ja else "Scenario Quick Reference — What each scenario tests"), expanded=False):
        sc1, sc2, sc3, sc4 = st.columns(4)
        for col, (sk, info) in zip([sc1, sc2, sc3, sc4], _SCEN_INFO.items()):
            lang_key = "ja" if ja else "en"
            d = info[lang_key]
            with col:
                st.markdown(f"""<div style="border-radius:10px;padding:14px;border-left:5px solid {info['color']};background:{info['bg']};height:100%">
                    <div style="font-weight:800;font-size:0.88rem;margin-bottom:6px">{info['icon']} {d['title']}</div>
                    <div style="font-size:0.74rem;color:#374151;margin-bottom:6px"><b>{"条件" if ja else "Condition"}:</b> {d['condition']}</div>
                    <div style="font-size:0.73rem;color:#555;margin-bottom:6px">{d['what']}</div>
                    <div style="font-size:0.72rem;font-weight:600;color:{info['color']}">{d['outcome']}</div>
                </div>""", unsafe_allow_html=True)
    st.markdown("")

# ---- Dashboard overview (always shown below results) ----

runs = st.session_state.runs_log

st.markdown("### " + ("📊 システム概要" if ja else "📊 System Overview"))

# CRA Readiness
stage_labels = ["CVE取込","SBOM照合","矛盾検出","決定ルール","人的レビュー","ENISA報告"] if ja else ["CVE Ingestion","SBOM Matching","Conflict Detection","Decision Rules","Human Review","ENISA Reporting"]
cols = st.columns(6)
for col, label in zip(cols, stage_labels):
    with col:
        st.markdown(f'<div class="ready-pill"><div class="ready-dot"></div>{label}</div>', unsafe_allow_html=True)
st.caption("✅ " + ("全6ステージ稼働中" if ja else "All 6 stages operational"))
st.markdown("---")

# KPIs
k1,k2,k3,k4,k5=st.columns(5)
k1.metric("🏭 "+("対象製品" if ja else "Products"),len(PRODUCTS))
k2.metric("📏 "+("決定ルール" if ja else "Rules"),len(DECISION_RULES))
k3.metric("🗂️ "+("シナリオ" if ja else "Scenarios"),len(CVE_SCENARIOS))
k4.metric("▶️ "+("実行済み" if ja else "Runs"),len(runs))
report_count=sum(1 for r in runs if r["decision"]=="REPORT")
k5.metric("🔴 REPORT",report_count,delta=f"+{report_count}" if report_count else None,delta_color="inverse" if report_count else "off")

st.markdown("---")

# Session stats + products
if runs:
    stat_col, prod_col = st.columns([2, 3], gap="large")
    with stat_col:
        st.markdown("#### " + ("セッション決定内訳" if ja else "Session Decision Breakdown"))
        counts = Counter(r["decision"] for r in runs)
        fig = go.Figure(go.Pie(
            labels=list(counts.keys()), values=list(counts.values()), hole=0.55,
            marker=dict(colors=[{"REPORT":"#ff4b4b","NOT_REPORT":"#21c354","CONFLICT":"#ffa500","ESCALATED":"#7c3aed"}.get(l,"#aaa") for l in counts]),
            textinfo="label+percent"
        ))
        fig.update_layout(title=("決定内訳" if ja else "Decisions"),height=260,margin=dict(t=40,b=10,l=10,r=10),showlegend=False)
        st.plotly_chart(fig,use_container_width=True)
    with prod_col:
        st.markdown("#### " + ("🏭 J-TEC 製品" if ja else "🏭 J-TEC Products"))
        pc = st.columns(3)
        colors=[("#6366f1","#f5f3ff"),("#0ea5e9","#f0f9ff"),("#10b981","#f0fdf4")]
        for col,(pname,p),(clr,bg) in zip(pc,PRODUCTS.items(),colors):
            with col:
                comps=p["sbom"]["components"]
                st.markdown(f"""<div style="border-radius:10px;padding:14px;border-left:5px solid {clr};background:{bg}">
                    <div style="font-weight:800;font-size:0.95rem">{pname}</div>
                    <div style="font-size:0.78rem;color:#555;margin-top:2px">{p['type']}</div>
                    <div style="font-size:0.76rem;color:#888;margin-top:4px">v{p['version']} · {len(comps)} {"コンポーネント" if ja else "components"}</div>
                </div>""",unsafe_allow_html=True)
                with st.expander("SBOM"):
                    for c in comps:
                        st.caption(f"• **{c['name']}** v{c['version']}")
else:
    st.markdown("#### " + ("🏭 J-TEC 製品" if ja else "🏭 J-TEC Products"))
    pc = st.columns(3)
    colors=[("#6366f1","#f5f3ff"),("#0ea5e9","#f0f9ff"),("#10b981","#f0fdf4")]
    for col,(pname,p),(clr,bg) in zip(pc,PRODUCTS.items(),colors):
        with col:
            comps=p["sbom"]["components"]
            st.markdown(f"""<div style="border-radius:10px;padding:14px;border-left:5px solid {clr};background:{bg}">
                <div style="font-weight:800;font-size:0.95rem">{pname}</div>
                <div style="font-size:0.78rem;color:#555;margin-top:2px">{p['type']}</div>
                <div style="font-size:0.76rem;color:#888;margin-top:4px">v{p['version']} · {len(comps)} {"コンポーネント" if ja else "components"}</div>
            </div>""",unsafe_allow_html=True)
            with st.expander("SBOM"):
                for c in comps:
                    st.caption(f"• **{c['name']}** v{c['version']}")

st.markdown("---")

# Decision rules summary
st.markdown("#### " + ("📏 決定ルール" if ja else "📏 Decision Rules"))
rule_cols = st.columns(3)
rule_colors={"REPORT":("#fff5f5","#ff4b4b"),"NOT_REPORT":("#f0fff4","#21c354"),"CONFLICT":("#fff8ec","#ffa500"),"HUMAN_REVIEW":("#f5f3ff","#7c3aed")}
for i,rule in enumerate(DECISION_RULES):
    bg,accent=rule_colors.get(rule["action"],("#f9fafb","#6b7280"))
    auto_label=("✅ 自動" if ja else "✅ Auto") if rule["auto_decidable"] else ("👤 人的" if ja else "👤 Human")
    with rule_cols[i%3]:
        st.markdown(f"""<div style="border-radius:8px;padding:12px 14px;background:{bg};border-left:4px solid {accent};margin-bottom:10px">
            <div style="font-weight:700;font-size:0.88rem">{rule['rule_id']} — {rule['name']}</div>
            <div style="font-size:0.75rem;color:#6b7280;margin-top:4px">{rule['condition']}</div>
            <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
                <span style="background:{accent};color:white;padding:2px 8px;border-radius:10px;font-size:0.72rem;font-weight:600">{rule['action']}</span>
                <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;font-size:0.72rem">{auto_label}</span>
                <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;font-size:0.72rem">conf {rule['confidence_boost']:.0%}</span>
            </div>
        </div>""",unsafe_allow_html=True)

st.markdown("---")

# Market Coverage & CRA Jurisdiction
st.markdown("#### " + ("🌍 市場カバレッジ & 規制管轄" if ja else "🌍 Market Coverage & Regulatory Jurisdiction"))
st.caption(
    "各市場の監督機関・CSIRT・適用法令。英国はEU外のためCRAは適用されません。" if ja else
    "National authorities, CSIRTs, and applicable regulation per market. UK is non-EU — CRA does not apply there."
)

_MARKET = [
    {"flag":"🇩🇪","name":"Germany",       "name_ja":"ドイツ",         "nca":"BSI",           "csirt":"CERT-Bund",   "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇫🇷","name":"France",        "name_ja":"フランス",       "nca":"ANSSI",         "csirt":"CERT-FR",     "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇮🇹","name":"Italy",         "name_ja":"イタリア",       "nca":"ACN",           "csirt":"CSIRT Italia","reg":"CRA 2024/2847","eu":True },
    {"flag":"🇪🇸","name":"Spain",         "name_ja":"スペイン",       "nca":"CCN / INCIBE",  "csirt":"CCN-CERT",    "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇮🇪","name":"Ireland",       "name_ja":"アイルランド",   "nca":"NCSC Ireland",  "csirt":"NCSC-IE",     "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇬🇧","name":"United Kingdom","name_ja":"英国",           "nca":"DSIT / NCSC UK","csirt":"NCSC UK",     "reg":"PSTI Act 2022","eu":False},
]

mkt_cols = st.columns(3)
for i, c in enumerate(_MARKET):
    bg     = "#f0fff4" if c["eu"] else "#fff8ec"
    border = "#21c354" if c["eu"] else "#ffa500"
    badge_color = "#21c354" if c["eu"] else "#ffa500"
    cname  = c["name_ja"] if ja else c["name"]
    note   = ("EU加盟国 · CRA第14条 報告義務あり" if ja else "EU Member · Article 14 reporting required") if c["eu"] \
             else ("⚠️ EU外 · CRA非適用 · PSTI法 2022 準拠" if ja else "⚠️ Non-EU · CRA does not apply · PSTI Act 2022")
    nca_lbl  = "監督機関" if ja else "NCA"
    with mkt_cols[i % 3]:
        st.markdown(f"""<div style="border-radius:8px;padding:12px 14px;background:{bg};border-left:4px solid {border};margin-bottom:10px">
            <div style="font-weight:700;font-size:1rem">{c['flag']} {cname}</div>
            <div style="font-size:0.74rem;color:#374151;margin-top:5px">{nca_lbl}: <b>{c['nca']}</b></div>
            <div style="font-size:0.74rem;color:#374151">CSIRT: <b>{c['csirt']}</b></div>
            <div style="margin-top:6px">
                <span style="background:{badge_color};color:white;padding:2px 8px;border-radius:10px;font-size:0.7rem;font-weight:600">{c['reg']}</span>
            </div>
            <div style="font-size:0.7rem;color:#6b7280;margin-top:5px">{note}</div>
        </div>""", unsafe_allow_html=True)

with st.expander("ℹ️ " + ("国ごとの違いについて" if ja else "How country differences are handled")):
    if ja:
        st.markdown("""
**EU加盟国（ドイツ・フランス・イタリア・スペイン・アイルランド）**
- EU CRA 2024/2847 第14条が一律適用
- 能動的に悪用された脆弱性は**24時間以内**にENISAおよび各国CSIRTに報告義務
- 各国の監督機関（NCA）が市場監視を担当
- 本パイプラインの決定エンジンはすべてのEU加盟国に対応

**英国 🇬🇧**
- EUを離脱しているためCRAは**適用されません**
- 代わりにPSTI法（製品セキュリティ・通信インフラ法）2022が適用（2024年4月施行）
- 報告先：DSIT（デジタル・科学・インフラ・技術省）/ NCSC UK
- J-TECが英国向けに製品を販売する場合、**別途PST準拠フローが必要**
        """)
    else:
        st.markdown("""
**EU Member States (Germany, France, Italy, Spain, Ireland)**
- EU CRA 2024/2847 Article 14 applies uniformly across all EU members
- Actively exploited vulnerabilities must be reported to **ENISA + the national CSIRT within 24 hours**
- Each country's National Competent Authority (NCA) handles market surveillance
- This pipeline's decision engine covers all EU member states

**United Kingdom 🇬🇧**
- UK left the EU — **CRA does not apply**
- Instead: **PSTI Act 2022** (Product Security & Telecommunications Infrastructure Act), in force since April 2024
- Reporting goes to DSIT (Dept. for Science, Innovation & Technology) / NCSC UK
- If J-TEC sells products into the UK market, a **separate PSTI compliance flow is required**
        """)

st.markdown("---")
st.markdown(f"<div style='text-align:center;font-size:12px;color:gray;'>🔐 {t('footer')}</div>",unsafe_allow_html=True)
st.markdown(f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",unsafe_allow_html=True)
