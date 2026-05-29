"""
CRA Decision Traceability System — Executive Dashboard + Pipeline Runner
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
from collections import Counter

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from decision_engine import DecisionEngine
from enisa_reporter import (generate_enisa_submission_json, generate_compliance_artifact_html,
                            generate_cyclonedx_sbom, generate_enisa_article14_json,
                            generate_audit_csv, generate_pdf_report)
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
if "run_triggered"    not in st.session_state: st.session_state.run_triggered    = None
if "engine" not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS, cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES, thresholds=THRESHOLDS
    )

ja = st.session_state.lang == "ja"

# ============= CSS =============
st.markdown("""
<style>
/* ── Global: force white/light base ── */
.stApp { background-color: #ffffff; }
section[data-testid="stSidebar"] { background-color: #f8fafc; border-right: 1px solid #e2e8f0; }

/* ── CRA Pipeline readiness pills ── */
.ready-pill{display:inline-flex;align-items:center;gap:6px;background:#dcfce7;color:#166534;border:1px solid #bbf7d0;border-radius:20px;padding:5px 14px;font-size:0.82rem;font-weight:600}
.ready-dot{width:8px;height:8px;border-radius:50%;background:#16a34a}

/* ── Decision badges ── */
.badge-report    {background:#dc2626;color:white;padding:6px 20px;border-radius:6px;font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}
.badge-not-report{background:#16a34a;color:white;padding:6px 20px;border-radius:6px;font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}
.badge-conflict  {background:#d97706;color:white;padding:6px 20px;border-radius:6px;font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}

/* ── Pipeline stepper ── */
.stepper-wrap{display:flex;justify-content:space-between;align-items:center;margin:1rem 0 1.5rem 0}
.step-item{display:flex;flex-direction:column;align-items:center;flex:1;position:relative}
.step-item:not(:last-child)::after{content:"";position:absolute;top:18px;left:60%;width:80%;height:3px;background:#cbd5e1;z-index:0}
.step-item.done:not(:last-child)::after{background:#16a34a}
.step-circle{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:1rem;z-index:1;background:#e2e8f0;color:#64748b}
.step-circle.done{background:#16a34a;color:white}
.step-label{font-size:0.72rem;margin-top:4px;text-align:center;color:#64748b;max-width:80px}
.step-label.done{color:#16a34a;font-weight:600}

/* ── Audit trail badges ── */
.audit-badge{display:inline-block;padding:2px 10px;border-radius:6px;font-size:0.75rem;font-weight:600}
.audit-stage{background:#dbeafe;color:#1e40af}
.audit-decision{background:#dcfce7;color:#166534}
.audit-conflict{background:#fef9c3;color:#92400e}

/* ── Card / info boxes ── */
.info-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px}
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

def confidence_explainer_chart(rules_fired, final_score, threshold=0.80):
    """Horizontal bar chart showing all 6 rules with confidence contributions.
    Triggered rules shown in navy; non-triggered in light gray.
    Red dashed threshold line + final score marker."""
    # Map fired rules back to DECISION_RULES to get confidence_boost for each
    fired_ids = {}
    for r in rules_fired:
        if r["triggered"]:
            rid = r["rule"].split(":")[0].strip()  # e.g. "R1"
            fired_ids[rid] = r

    y_labels, x_values, bar_colors, hover_texts = [], [], [], []
    for rule in DECISION_RULES:
        rid = rule["rule_id"]
        short_name = rule["name"] if len(rule["name"]) <= 38 else rule["name"][:36] + "…"
        label = f"{rid}: {short_name}"
        boost = rule["confidence_boost"]
        triggered = rid in fired_ids

        y_labels.append(label)
        x_values.append(boost if boost > 0 else 0.02)  # tiny bar for R5 (0.0)
        bar_colors.append("#1e40af" if triggered else "#e2e8f0")
        hover_texts.append(
            f"<b>{rid}: {rule['name']}</b><br>"
            f"Confidence Boost: {boost:.0%}<br>"
            f"Status: {'✅ TRIGGERED' if triggered else '— Not Triggered'}<br>"
            f"Action: {rule['action']}"
        )

    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=y_labels, x=x_values,
        orientation="h",
        marker=dict(color=bar_colors, line=dict(width=0)),
        hovertext=hover_texts, hoverinfo="text",
        text=[f"{xv:.0%}" if xv > 0.02 else "0%" for xv in x_values],
        textposition="inside",
        textfont=dict(color=["white" if c == "#1e40af" else "#94a3b8" for c in bar_colors], size=11),
        showlegend=False
    ))
    # Auto-decide threshold line
    fig.add_vline(x=threshold, line_color="#dc2626", line_width=2, line_dash="dot",
                  annotation_text=f"Threshold {threshold:.0%}", annotation_position="top right",
                  annotation_font=dict(color="#dc2626", size=11))
    # Final score line
    fig.add_vline(x=final_score, line_color="#1e3a8a", line_width=3,
                  annotation_text=f"Score {final_score:.0%}", annotation_position="bottom right",
                  annotation_font=dict(color="#1e3a8a", size=12, family="sans-serif"))
    fig.update_layout(
        height=310, margin=dict(t=30, b=20, l=10, r=100),
        xaxis=dict(range=[0, 1.08], tickformat=".0%", title="Confidence Score", showgrid=True, gridcolor="#f1f5f9"),
        yaxis=dict(autorange="reversed", showgrid=False),
        plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
        title=dict(text="Rule Confidence Breakdown — All 6 Rules", font=dict(size=13, color="#1e293b"))
    )
    return fig

def cra_deadline_gantt(submission_ts_str, lang="en"):
    """Plotly Gantt chart for CRA Article 14 deadlines relative to detection time."""
    try:
        detect_dt = datetime.fromisoformat(submission_ts_str)
    except Exception:
        detect_dt = datetime.now()

    now = datetime.now()
    labels_en = ["🟡 Early Warning (24h)", "🟠 Full Notification (72h)", "📋 Final Report (90 days)"]
    labels_ja = ["🟡 早期警告 (24h)", "🟠 完全通知 (72h)", "📋 最終報告 (90日)"]
    labels = labels_ja if lang == "ja" else labels_en
    end_deltas = [timedelta(hours=24), timedelta(hours=72), timedelta(days=90)]
    colors = ["#fde68a", "#fed7aa", "#dbeafe"]
    bar_colors = ["#ca8a04", "#d97706", "#1e40af"]

    fig = go.Figure()
    for i, (lbl, delta, bg, fg) in enumerate(zip(labels, end_deltas, colors, bar_colors)):
        end_dt = detect_dt + delta
        elapsed_h = (now - detect_dt).total_seconds() / 3600
        total_h   = delta.total_seconds() / 3600
        pct_done  = min(elapsed_h / total_h, 1.0)
        done_end  = detect_dt + timedelta(seconds=min((now - detect_dt).total_seconds(), delta.total_seconds()))
        status = "OVERDUE ⚠️" if now > end_dt else f"{pct_done:.0%} elapsed"
        # Background bar (total period)
        fig.add_trace(go.Bar(
            y=[lbl], x=[delta.total_seconds() / 3600],
            base=[0], orientation="h",
            marker=dict(color=bg, line=dict(width=1, color="#e2e8f0")),
            showlegend=False, hoverinfo="skip", name=""
        ))
        # Progress bar (elapsed)
        fig.add_trace(go.Bar(
            y=[lbl], x=[min(elapsed_h, total_h)],
            base=[0], orientation="h",
            marker=dict(color=fg + "99"),
            showlegend=False,
            hovertemplate=f"<b>{lbl}</b><br>Deadline: {end_dt.strftime('%Y-%m-%d %H:%M')}<br>Status: {status}<extra></extra>",
            name=""
        ))

    # "Now" vertical line (hours since detection)
    now_h = (now - detect_dt).total_seconds() / 3600
    fig.add_vline(x=max(now_h, 0.5), line_color="#dc2626", line_width=2, line_dash="solid",
                  annotation_text=("現在" if lang == "ja" else "NOW"),
                  annotation_position="top left",
                  annotation_font=dict(color="#dc2626", size=11, family="sans-serif"))
    # SLA markers
    fig.add_vline(x=24,   line_color="#ca8a04", line_width=1, line_dash="dot")
    fig.add_vline(x=72,   line_color="#d97706", line_width=1, line_dash="dot")
    fig.add_vline(x=2160, line_color="#1e40af", line_width=1, line_dash="dot")  # 90 days

    fig.update_layout(
        barmode="overlay", height=220,
        margin=dict(t=40, b=20, l=10, r=20),
        xaxis=dict(title=("経過時間（時間）" if lang == "ja" else "Hours since detection"),
                   showgrid=True, gridcolor="#f1f5f9"),
        yaxis=dict(showgrid=False),
        plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
        title=dict(text=("CRA 第14条 規制スケジュール" if lang == "ja" else "CRA Article 14 Regulatory Schedule"),
                   font=dict(size=13, color="#1e293b"))
    )
    # Log-scale makes 24h/72h/90d all visible on the same axis
    fig.update_xaxes(type="log", tickvals=[1, 6, 24, 72, 168, 720, 2160],
                     ticktext=["1h", "6h", "24h", "72h", "7d", "30d", "90d"])
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
        if conflict_info["conflict_detected"]:
            st.warning(t("spin3_conflict",type=conflict_info["conflict_type"]))
        else:
            st.success(t("spin3_ok"))
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
        if conflict_info["conflict_detected"]:
            st.warning(t("spin3_conflict",type=conflict_info["conflict_type"]))
        else:
            st.success(t("spin3_ok"))
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
        # Only set the trigger flag here — pipeline runs in the main area
        # to keep spinner/success messages out of the sidebar
        st.session_state.pipeline_phase = "idle"
        st.session_state.pre_review = None
        st.session_state.pipeline_results = None
        st.session_state.run_triggered = {
            "scenario": selected_scenario,
            "product": selected_product,
        }
        st.rerun()

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

    st.caption("📚 " + ("上の「History」「Scenarios」から各ページへ" if ja else "Use the page list above to open History & Scenarios"))

# ============= MAIN AREA =============

# ---- Header ----
st.title(f"🔐 {t('app_title')}")
st.markdown(f"**{t('app_subtitle')}**")
st.markdown("---")

# Execute pipeline here (main area) so spinners/messages render outside the sidebar
if st.session_state.run_triggered:
    trig = st.session_state.run_triggered
    st.session_state.run_triggered = None
    if CVE_SCENARIOS[trig["scenario"]].get("human_review_required"):
        st.session_state.pre_review = run_stages_1_to_4(trig["scenario"], trig["product"])
        st.session_state.pipeline_phase = "awaiting_human"
    else:
        st.session_state.pipeline_results = run_pipeline(trig["scenario"], trig["product"])
        st.session_state.pipeline_phase = "complete"
    st.rerun()

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

    # Post-ENISA lifecycle prompt (only for REPORT decisions)
    if final == "REPORT":
        st.markdown(f"""
        <div style="background:#eff6ff;border-left:5px solid #1e40af;border-radius:8px;padding:12px 18px;margin:10px 0">
          <b style="color:#1e3a8a;font-size:0.85rem">{'⚠️ ENISA報告義務が発生しました — 規制ライフサイクルが開始されます' if ja else '⚠️ ENISA reporting obligation triggered — Regulatory lifecycle now active'}</b><br>
          <span style="color:#1e40af;font-size:0.8rem">{'サイドバーの「Compliance」ページで完全な報告後ライフサイクル管理（規制調整・修正・監査保管）を確認できます。' if ja else 'Open the Compliance page (sidebar) to manage the full post-reporting lifecycle: regulatory coordination, remediation governance, audit retention.'}</span>
        </div>""", unsafe_allow_html=True)

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
        if match["match_found"]:
            st.error(t("t2_vuln",reason=match["match_reason"]))
        else:
            st.success(t("t2_safe",reason=match["match_reason"]))
        st.markdown(t("t2_sbom_table"))
        df=sbom_table(results["product_name"],match.get("matching_component"),match["match_found"])
        st.dataframe(df.style.map(lambda v:"background-color:#fff5f5" if t("t2_vulnerable") in str(v) else "",subset=[t("t2_col_status")]),use_container_width=True,hide_index=True)

    with tab3:
        st.subheader(t("t3_header")); conflict=results["conflict_info"]
        if conflict["conflict_detected"]:
            st.warning(t("t3_conflict",type=conflict["conflict_type"]))
            c1,c2=st.columns(2)
            with c1:
                st.markdown(t("t3_evidence"))
                for ev in conflict["evidence_summary"]:
                    st.markdown(f"- {ev}")
            with c2:
                if conflict.get("vex_available"): st.info(t("t3_vex"))
        else:
            st.success(t("t3_no_conflict"))
            for ev in conflict["evidence_summary"]:
                st.markdown(f"- {ev}")
        with st.expander(t("t3_raw")): st.json(conflict)

    with tab4:
        st.subheader(t("t4_header")); decision=results["decision_proposal"]
        a,b,c,d_col=st.columns(4)
        a.metric(t("metric_proposed"),decision["decision_type"])
        b.metric(t("metric_match_confidence"),f"{decision['confidence_score']:.0%}")
        c.metric(t("metric_auto_decidable"),t("t4_yes_auto") if decision["auto_decidable"] else t("t4_no_auto"))
        d_col.metric("🎯 " + ("閾値" if ja else "Auto Threshold"), f"{THRESHOLDS['auto_decide_confidence']:.0%}")
        st.markdown("---")

        # ── Confidence Score Explainer ──
        st.markdown("##### 🎯 " + ("信頼スコア解説 — どのルールが判定に貢献したか" if ja else "Confidence Score Explainer — Which rules drove the decision"))
        expl_chart_col, verdict_col = st.columns([3, 2])
        with expl_chart_col:
            st.plotly_chart(confidence_explainer_chart(decision["rules_fired"], decision["confidence_score"], THRESHOLDS["auto_decide_confidence"]), use_container_width=True)
        with verdict_col:
            score = decision["confidence_score"]
            threshold = THRESHOLDS["auto_decide_confidence"]
            above = score >= threshold
            verdict_bg   = "#f0fdf4" if above else "#fff7ed"
            verdict_border = "#16a34a" if above else "#d97706"
            verdict_icon  = "✅" if above else "👤"
            verdict_label = ("自動判定" if ja else "AUTO-DECIDED") if above else ("人的レビュー必要" if ja else "HUMAN REVIEW NEEDED")
            verdict_text  = (f"信頼スコア {score:.0%} が閾値 {threshold:.0%} を上回っています。システムが自動的に判定を確定しました。" if ja
                             else f"Score {score:.0%} exceeds the auto-decide threshold of {threshold:.0%}. The system confirmed this decision automatically.") if above \
                            else (f"信頼スコア {score:.0%} が閾値 {threshold:.0%} を下回っています。コンプライアンス担当者の判断が必要です。" if ja
                                  else f"Score {score:.0%} is below the auto-decide threshold of {threshold:.0%}. A compliance officer must confirm this decision.")

            # Score progress bar HTML
            bar_pct = int(score * 100)
            thr_pct = int(threshold * 100)
            bar_color = "#16a34a" if above else "#d97706"
            st.markdown(f"""
            <div style="background:{verdict_bg};border:1px solid {verdict_border};border-radius:10px;padding:16px 18px;margin-top:4px">
              <div style="font-size:0.85rem;font-weight:700;color:{verdict_border};margin-bottom:8px">{verdict_icon} {verdict_label}</div>
              <div style="font-size:0.78rem;color:#374151;margin-bottom:12px">{verdict_text}</div>
              <div style="background:#e2e8f0;border-radius:20px;height:12px;position:relative;overflow:hidden">
                <div style="background:{bar_color};width:{bar_pct}%;height:100%;border-radius:20px;transition:width 0.5s"></div>
              </div>
              <div style="position:relative;height:18px">
                <div style="position:absolute;left:{thr_pct}%;transform:translateX(-50%);font-size:0.65rem;color:#dc2626;margin-top:2px">▲ {threshold:.0%}</div>
              </div>
              <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:#6b7280;margin-top:4px">
                <span>0%</span><span style="font-weight:700;color:{verdict_border}">{score:.0%}</span><span>100%</span>
              </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("")
            # Evidence source breakdown
            weighting = decision["evidence_weighting"]
            st.markdown(f"**{'📊 証拠信頼度' if ja else '📊 Evidence Confidence'}**")
            for src, val, icon in [
                (t("t4_ev_sbom"),  weighting["sbom_confidence"],      "🔩"),
                (t("t4_ev_nvd"),   weighting["cve_data_confidence"],   "🗄️"),
                (t("t4_ev_vex"),   weighting["vex_confidence"],        "📋"),
            ]:
                w_color = "#16a34a" if val >= 0.8 else "#d97706" if val >= 0.5 else "#94a3b8"
                st.markdown(f"""<div style="display:flex;justify-content:space-between;align-items:center;
                    padding:5px 8px;margin-bottom:4px;background:#f8fafc;border-radius:6px;font-size:0.78rem">
                    <span>{icon} {src}</span>
                    <span style="font-weight:700;color:{w_color}">{val:.0%}</span>
                </div>""", unsafe_allow_html=True)

        st.markdown("---")
        # ── Rule-by-rule detail ──
        st.markdown(t("t4_rules_eval"))
        num_triggered = sum(1 for r in decision["rules_fired"] if r["triggered"])
        for rule in decision["rules_fired"]:
            icon = "✅" if rule["triggered"] else "⬜"
            bg   = "#f0fdf4" if rule["triggered"] else "#f8fafc"
            border = "#16a34a" if rule["triggered"] else "#e2e8f0"
            st.markdown(f"""<div style="background:{bg};border:1px solid {border};border-radius:8px;
                padding:10px 14px;margin-bottom:8px">
                <div style="font-weight:700;font-size:0.85rem">{icon} {rule['rule']} &nbsp;
                <span style="font-weight:400;color:#6b7280">— {t('t4_triggered') if rule['triggered'] else t('t4_not_triggered')}</span></div>
                <div style="font-size:0.76rem;color:#4b5563;margin-top:4px">{rule['reasoning']}</div>
            </div>""", unsafe_allow_html=True)

    with tab5:
        st.subheader(t("t5_header")); review=results["review_result"]
        final_type = review["final_decision_type"]
        a,b,c=st.columns(3)
        a.metric(t("metric_reviewer"),review["reviewer"]); b.metric(t("metric_action"),review["action"]); c.metric(t("metric_decision_id"),review["decision_id"][:12]+"…")
        st.markdown(t("t5_justification")); st.info(review["justification"])
        st.markdown(t("t5_final")); st.markdown(decision_badge(final_type),unsafe_allow_html=True)

        st.markdown("---")

        # ── Customer Notification Email Preview ──
        st.markdown("##### 📧 " + ("顧客通知メール — プレビュー & 承認ワークフロー" if ja else "Customer Notification Email — Preview & Approval Workflow"))

        _cve_t  = results["cve"]
        _prod_t = results["product_name"]
        _dec_id = review["decision_id"][:16].upper()
        _now_ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        # Email type selector
        email_types = (["重大脆弱性アラート", "パッチ適用通知", "インシデント解決通知", "規制報告通知"]
                       if ja else
                       ["Critical Vulnerability Alert", "Patch Available Notification",
                        "Incident Resolved Notification", "Regulatory Filing Notice"])
        selected_email_type = st.selectbox(
            "📋 " + ("通知テンプレート" if ja else "Notification Template"),
            email_types, key="email_type_select"
        )

        # Generate email body based on selection
        _email_idx = email_types.index(selected_email_type)
        if _email_idx == 0:  # Critical alert
            _subj_en = f"[URGENT] Security Alert — {_cve_t['cve_id']} affects {_prod_t}"
            _subj_ja = f"【緊急】セキュリティアラート — {_cve_t['cve_id']} が {_prod_t} に影響"
            _body_en = f"""Dear Customer,

We are writing to inform you of a critical security vulnerability ({_cve_t['cve_id']}) that has been identified in {_prod_t} (CVSS Score: {_cve_t['cvss_score']} — {_cve_t['severity']}).

IMMEDIATE ACTION REQUIRED:
• This vulnerability is actively exploited in the wild
• Affected product: {_prod_t}
• Affected versions: {_cve_t['affected_versions']['range_start']} to {_cve_t['affected_versions']['range_end']}

Our security team has submitted a report to ENISA in accordance with EU Cyber Resilience Act Article 14 obligations (Ref: {_dec_id}).

We are working on a patch and will notify you as soon as it is available. In the meantime, please apply the interim mitigations described in our Security Advisory portal.

If you have any questions, please contact our security team at security@jtec.co.jp.

Regards,
J-TEC Security Response Team
{_now_ts}"""
            _body_ja = f"""お客様各位

{_prod_t}（CVSS: {_cve_t['cvss_score']} — {_cve_t['severity']}）に重大なセキュリティ脆弱性（{_cve_t['cve_id']}）が検出されましたため、緊急のご連絡を差し上げます。

【緊急対応が必要です】
• 本脆弱性は現在、野外で積極的に悪用されています
• 影響製品: {_prod_t}
• 影響バージョン: {_cve_t['affected_versions']['range_start']} ～ {_cve_t['affected_versions']['range_end']}

弊社はEU CRA第14条に基づき、ENISAへの報告を完了しました（参照番号: {_dec_id}）。

現在パッチを開発中です。完成次第速やかにご連絡いたします。それまでの間、セキュリティアドバイザリポータルに記載の暫定措置をお取りください。

ご不明な点は security@jtec.co.jp までお問い合わせください。

J-TEC セキュリティ対応チーム
{_now_ts}"""
        elif _email_idx == 1:  # Patch available
            _subj_en = f"[ACTION] Patch Available — {_cve_t['cve_id']} ({_prod_t})"
            _subj_ja = f"【要対応】パッチ公開 — {_cve_t['cve_id']} ({_prod_t})"
            _body_en = f"""Dear Customer,

A security patch is now available for {_cve_t['cve_id']} affecting {_prod_t}.

Patch Details:
• CVE: {_cve_t['cve_id']} | CVSS: {_cve_t['cvss_score']}
• Patch version: {_cve_t['affected_versions']['range_end'].replace('.', '.')}+hotfix1
• Download: https://support.jtec.co.jp/patches/{_cve_t['cve_id'].lower()}

Please apply this patch within 72 hours. If you require extended maintenance windows, contact your account manager.

J-TEC Security Response Team
{_now_ts}"""
            _body_ja = f"""お客様各位

{_prod_t}に影響する{_cve_t['cve_id']}のセキュリティパッチが公開されました。

パッチ詳細:
• CVE: {_cve_t['cve_id']} | CVSS: {_cve_t['cvss_score']}
• パッチバージョン: {_cve_t['affected_versions']['range_end']}+hotfix1
• ダウンロード: https://support.jtec.co.jp/patches/{_cve_t['cve_id'].lower()}

72時間以内にパッチを適用してください。

J-TEC セキュリティ対応チーム
{_now_ts}"""
        elif _email_idx == 2:  # Resolved
            _subj_en = f"[RESOLVED] Incident Closed — {_cve_t['cve_id']}"
            _subj_ja = f"【解決済み】インシデント終了 — {_cve_t['cve_id']}"
            _body_en = f"""Dear Customer,

We are pleased to inform you that the security incident related to {_cve_t['cve_id']} affecting {_prod_t} has been fully resolved.

Resolution Summary:
• Patch deployed to all affected systems
• ENISA final report submitted (Ref: {_dec_id})
• Monitoring extended for 30 days post-resolution

No further customer action is required. If you have not yet applied the patch, please do so at your earliest convenience.

Thank you for your patience during this process.

J-TEC Security Response Team
{_now_ts}"""
            _body_ja = f"""お客様各位

{_prod_t}に関する{_cve_t['cve_id']}セキュリティインシデントが完全に解決されましたことをお知らせします。

解決の概要:
• 影響システムへのパッチ展開完了
• ENISAへの最終報告提出済み（参照番号: {_dec_id}）
• 解決後30日間の監視継続

お客様側での追加対応は不要です。

J-TEC セキュリティ対応チーム
{_now_ts}"""
        else:  # Regulatory filing
            _subj_en = f"[COMPLIANCE] ENISA Filing Confirmation — {_cve_t['cve_id']}"
            _subj_ja = f"【規制】ENISA報告完了通知 — {_cve_t['cve_id']}"
            _body_en = f"""Dear Customer,

In accordance with our obligations under EU Cyber Resilience Act Article 14, we have submitted a vulnerability report to ENISA regarding {_cve_t['cve_id']} in {_prod_t}.

Filing Reference: {_dec_id}
Submission Date: {_now_ts}
Report Type: Actively Exploited Vulnerability (Art. 14(2)(a))

This notification is provided for your records and to ensure transparency in our regulatory compliance activities.

J-TEC Compliance Team
{_now_ts}"""
            _body_ja = f"""お客様各位

EU CRA第14条に基づく義務として、{_prod_t}に関する{_cve_t['cve_id']}の脆弱性報告をENISAに提出しましたことをご連絡します。

報告参照番号: {_dec_id}
提出日時: {_now_ts}
報告種別: 能動的悪用脆弱性（第14条(2)(a)）

本通知は記録保持および規制コンプライアンス活動の透明性確保のために送付しています。

J-TEC コンプライアンスチーム
{_now_ts}"""

        _subj = _subj_ja if ja else _subj_en
        _body = _body_ja if ja else _body_en

        # Email preview card
        with st.expander("📧 " + ("メールプレビュー" if ja else "Email Preview"), expanded=True):
            st.markdown(f"""
            <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;
                        font-family:'Helvetica Neue',Arial,sans-serif;overflow:hidden">
              <!-- Header bar -->
              <div style="background:#1e3a8a;padding:12px 20px">
                <span style="color:white;font-weight:700;font-size:0.9rem">J-TEC Co., Ltd. — Security Notification</span>
              </div>
              <!-- Meta row -->
              <div style="background:#f1f5f9;padding:10px 20px;font-size:0.77rem;color:#374151;border-bottom:1px solid #e2e8f0">
                <b>{'送信元' if ja else 'From'}:</b> security@jtec.co.jp &nbsp;|&nbsp;
                <b>{'件名' if ja else 'Subject'}:</b> {_subj}
              </div>
              <!-- Body -->
              <div style="padding:16px 20px;font-size:0.80rem;color:#1e293b;line-height:1.7;white-space:pre-wrap">{_body}</div>
              <!-- Footer -->
              <div style="background:#f1f5f9;padding:8px 20px;font-size:0.7rem;color:#94a3b8;border-top:1px solid #e2e8f0">
                J-TEC Co., Ltd. · 1-2-3 Marunouchi, Chiyoda, Tokyo 100-0005 · security@jtec.co.jp<br>
                {'本メールはJ-TECのCRAコンプライアンスシステムにより自動生成されました。' if ja else
                 'This email was generated by J-TEC CRA Compliance System. Decision ID: '}{_dec_id}
              </div>
            </div>""", unsafe_allow_html=True)

        # Download email as .eml / .txt
        st.download_button(
            label="⬇️ " + ("メールファイルをダウンロード (.txt)" if ja else "Download Email File (.txt)"),
            data=f"From: security@jtec.co.jp\nTo: [Customer Distribution List]\nSubject: {_subj}\nDate: {_now_ts}\n\n{_body}",
            file_name=f"Notification-{_cve_t['cve_id']}-{_email_idx+1}.txt",
            mime="text/plain",
            use_container_width=False
        )

        st.markdown("---")

        # ── Approval Workflow ──
        st.markdown("##### ✅ " + ("送信前承認ワークフロー" if ja else "Pre-Send Approval Workflow"))
        _chain = [
            {"role": ("セキュリティエンジニア" if ja else "Security Engineer"),  "name": "K. Tanaka",       "status": "approved", "ts": "09:12"},
            {"role": ("セキュリティマネージャー" if ja else "Security Manager"),  "name": "Y. Matsumoto",    "status": "approved", "ts": "09:28"},
            {"role": ("コンプライアンス担当" if ja else "Compliance Officer"),    "name": review["reviewer"],"status": "approved", "ts": review["review_timestamp"][11:16] if "T" in review["review_timestamp"] else "10:05"},
            {"role": ("法務責任者" if ja else "Legal Counsel"),                   "name": "R. Kobayashi",    "status": "pending",  "ts": "—"},
        ]
        ch_cols = st.columns(4)
        for ch, ccol in zip(_chain, ch_cols):
            s = ch["status"]
            bg     = "#f0fdf4" if s == "approved" else "#fff7ed"
            border = "#16a34a" if s == "approved" else "#d97706"
            icon   = "✅" if s == "approved" else "⏳"
            label  = ("承認済み" if ja else "APPROVED") if s == "approved" else ("保留中" if ja else "PENDING")
            with ccol:
                st.markdown(f"""<div style="background:{bg};border:1px solid {border};border-radius:8px;
                    padding:12px 14px;text-align:center">
                  <div style="font-size:1.4rem">{icon}</div>
                  <div style="font-size:0.78rem;font-weight:700;color:{border};margin-top:4px">{label}</div>
                  <div style="font-size:0.75rem;color:#374151;margin-top:2px">{ch['role']}</div>
                  <div style="font-size:0.72rem;color:#6b7280">{ch['name']}</div>
                  <div style="font-size:0.68rem;color:#94a3b8;margin-top:2px">{ch['ts']}</div>
                </div>""", unsafe_allow_html=True)
        st.caption("ℹ️ " + ("法務責任者の承認後、通知が顧客に送信されます。" if ja else
                            "Notification will be sent to customers once Legal Counsel approves."))

    with tab6:
        st.subheader(t("t6_header")); enisa=results["enisa_result"]
        final_dec = results["review_result"]["final_decision_type"]

        if final_dec != "REPORT":
            # ── Not applicable ──
            st.info("ℹ️ " + ("ENISA報告義務なし — このケースは自動報告対象外です。" if ja else
                              "ENISA submission not required — this case does not trigger Article 14 reporting."))
            c1,c2=st.columns(2)
            c1.metric(t("metric_status"), enisa["status"])
            c2.metric(t("metric_submitted"), "NO — " + final_dec)
            with st.expander(t("t6_payload_preview")):
                st.json(generate_enisa_submission_json(decision=results["review_result"],cve=results["cve"],
                        product_name=results["product_name"],sbom_match=results["sbom_match"],
                        submission_id=results["enisa_result"]["submission_id"]))
        else:
            # ── ENISA Submission Simulator ──
            st.markdown(f"""
            <div style="background:#eff6ff;border-left:5px solid #1e40af;border-radius:8px;padding:12px 18px;margin-bottom:12px">
              <b style="color:#1e3a8a;font-size:0.95rem">{'🏛️ ENISA 脆弱性報告ポータル — シミュレーター' if ja else '🏛️ ENISA Vulnerability Reporting Portal — Simulator'}</b><br>
              <span style="color:#1e40af;font-size:0.8rem">{'CRA 第14条に基づく能動的悪用脆弱性報告。本シミュレーターはENISAポータルの提出フローを再現します。' if ja else
              'Actively Exploited Vulnerability Report under CRA Article 14. This simulator replicates the ENISA portal submission flow.'}</span>
            </div>""", unsafe_allow_html=True)

            # Stepper: 4 steps
            sim_step_key = f"enisa_sim_step_{results['enisa_result']['submission_id'][:8]}"
            if sim_step_key not in st.session_state:
                st.session_state[sim_step_key] = 1   # start at step 1

            cur_step = st.session_state[sim_step_key]

            step_labels = (
                ["1. レポーター確認", "2. 脆弱性詳細", "3. 影響評価", "4. 送信確認"]
                if ja else
                ["1. Reporter Identity", "2. Vulnerability Details", "3. Impact Assessment", "4. Submit & Confirm"]
            )
            step_cols = st.columns(4)
            for si, (scol, slbl) in enumerate(zip(step_cols, step_labels), start=1):
                done = si < cur_step; active = si == cur_step
                circ_bg = "#16a34a" if done else "#1e3a8a" if active else "#e2e8f0"
                circ_fg = "white" if (done or active) else "#94a3b8"
                lbl_col = "#16a34a" if done else "#1e3a8a" if active else "#94a3b8"
                icon = "✓" if done else str(si)
                with scol:
                    st.markdown(f"""<div style="text-align:center">
                      <div style="width:36px;height:36px;border-radius:50%;background:{circ_bg};color:{circ_fg};
                           font-weight:700;font-size:1rem;display:inline-flex;align-items:center;justify-content:center">{icon}</div>
                      <div style="font-size:0.72rem;color:{lbl_col};margin-top:4px;font-weight:{'700' if active else '400'}">{slbl}</div>
                    </div>""", unsafe_allow_html=True)
            st.markdown("")

            cve_r  = results["cve"]
            prod_r = results["product_name"]
            rev_r  = results["review_result"]
            ref_id = enisa["enisa_reference_id"]
            sub_ts = enisa["submission_timestamp"]

            if cur_step == 1:
                st.markdown("#### " + ("レポーター情報の確認" if ja else "Reporter Identity Confirmation"))
                with st.form("enisa_step1"):
                    rc1, rc2 = st.columns(2)
                    with rc1:
                        org = st.text_input("🏢 " + ("組織名" if ja else "Organisation Name"), value="J-TEC Co., Ltd.")
                        role = st.selectbox("👤 " + ("役割" if ja else "Reporter Role"),
                            ["Compliance Officer", "CISO", "Security Engineer", "Legal Counsel"])
                    with rc2:
                        country = st.selectbox("🌍 " + ("登録国" if ja else "Country of Registration"),
                            ["Japan", "Germany", "France", "Italy", "Spain", "Ireland"])
                        contact = st.text_input("📧 " + ("連絡先メール" if ja else "Contact Email"),
                            value="compliance@jtec.co.jp", placeholder="compliance@company.com")
                    st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                        padding:10px 14px;font-size:0.78rem;color:#374151">
                        <b>{'記入前の確認' if ja else 'Pre-submission declaration'}</b><br>
                        {'私は、CRA 第14条に基づき、本脆弱性報告書の情報が正確かつ完全であることを宣言します。' if ja else
                         'I declare that the information in this vulnerability report is accurate and complete to the best of my knowledge, in accordance with CRA Article 14.'}
                    </div>""", unsafe_allow_html=True)
                    st.checkbox("✅ " + ("上記の宣言に同意します" if ja else "I agree to the above declaration"), value=True)
                    if st.form_submit_button("→ " + ("次へ: 脆弱性詳細" if ja else "Next: Vulnerability Details"),
                                             use_container_width=True, type="primary"):
                        st.session_state[sim_step_key] = 2; st.rerun()

            elif cur_step == 2:
                st.markdown("#### " + ("脆弱性詳細情報" if ja else "Vulnerability Details"))
                vc1, vc2 = st.columns(2)
                with vc1:
                    st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;font-size:0.80rem">
                        <b>CVE Identifier:</b> <code>{cve_r['cve_id']}</code><br><br>
                        <b>CVSS Score:</b> {cve_r['cvss_score']} ({cve_r['severity']})<br>
                        <b>Exploit Available:</b> {"Yes ⚠️" if cve_r.get("exploit_available") else "No"}<br>
                        <b>Affected Versions:</b> {cve_r['affected_versions']['range_start']} → {cve_r['affected_versions']['range_end']}<br>
                    </div>""", unsafe_allow_html=True)
                with vc2:
                    st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;font-size:0.80rem">
                        <b>{'影響製品' if ja else 'Affected Product'}:</b> {prod_r}<br><br>
                        <b>{'報告者決定' if ja else 'Reportable Decision'}:</b> <span style="color:#dc2626;font-weight:700">REPORT</span><br>
                        <b>{'決定信頼度' if ja else 'Decision Confidence'}:</b> {results['decision_proposal']['confidence_score']:.0%}<br>
                        <b>{'審査担当者' if ja else 'Reviewer'}:</b> {rev_r['reviewer']}<br>
                    </div>""", unsafe_allow_html=True)
                with st.form("enisa_step2"):
                    st.text_area("📝 " + ("脆弱性の説明（英語）" if ja else "Vulnerability Description (English)"),
                        value=cve_r.get("description",""),height=80,
                        help="Pre-filled from CVE ingestion" if not ja else "CVE取込から自動入力")
                    st.text_area("🔧 " + ("暫定対応措置" if ja else "Interim Mitigation Measures"),
                        value="Vendor patch under development. Firewall rules applied as interim measure." if not ja
                              else "ベンダーパッチ開発中。暫定措置としてファイアウォールルールを適用。",
                        height=70)
                    sc2c1, sc2c2 = st.columns(2)
                    with sc2c1:
                        if st.form_submit_button("← " + ("戻る" if ja else "Back"), use_container_width=True):
                            st.session_state[sim_step_key] = 1; st.rerun()
                    with sc2c2:
                        if st.form_submit_button("→ " + ("次へ: 影響評価" if ja else "Next: Impact Assessment"),
                                                 use_container_width=True, type="primary"):
                            st.session_state[sim_step_key] = 3; st.rerun()

            elif cur_step == 3:
                st.markdown("#### " + ("影響評価 & 市場範囲" if ja else "Impact Assessment & Market Scope"))
                with st.form("enisa_step3"):
                    ic1, ic2 = st.columns(2)
                    with ic1:
                        st.multiselect("🌍 " + ("影響を受ける加盟国" if ja else "Affected EU Member States"),
                            ["Germany 🇩🇪", "France 🇫🇷", "Italy 🇮🇹", "Spain 🇪🇸", "Ireland 🇮🇪"],
                            default=["Germany 🇩🇪", "France 🇫🇷", "Ireland 🇮🇪"])
                        st.selectbox("⚠️ " + ("影響レベル" if ja else "Impact Severity"),
                            ["CRITICAL — Immediate action required", "HIGH — Action required within 24h",
                             "MEDIUM — Action required within 72h"], index=0)
                    with ic2:
                        st.number_input("🏭 " + ("影響を受ける製品数" if ja else "Number of Affected Products"),
                            min_value=1, max_value=100, value=1)
                        st.number_input("👥 " + ("推定影響ユーザー数" if ja else "Estimated Affected Users (approx.)"),
                            min_value=0, value=500, step=100)
                    st.markdown(f"""<div style="background:#fefce8;border:1px solid #fde68a;border-radius:8px;
                        padding:10px 14px;font-size:0.77rem;color:#92400e;margin-top:8px">
                        ⏱️ <b>{'CRA 第14条 SLA' if ja else 'CRA Article 14 SLA'}</b>:&nbsp;
                        {'能動的悪用脆弱性の早期警告は検知後 24時間以内、完全報告は 72時間以内に提出が義務です。' if ja else
                         'Early warning within 24h of detection. Full notification within 72h. Final report within 90 days.'}
                    </div>""", unsafe_allow_html=True)
                    ic3c1, ic3c2 = st.columns(2)
                    with ic3c1:
                        if st.form_submit_button("← " + ("戻る" if ja else "Back"), use_container_width=True):
                            st.session_state[sim_step_key] = 2; st.rerun()
                    with ic3c2:
                        if st.form_submit_button("→ " + ("送信確認へ" if ja else "Proceed to Submit"),
                                                 use_container_width=True, type="primary"):
                            st.session_state[sim_step_key] = 4; st.rerun()

            elif cur_step == 4:
                # Confirmation screen
                st.markdown("---")
                st.markdown(f"""
                <div style="background:#f0fdf4;border:2px solid #16a34a;border-radius:12px;padding:20px 24px;text-align:center;margin-bottom:16px">
                  <div style="font-size:2rem;margin-bottom:4px">✅</div>
                  <div style="font-size:1.1rem;font-weight:800;color:#15803d">
                    {'ENISA 提出完了' if ja else 'ENISA Submission Confirmed'}
                  </div>
                  <div style="font-size:0.85rem;color:#166534;margin-top:6px">
                    {'CRA 第14条に基づく脆弱性報告が正常に受理されました。' if ja else
                     'Your vulnerability report under CRA Article 14 has been accepted.'}
                  </div>
                </div>""", unsafe_allow_html=True)

                cc1, cc2, cc3 = st.columns(3)
                cc1.metric("🔖 " + ("参照番号" if ja else "Reference ID"), ref_id)
                cc2.metric("🕐 " + ("提出日時" if ja else "Submitted At"),
                           sub_ts[:19].replace("T"," ") if sub_ts else "—")
                cc3.metric("📋 " + ("規制条文" if ja else "Regulation"), "CRA Art. 14")

                st.markdown("##### " + ("📅 次のステップ & 締め切り" if ja else "📅 Next Steps & Deadlines"))
                deadlines = [
                    ("✅", "#16a34a", ("早期警告 — 完了" if ja else "Early Warning — DONE"),
                     ("検知後24時間以内（第14条）" if ja else "Within 24h of detection (Art. 14)")),
                    ("⏳", "#d97706", ("完全通知 — 進行中" if ja else "Full Notification — IN PROGRESS"),
                     ("検知後72時間以内" if ja else "Within 72h of detection")),
                    ("📋", "#1e40af", ("最終報告 — 保留" if ja else "Final Report — PENDING"),
                     ("インシデント解決後90日以内" if ja else "Within 90 days of resolution")),
                    ("🏛️", "#6366f1", ("国家機関への通知" if ja else "National Authority Notification"),
                     ("各加盟国のNCA/CSIRTへ通知" if ja else "Notify NCA/CSIRT in each affected member state")),
                ]
                dl_cols = st.columns(4)
                for (icon, color, title, desc), dcol in zip(deadlines, dl_cols):
                    with dcol:
                        st.markdown(f"""<div style="background:#f8fafc;border-left:4px solid {color};
                            border-radius:8px;padding:12px 14px;height:100%">
                          <div style="font-size:1.3rem">{icon}</div>
                          <div style="font-weight:700;font-size:0.82rem;color:{color};margin-top:4px">{title}</div>
                          <div style="font-size:0.72rem;color:#6b7280;margin-top:3px">{desc}</div>
                        </div>""", unsafe_allow_html=True)

                # ── Regulatory Deadline Calendar ──
                st.markdown("---")
                st.markdown("##### 📅 " + ("CRA 第14条 規制スケジュール" if ja else "CRA Article 14 Regulatory Schedule"))
                st.caption("🔴 " + ("赤い縦線 = 現在時刻　| 各バーは24h / 72h / 90日の提出期限を示します。" if ja
                                    else "Red vertical line = NOW  |  Bars show 24h early warning / 72h full notification / 90-day final report deadlines."))
                st.plotly_chart(
                    cra_deadline_gantt(enisa.get("submission_timestamp", datetime.now().isoformat()),
                                       lang="ja" if ja else "en"),
                    use_container_width=True
                )

                st.markdown("")
                if st.button("🔄 " + ("新しいシミュレーションを開始" if ja else "Run New Simulation"),
                             use_container_width=False):
                    st.session_state[sim_step_key] = 1; st.rerun()

                st.markdown("---")
                with st.expander(t("t6_payload_preview")):
                    st.json(generate_enisa_submission_json(
                        decision=results["review_result"], cve=results["cve"],
                        product_name=results["product_name"], sbom_match=results["sbom_match"],
                        submission_id=results["enisa_result"]["submission_id"]))

    with tab7:
        st.subheader(t("t7_header"))
        _cve    = results["cve"]
        _prod   = results["product_name"]
        _proddata = PRODUCTS.get(_prod, {})
        _match  = results["sbom_match"]
        _dec    = results["review_result"]
        _audit  = results["audit_trail"]
        _sid    = results["enisa_result"]["submission_id"]
        _scen   = results["scenario_name"]

        # Pre-generate all artifacts
        _html_report  = generate_compliance_artifact_html(
            decision_id=_dec["decision_id"], cve=_cve, product_name=_prod,
            sbom_match=_match, decision=_dec, audit_trail=_audit)
        _enisa_basic  = generate_enisa_submission_json(
            decision=_dec, cve=_cve, product_name=_prod,
            sbom_match=_match, submission_id=_sid)
        _enisa_full   = generate_enisa_article14_json(
            decision=_dec, cve=_cve, product_name=_prod, product_data=_proddata,
            sbom_match=_match, submission_id=_sid, audit_trail=_audit)
        _cyclonedx    = generate_cyclonedx_sbom(
            product_name=_prod, product_data=_proddata,
            cve=_cve, sbom_match=_match)
        _csv_bytes    = generate_audit_csv(
            audit_trail=_audit, cve_id=_cve["cve_id"],
            product_name=_prod, decision_type=_dec["final_decision_type"])
        _pdf_bytes    = generate_pdf_report(
            cve=_cve, product_name=_prod, product_data=_proddata,
            sbom_match=_match, decision=_dec,
            audit_trail=_audit, scenario_name=_scen)

        cveid = _cve["cve_id"]

        # ── Row 1: PDF + HTML ──
        st.markdown("##### 📄 " + ("監査レポート" if ja else "Audit Reports"))
        r1c1, r1c2 = st.columns(2)
        with r1c1:
            st.markdown("**📕 PDF Compliance Report**")
            st.caption("Branded A4 PDF with full audit trail, rules applied, and decision justification. Best for client-facing distribution." if not ja
                       else "監査証跡・適用ルール・決定理由を含むA4ブランドPDF。クライアント配布に最適。")
            if _pdf_bytes:
                st.download_button(
                    label="⬇️ Download PDF Report",
                    data=_pdf_bytes,
                    file_name=f"CRA-Report-{cveid}.pdf",
                    mime="application/pdf",
                    use_container_width=True, type="primary")
            else:
                st.warning("ReportLab not available in this environment.")
        with r1c2:
            st.markdown("**🌐 HTML Compliance Artifact**")
            st.caption("Self-contained HTML report — open in any browser, print to PDF, or embed in portals." if not ja
                       else "単体HTMLレポート — ブラウザで表示・PDF印刷・ポータル埋め込み可能。")
            st.download_button(
                label="⬇️ Download HTML Report",
                data=_html_report,
                file_name=f"CRA-{cveid}.html",
                mime="text/html",
                use_container_width=True)

        st.markdown("---")

        # ── Row 2: ENISA JSON (Basic + Full Article 14) ──
        st.markdown("##### 🏛️ " + ("ENISA報告データ" if ja else "ENISA Reporting Data"))
        r2c1, r2c2 = st.columns(2)
        with r2c1:
            st.markdown("**📋 ENISA Submission JSON** *(Basic)*")
            st.caption("Compact submission payload — matches the ENISA vulnerability portal intake format." if not ja
                       else "コンパクトな提出ペイロード — ENISAポータル受付フォーマット準拠。")
            st.download_button(
                label="⬇️ Download ENISA JSON",
                data=json.dumps(_enisa_basic, indent=2),
                file_name=f"ENISA-Basic-{cveid}.json",
                mime="application/json",
                use_container_width=True)
        with r2c2:
            st.markdown("**📜 CRA Article 14 Full Notification JSON**")
            st.caption("Full structured Article 14 payload: timeline, evidence block, affected markets, regulator metadata." if not ja
                       else "完全な第14条構造化ペイロード：タイムライン・証拠・影響市場・規制機関メタデータ含む。")
            st.download_button(
                label="⬇️ Download Article 14 JSON",
                data=json.dumps(_enisa_full, indent=2),
                file_name=f"ENISA-Article14-{cveid}.json",
                mime="application/json",
                use_container_width=True)

        # Preview toggle
        with st.expander("👁️ " + ("Article 14 JSONプレビュー" if ja else "Preview Article 14 JSON")):
            st.json(_enisa_full)

        st.markdown("---")

        # ── Row 3: SBOM CycloneDX + CSV Audit Log ──
        st.markdown("##### 📦 " + ("SBOM・監査ログ" if ja else "SBOM & Audit Log"))
        r3c1, r3c2 = st.columns(2)
        with r3c1:
            st.markdown("**🔩 CycloneDX 1.6 SBOM Export**")
            st.caption("Industry-standard Software Bill of Materials in CycloneDX JSON format. Vulnerable component annotated inline." if not ja
                       else "CycloneDX JSON形式の業界標準SBOM。脆弱コンポーネントをインラインで注釈付き。")
            st.download_button(
                label="⬇️ Download CycloneDX SBOM",
                data=json.dumps(_cyclonedx, indent=2),
                file_name=f"SBOM-CycloneDX-{_prod.replace(' ','-')}-{cveid}.json",
                mime="application/json",
                use_container_width=True)
        with r3c2:
            st.markdown("**📊 Audit Trail CSV / Excel**")
            st.caption("Complete pipeline audit log as CSV — open directly in Excel, import to SIEM, or attach to ENISA submission." if not ja
                       else "完全なパイプライン監査ログCSV — Excel直接表示・SIEM取込み・ENISA提出添付に対応。")
            st.download_button(
                label="⬇️ Download Audit Log CSV",
                data=_csv_bytes,
                file_name=f"AuditLog-{cveid}-{_prod.replace(' ','-')}.csv",
                mime="text/csv",
                use_container_width=True)

        # SBOM preview
        with st.expander("👁️ " + ("CycloneDX SBOMプレビュー" if ja else "Preview CycloneDX SBOM")):
            st.json(_cyclonedx)

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
