"""
CRA Decision Traceability System — Dashboard & Pipeline Runner
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from collections import Counter

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from decision_engine import DecisionEngine
from translations import t, SCENARIO_JA
from utils import inject_css, decision_badge, pipeline_stepper, lang_toggle_sidebar, sidebar_current_run, sidebar_home_button
from readiness_widgets import render_personalized_banner, render_personalized_cta, sidebar_readiness_score

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Session state init ──
if "lang"             not in st.session_state: st.session_state.lang             = "en"
if "runs_log"         not in st.session_state: st.session_state.runs_log         = []
if "pipeline_results" not in st.session_state: st.session_state.pipeline_results = None
if "pipeline_phase"   not in st.session_state: st.session_state.pipeline_phase   = "idle"
if "pre_review"       not in st.session_state: st.session_state.pre_review       = None
if "run_triggered"    not in st.session_state: st.session_state.run_triggered    = None
if "engine"           not in st.session_state:
    st.session_state.engine = DecisionEngine(
        products=PRODUCTS, cve_scenarios=CVE_SCENARIOS,
        decision_rules=DECISION_RULES, thresholds=THRESHOLDS
    )

inject_css()
ja = st.session_state.lang == "ja"


# ─────────────────────────────────────────────
#  Pipeline functions (run from dashboard)
# ─────────────────────────────────────────────

def run_stages_1_to_4(scenario_key, product_name):
    engine = st.session_state.engine; engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]; cve_id = scenario["cve_id"]
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
    return {"scenario_key": scenario_key, "scenario_name": scenario["name"],
            "product_name": product_name, "cve": cve, "sbom_match": sbom_match,
            "conflict_info": conflict_info, "decision_proposal": decision_proposal,
            "partial_audit_trail": engine.get_audit_trail()}


def run_pipeline(scenario_key, product_name):
    engine = st.session_state.engine; engine.reset_audit_trail()
    scenario = CVE_SCENARIOS[scenario_key]; cve_id = scenario["cve_id"]
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
    results = {"scenario_key": scenario_key, "scenario_name": scenario["name"],
               "product_name": product_name, "cve": cve, "sbom_match": sbom_match,
               "conflict_info": conflict_info, "decision_proposal": decision_proposal,
               "review_result": review_result, "enisa_result": enisa_result,
               "audit_trail": engine.get_audit_trail()}
    st.session_state.runs_log.append({
        "scenario": scenario["name"].split(":")[0].split("：")[0],
        "decision": review_result["final_decision_type"],
        "product": product_name,
        "ts": datetime.now().strftime("%H:%M:%S"),
    })
    return results


# ─────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────

with st.sidebar:
    ja = lang_toggle_sidebar()
    ja = st.session_state.lang == "ja"

    st.markdown("---")
    st.header(t("sidebar_scenarios"))

    selected_scenario = st.selectbox(
        t("sidebar_choose"),
        options=list(CVE_SCENARIOS.keys()),
        format_func=lambda k: t(f"scenario_{k}_name"),
        key="scenario_selector"
    )
    s = CVE_SCENARIOS[selected_scenario]
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(s["severity"], "⚪")
    human_flag = t("sidebar_human_flag") if s.get("human_review_required") else ""
    st.markdown(f"> **CVE:** `{s['cve_id']}`\n> **{t('metric_severity')}:** {sev_icon} {s['severity']} (CVSS {s['cvss_score']})\n{human_flag}")

    _sideinfo = {
        "scenario_a": ("Tests: critical exploit present → auto REPORT",   "テスト: 重大エクスプロイト → 自動報告"),
        "scenario_b": ("Tests: component absent in SBOM → NOT REPORT",    "テスト: SBOMに未存在 → 報告不要"),
        "scenario_c": ("Tests: VEX conflict → human escalation",          "テスト: VEX矛盾 → 人的エスカレーション"),
        "scenario_d": ("Tests: ambiguous medium CVE → you decide",        "テスト: 曖昧な中程度CVE → あなたが判断"),
    }
    en_note, ja_note = _sideinfo.get(selected_scenario, ("", ""))
    st.caption("ℹ️ " + (ja_note if ja else en_note))

    st.markdown("---")
    st.header(t("sidebar_product_header"))
    product_names = list(PRODUCTS.keys())
    default_idx = {"scenario_a": 1, "scenario_b": 0, "scenario_c": 2, "scenario_d": 2}.get(selected_scenario, 0)
    selected_product = st.selectbox(t("sidebar_product_label"), product_names, index=default_idx)
    prod = PRODUCTS[selected_product]
    with st.expander(t("sidebar_sbom_expander", n=len(prod["sbom"]["components"]))):
        for c in prod["sbom"]["components"]:
            st.caption(f"• {c['name']} v{c['version']} ({c['vendor']})")

    st.markdown("---")
    run_btn = st.button(t("sidebar_run_btn"), use_container_width=True, type="primary")
    if run_btn:
        st.session_state.pipeline_phase   = "idle"
        st.session_state.pre_review       = None
        st.session_state.pipeline_results = None
        st.session_state.run_triggered    = {"scenario": selected_scenario, "product": selected_product}
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
    sidebar_readiness_score()
    st.page_link("pages/0_Readiness_Check.py",
                 label="🛡️ " + ("CRA準備状況評価" if ja else "CRA Readiness Assessment"))
    st.page_link("pages/7_Accountability.py",
                 label="🔍 " + ("説明責任レコード" if ja else "Accountability Record"))
    sidebar_current_run()
    st.markdown("---")
    sidebar_home_button()


# ─────────────────────────────────────────────
#  MAIN AREA — header
# ─────────────────────────────────────────────

st.title(f"🔐 {t('app_title')}")
st.markdown(f"**{t('app_subtitle')}**")
st.markdown("---")

# ── Execute pipeline (deferred from sidebar) ──
if st.session_state.run_triggered:
    trig = st.session_state.run_triggered
    st.session_state.run_triggered = None
    if CVE_SCENARIOS[trig["scenario"]].get("human_review_required"):
        st.session_state.pre_review    = run_stages_1_to_4(trig["scenario"], trig["product"])
        st.session_state.pipeline_phase = "awaiting_human"
    else:
        st.session_state.pipeline_results = run_pipeline(trig["scenario"], trig["product"])
        st.session_state.pipeline_phase   = "complete"
    st.rerun()


# ─────────────────────────────────────────────
#  STATE: Awaiting Human Review
# ─────────────────────────────────────────────

if st.session_state.pipeline_phase == "awaiting_human" and st.session_state.pre_review:
    pre      = st.session_state.pre_review
    proposal = pre["decision_proposal"]

    st.markdown(t("section_pipeline"))
    pipeline_stepper(completed=4)
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric(t("metric_cve"),        pre["cve"]["cve_id"])
    col2.metric(t("metric_cvss"),       pre["cve"]["cvss_score"])
    col3.metric(t("metric_severity"),   pre["cve"]["severity"])
    col4.metric(t("metric_confidence"), f"{proposal['confidence_score']:.0%}",
                delta=t("hr_below_threshold"))

    st.markdown(f"""
    <div style="background:#fff7ed;border-left:5px solid #d97706;border-radius:8px;
                padding:18px 22px;margin:16px 0">
      <div style="font-size:1.05rem;font-weight:800;color:#92400e;margin-bottom:6px">
        👤 {'人的レビューが必要です — パイプラインが一時停止中' if ja else 'Human Review Required — Pipeline Paused at Stage 5'}
      </div>
      <div style="font-size:0.85rem;color:#78350f;margin-bottom:10px">
        {'自動判定の信頼スコアが閾値を下回っています。コンプライアンス担当者が「Decision Analysis」ページで最終判断を行ってください。'
         if ja else
         'The automated confidence score is below the auto-decide threshold. '
         'A compliance officer must review the evidence and confirm the final decision on the Decision Analysis page.'}
      </div>
    </div>""", unsafe_allow_html=True)

    st.page_link("pages/2_Decision.py",
                 label="⚖️ " + ("Decision Analysis ページで審査を完了する →"
                                 if ja else "Go to Decision Analysis to complete review →"))


# ─────────────────────────────────────────────
#  STATE: Complete — 3-Act Navigation Cards
# ─────────────────────────────────────────────

elif st.session_state.pipeline_phase == "complete" and st.session_state.pipeline_results:
    results = st.session_state.pipeline_results
    final   = results["review_result"]["final_decision_type"]

    # Decision banner
    st.markdown(f"{t('section_decision_banner')} {decision_badge(final)}", unsafe_allow_html=True)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric(t("metric_scenario"),  results["scenario_name"].split(":")[0].split("：")[0])
    c2.metric(t("metric_product"),   results["product_name"])
    c3.metric(t("metric_cve"),       results["cve"]["cve_id"])
    c4.metric(t("metric_cvss"),      results["cve"]["cvss_score"])
    c5.metric(t("metric_severity"),  results["cve"]["severity"])

    if final == "REPORT":
        st.markdown(f"""
        <div style="background:#eff6ff;border-left:5px solid #1e40af;border-radius:8px;
                    padding:12px 18px;margin:10px 0">
          <b style="color:#1e3a8a;font-size:0.85rem">
            {'⚠️ ENISA報告義務が発動 — 規制ライフサイクル開始' if ja
             else '⚠️ ENISA reporting obligation triggered — Regulatory lifecycle now active'}
          </b>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### " + ("📋 詳細結果を探索する — 3つのアクト" if ja
                          else "📋 Explore Full Results — 3 Acts"))
    st.caption("" + ("各カードのリンクをクリックして詳細ページへ移動してください。"
                     if ja else
                     "Click a link on any card to open that page's full detail view."))
    st.markdown("")

    cve_r    = results["cve"]
    sbom_r   = results["sbom_match"]
    conf_r   = results["decision_proposal"]
    enisa_r  = results["enisa_result"]
    rev_r    = results["review_result"]

    act1, act2, act3 = st.columns(3, gap="large")

    # ── Act 1 ──
    with act1:
        s_match = ("🔴 " + ("一致あり" if ja else "MATCHED")) if sbom_r["match_found"] else ("🟢 " + ("一致なし" if ja else "NO MATCH"))
        s_conf  = ("⚠️ " + ("矛盾検出" if ja else "CONFLICT")) if results["conflict_info"]["conflict_detected"] else ("✅ " + ("矛盾なし" if ja else "NONE"))
        st.markdown(f"""
        <div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:12px;
                    padding:22px 20px;border-top:5px solid #0ea5e9;min-height:200px">
          <div style="font-size:1.25rem;font-weight:800;color:#0369a1;margin-bottom:14px">
            🔍 {'アクト 1' if ja else 'Act 1'} — {'検出' if ja else 'Detection'}
          </div>
          <div style="font-size:0.82rem;color:#374151;line-height:2.1">
            <b>CVE:</b> {cve_r['cve_id']}<br>
            <b>CVSS:</b> {cve_r['cvss_score']} — {cve_r['severity']}<br>
            <b>{'SBOMマッチ' if ja else 'SBOM Match'}:</b> {s_match}<br>
            <b>{'矛盾' if ja else 'Conflict'}:</b> {s_conf}
          </div>
        </div>""", unsafe_allow_html=True)
        st.markdown("")
        st.page_link("pages/1_Detection.py",
                     label="🔍 " + ("CVE検出・SBOM・矛盾の詳細 →" if ja
                                     else "CVE · SBOM · Conflict Details →"))

    # ── Act 2 ──
    with act2:
        auto_lbl = ("✅ " + ("自動判定" if ja else "Auto-decided")) if conf_r["auto_decidable"] \
               else ("👤 " + ("人的判定" if ja else "Human-decided"))
        st.markdown(f"""
        <div style="background:#f5f3ff;border:1px solid #ddd6fe;border-radius:12px;
                    padding:22px 20px;border-top:5px solid #7c3aed;min-height:200px">
          <div style="font-size:1.25rem;font-weight:800;color:#6d28d9;margin-bottom:14px">
            ⚖️ {'アクト 2' if ja else 'Act 2'} — {'判定' if ja else 'Decision'}
          </div>
          <div style="font-size:0.82rem;color:#374151;line-height:2.1">
            <b>{'判定' if ja else 'Decision'}:</b> {conf_r['decision_type']}<br>
            <b>{'信頼度' if ja else 'Confidence'}:</b> {conf_r['confidence_score']:.0%}<br>
            <b>{'方式' if ja else 'Method'}:</b> {auto_lbl}<br>
            <b>{'審査者' if ja else 'Reviewer'}:</b> {rev_r['reviewer']}
          </div>
        </div>""", unsafe_allow_html=True)
        st.markdown("")
        st.page_link("pages/2_Decision.py",
                     label="⚖️ " + ("信頼スコア・審査・通知の詳細 →" if ja
                                     else "Confidence · Review · Notification →"))

    # ── Act 3 ──
    with act3:
        enisa_lbl = ("✅ " + ("提出済み" if ja else "SUBMITTED")) if enisa_r["submitted"] \
                else ("⬜ " + ("対象外" if ja else "NOT APPLICABLE"))
        ref_short = (enisa_r["enisa_reference_id"][:20] + "…") if enisa_r.get("enisa_reference_id") else "—"
        st.markdown(f"""
        <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;
                    padding:22px 20px;border-top:5px solid #16a34a;min-height:200px">
          <div style="font-size:1.25rem;font-weight:800;color:#15803d;margin-bottom:14px">
            📡 {'アクト 3' if ja else 'Act 3'} — {'報告' if ja else 'Reporting'}
          </div>
          <div style="font-size:0.82rem;color:#374151;line-height:2.1">
            <b>ENISA:</b> {enisa_lbl}<br>
            <b>Ref:</b> {ref_short}<br>
            <b>{'ダウンロード' if ja else 'Downloads'}:</b> {'6件準備完了 📦' if ja else '6 artifacts ready 📦'}<br>
            <b>{'規制' if ja else 'Regulation'}:</b> CRA Art. 14
          </div>
        </div>""", unsafe_allow_html=True)
        st.markdown("")
        st.page_link("pages/3_Reporting.py",
                     label="📡 " + ("ENISA提出・期限・ダウンロード →" if ja
                                     else "ENISA Submission · Deadlines · Downloads →"))

    st.markdown("")
    if final == "REPORT":
        st.page_link("pages/4_Compliance.py",
                     label="📋 " + ("報告後の規制ライフサイクルを管理する →" if ja
                                     else "Manage Post-Reporting Compliance Lifecycle →"))

    # ── Personalised CTA (shown if user came from readiness check) ──
    render_personalized_cta()

    st.markdown("---")

    # Pipeline stepper (full)
    st.markdown(t("section_pipeline"))
    pipeline_stepper(completed=6)
    st.markdown("---")


# ─────────────────────────────────────────────
#  IDLE — Scenario Quick Reference
# ─────────────────────────────────────────────

if st.session_state.pipeline_phase == "idle":
    # ── Personalized banner (shown when coming from readiness check) ──
    render_personalized_banner()

    _SCEN_INFO = {
        "scenario_a": {
            "color": "#ff4b4b", "bg": "#fff5f5", "icon": "🔴",
            "en": {"title": "Scenario A — REPORT Required",
                   "condition": "CVSS 9.8 CRITICAL · Exploit available · Component matched in SBOM",
                   "what": "A critical known-exploited vulnerability is found in an active product component.",
                   "outcome": "Automatic REPORT to ENISA within 24h (Article 14 obligation triggered)"},
            "ja": {"title": "シナリオ A — 報告義務あり",
                   "condition": "CVSS 9.8 クリティカル · エクスプロイトあり · SBOMコンポーネント一致",
                   "what": "既知の悪用済み重大脆弱性が製品コンポーネントで検出。",
                   "outcome": "24時間以内にENISAへ自動報告（第14条義務発動）"},
        },
        "scenario_b": {
            "color": "#21c354", "bg": "#f0fff4", "icon": "🟢",
            "en": {"title": "Scenario B — NOT REPORT",
                   "condition": "CVSS 7.5 HIGH · No exploit · Component NOT in SBOM",
                   "what": "A high-severity CVE is found but the affected component is absent from the SBOM.",
                   "outcome": "No reporting required — vulnerability does not affect this product"},
            "ja": {"title": "シナリオ B — 報告不要",
                   "condition": "CVSS 7.5 HIGH · エクスプロイトなし · SBOMに該当なし",
                   "what": "高深刻度CVEが存在するが、対象コンポーネントはSBOMに含まれない。",
                   "outcome": "報告不要 — この製品に対して脆弱性の影響なし"},
        },
        "scenario_c": {
            "color": "#ffa500", "bg": "#fff8ec", "icon": "🟠",
            "en": {"title": "Scenario C — Conflicting Evidence",
                   "condition": "CVSS 8.1 HIGH · VEX 'not_affected' claim · But component matched",
                   "what": "VEX claims not affected, but SBOM matching shows the component is present.",
                   "outcome": "Conflict flagged → Human review escalation"},
            "ja": {"title": "シナリオ C — 証拠の矛盾",
                   "condition": "CVSS 8.1 HIGH · VEX「影響なし」 · SBOMコンポーネント一致",
                   "what": "VEXは影響なしと主張するが、SBOMマッチングでコンポーネントが存在することが判明。",
                   "outcome": "矛盾検出 → 人的レビューへエスカレーション"},
        },
        "scenario_d": {
            "color": "#7c3aed", "bg": "#f5f3ff", "icon": "👤",
            "en": {"title": "Scenario D — Human Decision Required",
                   "condition": "CVSS 6.8 MEDIUM · No exploit · Partial VEX mitigation only",
                   "what": "Ambiguous case: moderate CVSS, no active exploit, VEX shows partial mitigation.",
                   "outcome": "Human review panel activates — you make the compliance decision"},
            "ja": {"title": "シナリオ D — 人的判断が必要",
                   "condition": "CVSS 6.8 MEDIUM · エクスプロイトなし · VEX部分的緩和のみ",
                   "what": "曖昧なケース：中程度のCVSS、悪用なし、VEXはFW緩和を示すがコンポーネントは存在。",
                   "outcome": "人的レビューパネルが起動 — あなたがコンプライアンス判断を行う"},
        },
    }
    with st.expander("📖 " + ("シナリオ早見表 — 実行前にご確認ください" if ja
                               else "Scenario Quick Reference — What each scenario tests"), expanded=False):
        sc1, sc2, sc3, sc4 = st.columns(4)
        for col, (sk, info) in zip([sc1, sc2, sc3, sc4], _SCEN_INFO.items()):
            d = info["ja" if ja else "en"]
            with col:
                st.markdown(f"""<div style="border-radius:10px;padding:14px;
                    border-left:5px solid {info['color']};background:{info['bg']}">
                  <div style="font-weight:800;font-size:0.88rem;margin-bottom:6px">
                    {info['icon']} {d['title']}</div>
                  <div style="font-size:0.74rem;color:#374151;margin-bottom:6px">
                    <b>{'条件' if ja else 'Condition'}:</b> {d['condition']}</div>
                  <div style="font-size:0.73rem;color:#555;margin-bottom:6px">{d['what']}</div>
                  <div style="font-size:0.72rem;font-weight:600;color:{info['color']}">{d['outcome']}</div>
                </div>""", unsafe_allow_html=True)
    st.markdown("")

    # ── CRA Readiness Assessment CTA ──
    ra_col, _ = st.columns([3, 1])
    with ra_col:
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
            border-radius: 14px;
            padding: 26px 32px;
            color: white;
            margin-bottom: 12px;
        ">
            <div style="font-size:1.7rem; margin-bottom:6px;">🛡️</div>
            <div style="font-size:1.15rem; font-weight:800; margin-bottom:6px;">
                {'CRA準備状況評価 — 御社は対応できていますか？' if ja
                 else 'CRA Readiness Assessment — Is your organisation prepared?'}
            </div>
            <div style="font-size:0.88rem; color:#bfdbfe; margin-bottom:4px;">
                {'8問 · 約5分 · パーソナライズされたアクションプランと無料レポート'
                 if ja else
                 '8 questions · 5 minutes · Personalised action plan + free report'}
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.page_link(
            "pages/0_Readiness_Check.py",
            label="🛡️ " + ("CRA準備状況評価を開始する →" if ja
                            else "Start CRA Readiness Assessment →"),
        )

    st.markdown("---")


# ─────────────────────────────────────────────
#  DASHBOARD — always visible
# ─────────────────────────────────────────────

runs = st.session_state.runs_log


def _product_cards(is_ja):
    pc = st.columns(3)
    colors = [("#6366f1", "#f5f3ff"), ("#0ea5e9", "#f0f9ff"), ("#10b981", "#f0fdf4")]
    for col, (pname, p), (clr, bg) in zip(pc, PRODUCTS.items(), colors):
        comps = p["sbom"]["components"]
        with col:
            st.markdown(f"""<div style="border-radius:10px;padding:14px;
                border-left:5px solid {clr};background:{bg}">
              <div style="font-weight:800;font-size:0.95rem">{pname}</div>
              <div style="font-size:0.78rem;color:#555;margin-top:2px">{p['type']}</div>
              <div style="font-size:0.76rem;color:#888;margin-top:4px">
                v{p['version']} · {len(comps)} {"コンポーネント" if is_ja else "components"}</div>
            </div>""", unsafe_allow_html=True)
            with st.expander("SBOM"):
                for c in comps:
                    st.caption(f"• **{c['name']}** v{c['version']}")


st.markdown("### " + ("📊 システム概要" if ja else "📊 System Overview"))

stage_labels = (["CVE取込", "SBOM照合", "矛盾検出", "決定ルール", "人的レビュー", "ENISA報告"] if ja
                else ["CVE Ingestion", "SBOM Matching", "Conflict Detection",
                      "Decision Rules", "Human Review", "ENISA Reporting"])
cols = st.columns(6)
for col, label in zip(cols, stage_labels):
    with col:
        st.markdown(f'<div class="ready-pill"><div class="ready-dot"></div>{label}</div>',
                    unsafe_allow_html=True)
st.caption("✅ " + ("全6ステージ稼働中" if ja else "All 6 stages operational"))
st.markdown("---")

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("🏭 " + ("対象製品" if ja else "Products"),  len(PRODUCTS))
k2.metric("📏 " + ("決定ルール" if ja else "Rules"),    len(DECISION_RULES))
k3.metric("🗂️ " + ("シナリオ" if ja else "Scenarios"), len(CVE_SCENARIOS))
k4.metric("▶️ " + ("実行済み" if ja else "Runs"),       len(runs))
report_count = sum(1 for r in runs if r["decision"] == "REPORT")
k5.metric("🔴 REPORT", report_count,
          delta=f"+{report_count}" if report_count else None,
          delta_color="inverse" if report_count else "off")
st.markdown("---")

# Session decision chart + Products
if runs:
    stat_col, prod_col = st.columns([2, 3], gap="large")
    with stat_col:
        st.markdown("#### " + ("セッション決定内訳" if ja else "Session Decision Breakdown"))
        counts = Counter(r["decision"] for r in runs)
        fig = go.Figure(go.Pie(
            labels=list(counts.keys()), values=list(counts.values()), hole=0.55,
            marker=dict(colors=[{"REPORT": "#ff4b4b", "NOT_REPORT": "#21c354",
                                  "CONFLICT": "#ffa500", "ESCALATED": "#7c3aed"}.get(l, "#aaa")
                                 for l in counts]),
            textinfo="label+percent"))
        fig.update_layout(title=("決定内訳" if ja else "Decisions"), height=260,
                          margin=dict(t=40, b=10, l=10, r=10), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    with prod_col:
        st.markdown("#### " + ("🏭 J-TEC 製品" if ja else "🏭 J-TEC Products"))
        _product_cards(ja)
else:
    st.markdown("#### " + ("🏭 J-TEC 製品" if ja else "🏭 J-TEC Products"))
    _product_cards(ja)

st.markdown("---")

# Decision rules grid
st.markdown("#### " + ("📏 決定ルール" if ja else "📏 Decision Rules"))
rule_cols = st.columns(3)
rule_colors = {"REPORT": ("#fff5f5", "#ff4b4b"), "NOT_REPORT": ("#f0fff4", "#21c354"),
               "CONFLICT": ("#fff8ec", "#ffa500"), "HUMAN_REVIEW": ("#f5f3ff", "#7c3aed")}
for i, rule in enumerate(DECISION_RULES):
    bg, accent = rule_colors.get(rule["action"], ("#f9fafb", "#6b7280"))
    auto_label = ("✅ 自動" if ja else "✅ Auto") if rule["auto_decidable"] else ("👤 人的" if ja else "👤 Human")
    with rule_cols[i % 3]:
        st.markdown(f"""<div style="border-radius:8px;padding:12px 14px;background:{bg};
            border-left:4px solid {accent};margin-bottom:10px">
          <div style="font-weight:700;font-size:0.88rem">{rule['rule_id']} — {rule['name']}</div>
          <div style="font-size:0.75rem;color:#6b7280;margin-top:4px">{rule['condition']}</div>
          <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
            <span style="background:{accent};color:white;padding:2px 8px;border-radius:10px;
              font-size:0.72rem;font-weight:600">{rule['action']}</span>
            <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;
              font-size:0.72rem">{auto_label}</span>
            <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;
              font-size:0.72rem">conf {rule['confidence_boost']:.0%}</span>
          </div>
        </div>""", unsafe_allow_html=True)

st.markdown("---")

# Market coverage
st.markdown("#### " + ("🌍 市場カバレッジ & 規制管轄" if ja else "🌍 Market Coverage & Regulatory Jurisdiction"))
st.caption("各市場の監督機関・CSIRT・適用法令。英国はEU外のためCRAは適用されません。" if ja else
           "National authorities, CSIRTs, and applicable regulation per market. UK is non-EU — CRA does not apply.")
_MARKET = [
    {"flag":"🇩🇪","name":"Germany",        "name_ja":"ドイツ",       "nca":"BSI",           "csirt":"CERT-Bund",   "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇫🇷","name":"France",         "name_ja":"フランス",     "nca":"ANSSI",         "csirt":"CERT-FR",     "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇮🇹","name":"Italy",          "name_ja":"イタリア",     "nca":"ACN",           "csirt":"CSIRT Italia","reg":"CRA 2024/2847","eu":True },
    {"flag":"🇪🇸","name":"Spain",          "name_ja":"スペイン",     "nca":"CCN / INCIBE",  "csirt":"CCN-CERT",    "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇮🇪","name":"Ireland",        "name_ja":"アイルランド", "nca":"NCSC Ireland",  "csirt":"NCSC-IE",     "reg":"CRA 2024/2847","eu":True },
    {"flag":"🇬🇧","name":"United Kingdom", "name_ja":"英国",         "nca":"DSIT / NCSC UK","csirt":"NCSC UK",     "reg":"PSTI Act 2022","eu":False},
]
mkt_cols = st.columns(3)
for i, c in enumerate(_MARKET):
    bg = "#f0fff4" if c["eu"] else "#fff8ec"
    border = "#21c354" if c["eu"] else "#ffa500"
    cname = c["name_ja"] if ja else c["name"]
    note  = ("EU加盟国 · CRA第14条 報告義務あり" if ja else "EU Member · Article 14 reporting required") if c["eu"] \
          else ("⚠️ EU外 · CRA非適用 · PSTI法 2022" if ja else "⚠️ Non-EU · CRA N/A · PSTI Act 2022")
    with mkt_cols[i % 3]:
        st.markdown(f"""<div style="border-radius:8px;padding:12px 14px;background:{bg};
            border-left:4px solid {border};margin-bottom:10px">
          <div style="font-weight:700;font-size:1rem">{c['flag']} {cname}</div>
          <div style="font-size:0.74rem;color:#374151;margin-top:5px">
            {'監督機関' if ja else 'NCA'}: <b>{c['nca']}</b></div>
          <div style="font-size:0.74rem;color:#374151">CSIRT: <b>{c['csirt']}</b></div>
          <div style="margin-top:6px">
            <span style="background:{border};color:white;padding:2px 8px;border-radius:10px;
              font-size:0.7rem;font-weight:600">{c['reg']}</span></div>
          <div style="font-size:0.7rem;color:#6b7280;margin-top:5px">{note}</div>
        </div>""", unsafe_allow_html=True)

with st.expander("ℹ️ " + ("国ごとの違いについて" if ja else "How country differences are handled")):
    if ja:
        st.markdown("""
**EU加盟国（ドイツ・フランス・イタリア・スペイン・アイルランド）**
- EU CRA 2024/2847 第14条が一律適用
- 能動的に悪用された脆弱性は**24時間以内**にENISAおよび各国CSIRTに報告義務
- 各国の監督機関（NCA）が市場監視を担当

**英国 🇬🇧**
- EUを離脱しているためCRAは**適用されません**
- 代わりにPSTI法（製品セキュリティ・通信インフラ法）2022が適用（2024年4月施行）
""")
    else:
        st.markdown("""
**EU Member States (Germany, France, Italy, Spain, Ireland)**
- EU CRA 2024/2847 Article 14 applies uniformly across all EU members
- Actively exploited vulnerabilities must be reported to **ENISA + national CSIRT within 24 hours**

**United Kingdom 🇬🇧**
- UK left the EU — **CRA does not apply**
- Instead: **PSTI Act 2022** (Product Security & Telecommunications Infrastructure Act), in force April 2024
""")

st.markdown("---")
st.markdown(f"<div style='text-align:center;font-size:12px;color:gray;'>🔐 {t('footer')}</div>",
            unsafe_allow_html=True)
st.markdown(f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
            f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",
            unsafe_allow_html=True)
