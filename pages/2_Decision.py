"""
Act 2 — Decision Analysis
Stages 4-5: Confidence Score Explainer · Human Review · Customer Notification
"""

import streamlit as st
from datetime import datetime

from translations import t
from mock_data import THRESHOLDS, DECISION_RULES
from utils import (inject_css, lang_toggle_sidebar, sidebar_current_run,
                   sidebar_home_button, no_results_guard,
                   pipeline_stepper, cvss_gauge, sbom_table, decision_badge,
                   confidence_explainer_chart, complete_pipeline)
from readiness_widgets import render_key_stage_badge, render_stage_insights, render_personalized_cta, sidebar_readiness_score

st.set_page_config(
    page_title="Act 2: Decision — CRA System",
    page_icon="⚖️",
    layout="wide"
)

if "lang" not in st.session_state: st.session_state.lang = "en"

inject_css()

# ── Sidebar ──
with st.sidebar:
    lang_toggle_sidebar()
    ja = st.session_state.lang == "ja"
    sidebar_current_run()
    st.markdown("---")
    st.markdown("##### " + ("ナビゲーション" if ja else "Navigation"))
    st.page_link("app.py",                label="🏠 " + ("ダッシュボード" if ja else "Dashboard"))
    st.page_link("pages/1_Detection.py",  label="🔍 " + ("Act 1 — 検出" if ja else "Act 1 — Detection"))
    st.page_link("pages/3_Reporting.py",  label="📡 " + ("Act 3 — 報告" if ja else "Act 3 — Reporting"))
    st.page_link("pages/4_Compliance.py", label="📋 " + ("コンプライアンス" if ja else "Compliance"))
    st.page_link("pages/5_History.py",    label="📚 " + ("履歴" if ja else "History"))
    sidebar_readiness_score()
    st.markdown("---")
    sidebar_home_button()

ja = st.session_state.lang == "ja"

st.title("⚖️ " + ("アクト 2 — 判定分析" if ja else "Act 2 — Decision Analysis"))
st.markdown("**" + ("信頼スコア解説 · 人的審査 · 顧客通知 — パイプラインのステージ 4-5"
                    if ja else
                    "Confidence Explainer · Human Review · Customer Notification — Pipeline Stages 4–5") + "**")
st.markdown("---")

if not no_results_guard():
    st.stop()

results = st.session_state.pipeline_results
pre     = st.session_state.get("pre_review")
phase   = st.session_state.pipeline_phase


# ═══════════════════════════════════════════════════════
#  AWAITING HUMAN REVIEW — show the review form here
# ═══════════════════════════════════════════════════════
if phase == "awaiting_human" and pre:
    proposal = pre["decision_proposal"]

    st.warning(t("hr_paused"))
    st.markdown(t("section_pipeline"))
    pipeline_stepper(completed=4)
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric(t("metric_cve"),        pre["cve"]["cve_id"])
    col2.metric(t("metric_cvss"),       pre["cve"]["cvss_score"])
    col3.metric(t("metric_severity"),   pre["cve"]["severity"])
    col4.metric(t("metric_confidence"), f"{proposal['confidence_score']:.0%}",
                delta=t("hr_below_threshold"))

    # Evidence panel
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
        df.style.map(lambda v: "background-color:#fff5f5" if t("t2_vulnerable") in str(v) else "",
                     subset=[t("t2_col_status")]),
        use_container_width=True, hide_index=True)

    # Review form
    st.markdown("---")
    st.subheader(t("hr_stage5"))
    st.markdown(t("hr_intro"))
    with st.form("human_review_form"):
        reviewer_name = st.text_input(t("hr_reviewer_label"), placeholder=t("hr_reviewer_placeholder"))
        st.markdown(t("hr_assessment"))
        notes = st.text_area(t("hr_notes_label"), placeholder=t("hr_notes_placeholder"), height=110)
        st.markdown(t("hr_select_decision"))
        dc1, dc2, dc3 = st.columns(3)
        with dc1: approve_report     = st.form_submit_button(t("hr_btn_report"),     use_container_width=True, type="primary")
        with dc2: approve_not_report = st.form_submit_button(t("hr_btn_not_report"), use_container_width=True)
        with dc3: escalate           = st.form_submit_button(t("hr_btn_escalate"),   use_container_width=True)

    if approve_report or approve_not_report or escalate:
        if not reviewer_name.strip():
            st.error(t("hr_err_name"))
        elif not notes.strip():
            st.error(t("hr_err_notes"))
        else:
            if approve_report:
                action, override, label = "APPROVE", "REPORT",     "REPORT"
            elif approve_not_report:
                action, override, label = "APPROVE", "NOT_REPORT", "NOT_REPORT"
            else:
                action, override, label = "APPROVE", "CONFLICT",   "ESCALATED"
            with st.spinner(t("hr_completing")):
                res = complete_pipeline(pre, reviewer_name, action, override, notes)
            st.session_state.pipeline_results = res
            st.session_state.pipeline_phase   = "complete"
            st.success(t("hr_done", label=label, name=reviewer_name))
            st.rerun()

    st.stop()


# ═══════════════════════════════════════════════════════
#  COMPLETE — show full decision analysis
# ═══════════════════════════════════════════════════════
if not results:
    st.stop()

final   = results["review_result"]["final_decision_type"]
decision = results["decision_proposal"]
review   = results["review_result"]

st.markdown(f"{t('section_decision_banner')} {decision_badge(final)}", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c1.metric(t("metric_proposed"),       decision["decision_type"])
c2.metric(t("metric_match_confidence"), f"{decision['confidence_score']:.0%}")
c3.metric(t("metric_auto_decidable"), t("t4_yes_auto") if decision["auto_decidable"] else t("t4_no_auto"))
c4.metric("🎯 " + ("閾値" if ja else "Auto Threshold"), f"{THRESHOLDS['auto_decide_confidence']:.0%}")

st.markdown(t("section_pipeline"))
pipeline_stepper(completed=6)
st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 4 — Confidence Score Explainer
# ═══════════════════════════════════════════════════════
st.header("🎯 " + ("ステージ 4 — 信頼スコア解説" if ja else "Stage 4 — Confidence Score Explainer"))
render_key_stage_badge(4)
st.caption("" + ("どのルールが判定信頼スコアに貢献したかを視覚的に示します。"
                 if ja else
                 "See exactly which rules contributed to the final confidence score and why."))
render_stage_insights(4)

chart_col, verdict_col = st.columns([3, 2])
with chart_col:
    st.plotly_chart(
        confidence_explainer_chart(decision["rules_fired"], decision["confidence_score"],
                                   THRESHOLDS["auto_decide_confidence"]),
        use_container_width=True)
with verdict_col:
    score     = decision["confidence_score"]
    threshold = THRESHOLDS["auto_decide_confidence"]
    above     = score >= threshold
    vbg       = "#f0fdf4" if above else "#fff7ed"
    vborder   = "#16a34a" if above else "#d97706"
    v_icon    = "✅" if above else "👤"
    v_label   = ("自動判定" if ja else "AUTO-DECIDED") if above else ("人的レビュー必要" if ja else "HUMAN REVIEW NEEDED")
    v_text    = (
        (f"信頼スコア {score:.0%} が閾値 {threshold:.0%} を上回っています。自動判定が確定しました。"
         if ja else
         f"Score {score:.0%} exceeds the auto-decide threshold of {threshold:.0%}. "
         "Decision confirmed automatically.")
        if above else
        (f"信頼スコア {score:.0%} が閾値 {threshold:.0%} を下回っています。人的審査が必要でした。"
         if ja else
         f"Score {score:.0%} was below the auto-decide threshold of {threshold:.0%}. "
         "Human review was required.")
    )
    bar_pct   = int(score * 100)
    thr_pct   = int(threshold * 100)
    bar_color = "#16a34a" if above else "#d97706"
    st.markdown(f"""
    <div style="background:{vbg};border:1px solid {vborder};border-radius:10px;padding:16px 18px;margin-top:4px">
      <div style="font-size:0.85rem;font-weight:700;color:{vborder};margin-bottom:8px">{v_icon} {v_label}</div>
      <div style="font-size:0.78rem;color:#374151;margin-bottom:12px">{v_text}</div>
      <div style="background:#e2e8f0;border-radius:20px;height:12px;overflow:hidden">
        <div style="background:{bar_color};width:{bar_pct}%;height:100%;border-radius:20px"></div>
      </div>
      <div style="position:relative;height:18px">
        <div style="position:absolute;left:{thr_pct}%;transform:translateX(-50%);
          font-size:0.65rem;color:#dc2626;margin-top:2px">▲ {threshold:.0%}</div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:#6b7280;margin-top:4px">
        <span>0%</span>
        <span style="font-weight:700;color:{vborder}">{score:.0%}</span>
        <span>100%</span>
      </div>
    </div>""", unsafe_allow_html=True)
    st.markdown("")
    # Evidence confidence breakdown
    weighting = decision["evidence_weighting"]
    st.markdown(f"**{'📊 証拠信頼度' if ja else '📊 Evidence Confidence'}**")
    from translations import t as _t
    for src, val, icon in [
        (_t("t4_ev_sbom"), weighting["sbom_confidence"],    "🔩"),
        (_t("t4_ev_nvd"),  weighting["cve_data_confidence"], "🗄️"),
        (_t("t4_ev_vex"),  weighting["vex_confidence"],      "📋"),
    ]:
        w_color = "#16a34a" if val >= 0.8 else "#d97706" if val >= 0.5 else "#94a3b8"
        st.markdown(f"""<div style="display:flex;justify-content:space-between;align-items:center;
            padding:5px 8px;margin-bottom:4px;background:#f8fafc;border-radius:6px;font-size:0.78rem">
          <span>{icon} {src}</span>
          <span style="font-weight:700;color:{w_color}">{val:.0%}</span>
        </div>""", unsafe_allow_html=True)

st.markdown("**" + ("ルール詳細" if ja else "Rule Details") + "**")
for rule in decision["rules_fired"]:
    icon   = "✅" if rule["triggered"] else "⬜"
    bg     = "#f0fdf4" if rule["triggered"] else "#f8fafc"
    border = "#16a34a" if rule["triggered"] else "#e2e8f0"
    st.markdown(f"""<div style="background:{bg};border:1px solid {border};border-radius:8px;
        padding:10px 14px;margin-bottom:8px">
      <div style="font-weight:700;font-size:0.85rem">{icon} {rule['rule']} &nbsp;
        <span style="font-weight:400;color:#6b7280">— {t('t4_triggered') if rule['triggered'] else t('t4_not_triggered')}</span></div>
      <div style="font-size:0.76rem;color:#4b5563;margin-top:4px">{rule['reasoning']}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 5 — Human Review Record
# ═══════════════════════════════════════════════════════
st.header("👤 " + ("ステージ 5 — 人的審査レコード" if ja else "Stage 5 — Human Review Record"))
render_key_stage_badge(5)
st.caption("" + ("コンプライアンス担当者による最終審査の記録です。"
                 if ja else
                 "The compliance officer's final review and decision justification."))
render_stage_insights(5)

a, b, c = st.columns(3)
a.metric(t("metric_reviewer"),   review["reviewer"])
b.metric(t("metric_action"),     review["action"])
c.metric(t("metric_decision_id"), review["decision_id"][:12] + "…")

st.markdown(t("t5_justification"))
st.info(review["justification"])
st.markdown(t("t5_final"))
st.markdown(decision_badge(review["final_decision_type"]), unsafe_allow_html=True)

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  Customer Notification Email Preview
# ═══════════════════════════════════════════════════════
st.header("📧 " + ("顧客通知メール — プレビュー & 承認ワークフロー"
                   if ja else
                   "Customer Notification Email — Preview & Approval Workflow"))
st.caption("" + ("送信前に適切なテンプレートを選択し、承認チェーンを確認してください。"
                 if ja else
                 "Select the appropriate template and verify the approval chain before sending."))

_cve_t  = results["cve"]
_prod_t = results["product_name"]
_dec_id = review["decision_id"][:16].upper()
_now_ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

email_types = (
    ["重大脆弱性アラート", "パッチ適用通知", "インシデント解決通知", "規制報告通知"]
    if ja else
    ["Critical Vulnerability Alert", "Patch Available Notification",
     "Incident Resolved Notification", "Regulatory Filing Notice"]
)
selected_email_type = st.selectbox(
    "📋 " + ("通知テンプレート" if ja else "Notification Template"),
    email_types, key="email_type_select")
_email_idx = email_types.index(selected_email_type)

if _email_idx == 0:
    _subj = (f"【緊急】セキュリティアラート — {_cve_t['cve_id']} が {_prod_t} に影響" if ja
             else f"[URGENT] Security Alert — {_cve_t['cve_id']} affects {_prod_t}")
    _body = (
        f"お客様各位\n\n{_prod_t}（CVSS: {_cve_t['cvss_score']} — {_cve_t['severity']}）に"
        f"重大なセキュリティ脆弱性（{_cve_t['cve_id']}）が検出されました。\n\n"
        f"【緊急対応が必要です】\n• 影響製品: {_prod_t}\n"
        f"• 影響バージョン: {_cve_t['affected_versions']['range_start']} ～ {_cve_t['affected_versions']['range_end']}\n"
        f"• ENISA報告完了（参照: {_dec_id}）\n\nJ-TEC セキュリティ対応チーム\n{_now_ts}"
        if ja else
        f"Dear Customer,\n\nA critical vulnerability ({_cve_t['cve_id']}) has been identified in "
        f"{_prod_t} (CVSS: {_cve_t['cvss_score']} — {_cve_t['severity']}).\n\n"
        f"IMMEDIATE ACTION REQUIRED:\n• Affected product: {_prod_t}\n"
        f"• Affected versions: {_cve_t['affected_versions']['range_start']} to "
        f"{_cve_t['affected_versions']['range_end']}\n"
        f"• ENISA report submitted (Ref: {_dec_id})\n\n"
        f"J-TEC Security Response Team\n{_now_ts}"
    )
elif _email_idx == 1:
    _subj = (f"【要対応】パッチ公開 — {_cve_t['cve_id']} ({_prod_t})" if ja
             else f"[ACTION] Patch Available — {_cve_t['cve_id']} ({_prod_t})")
    _body = (
        f"お客様各位\n\n{_prod_t}の{_cve_t['cve_id']}パッチが公開されました。\n"
        f"72時間以内にパッチを適用してください。\n\nJ-TEC セキュリティ対応チーム\n{_now_ts}"
        if ja else
        f"Dear Customer,\n\nA security patch is now available for {_cve_t['cve_id']} "
        f"affecting {_prod_t}.\n"
        f"Please apply this patch within 72 hours.\n\nJ-TEC Security Response Team\n{_now_ts}"
    )
elif _email_idx == 2:
    _subj = (f"【解決済み】インシデント終了 — {_cve_t['cve_id']}" if ja
             else f"[RESOLVED] Incident Closed — {_cve_t['cve_id']}")
    _body = (
        f"お客様各位\n\n{_cve_t['cve_id']}セキュリティインシデントが解決されました。\n"
        f"ENISA最終報告提出済み（参照: {_dec_id}）\n\nJ-TEC セキュリティ対応チーム\n{_now_ts}"
        if ja else
        f"Dear Customer,\n\nThe security incident related to {_cve_t['cve_id']} has been "
        f"fully resolved.\nENISA final report submitted (Ref: {_dec_id}).\n\n"
        f"J-TEC Security Response Team\n{_now_ts}"
    )
else:
    _subj = (f"【規制】ENISA報告完了 — {_cve_t['cve_id']}" if ja
             else f"[COMPLIANCE] ENISA Filing Confirmation — {_cve_t['cve_id']}")
    _body = (
        f"お客様各位\n\nEU CRA第14条に基づき、{_cve_t['cve_id']}のENISA報告を完了しました。\n"
        f"参照番号: {_dec_id} | 提出日時: {_now_ts}\n\nJ-TEC コンプライアンスチーム"
        if ja else
        f"Dear Customer,\n\nIn accordance with CRA Article 14, we have submitted a "
        f"vulnerability report to ENISA regarding {_cve_t['cve_id']}.\n"
        f"Filing Reference: {_dec_id} | Submitted: {_now_ts}\n\nJ-TEC Compliance Team"
    )

with st.expander("📧 " + ("メールプレビュー" if ja else "Email Preview"), expanded=True):
    st.markdown(f"""
    <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;
                font-family:'Helvetica Neue',Arial,sans-serif;overflow:hidden">
      <div style="background:#1e3a8a;padding:12px 20px">
        <span style="color:white;font-weight:700;font-size:0.9rem">
          J-TEC Co., Ltd. — Security Notification</span>
      </div>
      <div style="background:#f1f5f9;padding:10px 20px;font-size:0.77rem;color:#374151;
                  border-bottom:1px solid #e2e8f0">
        <b>{'送信元' if ja else 'From'}:</b> security@jtec.co.jp &nbsp;|&nbsp;
        <b>{'件名' if ja else 'Subject'}:</b> {_subj}
      </div>
      <div style="padding:16px 20px;font-size:0.80rem;color:#1e293b;line-height:1.7;
                  white-space:pre-wrap">{_body}</div>
      <div style="background:#f1f5f9;padding:8px 20px;font-size:0.7rem;color:#94a3b8;
                  border-top:1px solid #e2e8f0">
        J-TEC Co., Ltd. · 1-2-3 Marunouchi, Chiyoda, Tokyo 100-0005 · security@jtec.co.jp<br>
        {'本メールはJ-TECのCRAコンプライアンスシステムにより自動生成 — Decision ID: '
         if ja else
         'Generated by J-TEC CRA Compliance System — Decision ID: '}{_dec_id}
      </div>
    </div>""", unsafe_allow_html=True)

st.download_button(
    label="⬇️ " + ("メールファイルをダウンロード (.txt)" if ja else "Download Email File (.txt)"),
    data=f"From: security@jtec.co.jp\nTo: [Customer Distribution List]\n"
         f"Subject: {_subj}\nDate: {_now_ts}\n\n{_body}",
    file_name=f"Notification-{_cve_t['cve_id']}-{_email_idx+1}.txt",
    mime="text/plain")

st.markdown("---")

# Approval workflow
st.markdown("##### ✅ " + ("送信前承認ワークフロー" if ja else "Pre-Send Approval Workflow"))
_chain = [
    {"role": ("セキュリティエンジニア" if ja else "Security Engineer"),  "name": "K. Tanaka",      "status": "approved", "ts": "09:12"},
    {"role": ("セキュリティマネージャー" if ja else "Security Manager"),  "name": "Y. Matsumoto",   "status": "approved", "ts": "09:28"},
    {"role": ("コンプライアンス担当" if ja else "Compliance Officer"),    "name": review["reviewer"],"status": "approved",
     "ts": review["review_timestamp"][11:16] if "T" in review.get("review_timestamp", "") else "10:05"},
    {"role": ("法務責任者" if ja else "Legal Counsel"),                   "name": "R. Kobayashi",   "status": "pending",  "ts": "—"},
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

render_personalized_cta()

st.markdown("---")

# ── Next step navigation ──
st.markdown("### " + ("次のステップ" if ja else "Next Step"))
nav1, nav2 = st.columns(2)
with nav1:
    st.page_link("pages/1_Detection.py",
                 label="← " + ("Act 1: 検出へ戻る" if ja else "Back to Act 1: Detection"))
with nav2:
    st.page_link("pages/3_Reporting.py",
                 label="📡 " + ("Act 3: 報告・ダウンロードへ →" if ja else "Act 3: Reporting & Downloads →"))

st.markdown(f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:18px;"
            f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",
            unsafe_allow_html=True)
