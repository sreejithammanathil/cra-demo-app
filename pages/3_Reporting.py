"""
Act 3 — Reporting & Downloads
Stage 6: ENISA Submission Simulator · Article 14 Deadline Calendar · Artifact Downloads · Audit Trail
"""

import streamlit as st
import json
import pandas as pd
from datetime import datetime

from translations import t
from mock_data import PRODUCTS
from enisa_reporter import (generate_enisa_submission_json, generate_compliance_artifact_html,
                             generate_cyclonedx_sbom, generate_enisa_article14_json,
                             generate_audit_csv, generate_pdf_report)
from utils import (inject_css, lang_toggle_sidebar, sidebar_current_run,
                   sidebar_home_button, no_results_guard,
                   pipeline_stepper, decision_badge, cra_deadline_gantt)
from readiness_widgets import render_key_stage_badge, render_stage_insights, render_personalized_cta, sidebar_readiness_score

st.set_page_config(
    page_title="Act 3: Reporting — CRA System",
    page_icon="📡",
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
    st.page_link("pages/2_Decision.py",   label="⚖️ " + ("Act 2 — 判定" if ja else "Act 2 — Decision"))
    st.page_link("pages/4_Compliance.py",     label="📋 " + ("コンプライアンス" if ja else "Compliance"))
    st.page_link("pages/5_History.py",         label="📚 " + ("履歴" if ja else "History"))
    st.page_link("pages/7_Accountability.py",  label="🔍 " + ("説明責任" if ja else "Accountability"))
    sidebar_readiness_score()
    st.markdown("---")
    sidebar_home_button()

ja = st.session_state.lang == "ja"

st.title("📡 " + ("アクト 3 — 報告 & ダウンロード" if ja else "Act 3 — Reporting & Downloads"))
st.markdown("**" + ("ENISA提出シミュレーター · 規制期限 · アーティファクトダウンロード — パイプライン ステージ 6"
                    if ja else
                    "ENISA Submission Simulator · Regulatory Deadlines · Artifact Downloads — Pipeline Stage 6") + "**")
st.markdown("---")

if not no_results_guard():
    st.stop()

results = st.session_state.pipeline_results
if not results:
    st.stop()

final   = results["review_result"]["final_decision_type"]
enisa   = results["enisa_result"]
rev     = results["review_result"]
_cve    = results["cve"]
_prod   = results["product_name"]
_proddata = PRODUCTS.get(_prod, {})
_match  = results["sbom_match"]
_audit  = results["audit_trail"]
_sid    = enisa["submission_id"]
_scen   = results["scenario_name"]

st.markdown(f"{t('section_decision_banner')} {decision_badge(final)}", unsafe_allow_html=True)
st.markdown(t("section_pipeline"))
pipeline_stepper(completed=6)
st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 6 — ENISA Submission Simulator
# ═══════════════════════════════════════════════════════
st.header("🏛️ " + ("ステージ 6 — ENISA 提出シミュレーター"
                    if ja else "Stage 6 — ENISA Submission Simulator"))
render_key_stage_badge(6)
render_stage_insights(6)

if final != "REPORT":
    st.info("ℹ️ " + ("ENISA報告義務なし — このケースは自動報告対象外です。"
                      if ja else
                      "ENISA submission not required — this case does not trigger Article 14 reporting."))
    c1, c2 = st.columns(2)
    c1.metric(t("metric_status"), enisa["status"])
    c2.metric(t("metric_submitted"), "NO — " + final)
else:
    # ── Portal simulation ──
    st.markdown(f"""
    <div style="background:#eff6ff;border-left:5px solid #1e40af;border-radius:8px;padding:12px 18px;margin-bottom:12px">
      <b style="color:#1e3a8a;font-size:0.95rem">
        {'🏛️ ENISA 脆弱性報告ポータル — シミュレーター' if ja else '🏛️ ENISA Vulnerability Reporting Portal — Simulator'}
      </b><br>
      <span style="color:#1e40af;font-size:0.8rem">
        {'CRA 第14条に基づく能動的悪用脆弱性報告フローを再現します。'
         if ja else 'Replicates the ENISA portal submission flow for CRA Article 14 reporting.'}
      </span>
    </div>""", unsafe_allow_html=True)

    sim_step_key = f"enisa_sim_step_{_sid[:8]}"
    if sim_step_key not in st.session_state:
        st.session_state[sim_step_key] = 1
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
                   font-weight:700;font-size:1rem;display:inline-flex;align-items:center;
                   justify-content:center">{icon}</div>
              <div style="font-size:0.72rem;color:{lbl_col};margin-top:4px;
                   font-weight:{'700' if active else '400'}">{slbl}</div>
            </div>""", unsafe_allow_html=True)
    st.markdown("")

    # ── Step 1 ──
    if cur_step == 1:
        st.markdown("#### " + ("レポーター情報の確認" if ja else "Reporter Identity Confirmation"))
        with st.form("enisa_step1"):
            rc1, rc2 = st.columns(2)
            with rc1:
                st.text_input("🏢 " + ("組織名" if ja else "Organisation Name"), value="J-TEC Co., Ltd.")
                st.selectbox("👤 " + ("役割" if ja else "Reporter Role"),
                             ["Compliance Officer", "CISO", "Security Engineer", "Legal Counsel"])
            with rc2:
                st.selectbox("🌍 " + ("登録国" if ja else "Country of Registration"),
                             ["Japan", "Germany", "France", "Italy", "Spain", "Ireland"])
                st.text_input("📧 " + ("連絡先メール" if ja else "Contact Email"),
                              value="compliance@jtec.co.jp")
            st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                padding:10px 14px;font-size:0.78rem;color:#374151">
                <b>{'記入前の確認' if ja else 'Pre-submission declaration'}</b><br>
                {'私は、CRA 第14条に基づき、本報告書の情報が正確かつ完全であることを宣言します。'
                 if ja else
                 'I declare that the information in this report is accurate and complete, '
                 'in accordance with CRA Article 14.'}
            </div>""", unsafe_allow_html=True)
            st.checkbox("✅ " + ("上記の宣言に同意します" if ja else "I agree to the above declaration"), value=True)
            if st.form_submit_button("→ " + ("次へ: 脆弱性詳細" if ja else "Next: Vulnerability Details"),
                                     use_container_width=True, type="primary"):
                st.session_state[sim_step_key] = 2; st.rerun()

    elif cur_step == 2:
        st.markdown("#### " + ("脆弱性詳細情報" if ja else "Vulnerability Details"))
        vc1, vc2 = st.columns(2)
        with vc1:
            st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                padding:12px 14px;font-size:0.80rem">
              <b>CVE:</b> <code>{_cve['cve_id']}</code><br><br>
              <b>CVSS:</b> {_cve['cvss_score']} ({_cve['severity']})<br>
              <b>Exploit:</b> {"Yes ⚠️" if _cve.get("exploit_available") else "No"}<br>
              <b>Versions:</b> {_cve['affected_versions']['range_start']} → {_cve['affected_versions']['range_end']}
            </div>""", unsafe_allow_html=True)
        with vc2:
            st.markdown(f"""<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                padding:12px 14px;font-size:0.80rem">
              <b>{'影響製品' if ja else 'Affected Product'}:</b> {_prod}<br><br>
              <b>{'判定' if ja else 'Decision'}:</b>
              <span style="color:#dc2626;font-weight:700">REPORT</span><br>
              <b>{'信頼度' if ja else 'Confidence'}:</b> {results['decision_proposal']['confidence_score']:.0%}<br>
              <b>{'審査者' if ja else 'Reviewer'}:</b> {rev['reviewer']}
            </div>""", unsafe_allow_html=True)
        with st.form("enisa_step2"):
            st.text_area("📝 " + ("脆弱性の説明" if ja else "Vulnerability Description"),
                         value=_cve.get("description", ""), height=80)
            st.text_area("🔧 " + ("暫定対応措置" if ja else "Interim Mitigation Measures"),
                         value="Vendor patch under development. Firewall rules applied." if not ja
                               else "ベンダーパッチ開発中。暫定措置としてファイアウォールルールを適用。",
                         height=70)
            s2c1, s2c2 = st.columns(2)
            with s2c1:
                if st.form_submit_button("← " + ("戻る" if ja else "Back"), use_container_width=True):
                    st.session_state[sim_step_key] = 1; st.rerun()
            with s2c2:
                if st.form_submit_button("→ " + ("次へ: 影響評価" if ja else "Next: Impact Assessment"),
                                         use_container_width=True, type="primary"):
                    st.session_state[sim_step_key] = 3; st.rerun()

    elif cur_step == 3:
        st.markdown("#### " + ("影響評価 & 市場範囲" if ja else "Impact Assessment & Market Scope"))
        with st.form("enisa_step3"):
            ic1, ic2 = st.columns(2)
            with ic1:
                st.multiselect("🌍 " + ("影響を受ける加盟国" if ja else "Affected EU Member States"),
                               ["Germany 🇩🇪","France 🇫🇷","Italy 🇮🇹","Spain 🇪🇸","Ireland 🇮🇪"],
                               default=["Germany 🇩🇪","France 🇫🇷","Ireland 🇮🇪"])
                st.selectbox("⚠️ " + ("影響レベル" if ja else "Impact Severity"),
                             ["CRITICAL — Immediate action required",
                              "HIGH — Action required within 24h",
                              "MEDIUM — Action required within 72h"])
            with ic2:
                st.number_input("🏭 " + ("影響製品数" if ja else "Affected Products"), min_value=1, value=1)
                st.number_input("👥 " + ("推定影響ユーザー数" if ja else "Estimated Affected Users"), min_value=0, value=500, step=100)
            st.markdown(f"""<div style="background:#fefce8;border:1px solid #fde68a;border-radius:8px;
                padding:10px 14px;font-size:0.77rem;color:#92400e;margin-top:8px">
                ⏱️ <b>CRA Art. 14 SLA</b>: {
                '早期警告 24h以内 · 完全通知 72h以内 · 最終報告 90日以内' if ja else
                'Early warning within 24h · Full notification within 72h · Final report within 90 days'}
            </div>""", unsafe_allow_html=True)
            s3c1, s3c2 = st.columns(2)
            with s3c1:
                if st.form_submit_button("← " + ("戻る" if ja else "Back"), use_container_width=True):
                    st.session_state[sim_step_key] = 2; st.rerun()
            with s3c2:
                if st.form_submit_button("→ " + ("送信確認へ" if ja else "Proceed to Submit"),
                                         use_container_width=True, type="primary"):
                    st.session_state[sim_step_key] = 4; st.rerun()

    elif cur_step == 4:
        # Confirmation
        st.markdown(f"""
        <div style="background:#f0fdf4;border:2px solid #16a34a;border-radius:12px;
                    padding:20px 24px;text-align:center;margin-bottom:16px">
          <div style="font-size:2rem;margin-bottom:4px">✅</div>
          <div style="font-size:1.1rem;font-weight:800;color:#15803d">
            {'ENISA 提出完了' if ja else 'ENISA Submission Confirmed'}
          </div>
          <div style="font-size:0.85rem;color:#166534;margin-top:6px">
            {'CRA 第14条に基づく脆弱性報告が正常に受理されました。'
             if ja else 'Your vulnerability report under CRA Article 14 has been accepted.'}
          </div>
        </div>""", unsafe_allow_html=True)

        cc1, cc2, cc3 = st.columns(3)
        cc1.metric("🔖 " + ("参照番号" if ja else "Reference ID"),
                   enisa.get("enisa_reference_id", "—"))
        cc2.metric("🕐 " + ("提出日時" if ja else "Submitted At"),
                   enisa.get("submission_timestamp", "")[:19].replace("T", " "))
        cc3.metric("📋 " + ("規制条文" if ja else "Regulation"), "CRA Art. 14")

        st.markdown("##### " + ("📅 次のステップ & 締め切り" if ja else "📅 Next Steps & Deadlines"))
        dl_items = [
            ("✅", "#16a34a", ("早期警告 — 完了" if ja else "Early Warning — DONE"),      ("検知後24h以内" if ja else "Within 24h of detection")),
            ("⏳", "#d97706", ("完全通知 — 進行中" if ja else "Full Notification — IN PROGRESS"), ("検知後72h以内" if ja else "Within 72h of detection")),
            ("📋", "#1e40af", ("最終報告 — 保留" if ja else "Final Report — PENDING"),     ("解決後90日以内" if ja else "Within 90 days of resolution")),
            ("🏛️","#6366f1", ("国家機関通知" if ja else "National Authority Notification"), ("各NCA/CSIRTへ通知" if ja else "Notify NCA/CSIRT in each affected state")),
        ]
        dl_cols = st.columns(4)
        for (icon, color, title, desc), dcol in zip(dl_items, dl_cols):
            with dcol:
                st.markdown(f"""<div style="background:#f8fafc;border-left:4px solid {color};
                    border-radius:8px;padding:12px 14px">
                  <div style="font-size:1.3rem">{icon}</div>
                  <div style="font-weight:700;font-size:0.82rem;color:{color};margin-top:4px">{title}</div>
                  <div style="font-size:0.72rem;color:#6b7280;margin-top:3px">{desc}</div>
                </div>""", unsafe_allow_html=True)

        # Deadline Gantt
        st.markdown("---")
        st.markdown("##### 📅 " + ("CRA 第14条 規制スケジュール" if ja else "CRA Article 14 Regulatory Schedule"))
        st.caption("🔴 " + ("赤い縦線 = 現在時刻" if ja else "Red line = NOW  |  Bars show SLA deadlines"))
        st.plotly_chart(
            cra_deadline_gantt(enisa.get("submission_timestamp", datetime.now().isoformat()),
                               lang="ja" if ja else "en"),
            use_container_width=True)

        st.markdown("")
        if st.button("🔄 " + ("新しいシミュレーションを開始" if ja else "Run New Simulation")):
            st.session_state[sim_step_key] = 1; st.rerun()

        with st.expander(t("t6_payload_preview")):
            st.json(generate_enisa_submission_json(
                decision=rev, cve=_cve, product_name=_prod,
                sbom_match=_match, submission_id=_sid))

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  Artifact Downloads
# ═══════════════════════════════════════════════════════
st.header("📦 " + ("アーティファクト & ダウンロード" if ja else "Artifacts & Downloads"))
st.caption("" + ("コンプライアンスに必要な全ドキュメントを一括ダウンロードできます。"
                 if ja else
                 "Download all compliance artifacts generated from this pipeline run."))

# Pre-generate artifacts
_html_report = generate_compliance_artifact_html(
    decision_id=rev["decision_id"], cve=_cve, product_name=_prod,
    sbom_match=_match, decision=rev, audit_trail=_audit)
_enisa_basic = generate_enisa_submission_json(
    decision=rev, cve=_cve, product_name=_prod, sbom_match=_match, submission_id=_sid)
_enisa_full  = generate_enisa_article14_json(
    decision=rev, cve=_cve, product_name=_prod, product_data=_proddata,
    sbom_match=_match, submission_id=_sid, audit_trail=_audit)
_cyclonedx   = generate_cyclonedx_sbom(
    product_name=_prod, product_data=_proddata, cve=_cve, sbom_match=_match)
_csv_bytes   = generate_audit_csv(
    audit_trail=_audit, cve_id=_cve["cve_id"], product_name=_prod,
    decision_type=rev["final_decision_type"])
_pdf_bytes   = generate_pdf_report(
    cve=_cve, product_name=_prod, product_data=_proddata,
    sbom_match=_match, decision=rev, audit_trail=_audit, scenario_name=_scen)

cveid = _cve["cve_id"]

# Row 1: Audit Reports
st.markdown("##### 📄 " + ("監査レポート" if ja else "Audit Reports"))
r1c1, r1c2 = st.columns(2)
with r1c1:
    st.markdown("**📕 PDF Compliance Report**")
    st.caption("Branded A4 PDF with full audit trail, rules applied, and decision justification." if not ja
               else "監査証跡・適用ルール・決定理由を含むA4 PDF。")
    if _pdf_bytes:
        st.download_button(label="⬇️ Download PDF Report", data=_pdf_bytes,
                           file_name=f"CRA-Report-{cveid}.pdf", mime="application/pdf",
                           use_container_width=True, type="primary")
    else:
        st.warning("ReportLab not available in this environment.")
with r1c2:
    st.markdown("**🌐 HTML Compliance Artifact**")
    st.caption("Self-contained HTML — open in any browser, print to PDF, or embed in portals." if not ja
               else "単体HTMLレポート — ブラウザで表示・PDF印刷可能。")
    st.download_button(label="⬇️ Download HTML Report", data=_html_report,
                       file_name=f"CRA-{cveid}.html", mime="text/html",
                       use_container_width=True)

st.markdown("---")

# Row 2: ENISA JSON
st.markdown("##### 🏛️ " + ("ENISA報告データ" if ja else "ENISA Reporting Data"))
r2c1, r2c2 = st.columns(2)
with r2c1:
    st.markdown("**📋 ENISA Submission JSON** *(Basic)*")
    st.caption("Compact submission payload matching the ENISA vulnerability portal intake format." if not ja
               else "ENISAポータル受付フォーマット準拠のコンパクトなペイロード。")
    st.download_button(label="⬇️ Download ENISA JSON",
                       data=json.dumps(_enisa_basic, indent=2),
                       file_name=f"ENISA-Basic-{cveid}.json", mime="application/json",
                       use_container_width=True)
with r2c2:
    st.markdown("**📜 CRA Article 14 Full Notification JSON**")
    st.caption("Full structured Article 14 payload with timeline, evidence, and regulator metadata." if not ja
               else "完全な第14条構造化ペイロード：タイムライン・証拠・規制機関メタデータ含む。")
    st.download_button(label="⬇️ Download Article 14 JSON",
                       data=json.dumps(_enisa_full, indent=2),
                       file_name=f"ENISA-Article14-{cveid}.json", mime="application/json",
                       use_container_width=True)

with st.expander("👁️ " + ("Article 14 JSONプレビュー" if ja else "Preview Article 14 JSON")):
    st.json(_enisa_full)

st.markdown("---")

# Row 3: SBOM + CSV
st.markdown("##### 🔩 " + ("SBOM & 監査ログ" if ja else "SBOM & Audit Log"))
r3c1, r3c2 = st.columns(2)
with r3c1:
    st.markdown("**🔩 CycloneDX 1.6 SBOM Export**")
    st.caption("Industry-standard SBOM in CycloneDX JSON. Vulnerable component annotated inline." if not ja
               else "CycloneDX JSON形式の業界標準SBOM。脆弱コンポーネントをインラインで注釈付き。")
    st.download_button(label="⬇️ Download CycloneDX SBOM",
                       data=json.dumps(_cyclonedx, indent=2),
                       file_name=f"SBOM-CycloneDX-{_prod.replace(' ','-')}-{cveid}.json",
                       mime="application/json", use_container_width=True)
with r3c2:
    st.markdown("**📊 Audit Trail CSV / Excel**")
    st.caption("Complete pipeline audit log as CSV — import to SIEM or attach to ENISA submission." if not ja
               else "完全な監査ログCSV — SIEM取込み・ENISA提出添付に対応。")
    st.download_button(label="⬇️ Download Audit Log CSV", data=_csv_bytes,
                       file_name=f"AuditLog-{cveid}-{_prod.replace(' ','-')}.csv",
                       mime="text/csv", use_container_width=True)

with st.expander("👁️ " + ("CycloneDX SBOMプレビュー" if ja else "Preview CycloneDX SBOM")):
    st.json(_cyclonedx)

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  Full Audit Trail
# ═══════════════════════════════════════════════════════
st.header("🗂️ " + ("完全監査証跡" if ja else "Complete Audit Trail"))
st.caption(t("section_audit_caption"))
audit_df = pd.DataFrame(_audit)
if not audit_df.empty:
    audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"])
    for _, row in audit_df.iterrows():
        action = str(row.get("action", ""))
        badge_cls = ("audit-stage"    if any(k in action for k in ["CVE", "SBOM", "Stage"])
                     else "audit-decision" if "DECISION" in action else "audit-conflict")
        st.markdown(
            f'`{row["timestamp"].strftime("%H:%M:%S")}` &nbsp;'
            f'<span class="audit-badge {badge_cls}">{action}</span>'
            f' &nbsp; {row.get("details", "")}',
            unsafe_allow_html=True)

render_personalized_cta()

st.markdown("---")

# ── Next step navigation ──
st.markdown("### " + ("次のステップ" if ja else "Next Step"))
nav1, nav2, nav3 = st.columns(3)
with nav1:
    st.page_link("pages/2_Decision.py",
                 label="← " + ("Act 2: 判定へ戻る" if ja else "Back to Act 2: Decision"))
with nav2:
    st.page_link("pages/4_Compliance.py",
                 label="📋 " + ("コンプライアンス ライフサイクルへ →" if ja else "Compliance Lifecycle →"))
with nav3:
    st.page_link("pages/7_Accountability.py",
                 label="🔍 " + ("説明責任レコードを表示 →" if ja else "View Accountability Record →"))

st.markdown(f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:18px;"
            f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",
            unsafe_allow_html=True)
