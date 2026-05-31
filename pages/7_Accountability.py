"""
Decision Accountability Layer — CRA Decision Traceability System
Five-tab explainability, timeline, ownership, evidence, and justification view.
"""

import json
import streamlit as st
import pandas as pd

from translations import t
from utils import (inject_css, lang_toggle_sidebar, sidebar_current_run,
                   sidebar_home_button, no_results_guard, decision_badge, pipeline_stepper)
from decision_explainer import (
    generate_decision_explanation,
    generate_timeline,
    generate_accountability_record,
    generate_evidence_repository,
    generate_justification_record,
)

st.set_page_config(
    page_title="Decision Accountability — CRA System",
    page_icon="🔏",
    layout="wide",
)

if "lang" not in st.session_state:
    st.session_state.lang = "en"

inject_css()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    lang_toggle_sidebar()
    ja = st.session_state.lang == "ja"
    sidebar_current_run()
    st.markdown("---")
    st.markdown("##### " + ("ナビゲーション" if ja else "Navigation"))
    st.page_link("app.py",                label="🏠 " + ("ダッシュボード" if ja else "Dashboard"))
    st.page_link("pages/1_Detection.py",  label="🔍 " + ("Act 1 — 検出" if ja else "Act 1 — Detection"))
    st.page_link("pages/2_Decision.py",   label="⚖️ " + ("Act 2 — 判定" if ja else "Act 2 — Decision"))
    st.page_link("pages/3_Reporting.py",  label="📡 " + ("Act 3 — 報告" if ja else "Act 3 — Reporting"))
    st.page_link("pages/4_Compliance.py", label="📋 " + ("コンプライアンス" if ja else "Compliance"))
    st.markdown("---")
    sidebar_home_button()

ja = st.session_state.lang == "ja"

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🔏 " + ("判定アカウンタビリティ・レイヤー" if ja else "Decision Accountability Layer"))
st.markdown("**" + (
    "説明可能性 · トレーサビリティ · 監査可能性 · ガバナンス — すべての判定の完全な説明"
    if ja else
    "Explainability · Traceability · Auditability · Governance — Complete decision justification"
) + "**")
st.markdown("---")

if not no_results_guard():
    st.stop()

results = st.session_state.pipeline_results
if not results:
    st.stop()

lang = "ja" if ja else "en"

# Pre-generate all accountability artifacts once
expl   = generate_decision_explanation(results, lang)
tl     = generate_timeline(results, lang)
acct   = generate_accountability_record(results)
evrepo = generate_evidence_repository(results)
just   = generate_justification_record(results, lang)

final  = results["review_result"]["final_decision_type"]

# Decision badge at top
st.markdown(
    f"**{'最終判定' if ja else 'Final Decision'}:** {decision_badge(final)} &nbsp; "
    f"**{'信頼スコア' if ja else 'Confidence'}:** `{expl['confidence_score']:.0%}` &nbsp; "
    f"**{'方式' if ja else 'Method'}:** {'自動判定' if expl['auto_decided'] else '人的判定'}"
    if ja else
    f"**Final Decision:** {decision_badge(final)} &nbsp; "
    f"**Confidence:** `{expl['confidence_score']:.0%}` &nbsp; "
    f"**Method:** {'Auto-decided' if expl['auto_decided'] else 'Human-decided'}",
    unsafe_allow_html=True,
)
st.markdown("---")

# ── Five Tabs ─────────────────────────────────────────────────────────────────
tab_labels = (
    ["🔍 説明", "📅 タイムライン", "👥 アカウンタビリティ", "🗃️ 証拠リポジトリ", "📋 正当化記録"]
    if ja else
    ["🔍 Explanation", "📅 Timeline", "👥 Accountability", "🗃️ Evidence Repository", "📋 Justification Record"]
)
tab1, tab2, tab3, tab4, tab5 = st.tabs(tab_labels)


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — Decision Explanation
# ══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🔍 " + ("判定説明" if ja else "Decision Explanation"))
    st.caption("" + ("この判定がなぜ行われたか — 証拠・ルール・理由の完全な解説。"
                     if ja else
                     "Why this decision was made — complete evidence, rules, and reasoning."))
    st.markdown("")

    # ── Decision Summary card ──
    badge_colors = {
        "REPORT":     ("#dc2626", "#fef2f2"),
        "NOT_REPORT": ("#16a34a", "#f0fdf4"),
        "CONFLICT":   ("#d97706", "#fff7ed"),
        "ESCALATED":  ("#7c3aed", "#f5f3ff"),
    }
    fc, fbg = badge_colors.get(final, ("#6b7280", "#f9fafb"))

    st.markdown(f"""
    <div style="background:{fbg};border-left:6px solid {fc};border-radius:10px;padding:20px 24px;margin-bottom:16px">
      <div style="font-size:0.72rem;font-weight:700;color:#6b7280;text-transform:uppercase;
                  letter-spacing:1px;margin-bottom:6px">
        {"判定サマリー" if ja else "DECISION SUMMARY"}
      </div>
      <div style="font-size:1.8rem;font-weight:900;color:{fc};margin-bottom:8px">
        {expl['outcome_label']}
      </div>
      <div style="display:flex;gap:20px;flex-wrap:wrap;font-size:0.82rem">
        <span><b>{"信頼スコア" if ja else "Confidence"}:</b> {expl['confidence_score']:.0%}</span>
        <span><b>{"判定方式" if ja else "Method"}:</b>
          {"自動判定" if expl['auto_decided'] else "👤 人的判定" if ja else "👤 Human-decided"}</span>
        <span><b>CVE:</b> {results['cve']['cve_id']}</span>
        <span><b>{"製品" if ja else "Product"}:</b> {results['product_name']}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Reason bullets ──
    st.markdown("#### " + ("📌 判定理由" if ja else "📌 Decision Reasons"))
    for bullet in expl["reason_bullets"]:
        icon = "🔴" if "exploit" in bullet.lower() or "report" in bullet.lower() else "📎"
        st.markdown(f"- {icon} {bullet}")

    st.markdown("---")
    col_ev, col_rule = st.columns(2, gap="large")

    # ── Evidence Summary Table ──
    with col_ev:
        st.markdown("#### " + ("🗂️ 証拠サマリー" if ja else "🗂️ Evidence Summary"))
        status_labels = {
            "confirmed": ("✅ Confirmed", "#f0fdf4", "#166534"),
            "clear":     ("🟢 Clear",     "#f0fdf4", "#166534"),
            "partial":   ("⚠️ Partial",   "#fff7ed", "#92400e"),
            "warning":   ("🔴 Conflict",  "#fef2f2", "#7f1d1d"),
            "none":      ("—  None",      "#f9fafb", "#6b7280"),
        }
        for ev in expl["evidence_table"]:
            sl, sbg, sfg = status_labels.get(ev["status"], ("—", "#f9fafb", "#6b7280"))
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;align-items:center;'
                f'border-bottom:1px solid #f1f5f9;padding:7px 2px;font-size:0.82rem">'
                f'<span style="color:#374151;flex:2">{ev["source"]}</span>'
                f'<span style="background:{sbg};color:{sfg};padding:2px 10px;border-radius:10px;'
                f'font-size:0.72rem;font-weight:700;white-space:nowrap">{sl}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
            st.caption(f"  ↳ {ev['detail']}")

    # ── Rule Evaluation Table ──
    with col_rule:
        st.markdown("#### " + ("⚖️ ルール評価" if ja else "⚖️ Rule Evaluation"))
        for rule in expl["rule_table"]:
            triggered = rule["result"]
            color  = "#dc2626" if triggered else "#6b7280"
            bg     = "#fef2f2" if triggered else "#f9fafb"
            icon   = "✅ TRUE" if triggered else "— FALSE"
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;align-items:center;'
                f'border-bottom:1px solid #f1f5f9;padding:7px 2px;font-size:0.82rem">'
                f'<span style="color:#374151;flex:2">'
                f'<b style="color:#1e3a8a">{rule["rule_id"]}</b> {rule["name"]}</span>'
                f'<span style="background:{bg};color:{color};padding:2px 10px;border-radius:10px;'
                f'font-size:0.72rem;font-weight:700">{icon}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
            st.caption(f"  ↳ {rule['condition']}")

    # ── Justification Paragraph ──
    st.markdown("---")
    st.markdown("#### " + ("📝 法的・規制上の正当化（全文）" if ja else "📝 Full Legal & Regulatory Justification"))
    st.markdown(
        f'<div style="background:#f8fafc;border-left:4px solid #1e3a8a;border-radius:6px;'
        f'padding:16px 20px;font-size:0.88rem;line-height:1.8;color:#374151">'
        f'{expl["justification_paragraph"]}'
        f'</div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — Decision History Timeline
# ══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("📅 " + ("判定履歴タイムライン" if ja else "Decision History Timeline"))
    st.caption("" + ("いつ・誰が・何を行ったか — パイプライン全体のイベント履歴。"
                     if ja else
                     "When, who, and what — every pipeline event in chronological order."))
    st.markdown("")

    if not tl:
        st.info("ℹ️ " + ("タイムラインデータがありません。" if ja else "No timeline data available."))
    else:
        # Visual timeline using HTML
        items_html = ""
        for i, ev in enumerate(tl):
            is_last    = i == len(tl) - 1
            actor_bg   = "#dbeafe" if ev["actor_type"] == "Human" else "#dcfce7"
            actor_clr  = "#1e40af" if ev["actor_type"] == "Human" else "#166534"
            connector  = "" if is_last else (
                '<div style="position:absolute;left:17px;top:38px;bottom:-10px;'
                'width:2px;background:#e2e8f0;z-index:0"></div>'
            )
            items_html += f"""
            <div style="position:relative;padding-left:48px;padding-bottom:18px">
              {connector}
              <!-- Circle -->
              <div style="position:absolute;left:0;top:0;width:36px;height:36px;
                          border-radius:50%;background:#1e3a8a;color:white;
                          display:flex;align-items:center;justify-content:center;
                          font-size:1rem;z-index:1">{ev['icon']}</div>
              <!-- Content -->
              <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                          padding:10px 14px;margin-left:4px">
                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
                  <span style="font-size:0.72rem;font-weight:700;color:#1e3a8a;
                               background:#eff6ff;border-radius:10px;padding:1px 8px">
                    Stage {ev['stage']}
                  </span>
                  <span style="font-weight:700;font-size:0.88rem;color:#1e293b">{ev['event']}</span>
                  <span style="margin-left:auto;font-size:0.72rem;color:#94a3b8">⏱ {ev['timestamp']}</span>
                </div>
                <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:0.75rem;color:#6b7280">
                  <span style="background:{actor_bg};color:{actor_clr};border-radius:10px;
                               padding:1px 8px;font-weight:600">
                    👤 {ev['actor']}
                  </span>
                  <span>🔄 State: <b>{ev['state']}</b></span>
                </div>
                <div style="margin-top:6px;font-size:0.78rem;color:#4b5563">{ev['details']}</div>
              </div>
            </div>"""
        st.markdown(
            f'<div style="padding:8px 0 0 0">{items_html}</div>',
            unsafe_allow_html=True,
        )

        # Timeline table
        st.markdown("---")
        st.markdown("##### " + ("タイムライン一覧" if ja else "Timeline Table View"))
        tl_df = pd.DataFrame([
            {
                ("ステージ" if ja else "Stage"):     ev["stage"],
                ("時刻" if ja else "Time"):           ev["timestamp"],
                ("イベント" if ja else "Event"):      ev["event"],
                ("アクター" if ja else "Actor"):      ev["actor"],
                ("状態" if ja else "Pipeline State"): ev["state"],
                ("詳細" if ja else "Details"):        ev["details"],
            }
            for ev in tl
        ])
        st.dataframe(tl_df, use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 3 — Decision Ownership & Accountability
# ══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("👥 " + ("判定オーナーシップとアカウンタビリティ" if ja else "Decision Ownership & Accountability"))
    st.caption("" + ("誰が判断し、誰が承認したか — ガバナンス記録。"
                     if ja else
                     "Who decided, who approved — the governance record."))
    st.markdown("")

    # ── Key identity cards ──
    c1, c2, c3 = st.columns(3)

    def _id_card(col, icon, title, actor, ts, notes, border_color):
        with col:
            col.markdown(f"""
            <div style="border-left:5px solid {border_color};background:#f8fafc;
                        border-radius:10px;padding:16px 18px">
              <div style="font-size:1.4rem">{icon}</div>
              <div style="font-size:0.68rem;font-weight:700;color:#6b7280;
                          text-transform:uppercase;letter-spacing:1px;margin:4px 0">
                {title}
              </div>
              <div style="font-weight:800;font-size:1rem;color:#1e293b">{actor}</div>
              <div style="font-size:0.74rem;color:#64748b;margin-top:4px">⏱ {ts}</div>
              <div style="font-size:0.72rem;color:#6b7280;margin-top:6px;
                          line-height:1.5;border-top:1px solid #e2e8f0;padding-top:6px">
                {notes}
              </div>
            </div>
            """, unsafe_allow_html=True)

    _id_card(c1, "🤖",
             "判定生成者" if ja else "Generated By",
             acct["system_generated_by"],
             acct["system_generated_at"],
             f"Confidence: {expl['confidence_score']:.0%} · Auto: {expl['auto_decided']}",
             "#2563eb")
    _id_card(c2, "👤",
             "レビュー実施者" if ja else "Reviewed By",
             acct["human_reviewed_by"],
             acct["human_reviewed_at"],
             f"Action: {acct['review_action']} · Status: {acct['review_status']}",
             "#d97706" if acct["review_action"] != "APPROVE" else "#16a34a")
    _id_card(c3, "🏛️" if acct["enisa_submitted"] else "⬜",
             "ENISAへ提出" if ja else "Submitted To ENISA",
             "ENISA Portal (Automated)" if acct["enisa_submitted"] else "N/A",
             results["enisa_result"].get("submission_timestamp",
                                         results["review_result"]["review_timestamp"]),
             f"Ref: {acct['enisa_ref']}" if acct["enisa_submitted"] else "No submission required",
             "#16a34a" if acct["enisa_submitted"] else "#6b7280")

    st.markdown("---")

    # ── Decision ID & metadata ──
    st.markdown("#### " + ("🆔 判定識別情報" if ja else "🆔 Decision Identification"))
    meta_c1, meta_c2 = st.columns(2)
    meta_c1.metric("Decision ID", acct["decision_id"])
    meta_c2.metric("Final Decision", acct["final_decision"])
    meta_c1.metric("CVE", results["cve"]["cve_id"])
    meta_c2.metric("Product", results["product_name"])

    st.markdown("---")

    # ── Accountability chain ──
    st.markdown("#### " + ("🔗 アカウンタビリティチェーン" if ja else "🔗 Accountability Chain"))
    for step in acct["accountability_chain"]:
        is_system = "🤖" in step["icon"]
        bg = "#eff6ff" if is_system else "#f0fdf4"
        border = "#2563eb" if is_system else "#16a34a"
        if "🏛️" in step["icon"]:
            bg, border = "#f0fdf4", "#16a34a"
        st.markdown(f"""
        <div style="background:{bg};border-left:5px solid {border};border-radius:8px;
                    padding:14px 18px;margin-bottom:10px">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span style="font-size:1.2rem">{step['icon']}</span>
            <div>
              <div style="font-size:0.72rem;color:#6b7280;font-weight:700;
                          text-transform:uppercase;letter-spacing:0.8px">
                {"ステップ" if ja else "Step"} {step['step']} — {step['role']}
              </div>
              <div style="font-weight:700;color:#1e293b;font-size:0.92rem">{step['actor']}</div>
            </div>
            <div style="margin-left:auto;text-align:right">
              <div style="font-size:0.82rem;font-weight:700;color:{border}">{step['action']}</div>
              <div style="font-size:0.72rem;color:#94a3b8">⏱ {step['timestamp']}</div>
            </div>
          </div>
          <div style="margin-top:8px;font-size:0.78rem;color:#4b5563;
                      border-top:1px solid #e2e8f0;padding-top:6px">
            {step['notes']}
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Review notes ──
    st.markdown("---")
    st.markdown("#### " + ("📝 審査ノート" if ja else "📝 Review Notes"))
    st.info(f"**{acct['human_reviewed_by']}** ({acct['review_action']}) — {acct['review_notes']}")


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 4 — Evidence Repository
# ══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("🗃️ " + ("証拠リポジトリ" if ja else "Evidence Repository"))
    st.caption("" + ("判定を支持するすべての証拠 — 種別・出典・信頼度・説明。"
                     if ja else
                     "All evidence supporting this decision — type, source, confidence, and description."))
    st.markdown("")

    STATUS_META = {
        "confirmed": ("✅ Confirmed",  "#f0fdf4", "#15803d", "#bbf7d0"),
        "clear":     ("🟢 Clear",      "#f0fdf4", "#15803d", "#bbf7d0"),
        "partial":   ("⚠️ Partial",    "#fff7ed", "#92400e", "#fed7aa"),
        "warning":   ("🔴 Warning",    "#fef2f2", "#b91c1c", "#fca5a5"),
        "none":      ("—  None",       "#f9fafb", "#6b7280", "#e5e7eb"),
    }

    for item in evrepo:
        sl, bg, fg, border = STATUS_META.get(item["status"], ("—", "#f9fafb", "#6b7280", "#e5e7eb"))
        conf_bar_w = int(item["confidence"] * 100)
        conf_col   = "#16a34a" if item["confidence"] >= 0.9 else "#d97706" if item["confidence"] >= 0.7 else "#dc2626"
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:10px;
                    padding:14px 18px;margin-bottom:12px">
          <!-- Header row -->
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px">
            <span style="font-size:1.2rem">{item['type_icon']}</span>
            <div>
              <div style="font-weight:800;color:#1e293b;font-size:0.92rem">{item['type']}</div>
              <div style="font-size:0.72rem;color:#6b7280">{item['source']}</div>
            </div>
            <div style="margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;gap:4px">
              <span style="background:{border};color:{fg};border-radius:10px;
                           padding:2px 10px;font-size:0.72rem;font-weight:700">{sl}</span>
              <span style="font-size:0.68rem;color:#94a3b8">⏱ {item['timestamp']}</span>
            </div>
          </div>
          <!-- Description -->
          <div style="font-size:0.82rem;color:#374151;margin-bottom:8px">{item['description']}</div>
          <!-- Confidence bar -->
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:0.68rem;color:#6b7280;width:70px">
              {"信頼度" if ja else "Confidence"}
            </span>
            <div style="flex:1;background:#e2e8f0;border-radius:999px;height:6px;overflow:hidden">
              <div style="background:{conf_col};width:{conf_bar_w}%;height:100%;border-radius:999px"></div>
            </div>
            <span style="font-size:0.72rem;font-weight:700;color:{conf_col};width:36px">
              {item['confidence']:.0%}
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Summary metrics ──
    st.markdown("---")
    st.markdown("##### " + ("証拠サマリー" if ja else "Evidence Summary"))
    em1, em2, em3, em4 = st.columns(4)
    em1.metric("Total Evidence Items", len(evrepo))
    em2.metric("Confirmed",    sum(1 for e in evrepo if e["status"] in ("confirmed","clear")))
    em3.metric("Partial/VEX",  sum(1 for e in evrepo if e["status"] == "partial"))
    em4.metric("Conflicts",    sum(1 for e in evrepo if e["status"] == "warning"))


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 5 — Decision Justification Record
# ══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("📋 " + ("判定正当化記録" if ja else "Decision Justification Record"))
    st.caption("" + ("監査担当者向けの完全な正当化記録 — この判定を即座に理解するために必要なすべて。"
                     if ja else
                     "Complete justification record for auditors — everything needed to "
                     "immediately understand this decision."))
    st.markdown("")

    # ── Identification block ──
    st.markdown(f"""
    <div style="background:#eff6ff;border-left:5px solid #1e3a8a;border-radius:8px;
                padding:14px 18px;margin-bottom:16px">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;
                  font-size:0.82rem">
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">Decision ID</b><br>
             <code style="color:#1e3a8a">{just['decision_id']}</code></div>
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">
             {"判定種別" if ja else "Decision Type"}</b><br>
             <b style="color:#dc2626">{just['decision_type']}</b></div>
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">CVE</b><br>
             <code>{just['cve_id']}</code></div>
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">
             {"製品" if ja else "Product"}</b><br>
             {just['product']}</div>
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">
             {"タイムスタンプ" if ja else "Timestamp"}</b><br>
             {just['decision_timestamp']}</div>
        <div><b style="color:#6b7280;font-size:0.68rem;text-transform:uppercase">ENISA Ref</b><br>
             <code>{just['enisa_reference']}</code></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    jc1, jc2 = st.columns(2, gap="large")

    with jc1:
        # ── Decision reasons ──
        st.markdown("#### " + ("📌 判定理由" if ja else "📌 Decision Reasons"))
        for r in just["decision_reasons"]:
            st.markdown(f"- {r}")

        st.markdown("")

        # ── Supporting evidence ──
        st.markdown("#### " + ("📚 裏付け証拠" if ja else "📚 Supporting Evidence"))
        for e in just["supporting_evidence"]:
            st.markdown(f"- ✅ {e}")

    with jc2:
        # ── Triggered rules ──
        st.markdown("#### " + ("⚡ 発動したルール" if ja else "⚡ Triggered Rules"))
        if just["triggered_rules"]:
            for rule in just["triggered_rules"]:
                st.markdown(f"- 🔴 **{rule}**")
        else:
            st.info("No rules triggered.")

        st.markdown("")

        # ── Reviewer record ──
        st.markdown("#### " + ("👤 レビュー記録" if ja else "👤 Reviewer Record"))
        st.markdown(f"""
        | {"項目" if ja else "Field"} | {"値" if ja else "Value"} |
        |---|---|
        | {"レビュアー" if ja else "Reviewer"} | {just['reviewer_name']} |
        | {"アクション" if ja else "Action"} | {just['reviewer_action']} |
        | {"ステータス" if ja else "Status"} | {just['approval_status']} |
        """)
        st.markdown(f"**{'審査ノート' if ja else 'Review Notes'}:** {just['reviewer_notes']}")

    # ── Full narrative ──
    st.markdown("---")
    st.markdown("#### " + ("📄 完全な正当化文（監査用）" if ja else "📄 Full Justification Narrative (Audit-Ready)"))
    st.markdown(
        f'<div style="background:#f8fafc;border-left:4px solid #1e3a8a;border-radius:6px;'
        f'padding:16px 20px;font-size:0.88rem;line-height:1.9;color:#374151">'
        f'{just["full_narrative"]}'
        f'</div>',
        unsafe_allow_html=True,
    )

    # ── Audit trail ──
    st.markdown("---")
    with st.expander("🗂️ " + ("完全な監査証跡" if ja else "Complete Audit Trail"), expanded=False):
        if just["full_audit_trail"]:
            at_df = pd.DataFrame(just["full_audit_trail"])
            at_df["timestamp"] = pd.to_datetime(at_df["timestamp"])
            for _, row in at_df.iterrows():
                action = str(row.get("action", ""))
                badge_cls = ("audit-stage"    if any(k in action for k in ["CVE","SBOM","Stage"])
                             else "audit-decision" if "DECISION" in action
                             else "audit-conflict")
                st.markdown(
                    f'`{row["timestamp"].strftime("%H:%M:%S")}` &nbsp;'
                    f'<span class="audit-badge {badge_cls}">{action}</span>'
                    f' &nbsp; {row.get("details","")}',
                    unsafe_allow_html=True,
                )
        else:
            st.info("No audit trail entries.")

    # ── JSON export ──
    st.markdown("---")
    st.markdown("##### " + ("JSON エクスポート（監査ファイル）" if ja else "JSON Export (Audit Record)"))
    export = {k: v for k, v in just.items() if k != "full_audit_trail"}
    st.download_button(
        label="⬇️ " + ("監査記録をダウンロード (JSON)" if ja else "Download Audit Record (JSON)"),
        data=json.dumps(export, ensure_ascii=False, indent=2),
        file_name=f"audit_record_{just['decision_id'][:8]}.json",
        mime="application/json",
    )

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    f"{t('legal_declaration')}</div>",
    unsafe_allow_html=True,
)
