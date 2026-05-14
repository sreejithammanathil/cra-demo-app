"""
Post-ENISA Compliance Lifecycle — CRA Decision Traceability System
Enterprise Regulatory Vulnerability Lifecycle Management
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from mock_data import POST_ENISA_DATA
from translations import t

st.set_page_config(
    page_title="Compliance Lifecycle — CRA System",
    page_icon="🏛️",
    layout="wide"
)

if "lang" not in st.session_state:
    st.session_state.lang = "en"

lc1, lc2, _ = st.columns([1, 1, 6])
with lc1:
    if st.button("🇺🇸 EN", use_container_width=True,
                 type="primary" if st.session_state.lang == "en" else "secondary"):
        st.session_state.lang = "en"; st.rerun()
with lc2:
    if st.button("🇯🇵 JP", use_container_width=True,
                 type="primary" if st.session_state.lang == "ja" else "secondary"):
        st.session_state.lang = "ja"; st.rerun()

ja = st.session_state.lang == "ja"
d = POST_ENISA_DATA

st.title("🏛️ " + ("CRA 規制コンプライアンス・ライフサイクル管理" if ja else
                   "CRA Regulatory Compliance Lifecycle Management"))
st.markdown("**" + ("ENISA報告後の規制運用フェーズ — 脆弱性ライフサイクル完全統合管理" if ja else
                    "Post-ENISA Regulatory Operations — Enterprise Vulnerability Lifecycle Management") + "**")

# Case banner
st.markdown(f"""
<div style="background:#1e3a5f;border-left:5px solid #3b82f6;border-radius:8px;padding:12px 18px;margin:8px 0 16px 0;display:flex;gap:32px;flex-wrap:wrap">
  <div><span style="color:#93c5fd;font-size:0.75rem">{'ケース参照' if ja else 'Case Ref'}</span><br><b style="color:white;font-size:0.95rem">{d['case_ref']}</b></div>
  <div><span style="color:#93c5fd;font-size:0.75rem">CVE</span><br><b style="color:white;font-size:0.95rem">{d['cve_id']}</b></div>
  <div><span style="color:#93c5fd;font-size:0.75rem">{'製品' if ja else 'Product'}</span><br><b style="color:white;font-size:0.95rem">{d['product']}</b></div>
  <div><span style="color:#93c5fd;font-size:0.75rem">{'初期報告' if ja else 'Initial Report'}</span><br><b style="color:white;font-size:0.95rem">{d['initial_report_ts']}</b></div>
  <div><span style="color:#93c5fd;font-size:0.75rem">ENISA Submission ID</span><br><b style="color:white;font-size:0.95rem">{d['enisa_submission_id']}</b></div>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ── Helpers ──────────────────────────────────────────────────────────────────

def status_badge(s, compact=False):
    cfg = {
        "COMPLETE":               ("#dcfce7","#166534","✅ Complete"),
        "IN_PROGRESS":            ("#dbeafe","#1e40af","🔄 In Progress"),
        "PENDING":                ("#f3f4f6","#6b7280","⏳ Pending"),
        "MORE_EVIDENCE_REQUESTED":("#fef3c7","#92400e","📋 More Evidence Requested"),
        "UNDER_REVIEW":           ("#dbeafe","#1e40af","🔍 Under Review"),
        "AWAITING_NOTIFICATION":  ("#f3f4f6","#6b7280","⏳ Awaiting Notification"),
        "PATCH_IN_QA":            ("#dbeafe","#1e40af","🔬 Patch in QA"),
        "RESPONDED":              ("#dcfce7","#166534","✅ Responded"),
        "SENT":                   ("#dcfce7","#166534","✅ Sent"),
        "DRAFT":                  ("#fef3c7","#92400e","📝 Draft"),
        "NOT_STARTED":            ("#f3f4f6","#6b7280","⏳ Not Started"),
        "MONITORING":             ("#dbeafe","#1e40af","👁️ Monitoring"),
        "ACTIVE":                 ("#dcfce7","#166534","✅ Active"),
        "LOCKED":                 ("#dcfce7","#166534","🔒 Locked"),
        "PENDING_RESPONSE":       ("#fef3c7","#92400e","⚠️ Pending Response"),
    }
    bg, color, label = cfg.get(s, ("#f3f4f6","#6b7280",s))
    pad = "2px 8px" if compact else "4px 12px"
    size = "0.7rem" if compact else "0.78rem"
    return f'<span style="background:{bg};color:{color};padding:{pad};border-radius:10px;font-size:{size};font-weight:600">{label}</span>'

def risk_badge(level):
    colors = {"HIGH":("#fff5f5","#dc2626"),"MEDIUM":("#fff7ed","#c2410c"),"LOW":("#f0fff4","#16a34a")}
    bg, c = colors.get(level, ("#f3f4f6","#6b7280"))
    return f'<span style="background:{bg};color:{c};padding:4px 12px;border-radius:10px;font-size:0.82rem;font-weight:700">{level}</span>'

def section_header(icon, title_en, title_ja):
    st.markdown(f"#### {icon} {title_ja if ja else title_en}")

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_labels = (
    ["📋 ライフサイクル","🏛️ 規制調整","🔧 修正管理","📢 顧客通知",
     "🔍 根本原因分析","📄 最終報告","🔒 監査保管","👁️ 継続監視","📊 経営・法務"]
    if ja else
    ["📋 Lifecycle","🏛️ Regulatory","🔧 Remediation","📢 Customers",
     "🔍 RCA","📄 Final Report","🔒 Audit","👁️ Monitoring","📊 Executive"]
)
tabs = st.tabs(tab_labels)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Lifecycle Overview
# ══════════════════════════════════════════════════════════════════════════════
with tabs[0]:
    phases = d["lifecycle_phases"]
    n_done  = sum(1 for p in phases if p["status"] == "COMPLETE")
    n_wip   = sum(1 for p in phases if p["status"] == "IN_PROGRESS")
    n_pend  = sum(1 for p in phases if p["status"] == "PENDING")

    m1,m2,m3,m4,m5 = st.columns(5)
    m1.metric("📋 " + ("総フェーズ" if ja else "Total Phases"),  len(phases))
    m2.metric("✅ " + ("完了" if ja else "Complete"),            n_done,  delta=f"+{n_done}")
    m3.metric("🔄 " + ("進行中" if ja else "In Progress"),       n_wip)
    m4.metric("⏳ " + ("未着手" if ja else "Pending"),           n_pend)
    m5.metric("📅 " + ("経過日数" if ja else "Days Open"),        d["executive"]["days_open"])
    st.markdown("---")

    section_header("📋","Post-ENISA Operational Phases","ENISA報告後の運用フェーズ")
    st.caption("CRA Article 14 — full compliance lifecycle from initial submission to audit retention" if not ja
               else "CRA第14条 — 初期提出から監査保管までの完全コンプライアンスライフサイクル")
    st.markdown("")

    for p in phases:
        s = p["status"]
        icon  = "✅" if s=="COMPLETE" else "🔄" if s=="IN_PROGRESS" else "⏳"
        bg    = "#f0fff4" if s=="COMPLETE" else "#eff6ff" if s=="IN_PROGRESS" else "#f9fafb"
        border= "#21c354" if s=="COMPLETE" else "#3b82f6" if s=="IN_PROGRESS" else "#d1d5db"
        pname = p["name_ja"] if ja else p["name"]
        sla_str  = f"SLA: {p['sla_h']}h" if p['sla_h'] else "Ongoing"
        ts_str   = p["ts"] if p["ts"] else ("—")
        elapsed  = f"{p['elapsed_h']}h elapsed" if p['elapsed_h'] else ""
        over_sla = p['sla_h'] and p['elapsed_h'] and p['elapsed_h'] > p['sla_h']
        sla_warn = " ⚠️" if over_sla else ""

        col_icon, col_main, col_owner, col_status, col_sla = st.columns([0.3,3,1.8,1.5,1.5])
        with col_icon:   st.markdown(f"<div style='font-size:1.3rem;padding-top:6px'>{icon}</div>", unsafe_allow_html=True)
        with col_main:
            st.markdown(f"""<div style="background:{bg};border-left:4px solid {border};border-radius:6px;padding:8px 12px">
            <b style="font-size:0.9rem">{p['id']} — {pname}</b>
            <div style="font-size:0.74rem;color:#6b7280;margin-top:2px">{'' if not ts_str or ts_str=='—' else ('完了: ' if ja else 'Completed: ')+ts_str}</div>
            </div>""", unsafe_allow_html=True)
        with col_owner:  st.caption(p["owner"])
        with col_status: st.markdown(status_badge(s, compact=True), unsafe_allow_html=True)
        with col_sla:    st.caption(f"{sla_str}{' · '+elapsed if elapsed else ''}{sla_warn}")

    # Phase completion donut
    st.markdown("---")
    section_header("📊","Phase Completion Overview","フェーズ完了概要")
    fig = go.Figure(go.Pie(
        labels=["Complete","In Progress","Pending"],
        values=[n_done, n_wip, n_pend], hole=0.55,
        marker=dict(colors=["#21c354","#3b82f6","#d1d5db"]),
        textinfo="label+value"
    ))
    fig.update_layout(height=260, margin=dict(t=20,b=10,l=10,r=10), showlegend=True)
    _,chart_col,_ = st.columns([1,2,1])
    with chart_col:
        st.plotly_chart(fig, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Regulatory Coordination
# ══════════════════════════════════════════════════════════════════════════════
with tabs[1]:
    reg = d["regulatory"]
    section_header("🏛️","Regulatory Coordination Center","規制調整センター")

    # Status banner
    st.markdown(status_badge(reg["status"]), unsafe_allow_html=True)
    st.markdown("")

    r1,r2,r3,r4 = st.columns(4)
    r1.metric("📁 " + ("ケース参照" if ja else "Case Ref"),    d["case_ref"])
    r2.metric("👤 " + ("担当者" if ja else "Case Manager"),   reg["case_manager"].split("(")[0].strip())
    r3.metric("📅 " + ("経過日数" if ja else "Days Elapsed"),  f"{reg['days_elapsed']}/{reg['sla_days']}")
    r4.metric("⏰ " + ("回答期限" if ja else "Response Deadline"), reg["response_deadline"])

    # SLA progress
    pct = reg["days_elapsed"] / reg["sla_days"]
    color = "#ff4b4b" if pct > 0.8 else "#ffa500" if pct > 0.6 else "#21c354"
    st.markdown(f"""
    <div style="margin:12px 0 4px 0;font-size:0.82rem;font-weight:600">{"規制対応SLA 進捗" if ja else "Regulatory Response SLA"} — {reg['days_elapsed']}/{reg['sla_days']} {"日" if ja else "days"}</div>
    <div style="background:#e5e7eb;border-radius:8px;height:14px">
      <div style="background:{color};width:{pct*100:.0f}%;height:14px;border-radius:8px"></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    section_header("📋","Open Request","未処理リクエスト")
    st.warning(f"**{'未処理リクエスト:' if ja else 'Open Request:'}** {reg['open_request']}")
    st.caption(f"{'回答期限:' if ja else 'Response deadline:'} **{reg['response_deadline']}**")

    st.markdown("---")
    section_header("🌍","Authority Status by Country","各国当局ステータス")
    auth_cols = st.columns(3)
    for i, auth in enumerate(reg["authority_statuses"]):
        with auth_cols[i % 3]:
            st.markdown(status_badge(auth["status"], compact=True), unsafe_allow_html=True)
            st.markdown(f"**{auth['flag']} {auth['name']}**")
            st.markdown("")

    st.markdown("---")
    section_header("📨","Follow-up Requests","フォローアップリクエスト")
    fu_df = pd.DataFrame([{
        ("日付" if ja else "Date"):   r["date"],
        ("送信元" if ja else "From"):  r["from"],
        ("種別" if ja else "Type"):    r["type"],
        ("件名" if ja else "Subject"): r["subject"],
        ("状況" if ja else "Status"):  r["status"],
    } for r in reg["follow_ups"]])
    st.dataframe(fu_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    section_header("📜","Communication History","通信履歴")
    for c in reg["comms_log"]:
        dir_icon = "📤" if c["dir"]=="OUT" else "📥"
        dir_label = ("送信" if ja else "OUTBOUND") if c["dir"]=="OUT" else ("受信" if ja else "INBOUND")
        dir_color = "#1e40af" if c["dir"]=="IN" else "#166534"
        st.markdown(f"""
        <div style="border-left:3px solid {dir_color};padding:6px 12px;margin-bottom:6px;background:#f9fafb;border-radius:0 6px 6px 0">
          <span style="font-size:0.72rem;color:#6b7280">{c['ts']} · {dir_icon} {dir_label} · {c['ch']}</span><br>
          <span style="font-size:0.85rem">{c['summary']}</span>
        </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — Remediation Governance
# ══════════════════════════════════════════════════════════════════════════════
with tabs[2]:
    rem = d["remediation"]
    section_header("🔧","Remediation Governance","修正ガバナンス")
    st.markdown(status_badge(rem["status"]), unsafe_allow_html=True)
    st.markdown("")

    r1,r2,r3,r4 = st.columns(4)
    r1.metric("👤 " + ("担当者" if ja else "Owner"),         rem["owner"].split("—")[0].strip())
    r2.metric("📅 " + ("パッチETA" if ja else "Patch ETA"),  rem["patch_eta"])
    r3.metric("📦 " + ("バージョン" if ja else "Version"),   rem["patch_version"])
    r4.metric("🖥️ " + ("未解決システム" if ja else "Unresolved Systems"), rem["unresolved_systems"])

    st.markdown("---")
    section_header("🛡️","Mitigation Status","緩和状況")
    c1, c2 = st.columns(2)
    with c1:
        if rem["mitigation_available"]:
            st.success("✅ " + ("暫定緩和策: 公開済み" if ja else "Interim Mitigation: Published"))
            st.caption(rem["mitigation_desc"])
        else:
            st.error("❌ " + ("緩和策なし" if ja else "No mitigation available"))
    with c2:
        if rem["workaround_published"]:
            st.success("✅ " + ("ワークアラウンド: 公開済み" if ja else "Workaround: Published"))
            st.caption(f"{'公開日時:' if ja else 'Published:'} {rem['workaround_ts']}")

    st.markdown("---")
    section_header("🚀","Patch Rollout Plan","パッチ展開計画")
    wave_colors = {"COMPLETE":"#dcfce7","IN_PROGRESS":"#dbeafe","PENDING":"#f3f4f6"}
    wave_border = {"COMPLETE":"#21c354","IN_PROGRESS":"#3b82f6","PENDING":"#d1d5db"}
    for w in rem["rollout_waves"]:
        bg = wave_colors.get(w["status"],"#f3f4f6")
        br = wave_border.get(w["status"],"#d1d5db")
        wc1, wc2, wc3, wc4 = st.columns([0.3, 3, 1.5, 1.5])
        with wc1: st.markdown(f"<b style='font-size:1.1rem'>W{w['wave']}</b>", unsafe_allow_html=True)
        with wc2:
            st.markdown(f"""<div style="background:{bg};border-left:4px solid {br};border-radius:6px;padding:7px 12px">
            <b>{w['target']}</b> — {w['systems']} {'システム' if ja else 'systems'}</div>""", unsafe_allow_html=True)
        with wc3: st.caption(w["date"])
        with wc4: st.markdown(status_badge(w["status"], compact=True), unsafe_allow_html=True)

    st.markdown("---")
    section_header("📅","Remediation Timeline","修正タイムライン")
    for item in rem["timeline"]:
        is_eta = "(ETA)" in item["event"]
        color = "#9ca3af" if is_eta else "#374151"
        style = "italic" if is_eta else "normal"
        st.markdown(f"""
        <div style="display:flex;gap:12px;margin-bottom:6px;align-items:flex-start">
          <span style="font-size:0.78rem;color:#6b7280;min-width:90px">{item['date']}</span>
          <span style="color:#9ca3af;font-size:0.9rem">{'—' if is_eta else '●'}</span>
          <span style="font-size:0.85rem;color:{color};font-style:{style}">{item['event']}</span>
        </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Customer Notifications
# ══════════════════════════════════════════════════════════════════════════════
with tabs[3]:
    cn = d["customer_notifications"]
    section_header("📢","Customer Communication Tracking","顧客通信管理")

    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("📧 " + ("通知送信数" if ja else "Notified"),           cn["notifications_sent"])
    c2.metric("✅ " + ("確認応答" if ja else "Acknowledged"),          cn["acknowledgements"],
              delta=f"{cn['acknowledgements']/cn['notifications_sent']*100:.0f}%")
    c3.metric("🔴 " + ("高リスク顧客" if ja else "High-Risk"),         cn["high_risk"])
    c4.metric("⚠️ " + ("サポートエスカレーション" if ja else "Escalations"), cn["support_escalations"])
    c5.metric("📋 " + ("アドバイザリーID" if ja else "Advisory ID"),   cn["advisory_id"])

    st.markdown("---")
    section_header("📬","Communication Templates","通信テンプレート")
    for tmpl in cn["templates"]:
        is_sent = tmpl["status"] == "SENT"
        bg = "#f0fff4" if is_sent else "#f9fafb"
        border = "#21c354" if is_sent else "#d1d5db"
        tc1, tc2, tc3 = st.columns([3, 1.5, 1.5])
        with tc1:
            st.markdown(f"""<div style="background:{bg};border-left:4px solid {border};padding:7px 12px;border-radius:6px">
            <b>{'✅ ' if is_sent else '⏳ '}{tmpl['name_ja'] if ja else tmpl['name']}</b>
            </div>""", unsafe_allow_html=True)
        with tc2: st.caption(f"{'受信者:' if ja else 'Recipients:'} {tmpl['recipients']}")
        with tc3: st.caption(tmpl["ts"] if tmpl["ts"] else ("—"))

    st.markdown("---")
    c_left, c_right = st.columns(2)
    with c_left:
        section_header("✅","Approval Chain","承認チェーン")
        for a in cn["approval_chain"]:
            icon = "✅" if a["approved"] else "⏳"
            st.markdown(f"{icon} **{a['role']}** — {a['name']}")
            st.caption(f"  {'承認日時:' if ja else 'Approved:'} {a['ts']}")

    with c_right:
        section_header("🔴","High-Risk Customer Status","高リスク顧客ステータス")
        hr_df = pd.DataFrame([{
            ("顧客ID" if ja else "Customer"): r["id"],
            ("国" if ja else "Country"): r["country"],
            ("バージョン" if ja else "Version"): r["version"],
            ("状況" if ja else "Status"): r["status"],
            ("エスカレーション" if ja else "Escalation"): "⚠️ YES" if r["escalation"] else "—",
        } for r in cn["high_risk_detail"]])
        st.dataframe(hr_df, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 — Root Cause Analysis
# ══════════════════════════════════════════════════════════════════════════════
with tabs[4]:
    rca = d["rca"]
    section_header("🔍","Root Cause Analysis","根本原因分析")
    st.markdown(status_badge(rca["status"]), unsafe_allow_html=True)
    st.markdown("")

    r1,r2,r3 = st.columns(3)
    r1.metric("👤 " + ("調査担当" if ja else "Owner"),           rca["owner"].split("—")[0].strip())
    r2.metric("📅 " + ("調査開始" if ja else "Started"),         rca["started"])
    r3.metric("🎯 " + ("完了目標" if ja else "Target Complete"), rca["target_completion"])

    st.markdown("---")
    section_header("📋","Key Investigation Findings","主要調査結果")

    findings_data = [
        ("🔗", "Vulnerability Source"     if not ja else "脆弱性の起源",   rca["vuln_source"]),
        ("📦", "Dependency Origin"        if not ja else "依存関係の起源",  rca["dep_origin"]),
        ("⚙️", "Secure SDLC Gap"          if not ja else "セキュアSDLCのギャップ", rca["sdlc_gap"]),
        ("🕐", "Detection Failure"        if not ja else "検出の失敗",      rca["detection_failure"]),
        ("⛓️", "Exploit Chain"            if not ja else "エクスプロイトチェーン", rca["exploit_chain"]),
    ]
    for icon, label, text in findings_data:
        with st.expander(f"{icon} {label}"):
            st.markdown(text)

    st.markdown("---")
    section_header("📝","Findings Summary","調査結果要約")
    st.info(rca["findings"])

    section_header("💡","Lessons Learned","教訓")
    for i, lesson in enumerate(rca["lessons_learned"], 1):
        st.markdown(f"**{i}.** {lesson}")

    st.markdown("---")
    section_header("🚀","Preventive Actions","予防措置")
    pa_df = pd.DataFrame([{
        ("措置" if ja else "Action"):   a["action"],
        ("担当" if ja else "Owner"):    a["owner"],
        ("期限" if ja else "Deadline"): a["deadline"],
        ("状況" if ja else "Status"):   a["status"],
    } for a in rca["preventive_actions"]])
    st.dataframe(pa_df, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 — Final ENISA Report
# ══════════════════════════════════════════════════════════════════════════════
with tabs[5]:
    fr = d["final_report"]
    section_header("📄","Final ENISA Report","ENISA最終報告")
    st.markdown(status_badge(fr["status"]), unsafe_allow_html=True)
    st.markdown("")

    fr1,fr2,fr3 = st.columns(3)
    fr1.metric("📅 " + ("提出期限" if ja else "Due Date"),       fr["due"])
    fr2.metric("⏰ " + ("残り日数" if ja else "Days Remaining"), fr["days_remaining"])
    fr3.metric("📎 " + ("初期報告参照" if ja else "Initial Report Ref"), d["enisa_submission_id"])

    st.markdown("---")
    c_left, c_right = st.columns(2)
    with c_left:
        section_header("📋","Report Sections Status","報告書セクション状況")
        for sec in fr["sections"]:
            s = sec["status"]
            icon = "✅" if s=="COMPLETE" else "📝" if s=="DRAFT" else "🔄" if s=="IN_PROGRESS" else "⏳"
            color = "#166534" if s=="COMPLETE" else "#1e40af" if s in ("DRAFT","IN_PROGRESS") else "#6b7280"
            st.markdown(f'<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #f3f4f6"><span>{icon} {sec["name"]}</span><span style="color:{color};font-size:0.78rem;font-weight:600">{s}</span></div>',
                        unsafe_allow_html=True)

    with c_right:
        section_header("🔄","Initial vs Final Report Comparison","初期報告と最終報告の比較")
        cmp_df = pd.DataFrame([{
            ("項目" if ja else "Field"):          r["field"],
            ("初期報告" if ja else "Initial"):    r["initial"],
            ("最終報告（予定）" if ja else "Final (planned)"): r["final"],
        } for r in fr["initial_vs_final"]])
        st.dataframe(cmp_df, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 7 — Audit Retention
# ══════════════════════════════════════════════════════════════════════════════
with tabs[6]:
    aud = d["audit"]
    section_header("🔒","Audit Retention & Evidence Locking","監査保管・証拠ロック")

    a1,a2,a3,a4 = st.columns(4)
    a1.metric("📅 " + ("ケース開始" if ja else "Case Opened"),   aud["case_opened"])
    a2.metric("📁 " + ("保管期間" if ja else "Retention"),       f"{aud['retention_years']} {'年' if ja else 'years'}")
    a3.metric("🗓️ " + ("保管期限" if ja else "Expires"),         aud["retention_expiry"])
    a4.metric("📊 " + ("完全性" if ja else "Completeness"),       f"{aud['completeness_pct']}%")

    # Completeness gauge
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number", value=aud["completeness_pct"],
        title={"text": "証拠パッケージ完全性" if ja else "Evidence Package Completeness (%)"},
        gauge={"axis":{"range":[0,100]},"bar":{"color":"#3b82f6"},
               "steps":[{"range":[0,50],"color":"#fee2e2"},{"range":[50,80],"color":"#fef9c3"},{"range":[80,100],"color":"#dcfce7"}],
               "threshold":{"line":{"color":"black","width":3},"thickness":0.75,"value":100}}
    ))
    fig_gauge.update_layout(height=220, margin=dict(t=40,b=10,l=20,r=20))
    _,gcol,_ = st.columns([1,2,1])
    with gcol: st.plotly_chart(fig_gauge, use_container_width=True)

    st.markdown("---")
    section_header("📦","Evidence Packages","証拠パッケージ")
    ev_df = pd.DataFrame([{
        "ID":                       e["id"],
        ("名称" if ja else "Name"): e["name"],
        ("種別" if ja else "Type"): e["type"],
        ("サイズ" if ja else "Size"): f"{e['size_kb']} KB" if e["size_kb"] else "—",
        ("ハッシュ" if ja else "Hash"):  e["hash"],
        ("状況" if ja else "Status"):   e["status"],
        ("日時" if ja else "Date"):  e["ts"] if e["ts"] else "—",
    } for e in aud["evidence_packages"]])

    def _ev_color(v):
        if v == "LOCKED": return "background-color:#f0fff4;color:#166534"
        if v == "PENDING": return "background-color:#fef9c3;color:#92400e"
        return ""

    st.dataframe(
        ev_df.style.map(_ev_color, subset=[("状況" if ja else "Status")]),
        use_container_width=True, hide_index=True
    )

    st.markdown("---")
    section_header("⛓️","Chain of Custody","保管チェーン")
    for entry in aud["custody_log"]:
        st.markdown(f"""
        <div style="border-left:3px solid #3b82f6;padding:5px 12px;margin-bottom:5px;background:#f9fafb;border-radius:0 6px 6px 0">
          <span style="font-size:0.72rem;color:#6b7280">{entry['ts']} · {entry['actor']}</span><br>
          <span style="font-size:0.84rem">🔒 {entry['event']}</span>
        </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 8 — Post-Closure Monitoring
# ══════════════════════════════════════════════════════════════════════════════
with tabs[7]:
    mon = d["monitoring"]
    section_header("👁️","Post-Closure Monitoring","クロージャ後の継続監視")

    m1,m2,m3 = st.columns(3)
    m1.metric("🔭 " + ("監視状況" if ja else "Status"),          "🟢 Active" if mon["active"] else "Inactive")
    m2.metric("📅 " + ("監視終了予定" if ja else "Monitor Until"), mon["monitoring_until"])
    m3.metric("🕐 " + ("最終KEV確認" if ja else "Last KEV Check"), mon["last_kev_check"])

    st.markdown("---")
    intel_status_color = "#dcfce7" if mon["exploit_intel_status"]=="NO_NEW_ACTIVITY" else "#fff5f5"
    st.markdown(f"""
    <div style="background:{intel_status_color};border-radius:8px;padding:12px 18px;margin-bottom:12px">
      <b>{'エクスプロイトインテリジェンス:' if ja else 'Exploit Intelligence Status:'}</b>
      {'新たな活動なし ✅' if mon['exploit_intel_status']=='NO_NEW_ACTIVITY' else mon['exploit_intel_status']}
      {'　|　パッチバイパス:' if True else ''} {'未検出 ✅' if not mon['patch_bypass'] else '⚠️ 検出'}
    </div>""", unsafe_allow_html=True)

    section_header("📡","Intelligence Sources","インテリジェンスソース")
    src_cols = st.columns(len(mon["sources"]))
    for col, src in zip(src_cols, mon["sources"]):
        with col:
            st.markdown(f'<div style="background:#eff6ff;border-radius:8px;padding:8px;text-align:center;font-size:0.78rem;font-weight:600;color:#1e40af">{src}</div>',
                        unsafe_allow_html=True)

    st.markdown("---")
    section_header("🚨","Reopen Triggers","再開トリガー")
    st.caption("Cases will automatically be flagged for review if any of the following are detected:" if not ja
               else "以下のいずれかが検出された場合、ケースは自動的にレビューフラグが立てられます:")
    trig_cols = st.columns(2)
    for i, trig in enumerate(mon["reopen_triggers"]):
        with trig_cols[i % 2]:
            st.markdown(f"""
            <div style="background:#eff6ff;border-left:3px solid #3b82f6;border-radius:6px;padding:8px 12px;margin-bottom:8px">
              <b style="font-size:0.85rem">{'👁️ ' + (trig['trigger_ja'] if ja else trig['trigger'])}</b><br>
              <span style="font-size:0.72rem;color:#1e40af">{trig['status']}</span>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")
    section_header("📋","KEV / Exploit Intelligence Log","KEV・エクスプロイトログ")
    for entry in mon["kev_log"]:
        st.markdown(f"`{entry['date']}` — {entry['event']}")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 9 — Executive & Legal Panel
# ══════════════════════════════════════════════════════════════════════════════
with tabs[8]:
    exe = d["executive"]
    section_header("📊","Executive & Legal Risk Panel","経営・法務リスクパネル")

    # Risk row
    ec1,ec2,ec3,ec4 = st.columns(4)
    with ec1:
        st.markdown(f"""<div style="border-radius:10px;padding:16px;background:#fff7ed;border-left:5px solid #c2410c;text-align:center">
        <div style="font-size:0.78rem;color:#92400e;font-weight:600">{'総合リスク' if ja else 'Overall Risk'}</div>
        <div style="margin-top:6px">{risk_badge(exe['overall_risk'])}</div></div>""", unsafe_allow_html=True)
    with ec2:
        st.markdown(f"""<div style="border-radius:10px;padding:16px;background:#fff7ed;border-left:5px solid #c2410c;text-align:center">
        <div style="font-size:0.78rem;color:#92400e;font-weight:600">{'規制リスク' if ja else 'Regulatory Risk'}</div>
        <div style="margin-top:6px">{risk_badge(exe['regulatory_risk'])}</div>
        <div style="font-size:0.7rem;color:#6b7280;margin-top:4px">{exe['regulatory_detail']}</div></div>""", unsafe_allow_html=True)
    with ec3:
        st.markdown(f"""<div style="border-radius:10px;padding:16px;background:#f0fff4;border-left:5px solid #16a34a;text-align:center">
        <div style="font-size:0.78rem;color:#166534;font-weight:600">{'訴訟リスク' if ja else 'Litigation Risk'}</div>
        <div style="margin-top:6px">{risk_badge(exe['litigation_risk'])}</div>
        <div style="font-size:0.7rem;color:#6b7280;margin-top:4px">{exe['litigation_detail'][:60]}…</div></div>""", unsafe_allow_html=True)
    with ec4:
        st.markdown(f"""<div style="border-radius:10px;padding:16px;background:#eff6ff;border-left:5px solid #1e40af;text-align:center">
        <div style="font-size:0.78rem;color:#1e40af;font-weight:600">{'未解決露出' if ja else 'Unresolved Exposure'}</div>
        <div style="font-size:1.8rem;font-weight:800;color:#1e40af;margin-top:4px">{exe['unresolved_exposure']:,}</div>
        <div style="font-size:0.7rem;color:#6b7280">{'システム' if ja else 'systems'}</div></div>""", unsafe_allow_html=True)

    st.markdown("---")
    # Financial exposure
    section_header("💶","Estimated Financial Exposure","推定財務エクスポージャー")
    st.caption("Based on regulatory penalty risk, customer impact, and SLA breach exposure (EU CRA Article 64)" if not ja
               else "規制罰則リスク、顧客影響、SLA違反エクスポージャーに基づく（EU CRA第64条）")
    fig_fin = go.Figure()
    fig_fin.add_trace(go.Bar(name="Low Estimate" if not ja else "低推定",
                             x=["Financial Exposure" if not ja else "財務エクスポージャー"],
                             y=[exe["financial_low"]], marker_color="#fbbf24"))
    fig_fin.add_trace(go.Bar(name="High Estimate" if not ja else "高推定",
                             x=["Financial Exposure" if not ja else "財務エクスポージャー"],
                             y=[exe["financial_high"] - exe["financial_low"]], marker_color="#ef4444"))
    fig_fin.update_layout(barmode="stack", height=220, margin=dict(t=20,b=10,l=20,r=20),
                          yaxis_tickprefix="€", yaxis_tickformat=",")
    st.plotly_chart(fig_fin, use_container_width=True)
    st.caption(f"{'推定範囲:' if ja else 'Estimated range:'} **€{exe['financial_low']:,} – €{exe['financial_high']:,}**")

    st.markdown("---")
    section_header("📏","KPI & SLA Compliance","KPI・SLAコンプライアンス")
    m1,m2 = st.columns(2)
    with m1: st.metric("✅ " + ("SLA遵守率" if ja else "SLA Compliance"), f"{exe['sla_compliance_pct']}%")
    with m2: st.metric("⚠️ " + ("SLA違反件数" if ja else "SLA Breaches"), exe["sla_breaches"],
                       delta=exe["sla_breach_detail"][:50], delta_color="inverse")

    kpi_df = pd.DataFrame([{
        ("KPI" if not ja else "KPI"):          k["name_ja"] if ja else k["name"],
        ("実績" if ja else "Actual"):           k["value"],
        ("目標" if ja else "Target"):           k["target"],
        ("達成" if ja else "Met"):              "✅" if k["met"] else "⚠️",
    } for k in exe["kpis"]])

    def _kpi_color(v):
        if v == "✅": return "background-color:#f0fff4;color:#166534"
        if v == "⚠️": return "background-color:#fff5f5;color:#dc2626"
        return ""

    st.dataframe(
        kpi_df.style.map(_kpi_color, subset=[("達成" if ja else "Met")]),
        use_container_width=True, hide_index=True
    )

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    f"{t('legal_declaration')}</div>",
    unsafe_allow_html=True
)
