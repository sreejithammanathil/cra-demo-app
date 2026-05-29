"""
Act 1 — Detection Results
Stages 1-3: CVE Ingestion · SBOM Analysis · Conflict Detection
"""

import streamlit as st
import pandas as pd

from translations import t
from utils import (inject_css, lang_toggle_sidebar, sidebar_current_run,
                   sidebar_home_button, no_results_guard,
                   pipeline_stepper, cvss_gauge, sbom_table, cve_desc, decision_badge)

st.set_page_config(
    page_title="Act 1: Detection — CRA System",
    page_icon="🔍",
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
    st.page_link("pages/2_Decision.py",   label="⚖️ " + ("Act 2 — 判定" if ja else "Act 2 — Decision"))
    st.page_link("pages/3_Reporting.py",  label="📡 " + ("Act 3 — 報告" if ja else "Act 3 — Reporting"))
    st.page_link("pages/4_Compliance.py", label="📋 " + ("コンプライアンス" if ja else "Compliance"))
    st.page_link("pages/5_History.py",    label="📚 " + ("履歴" if ja else "History"))
    st.markdown("---")
    sidebar_home_button()

ja = st.session_state.lang == "ja"

st.title("🔍 " + ("アクト 1 — 脅威検出" if ja else "Act 1 — Threat Detection"))
st.markdown("**" + ("CVE取込 · SBOM照合 · 矛盾検出 — パイプラインのステージ 1-3"
                    if ja else
                    "CVE Ingestion · SBOM Matching · Conflict Detection — Pipeline Stages 1–3") + "**")
st.markdown("---")

if not no_results_guard():
    st.stop()

results = st.session_state.pipeline_results
pre     = st.session_state.get("pre_review")
phase   = st.session_state.pipeline_phase

# Use pre_review data if full results aren't complete yet
r = results if results else pre

# Pipeline stepper
steps_done = 6 if results else 4
st.markdown(t("section_pipeline"))
pipeline_stepper(completed=steps_done)
st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 1 — CVE Ingestion
# ═══════════════════════════════════════════════════════
st.header("📥 " + ("ステージ 1 — CVE 取込" if ja else "Stage 1 — CVE Ingestion"))
st.caption("" + ("NVDから脆弱性データを取り込み、基本メタデータを検証します。"
                 if ja else
                 "Load vulnerability data from NVD and validate core metadata."))

c1, c2 = st.columns([1, 2])
with c1:
    st.plotly_chart(cvss_gauge(r["cve"]["cvss_score"]), use_container_width=True)
with c2:
    st.markdown("**" + ("CVE 詳細" if ja else "CVE Details") + "**")
    st.info(cve_desc(r["scenario_key"]))
    a, b, c = st.columns(3)
    a.metric(t("metric_cve"),      r["cve"]["cve_id"])
    b.metric(t("metric_severity"), r["cve"]["severity"])
    c.metric(t("metric_exploit"),
             ("あり ⚠️" if r["cve"]["exploit_available"] else "なし ✅") if ja else
             ("YES ⚠️" if r["cve"]["exploit_available"] else "NO ✅"))
    st.markdown(f"{t('t1_affected_range')} "
                f"`{r['cve']['affected_versions']['range_start']}` → "
                f"`{r['cve']['affected_versions']['range_end']}`")

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 2 — SBOM Analysis
# ═══════════════════════════════════════════════════════
st.header("🔩 " + ("ステージ 2 — SBOM 照合分析" if ja else "Stage 2 — SBOM Match Analysis"))
st.caption("" + ("製品のSBOMコンポーネントとCVEの影響範囲を照合します。"
                 if ja else
                 "Cross-reference the product's SBOM components against the CVE's affected version range."))

match = r["sbom_match"]
a, b, c = st.columns(3)
a.metric(t("metric_product"),           match["product_name"])
b.metric(t("metric_match_confidence"),  f"{match['match_confidence']:.0%}")
c.metric(t("metric_component_found"),
         ("あり 🔴" if match["matching_component"] else "なし 🟢") if ja else
         ("YES 🔴" if match["matching_component"] else "NO 🟢"))

if match["match_found"]:
    st.error(t("t2_vuln", reason=match["match_reason"]))
else:
    st.success(t("t2_safe", reason=match["match_reason"]))

st.markdown("**" + ("SBOMコンポーネント一覧" if ja else "SBOM Component Inventory") + "**")
df = sbom_table(r["product_name"], match.get("matching_component"), match["match_found"])
vuln_col = t("t2_col_status")
st.dataframe(
    df.style.map(lambda v: "background-color:#fff5f5" if t("t2_vulnerable") in str(v) else "",
                 subset=[vuln_col]),
    use_container_width=True, hide_index=True)

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  STAGE 3 — Conflict Detection
# ═══════════════════════════════════════════════════════
st.header("⚡ " + ("ステージ 3 — 矛盾検出" if ja else "Stage 3 — Conflict Detection"))
st.caption("" + ("VEXステートメントとSBOM照合結果の矛盾を確認します。"
                 if ja else
                 "Check for contradictions between VEX statements and SBOM match results."))

conflict = r["conflict_info"]
if conflict["conflict_detected"]:
    st.warning(t("t3_conflict", type=conflict["conflict_type"]))
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**" + ("証拠サマリー" if ja else "Evidence Summary") + "**")
        for ev in conflict["evidence_summary"]:
            st.markdown(f"- {ev}")
    with col_b:
        if conflict.get("vex_available"):
            st.info(t("t3_vex"))
else:
    st.success(t("t3_no_conflict"))
    for ev in conflict["evidence_summary"]:
        st.markdown(f"- {ev}")

with st.expander(t("t3_raw")):
    st.json(conflict)

st.markdown("---")


# ═══════════════════════════════════════════════════════
#  Audit Trail (stages 1-3)
# ═══════════════════════════════════════════════════════
with st.expander("🗂️ " + ("監査証跡 — ステージ 1-3" if ja else "Audit Trail — Stages 1–3"), expanded=False):
    trail_src = r.get("partial_audit_trail") or r.get("audit_trail", [])
    audit_df = pd.DataFrame(trail_src)
    if not audit_df.empty:
        audit_df["timestamp"] = pd.to_datetime(audit_df["timestamp"])
        for _, row in audit_df.iterrows():
            action = str(row.get("action", ""))
            badge_cls = ("audit-stage" if any(k in action for k in ["CVE", "SBOM", "Stage"])
                         else "audit-decision" if "DECISION" in action else "audit-conflict")
            st.markdown(
                f'`{row["timestamp"].strftime("%H:%M:%S")}` &nbsp;'
                f'<span class="audit-badge {badge_cls}">{action}</span>'
                f' &nbsp; {row.get("details", "")}',
                unsafe_allow_html=True)

st.markdown("---")

# ── Next step navigation ──
st.markdown("### " + ("次のステップ" if ja else "Next Step"))
nav1, nav2 = st.columns(2)
with nav1:
    st.page_link("app.py", label="← " + ("ダッシュボードへ戻る" if ja else "Back to Dashboard"))
with nav2:
    st.page_link("pages/2_Decision.py",
                 label="⚖️ " + ("Act 2: 判定分析へ →" if ja else "Act 2: Decision Analysis →"))

st.markdown(f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:18px;"
            f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",
            unsafe_allow_html=True)
