"""
CRA Decision Traceability System — Executive Dashboard
Home screen: system overview, KPIs, session stats, products, rules
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from translations import t

st.set_page_config(
    page_title="CRA Decision Traceability System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---- shared session state ----
if "lang"             not in st.session_state: st.session_state.lang             = "en"
if "runs_log"         not in st.session_state: st.session_state.runs_log         = []
if "pipeline_results" not in st.session_state: st.session_state.pipeline_results = None
if "pipeline_phase"   not in st.session_state: st.session_state.pipeline_phase   = "idle"
if "pre_review"       not in st.session_state: st.session_state.pre_review       = None

ja = st.session_state.lang == "ja"

# ============= CSS =============
st.markdown("""
<style>
  /* Readiness stage pill */
  .ready-pill {
    display:inline-flex; align-items:center; gap:6px;
    background:#dcfce7; color:#166534;
    border:1px solid #bbf7d0; border-radius:20px;
    padding:5px 14px; font-size:0.82rem; font-weight:600;
  }
  .ready-dot { width:8px; height:8px; border-radius:50%; background:#21c354; }

  /* Nav card */
  .nav-card {
    border-radius:12px; padding:20px 18px;
    border:1px solid #e5e7eb;
    transition: box-shadow .15s;
    height: 100%;
  }
  .nav-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,.10); }
  .nav-card .nav-icon { font-size:2rem; margin-bottom:8px; }
  .nav-card .nav-title { font-size:1.05rem; font-weight:700; margin-bottom:4px; }
  .nav-card .nav-desc  { font-size:0.83rem; color:#6b7280; }

  /* Product card */
  .prod-card {
    border-radius:10px; padding:16px;
    border-left:5px solid #6366f1; background:#f5f3ff;
  }

  /* Section label */
  .section-lbl {
    font-size:0.72rem; font-weight:700; letter-spacing:.08em;
    text-transform:uppercase; color:#9ca3af; margin-bottom:6px;
  }

  /* Divider with label */
  .divider-lbl {
    display:flex; align-items:center; gap:10px; margin:24px 0 16px;
  }
  .divider-lbl span { font-size:1rem; font-weight:700; white-space:nowrap; }
  .divider-lbl::after {
    content:""; flex:1; height:1px; background:#e5e7eb;
  }
</style>
""", unsafe_allow_html=True)

# ============= HEADER ROW =============

top_left, top_right = st.columns([5, 1])
with top_left:
    st.title(f"🔐 {t('app_title')}")
    st.markdown(f"**{t('app_subtitle')}**")
with top_right:
    st.markdown("<div style='margin-top:18px'></div>", unsafe_allow_html=True)
    lc1, lc2 = st.columns(2)
    with lc1:
        if st.button("🇺🇸", use_container_width=True,
                     type="primary" if not ja else "secondary", help="English"):
            st.session_state.lang = "en"; st.rerun()
    with lc2:
        if st.button("🇯🇵", use_container_width=True,
                     type="primary" if ja else "secondary", help="日本語"):
            st.session_state.lang = "ja"; st.rerun()

st.markdown("---")

# ============= CRA READINESS STATUS BAR =============

st.markdown(
    f'<div class="divider-lbl"><span>{"⚙️ CRAコンプライアンス準備状況" if ja else "⚙️ CRA Compliance Readiness"}</span></div>',
    unsafe_allow_html=True
)

stage_labels_en = ["CVE Ingestion", "SBOM Matching", "Conflict Detection", "Decision Rules", "Human Review", "ENISA Reporting"]
stage_labels_ja = ["CVE取込", "SBOM照合", "矛盾検出", "決定ルール", "人的レビュー", "ENISA報告"]
stage_labels = stage_labels_ja if ja else stage_labels_en

cols = st.columns(6)
for col, label in zip(cols, stage_labels):
    with col:
        st.markdown(
            f'<div class="ready-pill"><div class="ready-dot"></div>{label}</div>',
            unsafe_allow_html=True
        )

st.markdown("<div style='margin-top:6px'></div>", unsafe_allow_html=True)
ready_label = "✅ システム準備完了 — 全6ステージが設定済みで稼働中" if ja else "✅ System ready — all 6 pipeline stages configured and operational"
st.caption(ready_label)

st.markdown("---")

# ============= KPI ROW =============

st.markdown(
    f'<div class="divider-lbl"><span>{"📊 システム概要" if ja else "📊 System Overview"}</span></div>',
    unsafe_allow_html=True
)

runs = st.session_state.runs_log
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("🏭 " + ("対象製品" if ja else "Products in Scope"),    len(PRODUCTS))
k2.metric("📏 " + ("決定ルール" if ja else "Decision Rules"),     len(DECISION_RULES))
k3.metric("🗂️ " + ("デモシナリオ" if ja else "Demo Scenarios"),  len(CVE_SCENARIOS))
k4.metric("▶️ " + ("実行済みシナリオ" if ja else "Scenarios Run"), len(runs))
report_count = sum(1 for r in runs if r["decision"] == "REPORT")
k5.metric("🔴 REPORT " + ("決定数" if ja else "decisions"), report_count,
          delta=f"+{report_count}" if report_count else None,
          delta_color="inverse" if report_count else "off")

st.markdown("---")

# ============= MAIN BODY: Stats + Navigation =============

st.markdown(
    f'<div class="divider-lbl"><span>{"🔍 セッション統計 & ナビゲーション" if ja else "🔍 Session Statistics & Navigation"}</span></div>',
    unsafe_allow_html=True
)

stats_col, nav_col = st.columns([3, 2], gap="large")

with stats_col:
    if not runs:
        st.info(
            "まだシナリオは実行されていません。左サイドバーの **🔬 パイプライン** ページに移動して開始してください。" if ja else
            "No scenarios run yet. Navigate to the **🔬 Pipeline** page in the sidebar to get started."
        )

        # Show what the stats will look like
        example_df = pd.DataFrame({
            ("決定タイプ" if ja else "Decision"): ["REPORT", "NOT_REPORT", "CONFLICT / ESCALATED"],
            ("件数" if ja else "Count"): [0, 0, 0]
        })
        st.dataframe(example_df, use_container_width=True, hide_index=True)

    else:
        # Donut chart
        from collections import Counter
        decision_counts = Counter(r["decision"] for r in runs)
        labels = list(decision_counts.keys())
        values = list(decision_counts.values())
        color_map = {"REPORT": "#ff4b4b", "NOT_REPORT": "#21c354",
                     "CONFLICT": "#ffa500", "ESCALATED": "#7c3aed"}
        colors = [color_map.get(l, "#aaa") for l in labels]

        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.55,
            marker=dict(colors=colors),
            textinfo="label+percent",
            hovertemplate="%{label}: %{value} run(s)<extra></extra>"
        ))
        fig.update_layout(
            title=("決定内訳" if ja else "Decision Breakdown"),
            height=280, margin=dict(t=40, b=10, l=10, r=10),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)

        # Run log table
        run_df = pd.DataFrame([
            {
                ("時刻" if ja else "Time"): r["ts"],
                ("シナリオ" if ja else "Scenario"): r["scenario"],
                ("製品" if ja else "Product"): r["product"],
                ("決定" if ja else "Decision"): r["decision"],
            }
            for r in reversed(runs)
        ])
        dec_col = "決定" if ja else "Decision"
        def _color(val):
            return {"REPORT":"background-color:#fff5f5","NOT_REPORT":"background-color:#f0fff4",
                    "CONFLICT":"background-color:#fff8ec","ESCALATED":"background-color:#fdf4ff"}.get(val,"")
        st.dataframe(run_df.style.applymap(_color, subset=[dec_col]),
                     use_container_width=True, hide_index=True)

with nav_col:
    nav_items = [
        ("🔬", ("決定パイプライン" if ja else "Decision Pipeline"),
         ("シナリオを選択し、6ステージの意思決定プロセスを実行します。" if ja else "Select a scenario and run the 6-stage decision process."),
         "pages/0_🔬_Pipeline.py"),
        ("📚", ("履歴 & 概要" if ja else "History & Overview"),
         ("全シナリオ、実行履歴、製品SBOMの概要を表示します。" if ja else "View all scenarios, run history, and product SBOM overview."),
         "pages/1_📚_History.py"),
        ("📖", ("シナリオ解説" if ja else "Scenario Explanations"),
         ("各シナリオの目的・決定ロジック・CRA関連性を解説します。" if ja else "Detailed walkthrough of each scenario's logic and CRA relevance."),
         "pages/2_📖_Scenarios.py"),
    ]
    for icon, title, desc, page in nav_items:
        with st.container(border=True):
            nc1, nc2 = st.columns([1, 4])
            with nc1:
                st.markdown(f"<div style='font-size:2rem;padding-top:4px'>{icon}</div>", unsafe_allow_html=True)
            with nc2:
                st.markdown(f"**{title}**")
                st.caption(desc)
            st.page_link(page, label=("→ 開く" if ja else "→ Open"), use_container_width=True)

st.markdown("---")

# ============= PRODUCTS AT A GLANCE =============

st.markdown(
    f'<div class="divider-lbl"><span>{"🏭 J-TEC 製品一覧" if ja else "🏭 J-TEC Products at a Glance"}</span></div>',
    unsafe_allow_html=True
)

prod_cols = st.columns(3)
prod_colors = ["#6366f1", "#0ea5e9", "#10b981"]
prod_bgs    = ["#f5f3ff",  "#f0f9ff",  "#f0fdf4"]

for col, (pname, p), color, bg in zip(prod_cols, PRODUCTS.items(), prod_colors, prod_bgs):
    with col:
        components = p["sbom"]["components"]
        comp_types = ", ".join(sorted(set(c["type"].capitalize() for c in components)))
        st.markdown(f"""
        <div style="border-radius:10px;padding:16px 18px;border-left:5px solid {color};background:{bg};margin-bottom:4px">
            <div style="font-weight:800;font-size:1rem">{pname}</div>
            <div style="font-size:0.8rem;color:#555;margin-top:2px">{p['type']}</div>
            <div style="font-size:0.78rem;color:#888;margin-top:4px">v{p['version']} &nbsp;·&nbsp; {len(components)} {"コンポーネント" if ja else "components"}</div>
            <div style="font-size:0.76rem;color:#aaa;margin-top:2px">{comp_types}</div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("SBOM" if not ja else "📦 SBOM詳細"):
            for c in components:
                vuln_icon = "⚙️" if c["type"] == "firmware" else "📦" if c["type"] == "library" else "🖥️"
                st.caption(f"{vuln_icon} **{c['name']}** v{c['version']} — {c['vendor']}")

st.markdown("---")

# ============= DECISION RULES SUMMARY =============

st.markdown(
    f'<div class="divider-lbl"><span>{"📏 決定ルール概要" if ja else "📏 Decision Rules Summary"}</span></div>',
    unsafe_allow_html=True
)

rule_cols = st.columns(3)
rule_colors = {
    "REPORT":      ("#fff5f5", "#ff4b4b"),
    "NOT_REPORT":  ("#f0fff4", "#21c354"),
    "CONFLICT":    ("#fff8ec", "#ffa500"),
    "HUMAN_REVIEW":("#f5f3ff", "#7c3aed"),
}

for i, rule in enumerate(DECISION_RULES):
    col = rule_cols[i % 3]
    bg, accent = rule_colors.get(rule["action"], ("#f9fafb", "#6b7280"))
    auto_label = ("✅ 自動" if ja else "✅ Auto") if rule["auto_decidable"] else ("👤 人的" if ja else "👤 Human")
    conf = f"{rule['confidence_boost']:.0%}"
    with col:
        st.markdown(f"""
        <div style="border-radius:8px;padding:12px 14px;background:{bg};border-left:4px solid {accent};margin-bottom:10px">
            <div style="font-weight:700;font-size:0.88rem">{rule['rule_id']} — {rule['name']}</div>
            <div style="font-size:0.75rem;color:#6b7280;margin-top:4px">{rule['condition']}</div>
            <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap">
                <span style="background:{accent};color:white;padding:2px 8px;border-radius:10px;font-size:0.72rem;font-weight:600">{rule['action']}</span>
                <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;font-size:0.72rem">{auto_label}</span>
                <span style="background:#f3f4f6;color:#374151;padding:2px 8px;border-radius:10px;font-size:0.72rem">conf {conf}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

# ============= FOOTER =============

st.markdown(f"<div style='text-align:center;font-size:12px;color:gray;'>🔐 {t('footer')}</div>",
            unsafe_allow_html=True)
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>{t('legal_declaration')}</div>",
    unsafe_allow_html=True
)
