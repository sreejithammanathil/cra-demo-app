"""
CRA Readiness Assessment — UI Components
All Streamlit rendering functions.  Called by readiness_flow.py.
"""

import streamlit as st
import plotly.graph_objects as go

from readiness_questions import QUESTIONS, MAX_SCORE
from readiness_scorer import calculate_score, get_recommendations

# ── helpers ────────────────────────────────────────────────────────────────

def _t(en: str, ja: str) -> str:
    return ja if st.session_state.get("lang") == "ja" else en


def _pct_color(pct: int) -> str:
    if pct >= 70:
        return "#16a34a"
    if pct >= 40:
        return "#ca8a04"
    return "#dc2626"


# ── Welcome screen ─────────────────────────────────────────────────────────

def display_welcome_screen(state_key: str) -> None:
    """Render intro card and 'Start Assessment' button."""

    st.markdown(f"""
    <div style="
        background: linear-gradient(135deg, #1e3a8a 0%, #2563eb 100%);
        border-radius: 16px;
        padding: 40px 48px;
        color: white;
        margin-bottom: 24px;
    ">
        <div style="font-size:2.8rem; margin-bottom:8px;">🛡️</div>
        <h1 style="color:white; margin:0 0 8px 0; font-size:1.9rem;">
            {_t('CRA Readiness Assessment', 'CRA準備状況評価')}
        </h1>
        <p style="color:#bfdbfe; font-size:1.05rem; margin:0 0 20px 0; max-width:680px;">
            {_t(
                'Discover how prepared your organisation is for the EU Cyber Resilience Act. '
                '8 questions · 5 minutes · Personalised action plan.',
                'EU Cyber Resilience Act（CRA）に対する貴組織の準備状況を把握してください。'
                '8問 · 約5分 · パーソナライズされたアクションプラン。'
            )}
        </p>
    </div>
    """, unsafe_allow_html=True)

    col_info, col_btn = st.columns([3, 1])
    with col_info:
        st.markdown(f"#### {_t('What you will get', 'このアセスメントで得られるもの')}")
        items_en = [
            "📊 Overall CRA readiness score (0–200 points)",
            "🔍 Category-by-category breakdown across 8 compliance areas",
            "⚡ Prioritised action plan with concrete next steps",
            "📚 Bite-sized learning for every area — tailored to J-TEC context",
        ]
        items_ja = [
            "📊 CRA準備状況の総合スコア（0〜200点）",
            "🔍 8つのコンプライアンス領域にわたるカテゴリ別評価",
            "⚡ 具体的な次のステップを含む優先アクションプラン",
            "📚 J-TECのコンテキストに合わせた各領域の学習コンテンツ",
        ]
        items = items_ja if st.session_state.get("lang") == "ja" else items_en
        for item in items:
            st.markdown(f"- {item}")

    with col_btn:
        st.markdown("<br><br>", unsafe_allow_html=True)
        if st.button(
            _t("▶ Start Assessment", "▶ 評価を開始"),
            type="primary",
            use_container_width=True,
            key=f"start_btn_{state_key}",
        ):
            st.session_state[state_key]["phase"] = "quiz"
            st.session_state[state_key]["current_q"] = 0
            st.rerun()

    st.markdown("---")


# ── Single question ────────────────────────────────────────────────────────

def display_question(state_key: str) -> None:
    """Render the current question with progress bar, options, and nav buttons."""
    s = st.session_state[state_key]
    idx = s["current_q"]
    q = QUESTIONS[idx]
    total_q = len(QUESTIONS)
    lang = st.session_state.get("lang", "en")
    ja = lang == "ja"

    # ── Progress bar ──
    pct_done = idx / total_q
    st.markdown(f"""
    <div style="margin-bottom:4px; font-size:0.82rem; color:#64748b;">
        {_t(f'Question {idx+1} of {total_q}', f'{total_q}問中 {idx+1}問目')}
        &nbsp;·&nbsp;
        {q['category_icon']} {q['category_ja'] if ja else q['category_en']}
    </div>
    <div style="background:#e2e8f0; border-radius:999px; height:8px; overflow:hidden; margin-bottom:24px;">
        <div style="background:#1e3a8a; width:{pct_done*100:.0f}%; height:100%; border-radius:999px;
                    transition:width 0.4s ease;"></div>
    </div>
    """, unsafe_allow_html=True)

    # ── Question text ──
    st.markdown(f"### {q['question_ja'] if ja else q['question_en']}")
    st.markdown("")

    # ── Answer options ──
    answer_key = f"radio_{state_key}_{q['id']}"
    options = q["options"]
    option_labels = [opt["text_ja"] if ja else opt["text_en"] for opt in options]

    # Pre-select if already answered
    existing = s["answers"].get(q["id"])
    existing_pts = [opt["points"] for opt in options]
    pre_idx = existing_pts.index(existing) if existing in existing_pts else None

    chosen_label = st.radio(
        label="",
        options=option_labels,
        index=pre_idx,
        key=answer_key,
        label_visibility="collapsed",
    )
    chosen_idx = option_labels.index(chosen_label) if chosen_label else None

    # ── Navigation buttons ──
    st.markdown("<br>", unsafe_allow_html=True)
    nav_left, nav_mid, nav_right = st.columns([1, 4, 1])

    with nav_left:
        if idx > 0:
            if st.button(_t("← Back", "← 戻る"), use_container_width=True,
                         key=f"back_{state_key}_{idx}"):
                # Save current answer before going back
                if chosen_idx is not None:
                    s["answers"][q["id"]] = options[chosen_idx]["points"]
                s["current_q"] -= 1
                st.rerun()

    with nav_right:
        is_last = idx == total_q - 1
        btn_label = _t("See Results →", "結果を見る →") if is_last else _t("Next →", "次へ →")
        disabled = chosen_idx is None
        if st.button(btn_label, type="primary", use_container_width=True,
                     disabled=disabled, key=f"next_{state_key}_{idx}"):
            s["answers"][q["id"]] = options[chosen_idx]["points"]
            if is_last:
                s["phase"] = "results"
            else:
                s["current_q"] += 1
            st.rerun()

    # ── Inline learning tip (shown after answering) ──
    if existing is not None:
        with st.expander(_t("💡 Learn more about this topic", "💡 このトピックについて詳しく"), expanded=False):
            st.info(q["learning_ja"] if ja else q["learning_en"])


# ── Results dashboard ──────────────────────────────────────────────────────

def display_results(state_key: str) -> None:
    """Full results page: score hero, radar chart, category bars, priority actions."""
    s = st.session_state[state_key]
    result = s.get("score_result") or calculate_score(s["answers"])
    s["score_result"] = result
    ja = st.session_state.get("lang") == "ja"

    lvl = result["readiness_level"]
    pct = result["percentage"]
    total = result["total_points"]

    # ── Hero card ──
    st.markdown(f"""
    <div style="
        background:{lvl['bg']};
        border-left:6px solid {lvl['color']};
        border-radius:12px;
        padding:28px 32px;
        margin-bottom:24px;
    ">
        <div style="font-size:2.5rem;">{lvl['icon']}</div>
        <h2 style="color:{lvl['color']}; margin:4px 0;">
            {lvl['label_ja'] if ja else lvl['label_en']}
        </h2>
        <div style="font-size:3rem; font-weight:800; color:{lvl['color']}; line-height:1.1;">
            {total} <span style="font-size:1.4rem; font-weight:400; color:#64748b;">/ {MAX_SCORE}
            &nbsp;({pct}%)</span>
        </div>
        <p style="color:#374151; margin-top:12px; font-size:0.97rem; max-width:700px;">
            {lvl['summary_ja'] if ja else lvl['summary_en']}
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Category breakdown bar chart ──
    st.subheader(_t("📊 Score by Category", "📊 カテゴリ別スコア"))
    breakdown = result["category_breakdown"]
    labels = [f"{b['icon']} {b['label_ja'] if ja else b['label_en']}" for b in breakdown]
    pcts = [b["pct"] for b in breakdown]
    colors = [_pct_color(p) for p in pcts]

    fig = go.Figure(go.Bar(
        x=pcts,
        y=labels,
        orientation="h",
        marker_color=colors,
        text=[f"{p}%" for p in pcts],
        textposition="inside",
        insidetextanchor="middle",
        hovertemplate="%{y}: %{x}%<extra></extra>",
    ))
    fig.add_vline(x=80, line_dash="dot", line_color="#1e3a8a", line_width=2,
                  annotation_text=_t("80% target", "目標80%"),
                  annotation_position="top right",
                  annotation_font_color="#1e3a8a")
    fig.update_layout(
        height=360,
        margin=dict(l=8, r=20, t=20, b=8),
        paper_bgcolor="white",
        plot_bgcolor="white",
        xaxis=dict(range=[0, 100], showgrid=True, gridcolor="#f1f5f9",
                   title=_t("Score (%)", "スコア（%）"), ticksuffix="%"),
        yaxis=dict(autorange="reversed", showgrid=False),
        font=dict(family="sans-serif", size=13),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Strengths & Gaps ──
    strengths = result["strengths"]
    gaps = result["gaps"]
    col_s, col_g = st.columns(2)

    with col_s:
        st.markdown(f"#### ✅ {_t('Strengths', '強み')}")
        if strengths:
            for b in strengths:
                st.success(f"{b['icon']} **{b['label_ja'] if ja else b['label_en']}** — {b['pct']}%")
        else:
            st.info(_t("Keep going — strengths will appear once you reach 70%+ in any area.",
                       "引き続き頑張ってください — 70%以上のエリアが強みとして表示されます。"))

    with col_g:
        st.markdown(f"#### ⚠️ {_t('Priority Gaps', '優先ギャップ')}")
        if gaps:
            for b in gaps:
                st.error(f"{b['icon']} **{b['label_ja'] if ja else b['label_en']}** — {b['pct']}%")
        else:
            st.success(_t("No critical gaps — well done!", "重大なギャップはありません — よくできました！"))

    # ── Priority action plan ──
    recs = get_recommendations(result, lang="ja" if ja else "en")
    if recs:
        st.markdown("---")
        st.subheader(_t("⚡ Priority Action Plan", "⚡ 優先アクションプラン"))
        urgency_label = {"high": ("🔴 " + _t("High Priority", "最優先")),
                         "medium": ("🟡 " + _t("Medium Priority", "中優先")),
                         "low": ("🟢 " + _t("Low Priority", "低優先"))}
        for rec in recs:
            badge = urgency_label.get(rec["urgency"], "")
            with st.expander(f"{rec['icon']} **{rec['title']}** &nbsp; {badge}", expanded=False):
                st.markdown(rec["body"])

    # ── CTA ──
    st.markdown("---")
    display_next_steps(state_key)


def display_next_steps(state_key: str) -> None:
    """Render the personalized-demo CTA, lead-capture form, and restart button."""
    ja = st.session_state.get("lang") == "ja"
    s  = st.session_state[state_key]
    result = s.get("score_result", {})

    # ── Feature 1/2 — Personalized Demo CTA ─────────────────────────────────
    from readiness_bridge import get_scenario_recommendation, get_cta
    from mock_data import CVE_SCENARIOS

    if result:
        rec  = get_scenario_recommendation(result)
        cta  = get_cta(result, "ja" if ja else "en")
        lvl  = result.get("readiness_level", {})
        pct  = result.get("percentage", 0)
        scen_name = CVE_SCENARIOS[rec["scenario_key"]]["name"].split(":")[0].split("：")[0]

        diff_colors = {
            "beginner": "#16a34a", "intermediate": "#d97706", "advanced": "#7c3aed",
        }
        diff_labels_map = {
            "beginner": ("beginner", "初級"),
            "intermediate": ("intermediate", "中級"),
            "advanced": ("advanced", "上級"),
        }
        dc = diff_colors.get(rec["difficulty"], "#1e3a8a")
        dlbl = diff_labels_map.get(rec["difficulty"], ("", ""))[1 if ja else 0]

        st.markdown(f"""
        <div style="background:linear-gradient(135deg,#1e3a8a 0%,#2563eb 100%);
                    border-radius:14px;padding:24px 28px;color:white;margin-bottom:16px">
          <div style="font-size:0.72rem;font-weight:700;letter-spacing:1.5px;
                      text-transform:uppercase;color:#bfdbfe;margin-bottom:6px">
            {"次のステップ" if ja else "YOUR NEXT STEP"}
          </div>
          <div style="font-size:1.15rem;font-weight:800;margin-bottom:6px">
            {rec['title_ja'] if ja else rec['title_en']}
          </div>
          <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:10px">
            <span style="font-size:0.82rem;color:#bfdbfe">
              {"推奨シナリオ：" if ja else "Recommended:"}
            </span>
            <span style="background:rgba(255,255,255,0.15);border-radius:20px;
                         padding:3px 12px;font-size:0.8rem;font-weight:700">
              {scen_name}
            </span>
            <span style="background:{dc}33;color:white;border-radius:20px;
                         padding:3px 10px;font-size:0.72rem;font-weight:700;
                         border:1px solid {dc}88">
              {dlbl}
            </span>
            <span style="color:#bfdbfe;font-size:0.78rem;flex:1">
              {rec['reason_ja'][:80] + '…' if ja and len(rec['reason_ja']) > 80
               else rec['reason_en'][:80] + '…' if not ja and len(rec['reason_en']) > 80
               else rec['reason_ja'] if ja else rec['reason_en']}
            </span>
          </div>
          <div style="font-size:0.78rem;color:#93c5fd">
            {cta['offer']} &nbsp;·&nbsp;
            ~{cta['weeks']} {"週間で100%達成" if ja else "weeks to 100%"}
          </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button(
            "🎯 " + ("パーソナライズされたデモを開始する →" if ja
                     else "Start Your Personalized Demo →"),
            type="primary",
            use_container_width=True,
            key=f"demo_launch_btn_{state_key}",
        ):
            st.session_state.readiness_result         = result
            st.session_state.readiness_recommendation = rec
            st.switch_page("app.py")

        st.markdown("")

    # ── Restart ──
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button(_t("🔄 Retake Assessment", "🔄 再評価する"),
                 use_container_width=False, key=f"restart_{state_key}"):
        # Reset quiz state but keep lang
        st.session_state[state_key] = {
            "phase": "welcome",
            "current_q": 0,
            "answers": {},
            "score_result": None,
            "lead_submitted": False,
            "lead_name": "",
        }
        st.rerun()
