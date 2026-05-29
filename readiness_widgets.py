"""
Readiness-to-Demo Streamlit widgets.
Imported by app.py and all Act pages to inject personalisation into the demo.
"""

import streamlit as st

from readiness_bridge import (
    get_key_stages, get_stage_insights, get_gap_solution_map,
    get_cta, get_scenario_recommendation,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _t(en: str, ja: str) -> str:
    return ja if st.session_state.get("lang") == "ja" else en


def _rr():
    """Shorthand: return readiness_result from session state (or None)."""
    return st.session_state.get("readiness_result")


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 3 — KEY stage badge
# ──────────────────────────────────────────────────────────────────────────────

def render_key_stage_badge(stage_num: int) -> None:
    """
    Call this right after st.header() for a pipeline stage.
    Shows a 🔴 KEY FOR YOU banner if this stage is in the user's key stages.
    Does nothing if no readiness_result is in session state.
    """
    rr = _rr()
    if not rr:
        return
    if stage_num not in get_key_stages(rr):
        return
    ja = st.session_state.get("lang") == "ja"
    label = "🔴 あなたに重要" if ja else "🔴 KEY FOR YOU"
    msg   = ("このステージはあなたの特定のギャップに直接対処します"
             if ja else "This stage directly addresses your identified gaps")
    st.markdown(
        f'<div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:8px;'
        f'padding:6px 14px;margin:2px 0 10px 0;display:inline-flex;align-items:center;gap:10px">'
        f'<span style="font-weight:800;color:#dc2626;font-size:0.83rem">{label}</span>'
        f'<span style="color:#7f1d1d;font-size:0.76rem">{msg}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 4 — Contextual educational insights per stage
# ──────────────────────────────────────────────────────────────────────────────

def render_stage_insights(stage_num: int) -> None:
    """
    Renders 0–2 personalised insight callout boxes for a stage.
    Call this after render_key_stage_badge() and the stage's caption.
    """
    rr = _rr()
    if not rr:
        return
    ja = st.session_state.get("lang") == "ja"
    insights = get_stage_insights(stage_num, rr, "ja" if ja else "en")
    for text in insights:
        st.info(text)


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 2 — Personalized context banner (shown on Dashboard idle state)
# ──────────────────────────────────────────────────────────────────────────────

def render_personalized_banner() -> None:
    """
    Full context banner shown on the Dashboard when the user has completed
    the readiness assessment. Includes score, gaps, gap→solution map, and
    a "Run Personalized Demo" button.
    """
    rr = _rr()
    if not rr:
        return
    ja       = st.session_state.get("lang") == "ja"
    lvl      = rr["readiness_level"]
    pct      = rr["percentage"]
    rec      = get_scenario_recommendation(rr)
    gsmap    = get_gap_solution_map(rr, "ja" if ja else "en")
    cta      = get_cta(rr, "ja" if ja else "en")

    # Difficulty badge
    diff_colors = {
        "beginner":     ("#16a34a", "#f0fdf4"),
        "intermediate": ("#d97706", "#fff7ed"),
        "advanced":     ("#7c3aed", "#f5f3ff"),
    }
    diff_labels = {
        "beginner":     ("beginner",     "初級"),
        "intermediate": ("intermediate", "中級"),
        "advanced":     ("advanced",     "上級"),
    }
    dc, dbg = diff_colors.get(rec["difficulty"], ("#1e3a8a", "#eff6ff"))
    dlabel  = diff_labels.get(rec["difficulty"], ("", ""))[1 if ja else 0]

    # Score to scenario name
    from mock_data import CVE_SCENARIOS
    scen_name = CVE_SCENARIOS[rec["scenario_key"]]["name"].split(":")[0].split("：")[0]

    # Gaps as chips
    gap_chips = "".join(
        f'<span style="background:#fef2f2;border:1px solid #fca5a5;border-radius:12px;'
        f'padding:2px 10px;font-size:0.76rem;color:#dc2626;margin:2px 3px 2px 0;display:inline-block">'
        f'{g["icon"]} {g["gap"]}</span>'
        for g in gsmap
    ) if gsmap else (
        '<span style="color:#6b7280;font-size:0.82rem">' +
        ("ギャップなし — CRAコンプライアンス体制は良好です" if ja else "No critical gaps — strong CRA posture") +
        '</span>'
    )

    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#eff6ff 0%,#f0fdf4 100%);
                border:2px solid {lvl['color']}44;border-radius:16px;
                padding:26px 30px;margin-bottom:20px">
      <!-- Header row -->
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap">
        <div style="font-size:1.5rem">🎯</div>
        <div>
          <div style="font-size:0.72rem;font-weight:700;color:#6b7280;text-transform:uppercase;
                      letter-spacing:1px">
            {"あなたのCRA準備状況チェックに基づく" if ja else "BASED ON YOUR CRA READINESS ASSESSMENT"}
          </div>
          <div style="font-size:1.1rem;font-weight:800;color:#1e293b;margin-top:2px">
            {rec['title_ja'] if ja else rec['title_en']}
          </div>
        </div>
        <div style="margin-left:auto;text-align:right">
          <div style="font-size:2rem;font-weight:900;color:{lvl['color']};line-height:1">{pct}%</div>
          <div style="font-size:0.72rem;color:#6b7280">{lvl['label_ja'] if ja else lvl['label_en']}</div>
        </div>
      </div>

      <!-- Two columns: gaps + solution map -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:18px">
        <!-- Left: Gaps -->
        <div>
          <div style="font-size:0.72rem;font-weight:700;color:#6b7280;text-transform:uppercase;
                      letter-spacing:0.8px;margin-bottom:8px">
            {"特定されたギャップ" if ja else "YOUR IDENTIFIED GAPS"}
          </div>
          <div style="line-height:2">{gap_chips}</div>
        </div>
        <!-- Right: Recommended scenario -->
        <div style="background:white;border-radius:10px;padding:14px 16px;
                    border:1px solid {dc}33">
          <div style="font-size:0.72rem;font-weight:700;color:#6b7280;text-transform:uppercase;
                      letter-spacing:0.8px;margin-bottom:6px">
            {"おすすめのシナリオ" if ja else "RECOMMENDED SCENARIO"}
          </div>
          <div style="font-weight:800;font-size:0.97rem;color:#1e293b;margin-bottom:4px">
            {scen_name}
            &nbsp;<span style="background:{dbg};color:{dc};border-radius:10px;
              padding:2px 9px;font-size:0.7rem;font-weight:700">{dlabel}</span>
          </div>
          <div style="font-size:0.79rem;color:#4b5563;line-height:1.5">
            {rec['reason_ja'] if ja else rec['reason_en']}
          </div>
        </div>
      </div>

      <!-- Estimated timeline -->
      <div style="font-size:0.75rem;color:#6b7280;margin-bottom:4px">
        {"🕐 推定コンプライアンス期間：" if ja else "🕐 Estimated path to 100% readiness: "}
        <b style="color:{lvl['color']}">{cta['weeks']} {"週間" if ja else "weeks"}</b>
        &nbsp;·&nbsp; {cta['offer']}
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Gap → Solution table ──
    if gsmap:
        with st.expander(
            "📋 " + ("ギャップ → ソリューションマッピング" if ja else "Gap → Solution Mapping"),
            expanded=True,
        ):
            hdr_gap = "✗ あなたのギャップ" if ja else "✗ Your Gap"
            hdr_sol = "✅ デモでの解決策" if ja else "✅ How the Demo Solves It"
            rows = "".join(
                f'<tr>'
                f'<td style="padding:6px 10px;color:#dc2626;font-size:0.82rem">'
                f'{g["icon"]} {g["gap"]}</td>'
                f'<td style="padding:6px 10px;color:#16a34a;font-size:0.82rem">'
                f'→ &nbsp; {g["solution"]}</td>'
                f'</tr>'
                for g in gsmap
            )
            st.markdown(
                f'<table style="width:100%;border-collapse:collapse;font-family:sans-serif">'
                f'<thead><tr>'
                f'<th style="text-align:left;padding:6px 10px;font-size:0.72rem;'
                f'color:#6b7280;text-transform:uppercase;border-bottom:2px solid #e2e8f0">'
                f'{hdr_gap}</th>'
                f'<th style="text-align:left;padding:6px 10px;font-size:0.72rem;'
                f'color:#6b7280;text-transform:uppercase;border-bottom:2px solid #e2e8f0">'
                f'{hdr_sol}</th>'
                f'</tr></thead>'
                f'<tbody>{rows}</tbody>'
                f'</table>',
                unsafe_allow_html=True,
            )

    # ── Run button ──
    rc1, rc2, rc3 = st.columns([2, 1, 1])
    with rc1:
        if st.button(
            f"▶ " + ("おすすめデモを実行する" if ja else "Run Personalized Demo"),
            type="primary",
            use_container_width=True,
            key="run_personalized_demo_btn",
        ):
            st.session_state.pipeline_phase   = "idle"
            st.session_state.pipeline_results = None
            st.session_state.pre_review       = None
            st.session_state.run_triggered = {
                "scenario": rec["scenario_key"],
                "product":  rec["product_name"],
            }
            st.rerun()
    with rc2:
        st.page_link(
            "pages/0_Readiness_Check.py",
            label="🔄 " + ("再評価する" if ja else "Retake Assessment"),
        )
    with rc3:
        if st.button(
            "✖ " + ("パーソナライズをクリア" if ja else "Clear Personalisation"),
            use_container_width=True,
            key="clear_personalisation_btn",
        ):
            st.session_state.pop("readiness_result", None)
            st.session_state.pop("readiness_recommendation", None)
            st.rerun()

    st.markdown("")


# ──────────────────────────────────────────────────────────────────────────────
#  Features 6 & 7 — Progress metrics + level-specific CTA (bottom of Act pages)
# ──────────────────────────────────────────────────────────────────────────────

def render_personalized_cta() -> None:
    """
    Renders the progress-metric card + level-specific CTA.
    Call at the bottom of each Act page and after pipeline completion.
    Does nothing if no readiness_result is in session state.
    """
    rr = _rr()
    if not rr:
        return
    ja    = st.session_state.get("lang") == "ja"
    lvl   = rr["readiness_level"]
    pct   = rr["percentage"]
    cta   = get_cta(rr, "ja" if ja else "en")
    weeks = cta["weeks"]

    st.markdown("---")
    st.markdown(f"""
    <div style="background:{lvl['bg']};border:2px solid {lvl['color']}55;
                border-radius:14px;padding:22px 28px;margin:8px 0">
      <div style="font-size:0.72rem;font-weight:700;color:{lvl['color']};
                  text-transform:uppercase;letter-spacing:1px;margin-bottom:10px">
        {"あなたへのおすすめ" if ja else "Your Next Step"}
        &nbsp;·&nbsp;
        {"あなたのスコアに基づく" if ja else "Based on your assessment score"}
      </div>
      <!-- Progress metrics row -->
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px">
        <div style="text-align:center;background:white;border-radius:10px;padding:10px 18px;
                    border:1px solid {lvl['color']}33;min-width:80px">
          <div style="font-size:1.7rem;font-weight:900;color:{lvl['color']};line-height:1">{pct}%</div>
          <div style="font-size:0.68rem;color:#6b7280;margin-top:2px">
            {"現在のスコア" if ja else "Your score"}
          </div>
        </div>
        <div style="font-size:1.3rem;color:#94a3b8;font-weight:300">→</div>
        <div style="text-align:center;background:white;border-radius:10px;padding:10px 18px;
                    border:1px solid #16a34a33;min-width:80px">
          <div style="font-size:1.7rem;font-weight:900;color:#16a34a;line-height:1">100%</div>
          <div style="font-size:0.68rem;color:#6b7280;margin-top:2px">
            {"目標" if ja else "Target"}
          </div>
        </div>
        <div style="font-size:1.3rem;color:#94a3b8;font-weight:300">⏱</div>
        <div style="text-align:center;background:white;border-radius:10px;padding:10px 18px;
                    border:1px solid #1e3a8a33;min-width:80px">
          <div style="font-size:1.7rem;font-weight:900;color:#1e3a8a;line-height:1">
            {weeks}{"週" if ja else "w"}
          </div>
          <div style="font-size:0.68rem;color:#6b7280;margin-top:2px">
            {"推定期間" if ja else "Estimate"}
          </div>
        </div>
        <div style="flex:1;min-width:180px">
          <div style="font-size:0.97rem;font-weight:700;color:#1e293b;margin-bottom:2px">
            {cta['message']}
          </div>
          <div style="font-size:0.78rem;color:#4b5563">{cta['offer']}</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    if st.button(
        f"📩 {cta['button']}",
        type="primary",
        key=f"cta_btn_{id(rr)}",
        use_container_width=False,
    ):
        # Navigate to readiness page lead capture
        st.switch_page("pages/0_Readiness_Check.py")


# ──────────────────────────────────────────────────────────────────────────────
#  Sidebar readiness score pill (call from sidebar_current_run area)
# ──────────────────────────────────────────────────────────────────────────────

def sidebar_readiness_score() -> None:
    """Small score pill shown in sidebar when readiness_result is in session."""
    rr = _rr()
    if not rr:
        return
    ja  = st.session_state.get("lang") == "ja"
    lvl = rr["readiness_level"]
    pct = rr["percentage"]
    st.markdown(
        f'<div style="background:{lvl["bg"]};border:1px solid {lvl["color"]}44;'
        f'border-radius:8px;padding:6px 12px;font-size:0.78rem;margin-bottom:6px">'
        f'<b style="color:{lvl["color"]}">{lvl["icon"]} {pct}%</b> &nbsp;'
        f'<span style="color:#6b7280">'
        f'{"準備状況" if ja else "Readiness"}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.page_link(
        "pages/0_Readiness_Check.py",
        label="🛡️ " + ("評価を見る" if ja else "View Assessment"),
    )
