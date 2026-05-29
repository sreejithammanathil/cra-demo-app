"""
Shared UI helpers, chart builders, and pipeline utilities for
CRA Decision Traceability System. All pages import from this module.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta

from mock_data import PRODUCTS, CVE_SCENARIOS, DECISION_RULES, THRESHOLDS
from translations import t, SCENARIO_JA


# ─────────────────────────────────────────────
#  CSS
# ─────────────────────────────────────────────

def inject_css():
    st.markdown("""<style>
.stApp{background-color:#ffffff}
section[data-testid="stSidebar"]{background-color:#f8fafc;border-right:1px solid #e2e8f0}
.ready-pill{display:inline-flex;align-items:center;gap:6px;background:#dcfce7;color:#166534;
  border:1px solid #bbf7d0;border-radius:20px;padding:5px 14px;font-size:0.82rem;font-weight:600}
.ready-dot{width:8px;height:8px;border-radius:50%;background:#16a34a}
.badge-report{background:#dc2626;color:white;padding:6px 20px;border-radius:6px;
  font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}
.badge-not-report{background:#16a34a;color:white;padding:6px 20px;border-radius:6px;
  font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}
.badge-conflict{background:#d97706;color:white;padding:6px 20px;border-radius:6px;
  font-weight:700;font-size:1.05rem;display:inline-block;letter-spacing:0.5px}
.stepper-wrap{display:flex;justify-content:space-between;align-items:center;margin:1rem 0 1.5rem 0}
.step-item{display:flex;flex-direction:column;align-items:center;flex:1;position:relative}
.step-item:not(:last-child)::after{content:"";position:absolute;top:18px;left:60%;
  width:80%;height:3px;background:#cbd5e1;z-index:0}
.step-item.done:not(:last-child)::after{background:#16a34a}
.step-circle{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;
  justify-content:center;font-weight:bold;font-size:1rem;z-index:1;
  background:#e2e8f0;color:#64748b}
.step-circle.done{background:#16a34a;color:white}
.step-label{font-size:0.72rem;margin-top:4px;text-align:center;color:#64748b;max-width:80px}
.step-label.done{color:#16a34a;font-weight:600}
.audit-badge{display:inline-block;padding:2px 10px;border-radius:6px;
  font-size:0.75rem;font-weight:600}
.audit-stage{background:#dbeafe;color:#1e40af}
.audit-decision{background:#dcfce7;color:#166534}
.audit-conflict{background:#fef9c3;color:#92400e}
.info-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px}
</style>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  Sidebar helpers
# ─────────────────────────────────────────────

def lang_toggle_sidebar():
    """Render EN/JP toggle. Returns True if Japanese."""
    ja = st.session_state.get("lang") == "ja"
    lc1, lc2 = st.columns(2)
    with lc1:
        if st.button("🇺🇸 EN", use_container_width=True,
                     type="primary" if not ja else "secondary", key="lang_en"):
            st.session_state.lang = "en"; st.rerun()
    with lc2:
        if st.button("🇯🇵 JP", use_container_width=True,
                     type="primary" if ja else "secondary", key="lang_jp"):
            st.session_state.lang = "ja"; st.rerun()
    return st.session_state.get("lang") == "ja"


def sidebar_current_run():
    """Show a compact 'current run' info block in the sidebar if results exist."""
    ja = st.session_state.get("lang") == "ja"
    results = st.session_state.get("pipeline_results")
    pre     = st.session_state.get("pre_review")
    phase   = st.session_state.get("pipeline_phase", "idle")

    if phase == "idle":
        return
    st.markdown("---")
    st.markdown("##### " + ("📋 現在の実行" if ja else "📋 Current Run"))
    if results:
        final = results["review_result"]["final_decision_type"]
        badge_color = {"REPORT": "#dc2626", "NOT_REPORT": "#16a34a"}.get(final, "#d97706")
        st.markdown(
            f"<span style='background:{badge_color};color:white;padding:2px 10px;"
            f"border-radius:6px;font-size:0.75rem;font-weight:700'>{final}</span>",
            unsafe_allow_html=True)
        st.caption(f"{results['cve']['cve_id']} · {results['product_name']}")
    elif pre and phase == "awaiting_human":
        st.warning("👤 " + ("人的審査待ち" if ja else "Awaiting human review"), icon=None)
        st.caption(f"{pre['cve']['cve_id']} · {pre['product_name']}")


def sidebar_home_button():
    """Show 'Back to Dashboard' button when pipeline is active."""
    ja = st.session_state.get("lang") == "ja"
    if st.session_state.get("pipeline_phase", "idle") != "idle":
        if st.button("🏠 " + ("ダッシュボードへ戻る" if ja else "Back to Dashboard"),
                     use_container_width=True, type="secondary"):
            st.session_state.pipeline_phase = "idle"
            st.session_state.pipeline_results = None
            st.session_state.pre_review = None
            st.rerun()


def no_results_guard():
    """Show 'run a scenario first' message and return False if no results available."""
    ja = st.session_state.get("lang") == "ja"
    phase = st.session_state.get("pipeline_phase", "idle")
    has_results = bool(st.session_state.get("pipeline_results"))
    awaiting    = phase == "awaiting_human" and bool(st.session_state.get("pre_review"))

    if not has_results and not awaiting:
        st.info("ℹ️ " + ("まだ結果がありません。ダッシュボードでシナリオを実行してください。"
                          if ja else
                          "No results yet — run a scenario from the Dashboard first."))
        st.page_link("app.py", label="🏠 " + ("ダッシュボードへ" if ja else "Go to Dashboard"))
        return False
    return True


# ─────────────────────────────────────────────
#  Visual helpers
# ─────────────────────────────────────────────

def decision_badge(d):
    cls = {"REPORT": "badge-report", "NOT_REPORT": "badge-not-report"}.get(d, "badge-conflict")
    return f'<span class="{cls}">{d}</span>'


def pipeline_stepper(completed=6):
    labels = [t("step_ingest"), t("step_sbom"), t("step_conflict"),
              t("step_rules"), t("step_review"), t("step_enisa")]
    items = ""
    for i, lbl in enumerate(labels, 1):
        done = "done" if i <= completed else ""
        icon = "✓" if i <= completed else str(i)
        items += (f'<div class="step-item {done}">'
                  f'<div class="step-circle {done}">{icon}</div>'
                  f'<div class="step-label {done}">{lbl.replace(chr(10), "<br>")}</div>'
                  f'</div>')
    st.markdown(f'<div class="stepper-wrap">{items}</div>', unsafe_allow_html=True)


def cvss_gauge(score):
    color = ("#ff4b4b" if score >= 8.5 else "#ffa500" if score >= 7.0
             else "#ffd700" if score >= 5.0 else "#21c354")
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score, domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "CVSS Score", "font": {"size": 16}},
        gauge={"axis": {"range": [0, 10]}, "bar": {"color": color},
               "steps": [{"range": [0, 4], "color": "#d4edda"},
                         {"range": [4, 7], "color": "#fff3cd"},
                         {"range": [7, 8.5], "color": "#ffe0b2"},
                         {"range": [8.5, 10], "color": "#f8d7da"}],
               "threshold": {"line": {"color": "black", "width": 3},
                             "thickness": 0.75, "value": score}}
    ))
    fig.update_layout(height=220, margin=dict(t=40, b=10, l=20, r=20))
    return fig


def sbom_table(product_name, matching_component, match_found):
    rows = []
    for c in PRODUCTS.get(product_name, {}).get("sbom", {}).get("components", []):
        is_vuln = match_found and c["name"].lower() in (matching_component or "").lower()
        rows.append({
            t("t2_col_component"): c["name"],
            t("t2_col_version"):   c["version"],
            t("t2_col_vendor"):    c["vendor"],
            t("t2_col_type"):      c["type"].capitalize(),
            t("t2_col_status"):    t("t2_vulnerable") if is_vuln else t("t2_safe_status"),
        })
    return pd.DataFrame(rows)


def cve_desc(scenario_key):
    if st.session_state.get("lang") == "ja":
        return SCENARIO_JA.get(scenario_key, {}).get(
            "cve_description", CVE_SCENARIOS[scenario_key]["cve_description"])
    return CVE_SCENARIOS[scenario_key]["cve_description"]


def confidence_explainer_chart(rules_fired, final_score, threshold=0.80):
    fired_ids = {r["rule"].split(":")[0].strip(): r
                 for r in rules_fired if r["triggered"]}
    y_labels, x_vals, colors, hovers = [], [], [], []
    for rule in DECISION_RULES:
        rid = rule["rule_id"]
        name = rule["name"] if len(rule["name"]) <= 38 else rule["name"][:36] + "…"
        boost = rule["confidence_boost"]
        triggered = rid in fired_ids
        y_labels.append(f"{rid}: {name}")
        x_vals.append(boost if boost > 0 else 0.02)
        colors.append("#1e40af" if triggered else "#e2e8f0")
        hovers.append(
            f"<b>{rid}: {rule['name']}</b><br>"
            f"Confidence Boost: {boost:.0%}<br>"
            f"Status: {'✅ TRIGGERED' if triggered else '— Not Triggered'}<br>"
            f"Action: {rule['action']}")
    fig = go.Figure()
    fig.add_trace(go.Bar(
        y=y_labels, x=x_vals, orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        hovertext=hovers, hoverinfo="text",
        text=[f"{v:.0%}" if v > 0.02 else "0%" for v in x_vals],
        textposition="inside",
        textfont=dict(color=["white" if c == "#1e40af" else "#94a3b8" for c in colors], size=11),
        showlegend=False))
    fig.add_vline(x=threshold, line_color="#dc2626", line_width=2, line_dash="dot",
                  annotation_text=f"Threshold {threshold:.0%}", annotation_position="top right",
                  annotation_font=dict(color="#dc2626", size=11))
    fig.add_vline(x=final_score, line_color="#1e3a8a", line_width=3,
                  annotation_text=f"Score {final_score:.0%}", annotation_position="bottom right",
                  annotation_font=dict(color="#1e3a8a", size=12))
    fig.update_layout(
        height=310, margin=dict(t=30, b=20, l=10, r=100),
        xaxis=dict(range=[0, 1.08], tickformat=".0%", title="Confidence Score",
                   showgrid=True, gridcolor="#f1f5f9"),
        yaxis=dict(autorange="reversed", showgrid=False),
        plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
        title=dict(text="Rule Confidence Breakdown — All 6 Rules",
                   font=dict(size=13, color="#1e293b")))
    return fig


def cra_deadline_gantt(submission_ts_str, lang="en"):
    try:
        detect_dt = datetime.fromisoformat(submission_ts_str)
    except Exception:
        detect_dt = datetime.now()
    now = datetime.now()
    labels = (["🟡 早期警告 (24h)", "🟠 完全通知 (72h)", "📋 最終報告 (90日)"] if lang == "ja"
              else ["🟡 Early Warning (24h)", "🟠 Full Notification (72h)", "📋 Final Report (90 days)"])
    deltas = [timedelta(hours=24), timedelta(hours=72), timedelta(days=90)]
    bgs = ["#fde68a", "#fed7aa", "#dbeafe"]
    fgs = ["#ca8a04", "#d97706", "#1e40af"]
    elapsed_h = (now - detect_dt).total_seconds() / 3600
    fig = go.Figure()
    for lbl, delta, bg, fg in zip(labels, deltas, bgs, fgs):
        total_h = delta.total_seconds() / 3600
        end_dt  = detect_dt + delta
        pct     = min(elapsed_h / total_h, 1.0)
        status  = "OVERDUE ⚠️" if now > end_dt else f"{pct:.0%} elapsed"
        fig.add_trace(go.Bar(y=[lbl], x=[total_h], base=[0], orientation="h",
                             marker=dict(color=bg, line=dict(width=1, color="#e2e8f0")),
                             showlegend=False, hoverinfo="skip", name=""))
        fig.add_trace(go.Bar(y=[lbl], x=[min(elapsed_h, total_h)], base=[0], orientation="h",
                             marker=dict(color=fg + "99"), showlegend=False,
                             hovertemplate=(f"<b>{lbl}</b><br>Deadline: {end_dt.strftime('%Y-%m-%d %H:%M')}"
                                            f"<br>Status: {status}<extra></extra>"), name=""))
    fig.add_vline(x=max(elapsed_h, 0.5), line_color="#dc2626", line_width=2,
                  annotation_text=("現在" if lang == "ja" else "NOW"),
                  annotation_position="top left",
                  annotation_font=dict(color="#dc2626", size=11))
    for xv, col in [(24, "#ca8a04"), (72, "#d97706"), (2160, "#1e40af")]:
        fig.add_vline(x=xv, line_color=col, line_width=1, line_dash="dot")
    fig.update_layout(
        barmode="overlay", height=220, margin=dict(t=40, b=20, l=10, r=20),
        xaxis=dict(title=("経過時間（時間）" if lang == "ja" else "Hours since detection"),
                   showgrid=True, gridcolor="#f1f5f9"),
        yaxis=dict(showgrid=False), plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
        title=dict(text=("CRA 第14条 規制スケジュール" if lang == "ja"
                         else "CRA Article 14 Regulatory Schedule"),
                   font=dict(size=13, color="#1e293b")))
    fig.update_xaxes(type="log", tickvals=[1, 6, 24, 72, 168, 720, 2160],
                     ticktext=["1h", "6h", "24h", "72h", "7d", "30d", "90d"])
    return fig


# ─────────────────────────────────────────────
#  Pipeline helper (called from Decision page)
# ─────────────────────────────────────────────

def complete_pipeline(pre, reviewer_name, reviewer_action, override_decision, notes):
    """Stages 5+6: human review + ENISA submission. Callable from any page."""
    engine = st.session_state.engine
    review_result = engine.human_review(pre["decision_proposal"], reviewer_action)
    review_result["reviewer"]              = reviewer_name or "Compliance Officer"
    review_result["justification"]         = notes or review_result["justification"]
    if override_decision:
        review_result["final_decision_type"] = override_decision
    enisa_result = engine.enisa_submit(review_result, pre["cve"], pre["product_name"])
    results = {**pre, "review_result": review_result,
               "enisa_result": enisa_result, "audit_trail": engine.get_audit_trail()}
    st.session_state.runs_log.append({
        "scenario": pre["scenario_name"].split(":")[0].split("：")[0],
        "decision": review_result["final_decision_type"],
        "product":  pre["product_name"],
        "ts":       datetime.now().strftime("%H:%M:%S"),
    })
    return results
