"""
CRA Readiness Assessment — Scoring Engine
Pure logic, no Streamlit imports.
"""

from readiness_questions import QUESTIONS, MAX_SCORE, CATEGORY_ORDER

# ─────────────────────────────────────────────
# Readiness levels (thresholds are % of MAX_SCORE)
# ─────────────────────────────────────────────
READINESS_LEVELS = [
    {
        "level": "NOT_READY",
        "min_pct": 0,
        "max_pct": 20,
        "label_en": "Not Ready",
        "label_ja": "未対応",
        "color": "#dc2626",      # red-600
        "bg": "#fef2f2",
        "icon": "🔴",
        "summary_en": (
            "Your organisation has significant gaps across all CRA compliance areas. "
            "Immediate action is needed to avoid regulatory risk when CRA enforcement begins."
        ),
        "summary_ja": (
            "貴社はすべてのCRAコンプライアンス領域において重大なギャップがあります。"
            "CRAの施行が始まる前に、規制リスクを回避するための早急な対応が必要です。"
        ),
    },
    {
        "level": "EARLY_STAGE",
        "min_pct": 20,
        "max_pct": 40,
        "label_en": "Early Stage",
        "label_ja": "初期段階",
        "color": "#ea580c",      # orange-600
        "bg": "#fff7ed",
        "icon": "🟠",
        "summary_en": (
            "You have some awareness of CRA requirements but foundational processes are missing. "
            "A structured compliance programme should start within the next 3 months."
        ),
        "summary_ja": (
            "CRAの要件についての認識はありますが、基本的なプロセスが不足しています。"
            "今後3ヶ月以内に体系的なコンプライアンスプログラムを開始する必要があります。"
        ),
    },
    {
        "level": "PARTIALLY_READY",
        "min_pct": 40,
        "max_pct": 60,
        "label_en": "Partially Ready",
        "label_ja": "一部対応済",
        "color": "#ca8a04",      # yellow-600
        "bg": "#fefce8",
        "icon": "🟡",
        "summary_en": (
            "You have a good foundation in some areas but critical gaps remain. "
            "Prioritise the gaps highlighted below to accelerate your compliance journey."
        ),
        "summary_ja": (
            "一部の領域では良い基盤がありますが、重要なギャップが残っています。"
            "以下に示すギャップを優先的に対応し、コンプライアンス対応を加速させてください。"
        ),
    },
    {
        "level": "MOSTLY_READY",
        "min_pct": 60,
        "max_pct": 80,
        "label_en": "Mostly Ready",
        "label_ja": "概ね対応済",
        "color": "#16a34a",      # green-600
        "bg": "#f0fdf4",
        "icon": "🟢",
        "summary_en": (
            "You are ahead of most manufacturers in CRA readiness. "
            "Focus on formalising the remaining gaps and stress-testing your incident response plan."
        ),
        "summary_ja": (
            "CRA対応において多くの製造業者より進んでいます。"
            "残りのギャップの正式化と、インシデント対応計画のストレステストに集中してください。"
        ),
    },
    {
        "level": "CRA_READY",
        "min_pct": 80,
        "max_pct": 101,
        "label_en": "CRA Ready",
        "label_ja": "CRA対応完了",
        "color": "#1e3a8a",      # navy
        "bg": "#eff6ff",
        "icon": "✅",
        "summary_en": (
            "Excellent — your organisation demonstrates strong CRA compliance posture. "
            "Continue to maintain your SBOM, monitor vulnerabilities, and run regular incident drills."
        ),
        "summary_ja": (
            "素晴らしい — 貴社はCRAコンプライアンスに対して強固な体制を示しています。"
            "SBOMの維持、脆弱性の監視、定期的なインシデント訓練を継続してください。"
        ),
    },
]


# ─────────────────────────────────────────────
# Category metadata (for results breakdown)
# ─────────────────────────────────────────────
_CAT_META = {q["category"]: {
    "icon": q["category_icon"],
    "label_en": q["category_en"],
    "label_ja": q["category_ja"],
} for q in QUESTIONS}


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def get_readiness_level(percentage: float) -> dict:
    """Return the readiness-level dict for a given score percentage (0–100)."""
    for lvl in READINESS_LEVELS:
        if lvl["min_pct"] <= percentage < lvl["max_pct"]:
            return lvl
    return READINESS_LEVELS[-1]  # 100% edge case → CRA_READY


def calculate_score(answers: dict) -> dict:
    """
    Parameters
    ----------
    answers : dict
        { "q1": <points_int>, "q2": <points_int>, ... }
        Only answered questions need to be present.

    Returns
    -------
    dict with keys:
        total_points, max_points, percentage,
        readiness_level (dict),
        category_breakdown (list of dicts),
        strengths (list of str),
        gaps (list of str),
        priority_actions (list of str)
    """
    total = sum(answers.values())
    pct = round(total / MAX_SCORE * 100, 1) if MAX_SCORE else 0
    level = get_readiness_level(pct)

    # Build per-category breakdown
    breakdown = []
    for q in QUESTIONS:
        qid = q["id"]
        cat = q["category"]
        max_pts = max(opt["points"] for opt in q["options"])
        earned = answers.get(qid, 0)
        cat_pct = round(earned / max_pts * 100) if max_pts else 0
        meta = _CAT_META.get(cat, {})
        breakdown.append({
            "qid": qid,
            "category": cat,
            "icon": meta.get("icon", ""),
            "label_en": meta.get("label_en", cat),
            "label_ja": meta.get("label_ja", cat),
            "earned": earned,
            "max": max_pts,
            "pct": cat_pct,
        })

    # Strengths = categories scoring ≥ 70 %
    strengths = [b for b in breakdown if b["pct"] >= 70]
    # Gaps = categories scoring < 50 %
    gaps = [b for b in breakdown if b["pct"] < 50]

    # Priority actions — one per gap question, from learning text
    priority_actions = []
    gap_ids = {b["qid"] for b in gaps}
    for q in QUESTIONS:
        if q["id"] in gap_ids:
            priority_actions.append({
                "qid": q["id"],
                "category": q["category"],
                "icon": q["category_icon"],
                "label_en": q["category_en"],
                "label_ja": q["category_ja"],
                "action_en": q["learning_en"],
                "action_ja": q["learning_ja"],
            })

    return {
        "total_points": total,
        "max_points": MAX_SCORE,
        "percentage": pct,
        "readiness_level": level,
        "category_breakdown": breakdown,
        "strengths": strengths,
        "gaps": gaps,
        "priority_actions": priority_actions,
    }


def get_recommendations(score_result: dict, lang: str = "en") -> list[dict]:
    """
    Returns a ranked list of recommendation cards based on the score result.
    Each dict has: icon, title, body, urgency ('high'/'medium'/'low').
    """
    pct = score_result["percentage"]
    recs = []

    for action in score_result["priority_actions"]:
        urgency = "high" if pct < 40 else ("medium" if pct < 70 else "low")
        recs.append({
            "icon": action["icon"],
            "title": action[f"label_{lang}"],
            "body": action[f"action_{lang}"],
            "urgency": urgency,
            "category": action["category"],
        })

    # Sort: high → medium → low
    order = {"high": 0, "medium": 1, "low": 2}
    recs.sort(key=lambda r: order[r["urgency"]])
    return recs
