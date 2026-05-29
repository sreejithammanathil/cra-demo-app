"""
CRA Readiness Bridge — Maps readiness assessment scores to a personalised demo experience.
Pure Python — no Streamlit imports. Call from readiness_widgets.py or pages.
"""

from mock_data import PRODUCTS

_PRODUCT_NAMES = list(PRODUCTS.keys())   # ['BagMaker-X 2100', 'TS5525', 'Model 137T']


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 1 & 8 — Scenario / product recommendation per readiness band
# ──────────────────────────────────────────────────────────────────────────────

def get_scenario_recommendation(score_result: dict) -> dict:
    """
    Returns the best scenario + product for this user's readiness score.
    Keys: scenario_key, product_name, difficulty, title_en/ja, reason_en/ja
    """
    pct = score_result.get("percentage", 0)

    if pct <= 25:
        return {
            "scenario_key": "scenario_b",
            "product_name": _PRODUCT_NAMES[0],   # BagMaker-X 2100
            "difficulty": "beginner",
            "title_en": "Start with the fundamentals",
            "title_ja": "まず基礎を学びましょう",
            "reason_en": (
                "This 'no component match' case is the clearest way to understand how SBOM-based "
                "decisions work. When a component isn't in your product, no report is needed — "
                "see how the system proves that in seconds."
            ),
            "reason_ja": (
                "このSBOM照合で一致なしのシナリオは、SBOMに基づく判定がどのように機能するかを最も明確に示します。"
                "製品にコンポーネントが含まれていない場合、報告は不要です — "
                "システムがそれを数秒で証明する様子をご覧ください。"
            ),
        }
    elif pct <= 60:
        return {
            "scenario_key": "scenario_a",
            "product_name": _PRODUCT_NAMES[1] if len(_PRODUCT_NAMES) > 1 else _PRODUCT_NAMES[0],
            "difficulty": "intermediate",
            "title_en": "See the real workflow — built for your situation",
            "title_ja": "あなたの状況のための実際のワークフローを見てください",
            "reason_en": (
                "A CRITICAL CVE that triggers full ENISA Article 14 reporting — this mirrors the gaps "
                "we found in your assessment. You'll see exactly what automated monitoring, "
                "decision logic, and 24-hour reporting looks like end-to-end."
            ),
            "reason_ja": (
                "ENISA第14条の報告を引き起こすCRITICAL CVE — これはあなたのアセスメントで発見されたギャップを"
                "直接反映しています。自動監視、意思決定ロジック、24時間報告がエンドツーエンドでどのように"
                "機能するかを正確に確認できます。"
            ),
        }
    else:
        return {
            "scenario_key": "scenario_c",
            "product_name": _PRODUCT_NAMES[2] if len(_PRODUCT_NAMES) > 2 else _PRODUCT_NAMES[0],
            "difficulty": "advanced",
            "title_en": "Master the complex edge cases — you're ready",
            "title_ja": "複雑なエッジケースをマスターする — あなたは準備ができています",
            "reason_en": (
                "You have strong fundamentals. Now see how the system handles conflicting VEX evidence "
                "and manual overrides — the real edge cases that trip up even experienced teams."
            ),
            "reason_ja": (
                "基礎はしっかりできています。VEXの矛盾する証拠と手動オーバーライドをシステムがどう処理するか — "
                "経験豊富なチームでも躓く実際のエッジケースをご覧ください。"
            ),
        }


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 3 — Key stage mapping
# ──────────────────────────────────────────────────────────────────────────────

_CAT_STAGE_MAP: dict[str, set] = {
    "MONITORING":    {1, 2},
    "SBOM":          {2},
    "ENISA":         {6},
    "POST_MARKET":   {6},
    "PROCESS":       {4, 5},
    "DOCUMENTATION": {4},
    "ROLE":          {4},
    "PLANNING":      {1, 6},
}


def get_key_stages(score_result: dict) -> set:
    """
    Returns set of stage numbers (1–6) that are KEY for this user.
    Always returns at least 2 stages.
    """
    gap_cats = {b["category"] for b in score_result.get("gaps", [])}
    key: set = set()
    for cat in gap_cats:
        key.update(_CAT_STAGE_MAP.get(cat, set()))
    # Guarantee minimum coverage
    if len(key) < 2:
        key.update({1, 2, 4} if score_result.get("percentage", 0) <= 40 else {4, 6})
    return key


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 4 — Personalised stage-level educational insights
# ──────────────────────────────────────────────────────────────────────────────

_STAGE_INSIGHTS: dict[str, dict[int, dict[str, str]]] = {
    "MONITORING": {
        1: {
            "en": (
                "💡 **This stage directly solves your monitoring gap.** Right now your team learns "
                "about CVEs reactively — from news or customer reports. This step shows how J-TEC's "
                "pipeline queries NVD automatically so you know within *hours*, not weeks."
            ),
            "ja": (
                "💡 **このステージはあなたの監視ギャップを直接解決します。** 現在、チームはCVEをニュースや顧客報告から"
                "事後的に知ります。このステップでは、J-TECのパイプラインがNVDを自動的にクエリし、"
                "数週間ではなく*数時間*以内に把握できる方法を示します。"
            ),
        },
        2: {
            "en": (
                "💡 **Monitoring alone isn't enough — you need your SBOM to know if YOU'RE affected.** "
                "This step shows how component matching turns a generic CVE alert into a "
                "'yes, your product is affected' or 'no, your version is safe' answer."
            ),
            "ja": (
                "💡 **監視だけでは不十分です — 影響を受けるかを知るにはSBOMが必要です。** "
                "このステップでは、コンポーネントマッチングが一般的なCVEアラートを"
                "「あなたの製品が影響を受ける」または「このバージョンは安全」という答えに変換する方法を示します。"
            ),
        },
    },
    "SBOM": {
        2: {
            "en": (
                "💡 **This is the stage that requires an SBOM — and shows exactly why you need one.** "
                "Without a component inventory you cannot determine if a CVE affects your product. "
                "Watch the system cross-reference the CVE's affected version range against every "
                "component in the SBOM in milliseconds."
            ),
            "ja": (
                "💡 **このステージはSBOMを必要とします — そしてなぜSBOMが必要かを正確に示します。** "
                "コンポーネントインベントリなしに、CVEが自社製品に影響するかを判断することはできません。"
                "システムがCVEの影響バージョン範囲と製品SBOMの各コンポーネントをミリ秒で照合する様子をご覧ください。"
            ),
        },
    },
    "ENISA": {
        6: {
            "en": (
                "💡 **This stage directly solves your 24-hour ENISA deadline gap.** Assembling a "
                "CRA Article 14 notification manually under time pressure is nearly impossible. "
                "Watch the system generate a complete, submission-ready notification — reference ID, "
                "timestamps, all mandatory fields — in seconds."
            ),
            "ja": (
                "💡 **このステージはあなたのENISA 24時間期限ギャップを直接解決します。** "
                "時間的プレッシャーの中でCRA第14条の通知を手動で作成することはほぼ不可能です。"
                "参照ID、タイムスタンプ、必須項目すべてを含む送信可能な通知を数秒で生成する様子をご覧ください。"
            ),
        },
    },
    "POST_MARKET": {
        6: {
            "en": (
                "💡 **CRA requires post-market monitoring — this ENISA submission is where it culminates.** "
                "This output proves you monitored, detected, assessed, and reported — "
                "the complete CRA Article 14 compliance chain in one document."
            ),
            "ja": (
                "💡 **CRAは市場後監視を義務付けています — このENISA提出がその集大成です。** "
                "この出力は、監視・検出・評価・報告したことを証明します — "
                "CRA第14条のコンプライアンスチェーン全体が一つの文書に。"
            ),
        },
    },
    "PROCESS": {
        4: {
            "en": (
                "💡 **Your assessment shows no documented decision process — here's what that looks like.** "
                "Six transparent rules, each with a full reasoning trail and confidence contribution. "
                "When a CVE arrives, these rules fire automatically and produce an auditable score. "
                "No guesswork, full accountability."
            ),
            "ja": (
                "💡 **あなたのアセスメントは文書化された意思決定プロセスがないことを示しています — これがその実例です。** "
                "6つの透明なルール、それぞれに完全な理由の追跡と信頼度貢献あり。CVEが入ると、"
                "これらのルールが自動的に起動し、監査可能なスコアを生成します。推測なし、完全な説明責任。"
            ),
        },
        5: {
            "en": (
                "💡 **A documented human review is the CRA-compliant fallback when automation can't decide.** "
                "This record shows who reviewed, what their justification was, and the final decision — "
                "exactly the paper trail regulators expect to see during an audit."
            ),
            "ja": (
                "💡 **自動化で判断できない場合、文書化された人的レビューがCRAコンプライアントな代替手段です。** "
                "このレコードは、誰がレビューし、その理由は何で、最終判断は何かを示します — "
                "監査中に規制当局が確認することを期待するまさにその証跡です。"
            ),
        },
    },
    "DOCUMENTATION": {
        4: {
            "en": (
                "💡 **CRA Article 31 requires auditable decision documentation — this is exactly it.** "
                "Every rule trigger, confidence boost, and reasoning is logged with a timestamp. "
                "This becomes part of your technical file, which must be retained for 10 years."
            ),
            "ja": (
                "💡 **CRA第31条は監査可能な意思決定文書を要求します — これがまさにその実例です。** "
                "各ルールトリガー、信頼度ブースト、理由がタイムスタンプ付きで記録されます。"
                "これはあなたの技術ファイルの一部となり、10年間保管する必要があります。"
            ),
        },
    },
    "ROLE": {
        4: {
            "en": (
                "💡 **As manufacturer, this decision is yours under CRA Article 14.** "
                "Rule R001 specifically checks: 'Is this a critical exploit in an active product?' "
                "If yes, YOU — as the product manufacturer — are obligated to report to ENISA. "
                "Understanding your role means knowing which rules apply."
            ),
            "ja": (
                "💡 **製造業者として、CRA第14条の下でこの判断はあなたの責任です。** "
                "ルールR001は「これは稼働中の製品の重大なエクスプロイトか？」を具体的に確認します。"
                "はいなら、製品の製造業者として、ENISAへの報告義務があります。"
                "自分の役割を理解することは、適用されるルールを知ることです。"
            ),
        },
    },
    "PLANNING": {
        1: {
            "en": (
                "💡 **Your compliance roadmap starts here — with automated vulnerability detection.** "
                "Step 1 of your journey is CVE ingestion. Everything else — SBOM matching, "
                "decision logic, ENISA reporting — builds on first knowing what vulnerabilities exist."
            ),
            "ja": (
                "💡 **あなたのコンプライアンスロードマップはここから始まります — 自動脆弱性検出から。** "
                "旅のステップ1はCVE取込です。その後のすべて — SBOMマッチング、意思決定ロジック、"
                "ENISAレポート — は、まずどのような脆弱性が存在するかを把握することに基づいています。"
            ),
        },
        6: {
            "en": (
                "💡 **Your roadmap ends here — a compliant, automated ENISA submission.** "
                "From detection to reporting in one seamless pipeline. "
                "This is the finish line of your CRA readiness journey."
            ),
            "ja": (
                "💡 **あなたのロードマップはここで終わります — コンプライアントな自動ENISAサブミッション。** "
                "検出から報告まで一つのシームレスなパイプラインで。"
                "これがあなたのCRA準備の旅のゴールラインです。"
            ),
        },
    },
}


def get_stage_insights(stage_num: int, score_result: dict, lang: str = "en") -> list[str]:
    """Return up to 2 personalised insight strings for a given stage (1–6)."""
    gap_cats = {b["category"] for b in score_result.get("gaps", [])}
    insights = []
    for cat in gap_cats:
        text = _STAGE_INSIGHTS.get(cat, {}).get(stage_num, {}).get(lang)
        if text:
            insights.append(text)
    return insights[:2]


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 5 — Gap → Solution mapping table
# ──────────────────────────────────────────────────────────────────────────────

_GAP_SOLUTION: dict[str, dict] = {
    "SBOM": {
        "en": ("No SBOM management",           "Stage 2 — automated component matching"),
        "ja": ("SBOMがない",                    "ステージ2 — 自動コンポーネントマッチング"),
        "stage": 2,
    },
    "MONITORING": {
        "en": ("No CVE monitoring",             "Stage 1 — automated CVE ingestion from NVD"),
        "ja": ("CVE監視がない",                 "ステージ1 — NVDからの自動CVE取込"),
        "stage": 1,
    },
    "ENISA": {
        "en": ("No ENISA reporting process",    "Stage 6 — automated Article 14 notification"),
        "ja": ("ENISAの報告プロセスがない",      "ステージ6 — 自動第14条通知"),
        "stage": 6,
    },
    "POST_MARKET": {
        "en": ("No post-market monitoring",     "Stage 6 — lifecycle tracking & submission"),
        "ja": ("市場後監視がない",               "ステージ6 — ライフサイクル追跡と提出"),
        "stage": 6,
    },
    "PROCESS": {
        "en": ("No incident response process",  "Stages 4–5 — decision rules + review trail"),
        "ja": ("インシデント対応プロセスがない",  "ステージ4-5 — 意思決定ルール + レビュー証跡"),
        "stage": 4,
    },
    "DOCUMENTATION": {
        "en": ("Missing security documentation","Stage 4 — auditable confidence records"),
        "ja": ("セキュリティ文書が不足",          "ステージ4 — 監査可能な信頼スコア記録"),
        "stage": 4,
    },
    "ROLE": {
        "en": ("CRA role not defined",          "Stage 4 — manufacturer obligation rules"),
        "ja": ("CRAの役割が未定義",              "ステージ4 — 製造業者義務ルール"),
        "stage": 4,
    },
    "PLANNING": {
        "en": ("No compliance roadmap",         "Full pipeline — end-to-end 6-stage journey"),
        "ja": ("コンプライアンスロードマップがない","パイプライン全体 — エンドツーエンド6ステージ"),
        "stage": 0,
    },
}


def get_gap_solution_map(score_result: dict, lang: str = "en") -> list[dict]:
    """
    Returns list of {icon, gap, solution, stage} for each identified gap.
    Deduplicates by stage number.
    """
    seen_stages: set = set()
    result = []
    for b in score_result.get("gaps", []):
        cat = b["category"]
        info = _GAP_SOLUTION.get(cat)
        if not info:
            continue
        stage = info["stage"]
        if stage in seen_stages and stage != 0:
            continue
        seen_stages.add(stage)
        gap_lbl, sol_lbl = info[lang]
        result.append({
            "icon": b["icon"],
            "gap": gap_lbl,
            "solution": sol_lbl,
            "stage": stage,
        })
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  Feature 6 & 7 — Progress metrics and level-specific CTAs
# ──────────────────────────────────────────────────────────────────────────────

_CTA_MAP: dict[str, dict[str, dict]] = {
    "NOT_READY": {
        "en": {
            "button": "Get Started: Full Implementation Package",
            "message": "You're new to CRA compliance — let's build your system from scratch.",
            "offer": "End-to-end: SBOM creation · CVE monitoring setup · ENISA automation · Staff training",
            "weeks": 16,
        },
        "ja": {
            "button": "今すぐ始める：フル実装パッケージ",
            "message": "CRAコンプライアンスは初めてです — ゼロから構築しましょう。",
            "offer": "エンドツーエンド：SBOM作成 · CVE監視設定 · ENISA自動化 · スタッフトレーニング",
            "weeks": 16,
        },
    },
    "EARLY_STAGE": {
        "en": {
            "button": "Get Started: Full Implementation Package",
            "message": "You have awareness — now let's build the processes.",
            "offer": "12-week programme: SBOM → Monitoring → Reporting → Documentation",
            "weeks": 12,
        },
        "ja": {
            "button": "今すぐ始める：フル実装パッケージ",
            "message": "認識はあります — プロセスを構築しましょう。",
            "offer": "12週間プログラム：SBOM → 監視 → 報告 → 文書化",
            "weeks": 12,
        },
    },
    "PARTIALLY_READY": {
        "en": {
            "button": "Close Your Gaps: Gap-Filling Service",
            "message": "You've started — let's finish the job and close your specific gaps.",
            "offer": "Targeted gap analysis + focused implementation for your missing areas",
            "weeks": 6,
        },
        "ja": {
            "button": "ギャップを埋める：ギャップフィリングサービス",
            "message": "始まっています — 特定のギャップを埋めて完成させましょう。",
            "offer": "ターゲットを絞ったギャップ分析 + 不足エリアへの集中実装",
            "weeks": 6,
        },
    },
    "MOSTLY_READY": {
        "en": {
            "button": "Activate BPO: Continuous Compliance",
            "message": "Almost there — automate the rest with 24/7 managed compliance.",
            "offer": "BPO service: automated CVE monitoring · ENISA reporting · quarterly reviews",
            "weeks": 4,
        },
        "ja": {
            "button": "BPOを起動：継続的コンプライアンス",
            "message": "もう少しです — 24時間365日管理コンプライアンスで残りを自動化しましょう。",
            "offer": "BPOサービス：自動CVE監視 · ENISAレポート · 四半期レビュー",
            "weeks": 4,
        },
    },
    "CRA_READY": {
        "en": {
            "button": "Activate BPO: Stay Compliant Forever",
            "message": "Excellent posture — automate it so compliance stays perfect.",
            "offer": "BPO partnership: 24/7 CVE watch · auto ENISA reports · quarterly audits",
            "weeks": 2,
        },
        "ja": {
            "button": "BPOを起動：永続的なコンプライアンス",
            "message": "優れた体制 — 自動化してコンプライアンスを常に完璧に保ちましょう。",
            "offer": "BPOパートナーシップ：24時間CVE監視 · 自動ENISAレポート · 四半期監査",
            "weeks": 2,
        },
    },
}


def get_cta(score_result: dict, lang: str = "en") -> dict:
    """Return CTA config dict for the user's readiness level."""
    level = score_result.get("readiness_level", {}).get("level", "PARTIALLY_READY")
    return _CTA_MAP.get(level, _CTA_MAP["PARTIALLY_READY"])[lang]
