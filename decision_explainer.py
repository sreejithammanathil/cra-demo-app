"""
CRA Decision Accountability Engine
Generates explainability, timeline, accountability, evidence, and justification
artifacts from pipeline_results. Pure Python — no Streamlit imports.
"""

from datetime import datetime
from mock_data import CVE_SCENARIOS, DECISION_RULES, THRESHOLDS


# ── Timestamp helpers ──────────────────────────────────────────────────────────

def _ts(iso_str: str) -> str:
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso_str or "—"


def _ts_short(iso_str: str) -> str:
    try:
        return datetime.fromisoformat(iso_str).strftime("%H:%M:%S")
    except Exception:
        return iso_str or "—"


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1 — Decision Explainability
# ══════════════════════════════════════════════════════════════════════════════

def generate_decision_explanation(results: dict, lang: str = "en") -> dict:
    """
    Returns:
        decision_type, confidence_score, auto_decided, outcome_label,
        reason_bullets (list[str]),
        evidence_table (list[dict]),
        rule_table     (list[dict]),
        justification_paragraph (str)
    """
    cve      = results["cve"]
    sbom     = results["sbom_match"]
    conflict = results["conflict_info"]
    proposal = results["decision_proposal"]
    review   = results["review_result"]
    enisa    = results["enisa_result"]
    final    = review["final_decision_type"]
    s_key    = results.get("scenario_key", "")
    s_data   = CVE_SCENARIOS.get(s_key, {})

    # ── Reason bullets ──────────────────────────────────────────────────────
    bullets = []
    if sbom["match_found"]:
        bullets.append(
            f"SBOM confirms {sbom['matching_component']} v{sbom.get('component_version','?')} "
            f"is within affected range {sbom['affected_range']}"
        )
    else:
        bullets.append(f"SBOM analysis: {sbom['match_reason']}")

    if cve.get("exploit_available"):
        bullets.append(f"Public exploit confirmed for {cve['cve_id']}")
    else:
        bullets.append("No public exploit confirmed at time of assessment")

    bullets.append(
        f"CVSS {cve['cvss_score']} ({cve['severity']}) — "
        f"{'exceeds' if cve['cvss_score'] >= THRESHOLDS['high_severity'] else 'below'} "
        f"HIGH threshold ({THRESHOLDS['high_severity']})"
    )

    if conflict["conflict_detected"]:
        bullets.append(f"Evidence conflict detected: {conflict['conflict_type']}")

    if not proposal["auto_decidable"]:
        bullets.append(
            f"Confidence {proposal['confidence_score']:.0%} < auto-decide threshold "
            f"({THRESHOLDS['auto_decide_confidence']:.0%}) — human review required"
        )

    if final == "REPORT":
        bullets.append("CRA Article 14 reporting obligation triggered — ENISA notification required")
    elif final == "NOT_REPORT":
        bullets.append("No CRA Article 14 reporting obligation — component not vulnerable")

    # ── Evidence table ───────────────────────────────────────────────────────
    evidence_table = [
        {
            "source":  "CVE Database (NVD)",
            "result":  "Found",
            "status":  "confirmed",
            "detail":  f"{cve['cve_id']} · CVSS {cve['cvss_score']} · {cve['severity']}",
        },
        {
            "source":  "SBOM Match",
            "result":  "Confirmed" if sbom["match_found"] else "Not Matched",
            "status":  "confirmed" if sbom["match_found"] else "clear",
            "detail":  sbom["match_reason"],
        },
        {
            "source":  "VEX Statement",
            "result":  "Present" if conflict.get("vex_available") else "None",
            "status":  "partial" if conflict.get("vex_available") else "none",
            "detail":  (s_data.get("vex_statement", "N/A")
                        if conflict.get("vex_available")
                        else "No VEX statement received"),
        },
        {
            "source":  "Exploit Availability",
            "result":  "Confirmed" if cve.get("exploit_available") else "Not Confirmed",
            "status":  "confirmed" if cve.get("exploit_available") else "clear",
            "detail":  ("Public exploit code confirmed in exploit databases"
                        if cve.get("exploit_available")
                        else "No known public exploit at time of assessment"),
        },
        {
            "source":  "Human Review",
            "result":  review.get("status", "Not Required"),
            "status":  "confirmed" if review.get("status") == "APPROVED" else "partial",
            "detail":  f"Reviewed by {review['reviewer']} — action: {review.get('action','APPROVE')}",
        },
        {
            "source":  "Conflict Detection",
            "result":  "Conflict Detected" if conflict["conflict_detected"] else "No Conflict",
            "status":  "warning" if conflict["conflict_detected"] else "clear",
            "detail":  (conflict.get("conflict_type", "—")
                        if conflict["conflict_detected"]
                        else "Evidence is internally consistent"),
        },
    ]

    # ── Rule evaluation table ────────────────────────────────────────────────
    # Evaluate each of the 6 rules against actual data
    conditions = {
        "R1": cve["cvss_score"] >= THRESHOLDS["critical_severity"] and cve.get("exploit_available", False),
        "R2": cve["cvss_score"] >= THRESHOLDS["high_severity"] and sbom["match_found"],
        "R3": not sbom["match_found"],
        "R4": conflict.get("vex_available", False) and not conflict.get("conflict_detected", True),
        "R5": conflict.get("conflict_detected", False),
        "R6": (sbom["match_found"]
               and not cve.get("exploit_available", False)
               and THRESHOLDS["medium_severity"] <= cve["cvss_score"] < THRESHOLDS["high_severity"]),
    }
    rule_table = []
    for dr in DECISION_RULES:
        rule_table.append({
            "rule_id":   dr["rule_id"],
            "name":      dr["name"],
            "condition": dr["condition"],
            "result":    conditions.get(dr["rule_id"], False),
            "action":    dr["action"],
        })

    # ── Human-readable justification ─────────────────────────────────────────
    para = _build_justification(results, s_data, lang)

    return {
        "decision_type":          final,
        "confidence_score":       proposal["confidence_score"],
        "auto_decided":           proposal["auto_decidable"],
        "outcome_label":          final.replace("_", " "),
        "reason_bullets":         bullets,
        "evidence_table":         evidence_table,
        "rule_table":             rule_table,
        "justification_paragraph": para,
    }


def _build_justification(results: dict, s_data: dict, lang: str) -> str:
    """Deterministic human-readable paragraph — no LLM required."""
    cve    = results["cve"]
    sbom   = results["sbom_match"]
    review = results["review_result"]
    enisa  = results["enisa_result"]
    final  = review["final_decision_type"]
    ts     = _ts(review["review_timestamp"])

    if lang == "ja":
        return _build_justification_ja(results, s_data)

    reviewer = review.get("reviewer", "Compliance Officer")
    conf_str = f"{results['decision_proposal']['confidence_score']:.0%}"
    action   = review.get("action", "APPROVE").lower() + "d"

    if final == "REPORT":
        ex = ("A public exploit is confirmed, elevating urgency."
              if cve.get("exploit_available")
              else "No public exploit is confirmed at this time.")
        return (
            f"On {ts}, the CRA compliance pipeline assessed {cve['cve_id']} "
            f"(CVSS {cve['cvss_score']}, {cve['severity']}) affecting "
            f"{cve['affected_versions']['library']} "
            f"{cve['affected_versions']['range_start']}–{cve['affected_versions']['range_end']}. "
            f"SBOM analysis of {sbom['product_name']} confirmed that {sbom['matching_component']} "
            f"v{sbom.get('component_version','?')} falls within the vulnerable range. "
            f"{ex} "
            f"The rules engine assigned a confidence score of {conf_str}. "
            f"The decision was reviewed by {reviewer}, who {action} it with justification: "
            f"\"{review['justification']}\". "
            f"Under CRA Article 14(2), a formal vulnerability notification was submitted to ENISA "
            f"(reference: {enisa.get('enisa_reference_id','N/A')}) "
            f"at {_ts(enisa['submission_timestamp'])}."
        )

    if final == "NOT_REPORT":
        return (
            f"On {ts}, the CRA compliance pipeline assessed {cve['cve_id']} "
            f"(CVSS {cve['cvss_score']}, {cve['severity']}) affecting "
            f"{cve['affected_versions']['library']} "
            f"{cve['affected_versions']['range_start']}–{cve['affected_versions']['range_end']}. "
            f"SBOM analysis of {sbom['product_name']} determined: {sbom['match_reason']}. "
            f"This CVE does not affect the installed component — no CRA Article 14 reporting "
            f"obligation is triggered for {sbom['product_name']}. "
            f"The decision (confidence: {conf_str}) was reviewed by {reviewer}, who confirmed: "
            f"\"{review['justification']}\"."
        )

    if final in ("CONFLICT", "ESCALATED"):
        vex = ""
        if results["conflict_info"].get("vex_available"):
            vex = (
                f"A VEX statement was received: \"{s_data.get('vex_statement','N/A')}\". "
                f"Claimed mitigation: \"{s_data.get('vex_justification','N/A')}\". "
            )
        return (
            f"On {ts}, the CRA compliance pipeline detected conflicting evidence for {cve['cve_id']} "
            f"(CVSS {cve['cvss_score']}, {cve['severity']}) in {sbom['product_name']}. "
            f"SBOM analysis found {sbom.get('matching_component','a matching component')} is present. "
            f"{vex}"
            f"Due to the conflict, automated decision was not possible (confidence: {conf_str}). "
            f"The case was escalated to {reviewer}, who assessed the evidence and {action} "
            f"with justification: \"{review['justification']}\"."
        )

    # Fallback (HUMAN_REVIEW / other)
    return (
        f"On {ts}, {cve['cve_id']} (CVSS {cve['cvss_score']}, {cve['severity']}) was assessed "
        f"for {sbom['product_name']}. The automated confidence score ({conf_str}) fell below the "
        f"auto-decide threshold ({THRESHOLDS['auto_decide_confidence']:.0%}), requiring human review. "
        f"{reviewer} reviewed the evidence and {action} a {final.replace('_',' ')} decision: "
        f"\"{review['justification']}\"."
    )


def _build_justification_ja(results: dict, s_data: dict) -> str:
    cve    = results["cve"]
    sbom   = results["sbom_match"]
    review = results["review_result"]
    enisa  = results["enisa_result"]
    final  = review["final_decision_type"]
    ts     = _ts(review["review_timestamp"])
    conf   = f"{results['decision_proposal']['confidence_score']:.0%}"
    rev    = review.get("reviewer", "コンプライアンス担当者")

    if final == "REPORT":
        ex = ("公開エクスプロイトが確認されており、緊急性が高まっています。"
              if cve.get("exploit_available")
              else "現時点では公開エクスプロイトは確認されていません。")
        return (
            f"{ts}、CRAコンプライアンスパイプラインは{cve['cve_id']}（CVSS {cve['cvss_score']}、"
            f"{cve['severity']}）を評価しました。{sbom['product_name']}のSBOM分析により、"
            f"{sbom['matching_component']} v{sbom.get('component_version','?')}が脆弱な範囲内に含まれることが確認されました。"
            f"{ex}ルールエンジンは信頼スコア{conf}を付与しました。"
            f"判定は{rev}によってレビューされ、承認されました：「{review['justification']}」。"
            f"CRA第14条(2)に基づき、ENISAに正式な脆弱性通知が提出されました"
            f"（参照番号：{enisa.get('enisa_reference_id','N/A')}）。"
        )
    if final == "NOT_REPORT":
        return (
            f"{ts}、CRAコンプライアンスパイプラインは{cve['cve_id']}（CVSS {cve['cvss_score']}、"
            f"{cve['severity']}）を評価しました。{sbom['product_name']}のSBOM分析の結果、"
            f"{sbom['match_reason']}。このCVEはインストール済みコンポーネントに影響を与えないため、"
            f"CRA第14条の報告義務は発生しません。判定（信頼スコア：{conf}）は"
            f"{rev}によって確認されました：「{review['justification']}」。"
        )
    return (
        f"{ts}、{cve['cve_id']}（CVSS {cve['cvss_score']}、{cve['severity']}）が"
        f"{sbom['product_name']}に対して評価されました。自動信頼スコア（{conf}）が"
        f"自動判定閾値（{THRESHOLDS['auto_decide_confidence']:.0%}）を下回ったため、人的レビューが必要でした。"
        f"{rev}が証拠を審査し、{final.replace('_',' ')}の判定を承認しました："
        f"「{review['justification']}」。"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 — Decision History Timeline
# ══════════════════════════════════════════════════════════════════════════════

_ACTION_META = {
    "CVE_INGESTED":       (1, "📥", "System",  "CVE ingested from NVD",           "CVE取込完了"),
    "SBOM_MATCHED":       (2, "🔩", "System",  "SBOM matching completed",         "SBOM照合完了"),
    "CONFLICT_DETECTED":  (3, "⚡", "System",  "Evidence conflict detected",      "証拠矛盾を検出"),
    "EVIDENCE_AMBIGUOUS": (3, "⚠️", "System",  "Ambiguous evidence flagged",      "曖昧な証拠を検出"),
    "DECISION_PROPOSED":  (4, "🎯", "System",  "Decision proposed",               "判定を提案"),
    "DECISION_REVIEWED":  (5, "👤", "Human",   "Human review completed",          "人的レビュー完了"),
    "ENISA_SUBMITTED":    (6, "🏛️", "System",  "ENISA notification submitted",    "ENISA通知提出"),
    "ENISA_SKIPPED":      (6, "⬜", "System",  "ENISA submission not required",   "ENISA提出不要"),
}

_STAGE_STATE = {
    1: "CVE_INGESTION", 2: "SBOM_ANALYSIS", 3: "CONFLICT_CHECK",
    4: "DECISION",      5: "REVIEW",         6: "REPORTING",
}


def generate_timeline(results: dict, lang: str = "en") -> list[dict]:
    """Build chronological timeline list from audit_trail + review metadata."""
    review = results["review_result"]
    events = []
    for entry in results.get("audit_trail", []):
        action = entry["action"]
        meta   = _ACTION_META.get(action, (0, "⚙️", "System", action.replace("_"," "), action))
        stage, icon, actor_type, label_en, label_ja = meta
        actor = review.get("reviewer", "Compliance Officer") if actor_type == "Human" else "Decision Engine"
        events.append({
            "timestamp":      _ts_short(entry["timestamp"]),
            "timestamp_full": _ts(entry["timestamp"]),
            "action":         action,
            "event":          label_ja if lang == "ja" else label_en,
            "actor":          actor,
            "actor_type":     actor_type,
            "stage":          stage,
            "icon":           icon,
            "details":        entry["details"],
            "state":          _STAGE_STATE.get(stage, "PROCESSING"),
        })
    return events


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 3 — Accountability Record
# ══════════════════════════════════════════════════════════════════════════════

def generate_accountability_record(results: dict) -> dict:
    review   = results["review_result"]
    proposal = results["decision_proposal"]
    enisa    = results["enisa_result"]
    cve      = results["cve"]

    chain = [
        {
            "step":      1,
            "role":      "Automated Decision System",
            "icon":      "🤖",
            "actor":     "CRA Decision Engine v1.0",
            "action":    f"Proposed: {proposal['decision_type']}",
            "timestamp": _ts(cve.get("ingested_at", "")),
            "notes":     f"Confidence: {proposal['confidence_score']:.0%} · Auto-decidable: {proposal['auto_decidable']}",
        },
        {
            "step":      2,
            "role":      "Compliance Officer — Human Review",
            "icon":      "👤",
            "actor":     review.get("reviewer", "Compliance Officer"),
            "action":    f"{review.get('action','APPROVE')}ED",
            "timestamp": _ts(review.get("review_timestamp", "")),
            "notes":     review.get("justification", "—"),
        },
    ]
    if enisa.get("submitted"):
        chain.append({
            "step":      3,
            "role":      "Regulatory Reporting System",
            "icon":      "🏛️",
            "actor":     "ENISA Portal (Automated)",
            "action":    "Submitted CRA Article 14 notification",
            "timestamp": _ts(enisa.get("submission_timestamp", "")),
            "notes":     f"Reference: {enisa.get('enisa_reference_id','N/A')}",
        })

    return {
        "decision_id":          review.get("decision_id", "—"),
        "final_decision":       review.get("final_decision_type", "—"),
        "system_generated_by":  "CRA Decision Engine v1.0",
        "system_generated_at":  _ts(cve.get("ingested_at", "")),
        "human_reviewed_by":    review.get("reviewer", "Compliance Officer"),
        "human_reviewed_at":    _ts(review.get("review_timestamp", "")),
        "review_action":        review.get("action", "APPROVE"),
        "review_status":        review.get("status", "APPROVED"),
        "review_notes":         review.get("justification", "—"),
        "enisa_submitted":      enisa.get("submitted", False),
        "enisa_ref":            enisa.get("enisa_reference_id", "N/A"),
        "accountability_chain": chain,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 4 — Evidence Repository
# ══════════════════════════════════════════════════════════════════════════════

def generate_evidence_repository(results: dict) -> list[dict]:
    """All evidence items: {type, type_icon, source, timestamp, confidence, description, status}"""
    cve      = results["cve"]
    sbom     = results["sbom_match"]
    conflict = results["conflict_info"]
    proposal = results["decision_proposal"]
    review   = results["review_result"]
    s_data   = CVE_SCENARIOS.get(results.get("scenario_key", ""), {})
    ts_ingest = _ts(cve.get("ingested_at", ""))

    items = []

    items.append({
        "type":        "CVE Intelligence",
        "type_icon":   "🛡️",
        "source":      "NVD (National Vulnerability Database)",
        "timestamp":   ts_ingest,
        "confidence":  0.98,
        "status":      "confirmed",
        "description": (
            f"{cve['cve_id']}: {cve['description']}. "
            f"CVSS {cve['cvss_score']} ({cve['severity']}). "
            f"Affects {cve['affected_versions']['library']} "
            f"{cve['affected_versions']['range_start']}–{cve['affected_versions']['range_end']}."
        ),
    })

    items.append({
        "type":        "SBOM Component Analysis",
        "type_icon":   "📦",
        "source":      f"Product SBOM — {sbom['product_name']}",
        "timestamp":   ts_ingest,
        "confidence":  sbom["match_confidence"],
        "status":      "confirmed" if sbom["match_found"] else "clear",
        "description": (
            f"Library searched: {sbom['affected_library']}. "
            f"Result: {sbom['match_reason']}. "
            + (f"Matching component: {sbom['matching_component']} v{sbom.get('component_version','?')}."
               if sbom["match_found"] else "Component not found in SBOM.")
        ),
    })

    items.append({
        "type":        "Exploit Intelligence",
        "type_icon":   "💣",
        "source":      "CISA KEV / Exploit-DB",
        "timestamp":   ts_ingest,
        "confidence":  0.95 if cve.get("exploit_available") else 0.80,
        "status":      "confirmed" if cve.get("exploit_available") else "clear",
        "description": (
            "Public exploit code confirmed available. Active exploitation risk is elevated."
            if cve.get("exploit_available") else
            "No public exploit confirmed. Theoretical exploitation remains possible under specific conditions."
        ),
    })

    if conflict.get("vex_available"):
        items.append({
            "type":        "VEX Statement",
            "type_icon":   "📋",
            "source":      f"Vendor Advisory — {sbom['product_name']}",
            "timestamp":   _ts(review.get("review_timestamp", "")),
            "confidence":  THRESHOLDS.get("vex_trust_score", 0.9),
            "status":      "partial",
            "description": (
                f"VEX claim: {s_data.get('vex_statement','N/A')}. "
                f"Claimed mitigation: {s_data.get('vex_justification','N/A')}."
            ),
        })

    if conflict["conflict_detected"]:
        items.append({
            "type":        "Conflict Detection",
            "type_icon":   "⚡",
            "source":      "Automated Conflict Analyser (Stage 3)",
            "timestamp":   ts_ingest,
            "confidence":  1.0,
            "status":      "warning",
            "description": (
                f"Conflict type: {conflict['conflict_type']}. "
                "Evidence from multiple sources is contradictory — automated decision impossible."
            ),
        })

    items.append({
        "type":        "Decision Rules Evaluation",
        "type_icon":   "⚖️",
        "source":      "CRA Decision Rules Engine — 6 Rules",
        "timestamp":   ts_ingest,
        "confidence":  proposal["confidence_score"],
        "status":      "confirmed",
        "description": (
            f"{len(proposal['rules_fired'])} rule(s) evaluated. "
            f"Proposed: {proposal['decision_type']}. "
            f"Confidence: {proposal['confidence_score']:.0%}. "
            f"Auto-decidable: {proposal['auto_decidable']}."
        ),
    })

    items.append({
        "type":        "Human Review Record",
        "type_icon":   "👤",
        "source":      f"Compliance Officer: {review.get('reviewer','Compliance Officer')}",
        "timestamp":   _ts(review.get("review_timestamp", "")),
        "confidence":  1.0,
        "status":      "confirmed" if review.get("status") == "APPROVED" else "warning",
        "description": (
            f"Action: {review.get('action','APPROVE')}. "
            f"Status: {review.get('status','APPROVED')}. "
            f"Justification: {review.get('justification','—')}."
        ),
    })

    return items


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 5 — Decision Justification Record (for auditor export)
# ══════════════════════════════════════════════════════════════════════════════

def generate_justification_record(results: dict, lang: str = "en") -> dict:
    review   = results["review_result"]
    proposal = results["decision_proposal"]
    enisa    = results["enisa_result"]
    cve      = results["cve"]
    sbom     = results["sbom_match"]

    triggered = [r["rule"] for r in proposal["rules_fired"] if r["triggered"]]

    evidence_pts = []
    if sbom["match_found"]:
        evidence_pts.append(
            f"SBOM: {sbom['matching_component']} v{sbom.get('component_version','?')} in affected range"
        )
    if cve.get("exploit_available"):
        evidence_pts.append(f"Exploit: Public exploit confirmed for {cve['cve_id']}")
    evidence_pts.append(f"CVSS: {cve['cvss_score']} ({cve['severity']})")

    explanation = generate_decision_explanation(results, lang)

    return {
        "decision_id":         review.get("decision_id", "—"),
        "cve_id":              cve["cve_id"],
        "product":             sbom["product_name"],
        "decision_type":       review["final_decision_type"],
        "decision_reasons":    explanation["reason_bullets"],
        "triggered_rules":     triggered,
        "supporting_evidence": evidence_pts,
        "reviewer_name":       review.get("reviewer", "—"),
        "reviewer_action":     review.get("action", "—"),
        "reviewer_notes":      review.get("justification", "—"),
        "approval_status":     review.get("status", "—"),
        "decision_timestamp":  _ts(review.get("review_timestamp", "")),
        "enisa_reference":     enisa.get("enisa_reference_id", "N/A"),
        "full_narrative":      explanation["justification_paragraph"],
        "full_audit_trail":    results.get("audit_trail", []),
    }
