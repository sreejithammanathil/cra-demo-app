"""
Translations for CRA Decision Traceability System
English (en) and Japanese (ja)
"""

TRANSLATIONS = {
    "en": {
        # App chrome
        "app_title": "CRA Decision Traceability System",
        "app_subtitle": "EU Cyber Resilience Act (2024/2847) — Live Demo for J-TEC Co., Ltd.",
        "footer": "CRA Decision Traceability System — Geoglyph Inc. &nbsp;|&nbsp; Demo for J-TEC Co., Ltd. &nbsp;|&nbsp; EU Cyber Resilience Act (2024/2847)",

        # Sidebar
        "sidebar_scenarios": "Demo Scenarios",
        "sidebar_choose": "Choose Scenario:",
        "sidebar_product_header": "J-TEC Product",
        "sidebar_product_label": "Product:",
        "sidebar_sbom_expander": "SBOM ({n} components)",
        "sidebar_run_btn": "🚀 RUN DEMO PIPELINE",
        "sidebar_stats_header": "Session Stats",
        "sidebar_stats_runs": "Scenarios Run",
        "sidebar_stats_report": "REPORT decisions",
        "sidebar_stats_not_report": "NOT_REPORT decisions",
        "sidebar_run_history": "Run history",
        "sidebar_human_flag": "👤 **Human review required**",

        # Landing
        "landing_prompt": "👈 Select a scenario from the sidebar and click **RUN DEMO PIPELINE** to begin.",
        "landing_hint": "View all scenarios, decision rules, and session history on the **📚 History** page (left sidebar).",

        # Metrics
        "metric_scenario": "Scenario",
        "metric_product": "Product",
        "metric_cve": "CVE",
        "metric_cvss": "CVSS Score",
        "metric_severity": "Severity",
        "metric_final_decision": "Final Decision",
        "metric_confidence": "System Confidence",
        "metric_exploit": "Exploit Available",
        "metric_component_found": "Component Found",
        "metric_match_confidence": "Match Confidence",
        "metric_auto_decidable": "Auto-Decidable",
        "metric_proposed": "Proposed Decision",
        "metric_reviewer": "Reviewer",
        "metric_action": "Action",
        "metric_decision_id": "Decision ID",
        "metric_status": "Status",
        "metric_submitted": "Submitted to ENISA",

        # Pipeline stepper labels
        "step_ingest": "CVE\nIngest",
        "step_sbom": "SBOM\nMatch",
        "step_conflict": "Conflict\nDetect",
        "step_rules": "Decision\nRules",
        "step_review": "Human\nReview",
        "step_enisa": "ENISA\nReport",

        # Section headers
        "section_pipeline": "#### Pipeline Stages",
        "section_decision_banner": "### Final Decision:",
        "section_audit": "Complete Audit Trail",
        "section_audit_caption": "End-to-end traceability — every decision step timestamped and logged.",

        # Tab labels
        "tab_ingest": "1️⃣ CVE Ingestion",
        "tab_sbom": "2️⃣ SBOM Match",
        "tab_conflict": "3️⃣ Conflict Detection",
        "tab_rules": "4️⃣ Decision Rules",
        "tab_review": "5️⃣ Human Review",
        "tab_enisa": "6️⃣ ENISA Report",
        "tab_artifacts": "📋 Compliance Artifacts",

        # Tab 1 - CVE Ingestion
        "t1_header": "Stage 1: CVE Ingestion from NVD",
        "t1_description": "**Description**",
        "t1_affected_range": "**Affected Version Range:**",

        # Tab 2 - SBOM
        "t2_header": "Stage 2: SBOM Matching",
        "t2_vuln": "🔴 **VULNERABLE** — {reason}",
        "t2_safe": "🟢 **NOT VULNERABLE** — {reason}",
        "t2_sbom_table": "**Full SBOM Component Analysis**",
        "t2_col_component": "Component",
        "t2_col_version": "Version",
        "t2_col_vendor": "Vendor",
        "t2_col_type": "Type",
        "t2_col_status": "Status",
        "t2_vulnerable": "🔴 VULNERABLE",
        "t2_safe_status": "🟢 Safe",

        # Tab 3 - Conflict
        "t3_header": "Stage 3: Conflict Detection",
        "t3_conflict": "⚠️ **Conflict Detected:** {type}",
        "t3_no_conflict": "✅ No conflicts detected — all evidence sources agree",
        "t3_evidence": "**Evidence Sources in Conflict**",
        "t3_vex": "📄 **VEX Document Available**\nVendor-provided statement present and reviewed.",
        "t3_raw": "🔍 Raw conflict data",

        # Tab 4 - Rules
        "t4_header": "Stage 4: Decision Rules Engine",
        "t4_yes_auto": "YES ✅",
        "t4_no_auto": "NO — Human needed",
        "t4_rules_eval": "**Rules Evaluation**",
        "t4_triggered": "✅ TRIGGERED",
        "t4_not_triggered": "⬜ Not triggered",
        "t4_evidence_weight": "**Evidence Weighting**",
        "t4_ev_sbom": "SBOM Matching",
        "t4_ev_nvd": "CVE Data (NVD)",
        "t4_ev_vex": "VEX Statement",

        # Tab 5 - Human Review
        "t5_header": "Stage 5: Human Review Queue",
        "t5_justification": "**Review Justification**",
        "t5_final": "**Final Decision**",

        # Tab 6 - ENISA
        "t6_header": "Stage 6: ENISA Reporting",
        "t6_ref": "✅ **ENISA Reference:** `{ref}`",
        "t6_submitted_at": "Submitted: {ts}",
        "t6_sla": "**24-hour SLA clock started from submission timestamp.**",
        "t6_no_submit": "No ENISA submission required for this decision type.",
        "t6_payload_preview": "📄 ENISA submission payload preview",

        # Tab 7 - Artifacts
        "t7_header": "Compliance Artifacts — Download for Regulatory Audit",
        "t7_html_title": "**📄 HTML Compliance Report**",
        "t7_html_caption": "Full audit artifact with decision trail, evidence, and ENISA payload.",
        "t7_html_btn": "📥 Download HTML Report",
        "t7_json_title": "**📋 ENISA JSON Payload**",
        "t7_json_caption": "Machine-readable report formatted for ENISA submission API.",
        "t7_json_btn": "📋 Download ENISA JSON",

        # Human review form (Scenario D)
        "hr_paused": "⏸️ **Pipeline paused at Stage 5 — Compliance Officer review required**",
        "hr_below_threshold": "⚠️ Below 80% threshold",
        "hr_evidence": "📋 Evidence for Review",
        "hr_why": "**Why the system cannot auto-decide:**",
        "hr_evidence_sources": "**Evidence Sources:**",
        "hr_sbom_analysis": "**SBOM Component Analysis:**",
        "hr_stage5": "👤 Stage 5: Compliance Officer Review",
        "hr_intro": "The automated system has flagged this case for human review. Review the evidence above and submit your decision below.",
        "hr_reviewer_label": "Reviewer Name / ID",
        "hr_reviewer_placeholder": "e.g. Tanaka-san, CO-042",
        "hr_assessment": "**Your Assessment:**",
        "hr_notes_label": "Justification / Notes",
        "hr_notes_placeholder": "e.g. Reviewed VEX statement and SBOM match. The firewall mitigation is adequate for our deployment context — NOT_REPORT.",
        "hr_select_decision": "**Select Decision:**",
        "hr_btn_report": "🔴 APPROVE — REPORT to ENISA",
        "hr_btn_not_report": "🟢 APPROVE — NOT_REPORT",
        "hr_btn_escalate": "⚠️ ESCALATE for Further Review",
        "hr_err_name": "Please enter your name / reviewer ID before submitting.",
        "hr_err_notes": "Please enter a justification before submitting.",
        "hr_completing": "⏳ Stage 5 & 6: Completing pipeline...",
        "hr_done": "✅ Decision recorded: **{label}** by {name}. Pipeline complete.",

        # Spinner / progress messages
        "spin1": "⏳ Stage 1: Ingesting CVE from NVD...",
        "spin1_ok": "✅ Stage 1: CVE {cve_id} ingested",
        "spin2": "⏳ Stage 2: Matching against SBOM...",
        "spin2_ok": "✅ Stage 2: {reason}",
        "spin3": "⏳ Stage 3: Detecting conflicts...",
        "spin3_conflict": "⚠️ Stage 3: Conflict ({type})",
        "spin3_ok": "✅ Stage 3: No conflicts",
        "spin4": "⏳ Stage 4: Applying decision rules...",
        "spin4_ok": "✅ Stage 4: Decision proposed ({decision}) — confidence {conf}",
        "spin5": "⏳ Stage 5: Human review...",
        "spin5_ok": "✅ Stage 5: Approved by Compliance Officer",
        "spin6": "⏳ Stage 6: ENISA submission...",
        "spin6_ok": "✅ Stage 6: {status}",

        # History page
        "hist_title": "Scenario Reference & Run History",
        "hist_subtitle": "Overview of all demo scenarios, decision rules, and decisions made this session.",
        "hist_scenarios": "🗂️ Demo Scenarios",
        "hist_why": "Why?",
        "hist_run_header": "🕓 Session Run History",
        "hist_no_runs": "No scenarios have been run yet in this session. Go to the **Pipeline** page and run a scenario.",
        "hist_time": "Time",
        "hist_scenario": "Scenario",
        "hist_product": "Product",
        "hist_decision": "Decision",
        "hist_summary": "**Session Summary**",
        "hist_total": "Total Runs",
        "hist_report": "REPORT",
        "hist_not_report": "NOT_REPORT",
        "hist_human": "Human / Escalated",
        "hist_rules": "📏 Decision Rules Engine",
        "hist_rule_id": "ID",
        "hist_rule_name": "Rule Name",
        "hist_rule_condition": "Condition",
        "hist_rule_action": "Action",
        "hist_rule_auto": "Auto-decide",
        "hist_rule_conf": "Confidence",
        "hist_rule_yes": "✅ Yes",
        "hist_rule_no": "❌ Human needed",
        "hist_products": "🏭 J-TEC Products in Scope",
        "hist_comp": "Component",
        "hist_version": "Version",
        "hist_vendor": "Vendor",
        "hist_type": "Type",

        # Scenario names (for sidebar selector)
        "scenario_a_name": "Scenario A: CVE Affects Component (REPORT)",
        "scenario_b_name": "Scenario B: Version Mismatch (NOT_REPORT)",
        "scenario_c_name": "Scenario C: Conflict Detection (VEX Override)",
        "scenario_d_name": "Scenario D: Ambiguous Evidence — Human Decision Required",

        # Outcome labels
        "outcome_report": "🔴 REPORT",
        "outcome_not_report": "🟢 NOT_REPORT",
        "outcome_conflict": "🟠 CONFLICT",
        "outcome_human": "👤 HUMAN DECISION",
        "outcome_label": "Outcome:",

        # Legal declaration
        "legal_declaration": (
            "**Brand Ownership Declaration** &nbsp;|&nbsp; "
            "The name and brand <strong>Geoglyph Inc.</strong> are the exclusive property of Geoglyph Inc. "
            "The name and brand <strong>J-TEC Co., Ltd.</strong> (株式会社J-TEC) are the exclusive property of J-TEC Co., Ltd. "
            "All trademarks, trade names, and brand identifiers referenced in this application are the respective property of their owners. "
            "This demo application is produced solely for evaluation and compliance demonstration purposes and does not imply any endorsement or partnership beyond the scope of this engagement."
        ),
    },

    "ja": {
        # App chrome
        "app_title": "CRA 意思決定トレーサビリティシステム",
        "app_subtitle": "EU サイバーレジリエンス法（2024/2847）— J-TEC株式会社 ライブデモ",
        "footer": "CRA 意思決定トレーサビリティシステム — Geoglyph Inc. &nbsp;|&nbsp; J-TEC株式会社向けデモ &nbsp;|&nbsp; EU サイバーレジリエンス法（2024/2847）",

        # Sidebar
        "sidebar_scenarios": "デモシナリオ",
        "sidebar_choose": "シナリオを選択：",
        "sidebar_product_header": "J-TEC 製品",
        "sidebar_product_label": "製品：",
        "sidebar_sbom_expander": "📦 SBOM（{n}コンポーネント）",
        "sidebar_run_btn": "🚀 デモパイプライン実行",
        "sidebar_stats_header": "セッション統計",
        "sidebar_stats_runs": "実行済みシナリオ",
        "sidebar_stats_report": "REPORT 決定",
        "sidebar_stats_not_report": "NOT_REPORT 決定",
        "sidebar_run_history": "実行履歴",
        "sidebar_human_flag": "👤 **人的レビューが必要**",

        # Landing
        "landing_prompt": "👈 サイドバーからシナリオを選択し、**デモパイプライン実行** をクリックしてください。",
        "landing_hint": "すべてのシナリオ・決定ルール・実行履歴は左サイドバーの **📚 履歴** ページで確認できます。",

        # Metrics
        "metric_scenario": "シナリオ",
        "metric_product": "製品",
        "metric_cve": "CVE",
        "metric_cvss": "CVSSスコア",
        "metric_severity": "深刻度",
        "metric_final_decision": "最終決定",
        "metric_confidence": "システム信頼度",
        "metric_exploit": "エクスプロイト有無",
        "metric_component_found": "コンポーネント検出",
        "metric_match_confidence": "照合信頼度",
        "metric_auto_decidable": "自動決定可否",
        "metric_proposed": "提案された決定",
        "metric_reviewer": "レビュー担当者",
        "metric_action": "アクション",
        "metric_decision_id": "決定ID",
        "metric_status": "ステータス",
        "metric_submitted": "ENISA 提出",

        # Pipeline stepper labels
        "step_ingest": "CVE\n取込",
        "step_sbom": "SBOM\n照合",
        "step_conflict": "矛盾\n検出",
        "step_rules": "決定\nルール",
        "step_review": "人的\nレビュー",
        "step_enisa": "ENISA\n報告",

        # Section headers
        "section_pipeline": "#### パイプラインステージ",
        "section_decision_banner": "### 最終決定：",
        "section_audit": "完全な監査証跡",
        "section_audit_caption": "エンドツーエンドのトレーサビリティ — すべての決定ステップがタイムスタンプ付きで記録されます。",

        # Tab labels
        "tab_ingest": "1️⃣ CVE取込",
        "tab_sbom": "2️⃣ SBOM照合",
        "tab_conflict": "3️⃣ 矛盾検出",
        "tab_rules": "4️⃣ 決定ルール",
        "tab_review": "5️⃣ 人的レビュー",
        "tab_enisa": "6️⃣ ENISA報告",
        "tab_artifacts": "📋 コンプライアンス成果物",

        # Tab 1 - CVE Ingestion
        "t1_header": "ステージ1：NVDからCVE取込",
        "t1_description": "**概要**",
        "t1_affected_range": "**影響バージョン範囲：**",

        # Tab 2 - SBOM
        "t2_header": "ステージ2：SBOM照合",
        "t2_vuln": "🔴 **脆弱性あり** — {reason}",
        "t2_safe": "🟢 **脆弱性なし** — {reason}",
        "t2_sbom_table": "**SBOMコンポーネント全体分析**",
        "t2_col_component": "コンポーネント",
        "t2_col_version": "バージョン",
        "t2_col_vendor": "ベンダー",
        "t2_col_type": "種別",
        "t2_col_status": "ステータス",
        "t2_vulnerable": "🔴 脆弱性あり",
        "t2_safe_status": "🟢 安全",

        # Tab 3 - Conflict
        "t3_header": "ステージ3：矛盾検出",
        "t3_conflict": "⚠️ **矛盾を検出：** {type}",
        "t3_no_conflict": "✅ 矛盾なし — すべての証拠ソースが一致しています",
        "t3_evidence": "**矛盾している証拠ソース**",
        "t3_vex": "📄 **VEX文書あり**\nベンダー提供のステートメントが存在し、レビュー済みです。",
        "t3_raw": "🔍 矛盾データ（生データ）",

        # Tab 4 - Rules
        "t4_header": "ステージ4：決定ルールエンジン",
        "t4_yes_auto": "可 ✅",
        "t4_no_auto": "不可 — 人的判断が必要",
        "t4_rules_eval": "**ルール評価**",
        "t4_triggered": "✅ 発動",
        "t4_not_triggered": "⬜ 非発動",
        "t4_evidence_weight": "**証拠重み付け**",
        "t4_ev_sbom": "SBOM照合",
        "t4_ev_nvd": "CVEデータ（NVD）",
        "t4_ev_vex": "VEXステートメント",

        # Tab 5 - Human Review
        "t5_header": "ステージ5：人的レビューキュー",
        "t5_justification": "**レビュー根拠**",
        "t5_final": "**最終決定**",

        # Tab 6 - ENISA
        "t6_header": "ステージ6：ENISA報告",
        "t6_ref": "✅ **ENISA参照番号：** `{ref}`",
        "t6_submitted_at": "提出日時：{ts}",
        "t6_sla": "**提出タイムスタンプから24時間SLAが開始されました。**",
        "t6_no_submit": "この決定タイプではENISAへの提出は不要です。",
        "t6_payload_preview": "📄 ENISA提出ペイロードプレビュー",

        # Tab 7 - Artifacts
        "t7_header": "コンプライアンス成果物 — 規制審査用ダウンロード",
        "t7_html_title": "**📄 HTMLコンプライアンスレポート**",
        "t7_html_caption": "意思決定証跡・証拠・ENISAペイロードを含む完全な監査成果物。",
        "t7_html_btn": "📥 HTMLレポートをダウンロード",
        "t7_json_title": "**📋 ENISA JSONペイロード**",
        "t7_json_caption": "ENISA提出API向けに整形された機械可読レポート。",
        "t7_json_btn": "📋 ENISA JSONをダウンロード",

        # Human review form (Scenario D)
        "hr_paused": "⏸️ **パイプラインがステージ5で一時停止 — コンプライアンス担当者のレビューが必要です**",
        "hr_below_threshold": "⚠️ 自動決定閾値（80%）未満",
        "hr_evidence": "📋 レビュー用証拠",
        "hr_why": "**システムが自動決定できない理由：**",
        "hr_evidence_sources": "**証拠ソース：**",
        "hr_sbom_analysis": "**SBOMコンポーネント分析：**",
        "hr_stage5": "👤 ステージ5：コンプライアンス担当者レビュー",
        "hr_intro": "自動化システムがこのケースを人的レビューに回しました。上記の証拠を確認し、以下に判断を入力してください。",
        "hr_reviewer_label": "レビュー担当者名 / ID",
        "hr_reviewer_placeholder": "例：田中、CO-042",
        "hr_assessment": "**あなたの判断：**",
        "hr_notes_label": "根拠・備考",
        "hr_notes_placeholder": "例：VEXステートメントとSBOM照合を確認。ファイアウォールによる緩和策は当社の運用環境では十分と判断 — NOT_REPORT。",
        "hr_select_decision": "**決定を選択：**",
        "hr_btn_report": "🔴 承認 — ENISAへ REPORT",
        "hr_btn_not_report": "🟢 承認 — NOT_REPORT",
        "hr_btn_escalate": "⚠️ さらなるレビューへエスカレーション",
        "hr_err_name": "提出前に担当者名またはIDを入力してください。",
        "hr_err_notes": "提出前に根拠を入力してください。",
        "hr_completing": "⏳ ステージ5・6：パイプラインを完了中...",
        "hr_done": "✅ 決定を記録しました：**{label}**（担当者：{name}）。パイプライン完了。",

        # Spinner / progress messages
        "spin1": "⏳ ステージ1：NVDからCVEを取込中...",
        "spin1_ok": "✅ ステージ1：CVE {cve_id} 取込完了",
        "spin2": "⏳ ステージ2：SBOMと照合中...",
        "spin2_ok": "✅ ステージ2：{reason}",
        "spin3": "⏳ ステージ3：矛盾を検出中...",
        "spin3_conflict": "⚠️ ステージ3：矛盾検出（{type}）",
        "spin3_ok": "✅ ステージ3：矛盾なし",
        "spin4": "⏳ ステージ4：決定ルールを適用中...",
        "spin4_ok": "✅ ステージ4：決定提案（{decision}）— 信頼度 {conf}",
        "spin5": "⏳ ステージ5：人的レビュー中...",
        "spin5_ok": "✅ ステージ5：コンプライアンス担当者が承認",
        "spin6": "⏳ ステージ6：ENISA提出中...",
        "spin6_ok": "✅ ステージ6：{status}",

        # History page
        "hist_title": "シナリオ参照 & 実行履歴",
        "hist_subtitle": "全デモシナリオ・決定ルール・本セッションでの決定の概要。",
        "hist_scenarios": "🗂️ デモシナリオ",
        "hist_why": "理由",
        "hist_run_header": "🕓 セッション実行履歴",
        "hist_no_runs": "このセッションではまだシナリオが実行されていません。**パイプライン**ページでシナリオを実行してください。",
        "hist_time": "時刻",
        "hist_scenario": "シナリオ",
        "hist_product": "製品",
        "hist_decision": "決定",
        "hist_summary": "**セッションサマリー**",
        "hist_total": "合計実行数",
        "hist_report": "REPORT",
        "hist_not_report": "NOT_REPORT",
        "hist_human": "人的判断 / エスカレーション",
        "hist_rules": "📏 決定ルールエンジン",
        "hist_rule_id": "ID",
        "hist_rule_name": "ルール名",
        "hist_rule_condition": "条件",
        "hist_rule_action": "アクション",
        "hist_rule_auto": "自動決定",
        "hist_rule_conf": "信頼度",
        "hist_rule_yes": "✅ 可",
        "hist_rule_no": "❌ 人的判断が必要",
        "hist_products": "🏭 対象J-TEC製品",
        "hist_comp": "コンポーネント",
        "hist_version": "バージョン",
        "hist_vendor": "ベンダー",
        "hist_type": "種別",

        # Scenario names (for sidebar selector)
        "scenario_a_name": "シナリオA：CVEがコンポーネントに影響（REPORT）",
        "scenario_b_name": "シナリオB：バージョン不一致（NOT_REPORT）",
        "scenario_c_name": "シナリオC：矛盾検出（VEXによる上書き）",
        "scenario_d_name": "シナリオD：曖昧な証拠 — 人的判断が必要",

        # Outcome labels
        "outcome_report": "🔴 REPORT（報告）",
        "outcome_not_report": "🟢 NOT_REPORT（報告不要）",
        "outcome_conflict": "🟠 矛盾",
        "outcome_human": "👤 人的判断",
        "outcome_label": "結果：",

        # Legal declaration
        "legal_declaration": (
            "**ブランド所有権に関する声明** &nbsp;|&nbsp; "
            "「<strong>Geoglyph Inc.</strong>」の名称およびブランドは、Geoglyph Inc.の独占的財産です。 "
            "「<strong>株式会社J-TEC（J-TEC Co., Ltd.）</strong>」の名称およびブランドは、株式会社J-TECの独占的財産です。 "
            "本アプリケーションに記載されているすべての商標、商号、およびブランド識別子は、それぞれの所有者の財産です。 "
            "本デモアプリケーションは評価およびコンプライアンスデモンストレーションのみを目的として作成されており、"
            "本業務の範囲を超えた推薦または提携関係を意味するものではありません。"
        ),
    }
}

# Japanese CVE descriptions & decision reasons for scenarios
SCENARIO_JA = {
    "scenario_a": {
        "cve_description": "OpenSSL 1.0.0〜1.1.1における重大なバッファオーバーフロー。鍵交換処理に影響。",
        "decision_reason": "インストール済みバージョン1.0.2uが影響範囲（1.0.0〜1.1.1）内。エクスプロイト確認済み。深刻度HIGH > 閾値。",
    },
    "scenario_b": {
        "cve_description": "不正な証明書を介したOpenSSL 1.0.0〜1.0.9へのリモートコード実行。",
        "decision_reason": "インストール済みバージョン1.1.1kは影響範囲（1.0.0〜1.0.9）外。コンポーネントは脆弱ではない。",
    },
    "scenario_c": {
        "cve_description": "HTTP/2接続処理を介したnginx 1.18.0へのDoS攻撃の可能性。",
        "decision_reason": "VEXが有効な緩和策を提供。当社の設定ではHTTP/2を完全に無効化しており、DoS攻撃経路は適用されない。",
    },
    "scenario_d": {
        "cve_description": "不正なTLS ClientHelloを介したlibssl 1.1.0〜1.1.2のメモリ破損。公開済みPoC未確認。特定条件下での理論的なリモートコード実行。",
        "decision_reason": "CVSS 6.8はHIGH閾値（7.0）未満のためルールR2は自動発動しない。コンポーネントは影響範囲内。エクスプロイト未確認。VEX緩和策は部分的（ファイアウォールのみ）。信頼度0.65は自動決定閾値（0.80）未満のため、人的判断が必要。",
    },
}


def t(key: str, lang: str = None, **kwargs) -> str:
    """Return translated string for key in current language."""
    import streamlit as st
    if lang is None:
        lang = st.session_state.get("lang", "en")
    text = TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key)
    if text is None:
        text = TRANSLATIONS["en"].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return text


def scenario_name(key: str) -> str:
    """Return scenario name in current language."""
    import streamlit as st
    lang = st.session_state.get("lang", "en")
    return t(f"scenario_{key}_name", lang)
