"""
Scenario Explanation Reference — CRA Decision Traceability System
"""

import streamlit as st
from translations import t

st.set_page_config(
    page_title="Scenario Explanations — CRA System",
    page_icon="📖",
    layout="wide"
)

if "lang" not in st.session_state:
    st.session_state.lang = "en"

# ---- Language toggle ----
lc1, lc2, _ = st.columns([1, 1, 6])
with lc1:
    if st.button("🇺🇸 English", use_container_width=True,
                 type="primary" if st.session_state.lang == "en" else "secondary"):
        st.session_state.lang = "en"
        st.rerun()
with lc2:
    if st.button("🇯🇵 日本語", use_container_width=True,
                 type="primary" if st.session_state.lang == "ja" else "secondary"):
        st.session_state.lang = "ja"
        st.rerun()

ja = st.session_state.lang == "ja"

# ============= PAGE HEADER =============

st.title("📖 " + ("シナリオ解説" if ja else "Scenario Explanations"))
st.markdown(
    "各デモシナリオの目的・判断ロジック・CRAコンプライアンスへの関連性を解説します。" if ja else
    "A detailed reference explaining what each demo scenario demonstrates, how the pipeline decides, and why it matters for CRA compliance."
)
st.markdown("---")

# ============= SCENARIO CONTENT =============

SCENARIOS = {
    "A": {
        "color": "#ff4b4b",
        "bg":    "#fff5f5",
        "badge": "REPORT",
        "badge_color": "#ff4b4b",
        "en": {
            "title": "Scenario A — CVE Directly Affects an Installed Component",
            "subtitle": "The clearest-cut case: a known vulnerability hits a component you are actually shipping.",
            "cve": "CVE-2026-0001 | OpenSSL | CVSS 8.5 HIGH | Exploit confirmed",
            "product": "TS5525 (OpenSSL 1.0.2u installed)",
            "what": """
**What this scenario demonstrates:**
A critical buffer overflow exists in OpenSSL versions 1.0.0–1.1.1.
The TS5525 product's SBOM lists OpenSSL 1.0.2u — which falls squarely inside that range.
A public exploit is confirmed. There is no ambiguity: the system fires **Rule R2** and proposes **REPORT**.
""",
            "stages": [
                ("1️⃣ CVE Ingestion", "NVD record for CVE-2026-0001 is loaded. CVSS 8.5, severity HIGH, exploit confirmed. All fields parsed and timestamped in the audit trail."),
                ("2️⃣ SBOM Matching", "The engine scans the TS5525 SBOM. It finds OpenSSL 1.0.2u. Version range check: 1.0.2u is between 1.0.0 and 1.1.1 → **MATCH FOUND**. Confidence 95%."),
                ("3️⃣ Conflict Detection", "No VEX document exists for this CVE. No conflicting evidence. Single clear signal: component is vulnerable."),
                ("4️⃣ Decision Rules", "Rule R2 fires: CVSS 8.5 ≥ 7.0 AND component is affected. Decision proposed: **REPORT**. Confidence 85% → above 80% threshold → auto-decidable."),
                ("5️⃣ Human Review", "Decision is auto-approvable. Compliance Officer confirms: component is vulnerable and must be reported under CRA Article 14."),
                ("6️⃣ ENISA Reporting", "ENISA submission generated. Reference ID issued. 24-hour SLA clock starts."),
            ],
            "logic": """
**Decision logic:**
- Rule R1 (CVSS ≥ 8.5 + exploit): *Not triggered* — CVSS is exactly 8.5, but R2 fires first.
- **Rule R2** (CVSS ≥ 7.0 + component affected): ✅ TRIGGERED → REPORT, confidence 85%.
- Auto-decide threshold: 80%. Since 85% > 80%, no human review needed.
""",
            "cra": """
**CRA Relevance (EU 2024/2847):**
- **Article 14** requires manufacturers to notify ENISA of actively exploited vulnerabilities within **24 hours** of becoming aware.
- This scenario covers the core obligation: known CVE + confirmed exploit + your product ships the affected version = mandatory report.
- The ENISA JSON payload generated is formatted for Article 14 early warning submission.
""",
            "takeaway": "✅ **Key takeaway:** An up-to-date SBOM combined with NVD monitoring is what makes this detection automatic. Without the SBOM, you would not know you ship OpenSSL 1.0.2u.",
        },
        "ja": {
            "title": "シナリオA — インストール済みコンポーネントにCVEが直接影響",
            "subtitle": "最も明確なケース：出荷製品に含まれるコンポーネントに既知の脆弱性が存在します。",
            "cve": "CVE-2026-0001 | OpenSSL | CVSS 8.5 HIGH | エクスプロイト確認済み",
            "product": "TS5525（OpenSSL 1.0.2u インストール済み）",
            "what": """
**このシナリオが示すもの：**
OpenSSL バージョン 1.0.0〜1.1.1 に重大なバッファオーバーフローが存在します。
TS5525製品のSBOMには OpenSSL 1.0.2u が記載されており、この範囲内に収まります。
公開済みのエクスプロイトが確認されています。曖昧さはなく、システムは**ルールR2**を発動し、**REPORT**を提案します。
""",
            "stages": [
                ("1️⃣ CVE取込", "CVE-2026-0001のNVDレコードを読み込みます。CVSS 8.5、深刻度HIGH、エクスプロイト確認済み。すべてのフィールドが解析され、監査証跡にタイムスタンプが記録されます。"),
                ("2️⃣ SBOM照合", "エンジンがTS5525のSBOMをスキャン。OpenSSL 1.0.2uを検出。バージョン範囲チェック：1.0.2uは1.0.0〜1.1.1の範囲内 → **照合一致**。信頼度95%。"),
                ("3️⃣ 矛盾検出", "このCVEに対するVEX文書は存在しません。矛盾する証拠なし。単一の明確なシグナル：コンポーネントは脆弱。"),
                ("4️⃣ 決定ルール", "ルールR2が発動：CVSS 8.5 ≥ 7.0 かつコンポーネントが影響を受ける。提案決定：**REPORT**。信頼度85% → 閾値80%を超える → 自動決定可能。"),
                ("5️⃣ 人的レビュー", "決定は自動承認可能。コンプライアンス担当者が確認：コンポーネントは脆弱であり、CRA第14条に基づき報告が必要。"),
                ("6️⃣ ENISA報告", "ENISAへの提出物を生成。参照IDが発行され、24時間SLAのカウントダウンが開始。"),
            ],
            "logic": """
**決定ロジック：**
- ルールR1（CVSS ≥ 8.5 + エクスプロイト）：*非発動* — CVSSはちょうど8.5ですが、R2が先に発動します。
- **ルールR2**（CVSS ≥ 7.0 + コンポーネント影響あり）：✅ 発動 → REPORT、信頼度85%。
- 自動決定閾値：80%。85% > 80% のため人的レビュー不要。
""",
            "cra": """
**CRAとの関連（EU 2024/2847）：**
- **第14条**では、製造業者が積極的に悪用されている脆弱性を認識してから**24時間以内**にENISAへ通知することを義務付けています。
- このシナリオは核心的な義務を示します：既知のCVE + 確認済みエクスプロイト + 影響を受けるバージョンを出荷 = 報告義務。
- 生成されるENISA JSONペイロードは第14条の早期警告提出フォーマットに対応しています。
""",
            "takeaway": "✅ **重要なポイント：** 最新のSBOMとNVDモニタリングを組み合わせることで、この検出が自動化されます。SBOMがなければ、OpenSSL 1.0.2uを出荷していることすら把握できません。",
        },
    },

    "B": {
        "color": "#21c354",
        "bg":    "#f0fff4",
        "badge": "NOT_REPORT",
        "badge_color": "#21c354",
        "en": {
            "title": "Scenario B — Version Outside Affected Range (False Positive Prevention)",
            "subtitle": "A high-severity CVE exists, but your installed version is not affected — no report needed.",
            "cve": "CVE-2026-0002 | OpenSSL | CVSS 9.2 CRITICAL | Exploit confirmed",
            "product": "BagMaker-X 2100 (OpenSSL 1.1.1k installed)",
            "what": """
**What this scenario demonstrates:**
A critical RCE vulnerability exists in OpenSSL versions **1.0.0–1.0.9**.
The BagMaker-X 2100 ships OpenSSL **1.1.1k** — which is *outside* that range.
Despite the terrifying CVSS 9.2 score, this product is simply **not affected**.
This is the most common source of alert fatigue: high-severity CVEs that don't actually apply.
""",
            "stages": [
                ("1️⃣ CVE Ingestion", "CVE-2026-0002 loaded. CVSS 9.2 CRITICAL, exploit available. Affected range: OpenSSL 1.0.0–1.0.9."),
                ("2️⃣ SBOM Matching", "Engine finds OpenSSL 1.1.1k in the BagMaker-X 2100 SBOM. Version check: 1.1.1k is NOT between 1.0.0 and 1.0.9 → **NO MATCH**. Confidence 95%."),
                ("3️⃣ Conflict Detection", "No VEX present. No conflict. Evidence is consistent: version is outside range."),
                ("4️⃣ Decision Rules", "Rule R3 fires: component_affected = False. Decision: **NOT_REPORT**. Confidence 95% → auto-decidable."),
                ("5️⃣ Human Review", "Auto-approved. Compliance Officer confirms: version 1.1.1k is outside the affected range — no obligation to report."),
                ("6️⃣ ENISA Reporting", "No ENISA submission. Status: SKIPPED. No SLA triggered."),
            ],
            "logic": """
**Decision logic:**
- Rules R1 and R2 evaluate to False — even though CVSS is 9.2, the component is not affected.
- **Rule R3** (version_mismatch / component_affected = False): ✅ TRIGGERED → NOT_REPORT, confidence 95%.
- Result: No reporting obligation. No ENISA submission.
""",
            "cra": """
**CRA Relevance (EU 2024/2847):**
- CRA reporting obligations only apply when a vulnerability **actually affects** a product in your portfolio.
- This scenario demonstrates that a robust SBOM with precise version data is a **compliance shield** — it lets you definitively prove non-applicability.
- Without the SBOM, the compliance team would need to manually investigate every high-severity CVE, creating enormous overhead.
""",
            "takeaway": "✅ **Key takeaway:** Not every high-severity CVE requires action. Precise SBOM versioning is what separates a 5-minute automated close from a 2-day manual investigation.",
        },
        "ja": {
            "title": "シナリオB — バージョンが影響範囲外（誤検知防止）",
            "subtitle": "深刻度の高いCVEが存在しますが、インストール済みバージョンは影響を受けません — 報告不要。",
            "cve": "CVE-2026-0002 | OpenSSL | CVSS 9.2 CRITICAL | エクスプロイト確認済み",
            "product": "BagMaker-X 2100（OpenSSL 1.1.1k インストール済み）",
            "what": """
**このシナリオが示すもの：**
OpenSSL バージョン **1.0.0〜1.0.9** に重大なRCE脆弱性が存在します。
BagMaker-X 2100 は OpenSSL **1.1.1k** を搭載しており、この範囲の*外*です。
CVSS 9.2という高スコアにもかかわらず、この製品は単純に**影響を受けません**。
これはアラート疲弊の最も一般的な原因です：実際には適用されない高深刻度CVE。
""",
            "stages": [
                ("1️⃣ CVE取込", "CVE-2026-0002を読み込み。CVSS 9.2 CRITICAL、エクスプロイト確認済み。影響範囲：OpenSSL 1.0.0〜1.0.9。"),
                ("2️⃣ SBOM照合", "BagMaker-X 2100のSBOMでOpenSSL 1.1.1kを検出。バージョンチェック：1.1.1kは1.0.0〜1.0.9の範囲外 → **照合なし**。信頼度95%。"),
                ("3️⃣ 矛盾検出", "VEX文書なし。矛盾なし。証拠は一致：バージョンは範囲外。"),
                ("4️⃣ 決定ルール", "ルールR3が発動：component_affected = False。決定：**NOT_REPORT**。信頼度95% → 自動決定可能。"),
                ("5️⃣ 人的レビュー", "自動承認。コンプライアンス担当者が確認：バージョン1.1.1kは影響範囲外 — 報告義務なし。"),
                ("6️⃣ ENISA報告", "ENISA提出なし。ステータス：スキップ。SLA未発動。"),
            ],
            "logic": """
**決定ロジック：**
- CVSS が 9.2 であってもコンポーネントが影響を受けないため、ルールR1・R2はFalseとなります。
- **ルールR3**（バージョン不一致 / component_affected = False）：✅ 発動 → NOT_REPORT、信頼度95%。
- 結果：報告義務なし。ENISA提出なし。
""",
            "cra": """
**CRAとの関連（EU 2024/2847）：**
- CRAの報告義務は、脆弱性がポートフォリオ内の製品に**実際に影響を与える**場合にのみ適用されます。
- このシナリオは、正確なバージョンデータを持つSBOMが**コンプライアンスの盾**であることを示します — 非該当性を明確に証明できます。
- SBOMがなければ、コンプライアンスチームはすべての高深刻度CVEを手動で調査する必要があり、膨大な作業負荷が生じます。
""",
            "takeaway": "✅ **重要なポイント：** すべての高深刻度CVEが対応を必要とするわけではありません。正確なSBOMバージョン管理こそが、5分間の自動クローズと2日間の手動調査を分けるものです。",
        },
    },

    "C": {
        "color": "#ffa500",
        "bg":    "#fff8ec",
        "badge": "CONFLICT → NOT_REPORT",
        "badge_color": "#ffa500",
        "en": {
            "title": "Scenario C — Evidence Conflict: SBOM vs. VEX Statement",
            "subtitle": "The SBOM says vulnerable. The vendor's VEX says mitigated. The system detects the conflict and escalates to human review.",
            "cve": "CVE-2026-0003 | nginx 1.18.0 | CVSS 5.7 MEDIUM | No public exploit",
            "product": "Model 137T (nginx 1.18.0 installed)",
            "what": """
**What this scenario demonstrates:**
nginx 1.18.0 is installed on the Model 137T and falls within the CVE's affected range (1.16.0–1.19.0).
At first glance: vulnerable. But then a **VEX (Vulnerability Exploitability eXchange)** document arrives from the vendor:
*"Our deployment disables HTTP/2 entirely — the DoS attack vector does not apply."*
The SBOM says one thing; the VEX says another. This is a **SBOM vs. VEX conflict**.
The system cannot auto-resolve this — it flags the conflict and sends it to a human reviewer.
""",
            "stages": [
                ("1️⃣ CVE Ingestion", "CVE-2026-0003 loaded. CVSS 5.7, no exploit. Affects nginx 1.16.0–1.19.0."),
                ("2️⃣ SBOM Matching", "nginx 1.18.0 found in Model 137T SBOM. Version 1.18.0 is within 1.16.0–1.19.0 → MATCH FOUND. Confidence 95%."),
                ("3️⃣ Conflict Detection", "VEX document arrives. VEX says: AFFECTED but mitigation in place. SBOM also says affected. Conflict type: **SBOM vs VEX** — both agree on impact but VEX claims the attack vector is neutralised. Conflict flagged."),
                ("4️⃣ Decision Rules", "Rule R5 fires: conflicting evidence detected. Decision type: **CONFLICT**. Confidence 0% → not auto-decidable → human review required."),
                ("5️⃣ Human Review", "Compliance Officer reviews both signals. VEX justification accepted: HTTP/2 is disabled in the deployment. Decision overridden to **NOT_REPORT**."),
                ("6️⃣ ENISA Reporting", "No submission required. VEX mitigation accepted. Status: SKIPPED."),
            ],
            "logic": """
**Decision logic:**
- R1 and R2 are not triggered (CVSS 5.7 < 7.0, no exploit).
- Rule R5 (conflicting_evidence = True): ✅ TRIGGERED → CONFLICT, confidence 0%.
- Confidence 0% < 80% threshold → **human review mandatory**.
- Human overrides to NOT_REPORT after accepting the VEX mitigation.
""",
            "cra": """
**CRA Relevance (EU 2024/2847):**
- CRA acknowledges that vendor VEX statements are valid evidence for non-reporting decisions, *provided they are reviewed and justified by a qualified person.*
- This scenario shows why the human review step exists: automated tools can detect conflicts, but only a Compliance Officer can weigh the business context.
- The accepted VEX rationale is captured in the audit trail — providing a defensible record if regulators query the non-report decision.
""",
            "takeaway": "✅ **Key takeaway:** VEX documents can legitimately reduce reporting burden — but only if they are reviewed by a human who understands the deployment context. The audit trail preserves that judgment.",
        },
        "ja": {
            "title": "シナリオC — 証拠の矛盾：SBOMとVEXステートメント",
            "subtitle": "SBOMは脆弱と判断。ベンダーのVEXは緩和済みと主張。システムが矛盾を検出し、人的レビューにエスカレーション。",
            "cve": "CVE-2026-0003 | nginx 1.18.0 | CVSS 5.7 MEDIUM | 公開エクスプロイトなし",
            "product": "Model 137T（nginx 1.18.0 インストール済み）",
            "what": """
**このシナリオが示すもの：**
Model 137T に nginx 1.18.0 がインストールされており、CVEの影響範囲（1.16.0〜1.19.0）内に収まります。
一見すると：脆弱。しかしベンダーから **VEX（脆弱性悪用可能性交換）** 文書が届きます：
*「当社の展開環境ではHTTP/2を完全に無効化しており、DoS攻撃経路は適用されません。」*
SBOMは一つのことを示し、VEXは別のことを示します。これが **SBOMとVEXの矛盾** です。
システムはこれを自動解決できず、矛盾をフラグし人的レビュー担当者に送ります。
""",
            "stages": [
                ("1️⃣ CVE取込", "CVE-2026-0003を読み込み。CVSS 5.7、エクスプロイトなし。nginx 1.16.0〜1.19.0に影響。"),
                ("2️⃣ SBOM照合", "Model 137TのSBOMでnginx 1.18.0を検出。バージョン1.18.0は1.16.0〜1.19.0の範囲内 → 照合一致。信頼度95%。"),
                ("3️⃣ 矛盾検出", "VEX文書が届く。VEXの内容：影響ありだが緩和策が存在。SBOMも影響ありを示す。矛盾タイプ：**SBOMとVEXの矛盾** — 両者は影響には同意するが、VEXは攻撃経路が無効化されていると主張。矛盾をフラグ。"),
                ("4️⃣ 決定ルール", "ルールR5が発動：矛盾する証拠を検出。決定タイプ：**CONFLICT**。信頼度0% → 自動決定不可 → 人的レビューが必要。"),
                ("5️⃣ 人的レビュー", "コンプライアンス担当者が両シグナルをレビュー。VEXの根拠を承認：展開環境でHTTP/2が無効化されている。決定を**NOT_REPORT**に変更。"),
                ("6️⃣ ENISA報告", "提出不要。VEX緩和策承認済み。ステータス：スキップ。"),
            ],
            "logic": """
**決定ロジック：**
- R1およびR2は非発動（CVSS 5.7 < 7.0、エクスプロイトなし）。
- **ルールR5**（conflicting_evidence = True）：✅ 発動 → CONFLICT、信頼度0%。
- 信頼度0% < 閾値80% → **人的レビュー必須**。
- 人的レビュー担当者がVEX緩和策を承認した後、NOT_REPORTに変更。
""",
            "cra": """
**CRAとの関連（EU 2024/2847）：**
- CRAは、ベンダーのVEXステートメントが非報告決定の有効な証拠として認められることを認識しています。*ただし、有資格者によるレビューと根拠の記録が必要です。*
- このシナリオは、人的レビューステップが存在する理由を示しています：自動化ツールは矛盾を検出できますが、業務上の文脈を判断できるのはコンプライアンス担当者だけです。
- 承認されたVEXの根拠は監査証跡に記録され、規制当局が非報告決定を照会した際の防御可能な記録となります。
""",
            "takeaway": "✅ **重要なポイント：** VEX文書は報告負担を正当に軽減できます — ただし、展開文脈を理解している人間によってレビューされた場合に限ります。監査証跡はその判断を保存します。",
        },
    },

    "D": {
        "color": "#7c3aed",
        "bg":    "#f5f3ff",
        "badge": "HUMAN DECISION",
        "badge_color": "#7c3aed",
        "en": {
            "title": "Scenario D — Ambiguous Evidence: Compliance Officer Must Decide",
            "subtitle": "Medium severity, no exploit, partial mitigation — the system lacks enough confidence to auto-decide. A human must judge.",
            "cve": "CVE-2026-0004 | libssl 1.1.1 | CVSS 6.8 MEDIUM | No confirmed exploit",
            "product": "Model 137T (libssl 1.1.1 installed)",
            "what": """
**What this scenario demonstrates:**
libssl 1.1.1 is in the affected range (1.1.0–1.1.2). The vulnerability is real.
But: CVSS is 6.8 — below the HIGH threshold of 7.0. No confirmed public exploit.
A VEX document states the risk is reduced by perimeter firewall rules — but *not fully eliminated*.
**Rule R6** fires: medium severity + component affected + no exploit + partial mitigation = system confidence only 65%.
Since 65% < 80% auto-decide threshold, the pipeline **pauses** and waits for a human decision.
""",
            "stages": [
                ("1️⃣ CVE Ingestion", "CVE-2026-0004 loaded. CVSS 6.8 MEDIUM, no confirmed exploit. Affects libssl 1.1.0–1.1.2."),
                ("2️⃣ SBOM Matching", "libssl 1.1.1 found in Model 137T SBOM. Version 1.1.1 is within 1.1.0–1.1.2 → MATCH FOUND. Confidence 95%."),
                ("3️⃣ Conflict Detection", "VEX present. States AFFECTED but with partial firewall mitigation. No direct conflict (both agree component is affected), but mitigation strength is rated PARTIAL. Evidence flagged as ambiguous."),
                ("4️⃣ Decision Rules", "Rule R6 fires: CVSS 6.8 ≥ 5.0, component affected, no exploit, partial mitigation. Preliminary decision: REPORT. Confidence: **65%** — below 80% threshold. Auto-decide: ❌ NOT POSSIBLE."),
                ("5️⃣ Human Review", "⏸️ PIPELINE PAUSED. Compliance Officer is presented with all evidence and must choose: APPROVE REPORT / APPROVE NOT_REPORT / ESCALATE."),
                ("6️⃣ ENISA Reporting", "Depends on the human's decision. If REPORT → ENISA submission generated. If NOT_REPORT → no submission."),
            ],
            "logic": """
**Decision logic:**
- R1 not triggered: CVSS 6.8 < 8.5 threshold.
- R2 not triggered: CVSS 6.8 < 7.0 threshold.
- R3 not triggered: component IS in affected range.
- **Rule R6** (medium severity + component affected + no exploit): ✅ TRIGGERED → preliminary REPORT, confidence 65%.
- 65% < 80% → **mandatory human review**. Pipeline halts at Stage 5.
- The human's final decision (REPORT / NOT_REPORT / ESCALATE) determines Stage 6.
""",
            "cra": """
**CRA Relevance (EU 2024/2847):**
- Not every vulnerability has a clear answer. CRA implicitly requires **documented human judgment** for borderline cases.
- The key CRA obligation is not just *whether* to report, but *that the decision is traceable and justified*.
- This scenario produces the richest audit trail: the system's uncertainty, the evidence presented to the reviewer, the reviewer's identity, and their written justification — all timestamped.
- If a regulator asks "why did you not report CVE-2026-0004?" — the answer is in the audit trail.
""",
            "takeaway": "✅ **Key takeaway:** Compliance is not just about the decision — it is about the **documented reasoning**. Scenario D shows how the system captures human judgment in a way that satisfies regulatory audit requirements.",
        },
        "ja": {
            "title": "シナリオD — 曖昧な証拠：コンプライアンス担当者が判断",
            "subtitle": "中程度の深刻度、エクスプロイトなし、部分的な緩和策 — 自動決定に十分な信頼度がなく、人間が判断する必要があります。",
            "cve": "CVE-2026-0004 | libssl 1.1.1 | CVSS 6.8 MEDIUM | 確認済みエクスプロイトなし",
            "product": "Model 137T（libssl 1.1.1 インストール済み）",
            "what": """
**このシナリオが示すもの：**
libssl 1.1.1 は影響範囲（1.1.0〜1.1.2）内にあります。脆弱性は実在します。
しかし：CVSSは6.8 — HIGHの閾値7.0を下回っています。確認済みの公開エクスプロイトはありません。
VEX文書には、境界ファイアウォールのルールによってリスクが低減されているが*完全には排除されていない*と記載されています。
**ルールR6**が発動：中程度の深刻度 + コンポーネント影響あり + エクスプロイトなし + 部分的緩和策 = システム信頼度はわずか65%。
65% < 自動決定閾値80% のため、パイプラインは**一時停止**し、人的判断を待ちます。
""",
            "stages": [
                ("1️⃣ CVE取込", "CVE-2026-0004を読み込み。CVSS 6.8 MEDIUM、確認済みエクスプロイトなし。libssl 1.1.0〜1.1.2に影響。"),
                ("2️⃣ SBOM照合", "Model 137TのSBOMでlibssl 1.1.1を検出。バージョン1.1.1は1.1.0〜1.1.2の範囲内 → 照合一致。信頼度95%。"),
                ("3️⃣ 矛盾検出", "VEX文書あり。影響ありだがファイアウォールによる部分的緩和策と記載。直接的な矛盾なし（両者ともコンポーネントへの影響に同意）ですが、緩和策の強度は「部分的」と評価。証拠は曖昧としてフラグ。"),
                ("4️⃣ 決定ルール", "ルールR6が発動：CVSS 6.8 ≥ 5.0、コンポーネント影響あり、エクスプロイトなし、部分的緩和策。暫定決定：REPORT。信頼度：**65%** — 閾値80%未満。自動決定：❌ 不可。"),
                ("5️⃣ 人的レビュー", "⏸️ パイプライン一時停止。コンプライアンス担当者にすべての証拠が提示され、選択が求められます：REPORT承認 / NOT_REPORT承認 / エスカレーション。"),
                ("6️⃣ ENISA報告", "人的判断によって決まります。REPORTの場合 → ENISA提出物が生成されます。NOT_REPORTの場合 → 提出なし。"),
            ],
            "logic": """
**決定ロジック：**
- R1非発動：CVSS 6.8 < 閾値8.5。
- R2非発動：CVSS 6.8 < 閾値7.0。
- R3非発動：コンポーネントは影響範囲内。
- **ルールR6**（中程度の深刻度 + コンポーネント影響あり + エクスプロイトなし）：✅ 発動 → 暫定REPORT、信頼度65%。
- 65% < 80% → **人的レビュー必須**。ステージ5でパイプライン停止。
- 人の最終決定（REPORT / NOT_REPORT / エスカレーション）がステージ6を決定。
""",
            "cra": """
**CRAとの関連（EU 2024/2847）：**
- すべての脆弱性に明確な答えがあるわけではありません。CRAは境界線上のケースに対して**文書化された人的判断**を暗黙的に要求しています。
- CRAの主要な義務は、報告するかどうかだけでなく、**その決定がトレーサブルかつ正当化可能であること**です。
- このシナリオは最も充実した監査証跡を生成します：システムの不確実性、レビュー担当者に提示された証拠、担当者のID、書面による根拠 — すべてタイムスタンプ付き。
- 規制当局が「なぜCVE-2026-0004を報告しなかったのか？」と尋ねた場合 — 答えは監査証跡にあります。
""",
            "takeaway": "✅ **重要なポイント：** コンプライアンスは決定だけに関するものではなく、**文書化された根拠**に関するものです。シナリオDは、システムが規制監査要件を満たす形で人的判断を記録する方法を示しています。",
        },
    },
}

# ============= RENDER SCENARIOS AS TABS =============

tab_labels = ["🔴 Scenario A", "🟢 Scenario B", "🟠 Scenario C", "🟣 Scenario D"]
tabs = st.tabs(tab_labels)

for tab, (key, data) in zip(tabs, SCENARIOS.items()):
    lang_data = data["ja"] if ja else data["en"]

    with tab:
        # Header card
        st.markdown(f"""
        <div style="border-left:6px solid {data['color']}; background:{data['bg']};
             border-radius:10px; padding:16px 20px; margin-bottom:16px;">
            <div style="font-size:1.25rem; font-weight:800; color:{data['color']}">
                {lang_data['title']}
            </div>
            <div style="margin-top:6px; color:#555; font-size:0.95rem">
                {lang_data['subtitle']}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Quick facts row
        qc1, qc2, qc3 = st.columns(3)
        qc1.info(f"**CVE / CVSS**\n\n{lang_data['cve']}")
        qc2.info(f"**{'製品' if ja else 'Product'}**\n\n{lang_data['product']}")
        qc3.info(
            f"**{'最終決定' if ja else 'Final Decision'}**\n\n"
            f"<span style='background:{data['badge_color']};color:white;"
            f"padding:3px 12px;border-radius:12px;font-weight:bold'>{data['badge']}</span>",
        )

        st.markdown("---")

        # What this demonstrates
        left, right = st.columns([3, 2])

        with left:
            st.markdown(lang_data["what"])

            # Stage walkthrough
            st.markdown(f"#### {'パイプライン ステージ別解説' if ja else 'Stage-by-Stage Walkthrough'}")
            for stage_label, stage_desc in lang_data["stages"]:
                with st.expander(stage_label):
                    st.markdown(stage_desc)

        with right:
            # Decision logic
            with st.container(border=True):
                st.markdown(lang_data["logic"])

            # CRA relevance
            with st.container(border=True):
                st.markdown(lang_data["cra"])

        # Takeaway banner
        st.markdown("---")
        st.success(lang_data["takeaway"])

# ============= FOOTER =============

st.markdown("---")
st.markdown(
    f"<div style='text-align:center;font-size:11px;color:#aaa;margin-top:8px;"
    f"border-top:1px solid #eee;padding-top:10px;line-height:1.7;'>"
    f"{t('legal_declaration')}</div>",
    unsafe_allow_html=True
)
