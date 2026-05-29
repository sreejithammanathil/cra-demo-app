"""
CRA Readiness Assessment — Question Database
8 bilingual (EN/JA) questions covering all key CRA readiness domains.
Pure data — no Streamlit imports.
"""

QUESTIONS = [
    {
        "id": "q1",
        "category": "SBOM",
        "category_icon": "📦",
        "category_en": "SBOM Management",
        "category_ja": "SBOM管理",
        "question_en": "Does your company maintain a Software Bill of Materials (SBOM) for your connected products?",
        "question_ja": "貴社の接続製品に対してソフトウェア部品表（SBOM）を管理していますか？",
        "options": [
            {
                "text_en": "Yes — we have detailed, up-to-date SBOMs for all products",
                "text_ja": "はい — 全製品の最新のSBOMを詳細に管理しています",
                "points": 30
            },
            {
                "text_en": "Partially — we have some documentation but no formal SBOM",
                "text_ja": "部分的 — 一部の文書はありますが、正式なSBOMはありません",
                "points": 15
            },
            {
                "text_en": "No — we don't currently track software components",
                "text_ja": "いいえ — 現在、ソフトウェアコンポーネントを追跡していません",
                "points": 0
            }
        ],
        "learning_en": (
            "An SBOM is a complete inventory of every software component in your product — "
            "like an ingredient list for software. For example, J-TEC's bag-making machine control "
            "software may include an embedded Linux OS, a Modbus TCP library, and an OPC-UA server. "
            "Under CRA Article 13, manufacturers must know exactly what is in their products. "
            "If a vulnerability is discovered in one of those components, you can only respond "
            "quickly if you know it's there. Start by listing all third-party libraries and "
            "open-source components used in each product."
        ),
        "learning_ja": (
            "SBOMとは、製品に含まれるすべてのソフトウェアコンポーネントの完全な一覧です。"
            "例えば、J-TECの製袋機の制御ソフトウェアには、組み込みLinux OS、Modbus TCPライブラリ、"
            "OPC-UAサーバーなどが含まれる場合があります。"
            "CRA第13条により、製造業者は製品に何が含まれているかを正確に把握する義務があります。"
            "コンポーネントに脆弱性が発見された際に迅速に対応するには、その存在を事前に把握している必要があります。"
            "まず各製品で使用しているサードパーティライブラリとオープンソースコンポーネントをリスト化してください。"
        ),
    },
    {
        "id": "q2",
        "category": "MONITORING",
        "category_icon": "👁️",
        "category_en": "CVE Monitoring",
        "category_ja": "CVE監視",
        "question_en": "How does your team currently track known software vulnerabilities (CVEs) in your products?",
        "question_ja": "貴社のチームは、製品内の既知のソフトウェア脆弱性（CVE）をどのように追跡していますか？",
        "options": [
            {
                "text_en": "Actively — we have alerts and a team that reviews CVE databases regularly",
                "text_ja": "積極的 — アラートを設定し、チームが定期的にCVEデータベースを確認しています",
                "points": 25
            },
            {
                "text_en": "Reactively — we check when customers report issues or we hear about a problem",
                "text_ja": "事後対応 — 顧客からの報告や問題発覚時にのみ確認します",
                "points": 10
            },
            {
                "text_en": "We don't have a systematic vulnerability tracking process",
                "text_ja": "体系的な脆弱性追跡プロセスがありません",
                "points": 0
            }
        ],
        "learning_en": (
            "CVE (Common Vulnerabilities and Exposures) are publicly disclosed security flaws in "
            "software components. For example, a vulnerability in the OpenSSL library used in "
            "J-TEC's remote monitoring portal could expose customer factory networks. "
            "CRA requires manufacturers to 'actively monitor' for vulnerabilities — not just "
            "wait for reports. Free tools like the NVD (National Vulnerability Database) and "
            "CISA's KEV catalog publish new CVEs daily. Set up automated alerts for the "
            "components in your SBOM so you know within hours when a relevant vulnerability appears."
        ),
        "learning_ja": (
            "CVE（共通脆弱性識別子）は、ソフトウェアコンポーネントに公開されたセキュリティ上の欠陥です。"
            "例えば、J-TECのリモート監視ポータルで使用しているOpenSSLライブラリの脆弱性が、"
            "顧客の工場ネットワークを危険にさらす可能性があります。"
            "CRAでは、製造業者が脆弱性を「積極的に監視」することを要求しています—報告を待つだけでは不十分です。"
            "NVD（国家脆弱性データベース）やCISAのKEVカタログなどの無料ツールが毎日新しいCVEを公開しています。"
            "SBOMに含まれるコンポーネントの自動アラートを設定し、関連する脆弱性が出た際に数時間以内に把握できるようにしてください。"
        ),
    },
    {
        "id": "q3",
        "category": "ENISA",
        "category_icon": "🏛️",
        "category_en": "ENISA Reporting",
        "category_ja": "ENISA報告",
        "question_en": "Are you aware of the CRA's mandatory 24-hour early warning requirement for actively exploited vulnerabilities?",
        "question_ja": "CRAが定める、能動的に悪用されている脆弱性に関する24時間以内の早期警告義務をご存知ですか？",
        "options": [
            {
                "text_en": "Yes — we understand it and have a process to meet this deadline",
                "text_ja": "はい — 内容を理解しており、この期限を守るためのプロセスがあります",
                "points": 25
            },
            {
                "text_en": "Somewhat — we've heard about reporting requirements but haven't prepared",
                "text_ja": "ある程度 — 報告義務については聞いたことがありますが、準備はしていません",
                "points": 10
            },
            {
                "text_en": "No — this is the first time we're hearing about this requirement",
                "text_ja": "いいえ — この義務について初めて聞きました",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA Article 14 requires manufacturers to report 'actively exploited' vulnerabilities "
            "to ENISA (EU cybersecurity agency) within 24 hours of discovery — a very tight deadline. "
            "A full technical report is due within 72 hours, and a final report within 90 days. "
            "For example, if a zero-day exploit targeting J-TEC's machine control software appears "
            "in the wild, you must notify ENISA and your national CSIRT within the same business day. "
            "Prepare a pre-filled notification template now, so when this happens you are filing "
            "details — not figuring out the process from scratch."
        ),
        "learning_ja": (
            "CRA第14条では、製造業者は「能動的に悪用されている」脆弱性を発見後24時間以内に"
            "ENISA（EU・サイバーセキュリティ機関）に報告することが義務付けられています。"
            "完全な技術報告は72時間以内、最終報告は90日以内に提出が必要です。"
            "例えば、J-TECの機械制御ソフトウェアを標的としたゼロデイエクスプロイトが出回った場合、"
            "同じ営業日中にENISAと国家CSIRTに通知しなければなりません。"
            "今から事前記入済みの通知テンプレートを用意しておくことで、"
            "緊急時にプロセスを一から考えることなく詳細情報の提出に集中できます。"
        ),
    },
    {
        "id": "q4",
        "category": "POST_MARKET",
        "category_icon": "📡",
        "category_en": "Post-Market Monitoring",
        "category_ja": "市場後監視",
        "question_en": "How do you currently collect and respond to security feedback from customers using your products?",
        "question_ja": "顧客からのセキュリティに関するフィードバックをどのように収集し対応していますか？",
        "options": [
            {
                "text_en": "Formally — we have a dedicated security feedback channel and incident tracking",
                "text_ja": "正式に — セキュリティフィードバック専用チャンネルとインシデント追跡があります",
                "points": 20
            },
            {
                "text_en": "Informally — we respond to issues when customers contact us directly",
                "text_ja": "非公式に — 顧客から直接連絡があった場合に対応しています",
                "points": 10
            },
            {
                "text_en": "We don't have a process for post-sale security monitoring",
                "text_ja": "販売後のセキュリティ監視プロセスがありません",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA requires manufacturers to monitor products throughout their entire lifecycle — "
            "not just at launch. A food company in Germany using J-TEC's automated packaging line "
            "might notice unusual network traffic from the machine's control panel. "
            "They need a clear way to report this to J-TEC, and J-TEC needs a process to "
            "investigate and respond. CRA Article 13(6) specifically requires a 'point of contact' "
            "for security vulnerabilities. Create a dedicated security email (security@company.com) "
            "and document how reports are handled and escalated."
        ),
        "learning_ja": (
            "CRAでは、製造業者が製品のライフサイクル全体を通じて監視することを求めています—"
            "発売時だけでなく継続的な対応が必要です。"
            "J-TECの自動包装ラインを使用しているドイツの食品会社が、"
            "機械のコントロールパネルから異常なネットワークトラフィックに気付くことがあるかもしれません。"
            "顧客がJ-TECに明確な方法で報告でき、J-TECが調査・対応するプロセスが必要です。"
            "CRA第13条(6)は、セキュリティ脆弱性の「連絡窓口」を明確に要求しています。"
            "専用のセキュリティメール（security@company.com）を作成し、報告の処理とエスカレーションを文書化してください。"
        ),
    },
    {
        "id": "q5",
        "category": "ROLE",
        "category_icon": "🏭",
        "category_en": "Supply Chain Role",
        "category_ja": "サプライチェーンの役割",
        "question_en": "Under the EU Cyber Resilience Act, how clearly has your company defined its role (manufacturer, importer, or distributor)?",
        "question_ja": "EU CRAにおいて、貴社の役割（製造業者、輸入業者、または流通業者）はどの程度明確に定義されていますか？",
        "options": [
            {
                "text_en": "Clearly defined — we know we are the manufacturer with full CRA obligations",
                "text_ja": "明確に定義済み — CRAのすべての義務を負う製造業者であると認識しています",
                "points": 20
            },
            {
                "text_en": "Partially clear — we design products but also distribute others' products",
                "text_ja": "部分的に明確 — 製品を設計しながら他社製品も流通しています",
                "points": 8
            },
            {
                "text_en": "Not determined — we haven't analyzed our role under CRA",
                "text_ja": "未決定 — CRAにおける自社の役割を分析していません",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA applies different obligations depending on your role in the supply chain. "
            "As the company that designs and sells bag-making machines with embedded software, "
            "J-TEC is a 'manufacturer' — the highest responsibility tier. "
            "Manufacturers must design-in security, provide security updates for the product's "
            "supported lifetime, and carry out conformity assessments. "
            "If you also resell third-party components or software, you may have additional "
            "obligations as a 'distributor.' Clearly documenting your role protects you legally "
            "and clarifies exactly which CRA articles apply to your business."
        ),
        "learning_ja": (
            "CRAはサプライチェーンにおける役割によって異なる義務を課します。"
            "組み込みソフトウェアを搭載した製袋機を設計・販売する会社として、"
            "J-TECは「製造業者」—最も高い責任水準—に該当します。"
            "製造業者はセキュリティを設計段階から組み込み、製品のサポート期間中セキュリティアップデートを提供し、"
            "適合性評価を実施しなければなりません。"
            "サードパーティのコンポーネントやソフトウェアの再販も行う場合は、「流通業者」としての追加義務が生じる場合があります。"
            "自社の役割を明確に文書化することで、法的保護が得られ、適用されるCRA条文が明確になります。"
        ),
    },
    {
        "id": "q6",
        "category": "DOCUMENTATION",
        "category_icon": "📄",
        "category_en": "Security Documentation",
        "category_ja": "セキュリティ文書化",
        "question_en": "What level of security documentation does your company currently maintain for its connected products?",
        "question_ja": "貴社の接続製品に対して、現在どのレベルのセキュリティ文書を維持していますか？",
        "options": [
            {
                "text_en": "Comprehensive — threat models, security requirements, test results, and EU Declaration of Conformity",
                "text_ja": "包括的 — 脅威モデル、セキュリティ要件、テスト結果、EU適合宣言を保有",
                "points": 25
            },
            {
                "text_en": "Basic — some network diagrams and configuration guides, but no security-specific docs",
                "text_ja": "基本的 — ネットワーク図と設定ガイドはあるが、セキュリティ専用の文書はない",
                "points": 10
            },
            {
                "text_en": "Minimal — we focus on functional documentation only",
                "text_ja": "最小限 — 機能面の文書のみに集中しています",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA Article 31 requires manufacturers to maintain technical documentation that "
            "demonstrates compliance — this must be kept for 10 years after a product is placed "
            "on the market. For J-TEC, this means documenting: which ports the machine's "
            "network interface opens, what authentication is required, how software updates "
            "are delivered securely, and what security testing was performed before release. "
            "The good news: you likely already have some of this for CE marking. "
            "CRA extends this to specifically cover cybersecurity. "
            "A gap analysis comparing your current docs to CRA Annex VII is a good starting point."
        ),
        "learning_ja": (
            "CRA第31条では、製造業者がコンプライアンスを証明する技術文書を維持することを義務付けており、"
            "製品を市場に投入した後10年間保管しなければなりません。"
            "J-TECの場合、機械のネットワークインターフェースが開くポート、必要な認証方式、"
            "ソフトウェアアップデートの安全な配信方法、リリース前に実施したセキュリティテストを文書化する必要があります。"
            "良いニュースとして、CEマーキングのために既にこれらの一部が存在している可能性があります。"
            "CRAはこれをサイバーセキュリティに特化した形で拡張しています。"
            "現在の文書とCRA附属書VIIを比較するギャップ分析が良い出発点です。"
        ),
    },
    {
        "id": "q7",
        "category": "PROCESS",
        "category_icon": "⚙️",
        "category_en": "Vulnerability Response",
        "category_ja": "脆弱性対応プロセス",
        "question_en": "If a critical security vulnerability were discovered in your product tomorrow, what would happen?",
        "question_ja": "明日、製品に重大なセキュリティ脆弱性が発見された場合、どのような対応になりますか？",
        "options": [
            {
                "text_en": "We'd follow a documented incident response plan with clear roles and deadlines",
                "text_ja": "明確な役割と期限が記載された文書化されたインシデント対応計画に従います",
                "points": 25
            },
            {
                "text_en": "We'd figure it out, but there's no formal plan — it depends on who's available",
                "text_ja": "何とか対応しますが、正式な計画はなく、対応できる担当者次第です",
                "points": 8
            },
            {
                "text_en": "We're not sure who would handle it or how long it would take",
                "text_ja": "誰が対応するか、どれくらい時間がかかるか分かりません",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA sets strict timelines: 24-hour early warning, 72-hour full report to ENISA, "
            "and 90-day final report. Without a documented process, meeting these is nearly impossible. "
            "Imagine a zero-day vulnerability in J-TEC's machine firmware discovered on a Friday afternoon. "
            "Without a plan: Who calls ENISA? Who writes the report? Who approves the customer notification? "
            "With a plan: Your security engineer files the early warning within hours, "
            "your compliance officer sends the customer alert, and your developers start the patch — "
            "all in parallel. Create a simple 1-page incident response runbook now. "
            "It doesn't need to be perfect; it just needs to exist."
        ),
        "learning_ja": (
            "CRAは厳しいタイムラインを設定しています：24時間以内の早期警告、72時間以内のENISAへの完全報告、"
            "90日以内の最終報告が必要です。文書化されたプロセスなしにこれらを守ることはほぼ不可能です。"
            "金曜日の午後にJ-TECの機械ファームウェアのゼロデイ脆弱性が発見されたと想像してください。"
            "計画がない場合：誰がENISAに連絡するのか？誰が報告書を書くのか？誰が顧客通知を承認するのか？"
            "計画がある場合：セキュリティエンジニアが数時間以内に早期警告を提出し、コンプライアンス担当者が顧客アラートを送信し、"
            "開発者がパッチの開発を開始—すべてが並行して進みます。"
            "今すぐシンプルな1ページのインシデント対応ランブックを作成してください。"
            "完璧である必要はありません；存在することが重要です。"
        ),
    },
    {
        "id": "q8",
        "category": "PLANNING",
        "category_icon": "🗓️",
        "category_en": "CRA Readiness Planning",
        "category_ja": "CRA対応計画",
        "question_en": "How is your company approaching the CRA compliance deadline and ongoing obligations?",
        "question_ja": "CRAのコンプライアンス期限と継続的な義務に対して、貴社はどのようなアプローチを取っていますか？",
        "options": [
            {
                "text_en": "Proactively — we have a CRA compliance roadmap with owners, milestones, and budget",
                "text_ja": "積極的 — 担当者・マイルストーン・予算を含むCRAコンプライアンスロードマップがあります",
                "points": 30
            },
            {
                "text_en": "Aware but not started — we know the deadlines but formal planning hasn't begun",
                "text_ja": "認識はあるが未着手 — 期限は把握しているが、正式な計画はまだ始まっていません",
                "points": 12
            },
            {
                "text_en": "Still learning — we're still researching what CRA requires from our business",
                "text_ja": "学習中 — 自社に何が求められるかを調査している段階です",
                "points": 0
            }
        ],
        "learning_en": (
            "CRA applies to all products with digital elements sold in the EU market from "
            "December 2027 (enforcement began phasing in from 2025). For J-TEC, every bag-making "
            "machine with a network interface, remote monitoring capability, or software update "
            "mechanism falls under CRA scope. "
            "The compliance journey typically takes 12-18 months for manufacturers new to "
            "product security frameworks: SBOM creation (2-4 months), security testing (2-3 months), "
            "documentation and assessment (3-4 months), and ongoing vulnerability management setup. "
            "Starting with a gap analysis and a phased roadmap is the most efficient path. "
            "Geoglyph can provide end-to-end CRA compliance support as a BPO partner."
        ),
        "learning_ja": (
            "CRAは2027年12月からEU市場で販売されるデジタル要素を持つすべての製品に適用されます"
            "（施行は2025年から段階的に開始されています）。"
            "J-TECの場合、ネットワークインターフェース、リモート監視機能、またはソフトウェアアップデート機能を持つ"
            "すべての製袋機がCRAの対象範囲に入ります。"
            "製品セキュリティフレームワークに新規参入する製造業者のコンプライアンス対応には通常12〜18ヶ月かかります："
            "SBOM作成（2〜4ヶ月）、セキュリティテスト（2〜3ヶ月）、文書化と評価（3〜4ヶ月）、"
            "継続的な脆弱性管理体制の構築が必要です。"
            "ギャップ分析と段階的なロードマップから始めるのが最も効率的な方法です。"
            "GeoglyphはBPOパートナーとしてCRAコンプライアンスのエンドツーエンドサポートを提供できます。"
        ),
    },
]

# Maximum possible score (sum of highest points per question)
MAX_SCORE = sum(max(opt["points"] for opt in q["options"]) for q in QUESTIONS)  # 200

# Category display order for results breakdown
CATEGORY_ORDER = [
    "SBOM", "MONITORING", "ENISA", "POST_MARKET",
    "ROLE", "DOCUMENTATION", "PROCESS", "PLANNING"
]
