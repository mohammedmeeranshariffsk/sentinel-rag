SentinelRAG

SentinelRAG is an AI-assisted static Android malware-behavior investigation prototype. It connects APK evidence, bounded program analysis, a versioned behavior catalog, optional threat RAG and structured Gemini reasoning into traceable JSON and Markdown reports.

It helps an analyst determine what suspicious behavior is supported by APK evidence, which relationships can be established, what remains unresolved and what external threat knowledge is relevant.

It does not produce a definitive malware-family verdict, execute APKs or claim complete program recovery.

Project Status

SentinelRAG has a working end-to-end investigation pipeline and is approximately 70% toward its portfolio-v1 target.

Current development focuses on analytical precision rather than adding generic scanner breadth.

Near-term work:

finish behavior-qualification calibration,
introduce declarative Behavior Rule Engine v2,
add deterministic cross-behavior correlation,
expand bounded source/sink analysis,
add APK semantic code retrieval,
add DEX-level fallback,
build labeled evaluation/benchmarking.

Planned capabilities are not presented as implemented functionality.

Architecture
flowchart TD
  A[APK inspection and SHA256] --> B[Apktool and JADX]
  B --> C[Artifact coverage and manifest]
  C --> D[Evidence extraction]

  K[Versioned local behavior catalog] --> E[Raw threat matching]
  D --> E

  E --> Q[Behavior qualification]
  Q --> F[Investigation seeds and source ownership]
  F --> G[Independent bounded behavior graphs]

  G --> H[BehaviorContext: LOCAL / APK / coverage / unresolved]

  H --> I[Optional graph-aware Threat RAG]
  I --> J[Optional structured Gemini reasoning]

  H --> V[Deterministic validation and finding policy]
  J --> V

  V --> R[Console, JSON and Markdown reports]

External knowledge stays separate from APK observations.

The model cannot independently add graph edges, source locations, evidence states, severity, data flows or family attribution. Reference validation checks exact canonical facts and relationships; arbitrary model narrative remains untrusted audit material.

Investigation Model

SentinelRAG separates raw indicators from qualified behavior investigations:

RAW INDICATOR
    ↓
BEHAVIOR HYPOTHESIS
    ↓
QUALIFICATION
    ↓
INVESTIGATION SEED
    ↓
BEHAVIOR GRAPH
    ↓
VALIDATED FINDING

Examples:

INTERNET alone does not establish exfiltration or C2.
getText alone does not establish credential theft.
onReceive alone does not establish boot persistence.
enqueue alone does not establish scheduled persistence.

Relationships matter more than isolated indicators.

Run

Use the existing Python environment with the project installed and external Apktool/JADX executables configured. No Android device or emulator is required.

sentinel inspect sample.apk

sentinel decompile sample.apk

sentinel extract sample.apk

sentinel analyze sample.apk --output-json reports/sample-analysis.json

sentinel analyze sample.apk --output-json reports/sample-analysis.json --output-markdown reports/sample-analysis.md

sentinel analyze sample.apk --no-llm --no-rag --graph-depth 1

sentinel analyze sample.apk --profile docs/research/trickmo/extraction-profile.json

sentinel knowledge status

sentinel knowledge validate

--profile is repeatable. --verbose prints analysis ID and stage timings.

Without explicit output paths, reports are written under reports/.

Both --no-llm and --no-rag may be used for fully offline analysis. Deterministic reports continue to work when optional AI services fail.

Decompiler limitations remain explicit; missing source does not mean missing behavior.

Configuration

Set APKTOOL_PATH and JADX_PATH in the environment or project .env.

For optional AI use GEMINI_API_KEY.

Never commit credentials.

Setting	Default
GEMINI_MODEL	gemini-3.5-flash-lite
GEMINI_EMBEDDING_MODEL	gemini-embedding-001
SENTINEL_EMBEDDING_DIMENSIONS	768
SENTINEL_GRAPH_DEPTH	1
SENTINEL_GRAPH_NODE_LIMIT	500 hard maximum
SENTINEL_GRAPH_METHOD_LIMIT	40 hard maximum
SENTINEL_BEHAVIOR_SEED_BUDGET	12 per behavior
SENTINEL_RETRIEVAL_TOP_K	3
SENTINEL_REASONING_ENABLED	true
SENTINEL_RAG_ENABLED	true

Reasoning contexts and graph expansion are bounded. Model availability and quota depend on the configured provider account.

Evidence Contract
LOCAL: source-located facts and supported graph/flow relationships in the bounded investigation.
APK: broader matches and manifest declarations. Co-occurrence does not imply one behavior flow.
KNOWLEDGE: external retrieved documents with source/document/chunk provenance and relevance score. Never APK proof.
LLM suggestions: untrusted hypotheses, explanations and recommendations retained separately for audit.

Ownership (APPLICATION, APPLICATION_CANDIDATE, UNKNOWN, THIRD_PARTY, FRAMEWORK, GENERATED) is independent of evidence state and artifact coverage.

Expected behavior sequences and source/sink annotations are investigation hints, not observed flows.

Model confidence does not set final evidence confidence or severity.

Example Report

A supported AndroGoat command flow can report:

[MEDIUM] Investigation: Process and Command Execution

Evidence State: OBSERVED

Source: ip2.getText().toString()

Transform: StringBuilder command construction ("ping ")

Sink: Runtime.getRuntime().exec(ip1)

Exploitability and command-injection impact require additional validation.

This establishes the supported local input-to-command-execution relationship. It does not independently establish runtime reachability, shell interpretation, confirmed command injection, exploitability or malicious intent.

Regression Samples
AndroGoat

Positive deterministic local-flow regression and false-positive control.

SpyNote

Primary real-malware precision regression for Accessibility, MediaProjection, persistence, credential/UI collection, device-admin behavior, dynamic loading, runtime receivers, launcher hiding and obfuscated ownership.

TrickMo

Incomplete-artifact regression for partial JADX recovery, unreadable/encrypted DEX, decompiler failure and weak generic indicators.

Real malware is analyzed statically only. Never install or execute malware as part of the SentinelRAG workflow.

Knowledge and Profiles

The versioned starter catalog covers 35 Android malware investigation areas. These are analyst-authored investigation templates with benign/false-positive context, not calibrated malware signatures.

Existing JSON threat records and research profiles remain supported.

A matching permission, API, method or string cannot independently establish a required behavior sequence, malicious intent or malware-family identity.

No comprehensive malware-family database or automatic Internet-ingestion system is currently claimed.

Current Roadmap
Qualification Precision
        ↓
Behavior Rule Engine v2
        ↓
Cross-Behavior Correlation
        ↓
Expanded Source/Sink Analysis
        ↓
APK Semantic Retrieval
        ↓
DEX-Level Fallback
        ↓
Evaluation / Benchmarking
        ↓
Portfolio-v1 Polish

The first job-application-ready checkpoint does not require every post-v1 enhancement. The current target is to reach roughly 80–85% portfolio readiness after qualification stabilizes, declarative behavior rules exist, initial correlation/source-sink improvements are implemented and an initial benchmark is available.

Tests and Limitations

Run:

& "C:\Users\meera\Desktop\AI engineering\venv\Scripts\python.exe" -m pytest -q

Normal tests block network access and mock providers.

SentinelRAG remains a portfolio prototype, not a production detection service. Static resolution is bounded; reflection, dynamic loading, Kotlin, ambiguous dispatch, incomplete source recovery and unobserved component transitions remain important limitations. The current deterministic flow engine is narrow and is not whole-program taint analysis.

Catalog precision, source attribution, relationship verification and severity calibration require a larger labeled corpus.

See:

PROJECT_STATE.md
PROJECT_PLAN.md
DECISIONS.md
docs/investigation-graphs.md

PROJECT_PLAN.md and DECISIONS.md are the architectural source of truth.