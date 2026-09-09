# SentinelRAG Project Plan

## North Star

SentinelRAG is primarily an AI-assisted Android malware behavior investigation system. It is not primarily a generic Android vulnerability scanner.

> Threat and malware research determines where SentinelRAG should look; program analysis determines what is actually present; RAG supplies relevant external threat knowledge; the LLM reasons over the combined evidence; deterministic validation controls what may be asserted as evidence.

No isolated API, string, permission, method, capability, threat match, retrieval score, or LLM statement is a malware verdict.

When implementation choices conflict with the project direction, `PROJECT_PLAN.md` and `DECISIONS.md` are the architectural source of truth. Update these documents intentionally before changing the project's core direction.

## Target Architecture

```text
Threat / Malware Research
        ↓
Maintained Local Threat Knowledge Repository
        ↓
Structured Malware Behavior Knowledge
        ├─ indicators and weights
        ├─ sources, sinks and relationships
        ├─ techniques and family references
        └─ provenance
        ↓
APK Inspection → Apktool + JADX → Manifest Analysis
        ↓
Static Evidence Extraction
        ├─ APIs, methods, strings and permissions
        ├─ components and intents
        └─ libraries and other indicators
        ↓
Threat / Behavior Matching → Investigation Seeds
        ↓
Call Graph + Bounded Context / Data-Flow Expansion
        ↓
Behavior Graph
        ↓
Security / Malware RAG
        ↓
LLM Malware Behavior Analysis
        ↓
Deterministic Evidence Validation
        ↓
Structured Findings / Report
```

The entire decompiled APK must not be sent to the LLM. Each seed should cause progressive, bounded context expansion. The resulting Behavior Graph will become the primary APK context supplied to the LLM.

A call graph alone is insufficient. Stronger behavior evidence combines call relationships, data flow, method boundaries, Android lifecycle and callback context, component and Intent transitions, relevant strings and permissions, endpoints, and the files and classes involved.

## Evidence Contract

Evidence scopes remain separate:

- `LOCAL`: evidence within a BehaviorSlice or future Behavior Graph.
- `APK`: broader indicators found elsewhere in the APK.
- `KNOWLEDGE`: retrieved external threat or security context.

Evidence states are `OBSERVED`, `INFERRED`, `SEMANTIC_SUSPECT`, `CORRELATED`, and `NOT_VERIFIABLE_FROM_APK`.

External knowledge never becomes APK evidence. Broader APK evidence does not establish participation in a local execution relationship. Program analysis and deterministic validation are authoritative for APK claims.

The LLM may propose hypotheses, correlate indicators, explain behavior, compare evidence with research, identify gaps, and request further investigation. It must not independently establish runtime execution, exploitability, malicious intent, malware-family attribution, or a source-to-sink flow absent from program analysis. Only concise analyst-facing reasoning is retained; hidden chain-of-thought is neither requested nor validated.

## Malware Behavior Knowledge Model

The next major milestone is a structured behavior model rather than a larger collection of isolated signatures. A behavior definition should eventually represent:

- behavior ID, name, description, confidence and indicator weights;
- APIs, methods, strings, permissions, components, intents and libraries;
- sources, sinks and behavioral relationships;
- associated techniques and conservative malware-family references;
- provenance, source references and research dates.

Relationships carry more evidentiary value than presence alone. `AccessibilityService` is a weak signal; a locally supported chain from an accessibility callback through credential-related text collection to network transmission is a substantially stronger hypothesis.

Initial investigation categories include accessibility abuse, credential collection, overlay deception, SMS and notification interception, command execution, dynamic and native code loading, boot and service persistence, device-admin abuse, sensitive-data and clipboard/contact/location collection, storage access, network communication, exfiltration, C2-like communication, anti-analysis, root behavior, and package discovery. These categories are investigation lenses, not automatic verdicts.

## Target Local Knowledge Repository

The exact layout may evolve. The intended direction is:

```text
data/
  threat_intel/
    behaviors/
    malware_families/
    techniques/
    campaigns/
  indicators/
    api_patterns.json
    method_patterns.json
    string_patterns.json
    permission_patterns.json
    component_patterns.json
  knowledge/
    android_security/
    malware_research/
    attack_techniques/
```

Research ingestion should eventually transform trusted Android malware and security research into provenance-aware local records containing indicators, relationships, techniques, family associations, source URLs, dates, and confidence. Research-derived knowledge guides investigation; it does not prove behavior in an analyzed APK. Automatic Internet research and updates are a later milestone.

## Milestones and Roadmap

Completed prototype foundation:

1. APK inspection, hashing, workspace handling and Apktool/JADX integration.
2. Manifest analysis and static extraction of APIs, methods, strings and permissions.
3. Generic capability extraction, structured threat knowledge and threat matching.
4. Ranked investigation seeds and bounded BehaviorSlice construction.
5. Gemini embeddings, Qdrant indexing and Top-K knowledge retrieval.
6. Provider-based Gemini structured reasoning with evidence-separated prompts.
7. Deterministic reference validation, structured findings, CLI output and JSON reports.
8. A bounded local Java flow analyzer for simple input-to-`Runtime.exec` relationships.
9. Explicit, repeatable extraction-profile loading for malware families and security
   violations, deterministic manifest/API/string/component seed matching, conservative
   behavior-bundle co-occurrence, optional bounded Gemini summaries, and profile results
   in console and JSON reports.
10. Concise CLI phase/seed/profile progress, JADX-manifest fallback for malformed APKs,
    package-source fallback for packed samples, receiver-aware profile API matching and
    one bounded retry for transient Gemini failures.

Next priorities:

1. Formalize the draft extraction-profile and verification-template schemas, stable IDs,
   review status, migrations and repository location.
2. Load and deterministically execute `verification-templates.json`; map required nodes
   and edges to APK evidence rather than stopping at artifact co-occurrence.
3. Call Graph Builder.
4. Bounded context and interprocedural data-flow expansion.
5. Android lifecycle, callback, component and Intent relationships.
6. Behavior Graph and relationship-aware Behavior Matcher.
7. Threat-knowledge retrieval for matched behavior and profile source references.
8. LLM behavior analysis over Behavior Graph context.
9. Expanded deterministic evidence and structured-claim validation.
10. Structured malware-analysis report with profile comparison and qualified similarity.
11. Bounded, evidence-driven agentic investigation.
12. Threat-research ingestion, profile review and knowledge maintenance.
13. Benign/malicious evaluation corpus, calibration and benchmarking.
14. Production observability and API.

The first version of the Malware Behavior Knowledge Model and multi-indicator matcher is
therefore **partially complete**. `ExtractionProfile`, typed artifacts, behavior bundles,
profile outcomes and provenance classifications exist. The draft TrickMo profile proves
the reusable shape. Verification-template execution, source-backed repository promotion,
graph relationships, calibration and family-level decision policy remain unfinished.

The existing local-flow analyzer is program-analysis infrastructure for this roadmap. It should grow toward relationships such as credential collection to transmission, SMS interception to exfiltration, accessibility events to credential extraction, download to dynamic loading, command construction to process execution, boot receiver to service startup, and overlay creation to credential collection. Broad OWASP vulnerability-flow coverage is not the immediate priority.

## Prototype Success

The prototype succeeds when `sentinel analyze <apk>` provides a reproducible vertical slice from real APK evidence through threat-informed investigation, bounded behavior context, relevant external knowledge, structured LLM reasoning, deterministic validation, and a structured report without presenting retrieved knowledge or unsupported model output as APK fact.

For profile-driven review, success additionally requires that the same CLI can accept one
or more versioned profiles, preserve their status and schema version, record exact APK
matches, distinguish single indicators from APK-wide co-occurrence, continue without an
LLM, and refuse relationship or family claims until deterministic APK evidence supports
them.

The demonstrated AndroGoat local flow is:

```text
EditText-derived input
        ↓
StringBuilder command construction with "ping "
        ↓
Runtime.getRuntime().exec(ip1)
```

Its deterministic classification is `USER_INPUT_TO_COMMAND_EXECUTION`, `OBSERVED`, `MEDIUM`. This proves a visible local source-to-sink relationship. It does not prove runtime reachability, exploitability, shell interpretation, command injection impact, malicious intent, or malware attribution.

## Current Non-Goals

- Full whole-program taint analysis or perfect call-graph recovery.
- Dynamic instrumentation or native-code reverse engineering.
- Automatic malware-family attribution or autonomous malware verdicts.
- Scanning every OWASP vulnerability category.
- Sending the entire APK source to an LLM.
- Replacing deterministic program analysis with an LLM.
- Building hundreds of regex rules.
- Unrestricted autonomous agents.
- Production-scale distributed infrastructure or dashboards.
