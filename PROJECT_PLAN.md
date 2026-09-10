# SentinelRAG Project Plan

## North Star

SentinelRAG is an AI-assisted Android malware-behavior investigation system, not a generic vulnerability scanner. Threat research determines where to investigate; APK artifacts and program analysis establish observations; RAG supplies external context; deterministic validation controls published findings.

No isolated permission, API, method, string, match score, retrieval similarity or LLM statement is a malware verdict.

Relationships matter more than isolated indicators.

## Current implemented pipeline

```text
Local versioned threat catalog + optional research profiles
  → APK inspection / Apktool / JADX
  → authoritative artifact coverage + manifest evidence
  → APIs / methods / strings / permissions / capabilities
  → raw threat matching
  → deterministic behavior qualification
  → investigation seeds + source ownership
  → independent bounded BehaviorGraphs
  → BehaviorContext (LOCAL / APK / unresolved / coverage)
  → optional graph-aware threat RAG (KNOWLEDGE only)
  → optional structured reasoning (untrusted)
  → deterministic exact-reference / relationship validation
  → policy-based findings + JSON / Markdown
```

The existing Accessibility compatibility path and profile-correlation reports remain available. Source ownership does not alter `EvidenceState` or `ArtifactCoverage`. Framework bodies remain expansion boundaries, and weak/rejected matches remain in the evidence inventory.

## Current checkpoint

The end-to-end portfolio prototype is implemented. Current development is focused on precision and relationship verification rather than pipeline construction.

Estimated portfolio-v1 completion: **~70%**.

Behavior qualification now separates raw matches from behaviors that justify deeper investigation:

```text
RAW INDICATOR
    ↓
BEHAVIOR HYPOTHESIS
    ↓
QUALIFICATION
    ↓
INVESTIGATION
    ↓
BEHAVIOR GRAPH
    ↓
VALIDATED FINDING
```

A raw indicator may remain reportable without creating an investigation.

Examples:

* `INTERNET` alone does not establish exfiltration or WebSocket/C2.
* `getText` alone does not establish credential theft.
* `onReceive` alone does not establish boot persistence.
* `enqueue` alone does not establish scheduled persistence.
* `Runtime.exec` alone does not establish root detection.

## Completed integration milestone

* Artifact/decompilation coverage with explicit limitations.
* Evidence extraction with source-location context.
* Ownership-aware investigation seeds and bounded BehaviorGraphs.
* Behavior-specific context, graph-aware retrieval and structured prompts.
* 35 starter behavior investigation templates.
* Deterministic behavior qualification before investigation creation.
* Deterministic local flow validation for the supported command-execution pattern.
* Deterministic claim/reference validation and separate source/sink annotations.
* Optional Gemini/RAG with deterministic offline reporting.
* JSON/Markdown reports, CLI controls, timings and safe provider/decompiler failures.

This implements the end-to-end portfolio prototype. It does not establish production detection accuracy or complete semantic verification.

## Next milestones, in order

1. **Finish behavior-qualification precision.** Tighten remaining generic qualification for crypto, reconnaissance, scheduled persistence, root detection and reflection using positive/negative regression controls.

2. **Behavior Rule Engine v2.** Move qualification from growing behavior-specific conditions toward declarative relationship-aware definitions containing anchors, supporting indicators, sources, sinks, context, required/optional relationships and false-positive guidance.

3. **Cross-behavior correlation.** Connect independently supported investigations only through deterministic evidence such as shared methods/classes, graph paths, component transitions or validated source/sink relationships.

4. **Expand bounded source/sink analysis.** Add parameters, returns, fields, helper calls and carefully scoped interprocedural propagation for malware-relevant sources and sinks.

5. **APK semantic code retrieval.** Add a separate semantic index over recovered APK methods/classes to help locate relevant implementation around already-qualified behaviors. Similarity remains an investigation aid, not evidence.

6. **DEX-level fallback.** When JADX recovery is incomplete but DEX remains readable, add bounded DEX-level evidence/program-analysis support instead of treating missing Java source as absence.

7. **Evaluation and benchmarking.** Build labeled benign/malicious and positive/negative behavior fixtures and measure precision, false positives, recall where ground truth exists, unresolved relationships and coverage.

8. **Portfolio-v1 polish.** Publish representative AndroGoat, SpyNote and TrickMo case studies, architecture diagrams, benchmark results, reproducible setup and explicit limitations.

A production web UI, distributed infrastructure, comprehensive malware-family database and whole-program taint engine are not required before job applications begin.

## Required invariants

* `LOCAL`, `APK` and `KNOWLEDGE` scopes never merge implicitly.
* Expected templates, ownership candidates, semantic similarity and LLM suggestions are not observed facts.
* Raw matches may guide investigation but do not independently establish behavior.
* Only supported deterministic validators establish data flow or graph relationships.
* Unsupported or ambiguous relationships stay unresolved.
* Model confidence does not set final evidence confidence or severity.
* Missing source creates uncertainty, not absence.
* Coverage limitations remain separate from evidence state.
* No runtime execution, exploitability, malicious intent or family attribution without independent support.
* No malware execution or installation is part of this tool or its regression workflow.

## Acceptance baseline

Maintain existing tests, provider mocks and blocked network access in normal pytest.

Regression review must preserve:

* **AndroGoat:** observed local input → command construction → `Runtime.exec`, `OBSERVED / MEDIUM`, without claiming confirmed injection or malicious intent.
* **SpyNote:** strong source-backed Accessibility, MediaProjection, location, persistence, dynamic-loading, device-admin and related investigations while generic indicators are increasingly rejected.
* **TrickMo:** PARTIAL coverage, unreadable/encrypted DEX limitations, partial JADX/failed Apktool where observed, and weak generic seeds remaining unselected without corroboration.

Development should continue through real-sample troubleshooting:

```text
real APK → report → highest-impact error → root cause
→ smallest generalized fix → regression tests → rerun
```
