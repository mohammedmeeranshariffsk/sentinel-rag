# SentinelRAG Project Plan

## North Star

SentinelRAG is an AI-assisted Android malware-behavior investigation system, not a generic vulnerability scanner. Research determines where to investigate; APK source establishes observations; RAG supplies context; deterministic validation controls published findings.

No isolated permission, API, string, match score, retrieval similarity or LLM statement is a malware verdict.

## Current implemented pipeline

```text
Local versioned threat catalog + optional research profiles
  ? APK inspection / Apktool / JADX
  ? authoritative artifact coverage + manifest evidence
  ? APIs / methods / strings / permissions / capabilities
  ? threat matching + qualified seeds + ownership
  ? independent bounded BehaviorGraphs
  ? BehaviorContext (LOCAL / APK / unresolved / coverage)
  ? optional graph-aware retrieval (KNOWLEDGE only)
  ? optional structured reasoning (untrusted)
  ? deterministic exact-reference/relationship validation
  ? policy-based findings + JSON / Markdown
```

The existing Accessibility compatibility path and profile correlation reports remain available. Source ownership does not alter EvidenceState or ArtifactCoverage. Framework bodies remain expansion boundaries, and excluded/weak matches remain in the evidence inventory.

## Completed integration milestone

- Behavior-specific context, graph-aware retrieval and bounded structured prompts.
- 35 starter behavior investigation templates with false-positive context and version metadata.
- Independent behavior graphs reusing extracted evidence, SourceIndex and ownership.
- Deterministic claim checks and a separate source/sink annotation model.
- Deterministic reports with optional AI disabled or unavailable.
- JSON/Markdown output, CLI controls, local knowledge validation, stage timing and safe errors.

This milestone implements the end-to-end portfolio prototype. It does not establish production detection accuracy or complete semantic verification.

## Next milestones, in order

1. Calibrate the starter catalog on labeled benign/malicious samples; replace broad terminal-name signals with validated type/context evidence.
2. Add a generic verification-template executor that requires source-backed relationships; preserve missing-edge and incomplete-coverage outcomes.
3. Expand local data-flow patterns and carefully scoped component transitions, with negative controls.
4. Improve resolver coverage for static helper calls, nested classes, overloads and Kotlin without pretending ambiguous targets are known.
5. Cache decompilation/extraction/indexing; impose external-tool timeouts, resource limits and isolation.
6. Add schema migrations, durable telemetry, reproducible benchmark artifacts and provider evaluation.
7. Broaden curated research with individual citations, revision history and provenance review.

## Required invariants

- LOCAL, APK and KNOWLEDGE scopes never merge implicitly.
- Expected templates, ownership candidates and LLM suggestions are not observed facts.
- Only supported local validators establish data flow; unresolved edges stay unresolved.
- Model confidence does not set final evidence confidence or severity.
- Missing source creates uncertainty, not absence.
- No runtime execution, exploitability, malicious intent or family attribution without independent support.
- No malware execution/installation is part of this tool or its regression workflow.

## Acceptance baseline

Maintain all existing tests, mock providers and block network in pytest. Review AndroGoat's positive command flow, TrickMo's weak generic seed and partial coverage, and SpyNote's obfuscated ownership/framework-noise controls. Test complete offline reports as well as optional provider failures.
