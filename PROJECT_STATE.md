# SentinelRAG Project State

## Architectural Checkpoint

Current branch: `refactor/threat-informed-architecture`

SentinelRAG has an end-to-end threat-informed analysis path with bounded local evidence, RAG context, structured Gemini reasoning, deterministic validation, structured findings, and optional JSON reporting. The primary product direction is Android malware behavior investigation. `PROJECT_PLAN.md` and `DECISIONS.md` govern future architectural choices.

## Implemented and Verified

- APK inspection, SHA-256 calculation and workspace creation.
- Apktool/JADX decompilation orchestration and application source resolution.
- Manifest parsing.
- Extraction models and extractors for APIs, methods, Java strings and permissions.
- Generic capability extraction.
- `ThreatKnowledge`, local JSON loading, deterministic `ThreatMatcher`, and ranked seeds.
- Bounded `BehaviorSlice` context with related quoted Java strings.
- RAG document/chunk models, loading, chunking, Gemini embeddings, Qdrant indexing, retrieval, and evidence-derived queries.
- Provider-independent reasoning, Gemini structured JSON generation, evidence-separated prompts, validated `SecurityReasoningResult`, and safe provider errors.
- Deterministic local/APK/knowledge reference and claim validation.
- Evidence states: `OBSERVED`, `INFERRED`, `SEMANTIC_SUSPECT`, `CORRELATED`, and `NOT_VERIFIABLE_FROM_APK`.
- Structured `SecurityFinding`, deterministic finding construction, concise CLI rendering, and `--output-json` reports.
- Bounded local Java flow recognition for simple `EditText.getText().toString()` propagation through assignment, concatenation or `StringBuilder.append()` into `Runtime.getRuntime().exec(variable)`.
- Tests that block network access and mock Gemini.

Current verified test baseline: `101 passed`.

## Current Runtime Pipeline

```text
APK → inspection/decompilation → extraction → threat matching
    → BehaviorSlice → RAG retrieval → Gemini structured reasoning
    → deterministic evidence validation → SecurityFinding
    → console output and optional JSON report
```

Gemini and individual-seed failures are reported safely and do not terminate remaining analysis. External knowledge remains contextual provenance and is never promoted to APK evidence.

## Demonstrated AndroGoat Behavior

```text
EditText-derived input
        ↓
StringBuilder command construction with prefix "ping "
        ↓
Runtime.getRuntime().exec(ip1)
```

- Category: `USER_INPUT_TO_COMMAND_EXECUTION`
- Evidence state: `OBSERVED`
- Severity: `MEDIUM`

The bounded analyzer establishes that user-derived text contributes to the command value passed to `Runtime.exec`. It does not establish runtime reachability, shell interpretation, separator handling, command-injection impact, exploitability, malicious intent, or malware attribution.

## Current Limitations

- Threat knowledge is a small prototype JSON dataset, not the planned behavior-oriented repository.
- `ThreatMatcher` scores isolated API, permission, string, and method overlap; it does not match behavior graphs or Android components.
- API extraction uses lightweight text matching and lacks complete Java/Kotlin type resolution.
- `BehaviorSlice` is line-bounded and lacks method, caller/callee, lifecycle, component and Intent expansion.
- Local flow analysis is a bounded regex/identifier propagation prototype. It does not handle branches, loops, fields, aliases, interprocedural calls, Kotlin, reflection, obfuscation, or complete Java semantics.
- No call graph or Behavior Graph exists.
- Broader APK matches lack sufficient location detail to establish local participation.
- Retrieval provenance records supplied fields but does not authenticate original research sources.
- Gemini reasoning depends on network, model availability, authentication, rate limits and quota. Findings publish deterministic summaries rather than unchecked model prose.
- Malware-family attribution remains unsupported without distinctive, validated evidence.
- Bounded agentic investigation and automatic research ingestion are not implemented.

## Immediate Next Milestone

Build the **Malware Behavior Knowledge Model + Behavior Matcher** before expanding into broad generic vulnerability flows.

This milestone should define relationship-aware, provenance-bearing behavior records and correlate multiple APK observations into stronger investigation seeds. It must preserve the distinction between research guidance, broader APK indicators, and locally established behavior.

## Retired Direction

The previous RuleEngine/BehaviorEngine-first architecture and broad deterministic vulnerability catalog are retired. Deterministic analysis remains valuable as focused evidence sensors and validators within the malware behavior investigation pipeline.
