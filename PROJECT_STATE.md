# SentinelRAG Project State

## Architectural Checkpoint

Current branch: `refactor/threat-informed-architecture`

SentinelRAG has an end-to-end threat-informed analysis path with bounded local evidence, RAG context, structured Gemini reasoning, deterministic validation, structured findings, and optional JSON reporting. The primary product direction is Android malware behavior investigation. `PROJECT_PLAN.md` and `DECISIONS.md` govern future architectural choices.

The working tree also contains an uncommitted reusable extraction-profile prototype. It
can review an APK against the TrickMo research profile or several explicitly supplied
profiles without embedding family-specific logic in the analysis pipeline.

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
- Versioned `ExtractionProfile` models and a reusable profile loader.
- Deterministic matching for requested permissions, component binding permissions, API
  method seeds, exact strings, package names and manifest intent actions.
- Profile provenance classifications that keep reported tokens, reported behavior,
  behavior-derived search targets and unverified candidates distinct.
- Repeatable `sentinel analyze --profile PATH` integration, conservative behavior-bundle
  outcomes, optional bounded Gemini summaries and `profile_analyses` JSON output.
- Profile analysis that continues and still produces deterministic findings when Gemini
  is unavailable.
- Repository-root `.env` resolution during CLI startup, independent of the terminal's
  current directory.
- Concise progress messages for inspection, decompilation, extraction, matching, RAG,
  reasoning, profiles and report writing.
- One bounded Gemini retry for transient `429`, `500`, `502`, `503` and `504` responses,
  with a 60-second request timeout and safe failure continuation.

Current verified test baseline: `113 passed`.

Repository cleanup removed unused empty `evidence`, `llm` and `scoring` packages, obsolete
empty top-level scaffolding, and the superseded live-network `scripts/test_rag.py` helper.
The active test suite was retained because its tests cover distinct contracts and remain
fast and network-isolated.

## Current Runtime Pipeline

```text
APK → inspection/decompilation → extraction → threat matching
    → BehaviorSlice → RAG retrieval → Gemini structured reasoning
    → deterministic evidence validation → SecurityFinding
    → console output and optional JSON report

Optional profile branch:

extracted APK evidence + one or more explicit extraction profiles
    → deterministic artifact matching
    → NO_SEED / INDICATOR_MATCH / APK_COOCCURRENCE
    → optional bounded Gemini summary
    → conservative INFO profile finding + profile_analyses JSON
```

Gemini and individual-seed failures are reported safely and do not terminate remaining analysis. External knowledge remains contextual provenance and is never promoted to APK evidence.

Profile review currently treats matched artifacts as broader `APK` evidence. It never
sets `family_attribution_supported`, and it does not emit `PARTIAL_RELATIONSHIP` or
`RELATIONSHIP_SUPPORTED` because no profile-template graph verifier exists yet.

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
- Manifest-package source filtering falls back to the full JADX source tree when that
  package contains only generated `R`/`BuildConfig` classes, as seen in packed samples.
- `BehaviorSlice` is line-bounded and lacks method, caller/callee, lifecycle, component and Intent expansion.
- Local flow analysis is a bounded regex/identifier propagation prototype. It does not handle branches, loops, fields, aliases, interprocedural calls, Kotlin, reflection, obfuscation, or complete Java semantics.
- No call graph or Behavior Graph exists.
- Broader APK matches lack sufficient location detail to establish local participation.
- Retrieval provenance records supplied fields but does not authenticate original research sources.
- Gemini reasoning depends on network, model availability, authentication, rate limits and quota. Findings publish deterministic summaries rather than unchecked model prose.
- The installed Google GenAI SDK logs an AFC recommendation from its public
  `Models.generate_content()` wrapper even when reasoning supplies no tools; SentinelRAG
  does not configure tools or function calling for structured output.
- Malware-family attribution remains unsupported without distinctive, validated evidence.
- Bounded agentic investigation and automatic research ingestion are not implemented.
- The profile schema is a draft Pydantic contract rather than a finalized JSON Schema with
  migrations and repository promotion rules.
- Profile matching records the first source location for an API/string seed and does not
  yet preserve every occurrence.
- API profile matching uses lightweight receiver-type resolution but lacks complete
  declaring-type and descriptor resolution; unresolved or complex calls can be missed.
- Structural profile checks such as malformed ZIP and JSONPacker flow are modeled but not
  executed by the current profile analyzer.
- `verification-templates.json` is research input only; the runtime does not yet load or
  verify its required nodes and edges.
- Profile LLM output is reference-bounded and confidence-capped, while its free-form
  reasoning summary remains explanatory model output rather than deterministically
  validated APK fact.

## Immediate Next Milestone

Build the **verification-template executor and Behavior Graph foundation** before
expanding into broad generic vulnerability flows or additional family attribution.

The extraction-profile prototype already provides typed, provenance-bearing investigation
seeds and APK-wide correlation. The next milestone must load required nodes and edges,
construct bounded call/component/data-flow evidence, and promote outcomes beyond
co-occurrence only when those relationships resolve inside the analyzed APK. It must
preserve the distinction between research guidance, broader APK indicators, and locally
established behavior.

## Retired Direction

The previous RuleEngine/BehaviorEngine-first architecture and broad deterministic vulnerability catalog are retired. Deterministic analysis remains valuable as focused evidence sensors and validators within the malware behavior investigation pipeline.
