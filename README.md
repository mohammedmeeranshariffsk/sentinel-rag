# SentinelRAG

SentinelRAG is a threat-informed Android malware behavior investigation system that combines static program analysis, structured threat knowledge, retrieval-augmented generation (RAG), and evidence-grounded LLM reasoning.

It uses malware research to decide where to investigate, APK analysis to establish what is present, external knowledge to provide context, and deterministic validation to control what the final report may claim.

```text
Threat knowledge
      ↓
APK → decompile → extract evidence → match investigation seeds
                                      ↓
                              bounded BehaviorSlice
                                      ↓
                         retrieve external knowledge
                                      ↓
                         structured Gemini reasoning
                                      ↓
                         deterministic validation
                                      ↓
                         findings + JSON report
```

An API name, permission, string, threat match, retrieved document, or LLM statement is never treated as a malware verdict by itself.

## Why SentinelRAG

Signature-only scanners are limited to known patterns, while unconstrained whole-application LLM analysis can lose provenance and invent evidence. SentinelRAG combines focused program analysis with threat-informed retrieval and structured reasoning:

- threat knowledge produces investigation seeds;
- bounded source context keeps APK evidence reviewable;
- RAG provides relevant external context without turning it into APK proof;
- deterministic validation separates observed evidence from hypotheses;
- structured findings retain source and knowledge provenance.

The project is primarily about malware behavior relationships, not broad generic Android vulnerability coverage.

## What Works Today

- APK inspection, SHA-256 hashing and analysis workspace creation.
- Apktool and JADX decompilation orchestration.
- Android manifest parsing.
- API, method, Java string and permission extraction.
- Generic capability extraction.
- Structured local threat knowledge and deterministic threat matching.
- Ranked investigation seeds.
- Bounded `BehaviorSlice` source context and related strings.
- Gemini embeddings, Qdrant indexing and Top-K security-knowledge retrieval.
- Evidence-separated prompts and schema-constrained Gemini reasoning through a provider abstraction.
- Deterministic validation of local APK, broader APK and external-knowledge references.
- Structured evidence states and `SecurityFinding` models.
- Concise analyst-oriented CLI output and optional JSON reports.
- Bounded local Java flow recognition for straightforward `EditText` input through concatenation or `StringBuilder` into `Runtime.exec`.
- Network-isolated unit tests with mocked Gemini calls.

The verified test baseline is currently `101 passed`.

## Demonstrated AndroGoat Flow

SentinelRAG deterministically recognizes this bounded relationship:

```text
EditText-derived input
        ↓
StringBuilder command construction with "ping "
        ↓
Runtime.getRuntime().exec(ip1)
```

The resulting prototype finding is:

- Category: `USER_INPUT_TO_COMMAND_EXECUTION`
- Evidence state: `OBSERVED`
- Severity: `MEDIUM`

This establishes that user-derived text contributes to a value passed to `Runtime.exec`. It does not establish that the path executes at runtime, that a shell interprets separators, that command injection is exploitable, or that the application has malicious intent or belongs to a malware family.

## Evidence Model

SentinelRAG keeps three scopes separate:

| Scope | Meaning |
|---|---|
| `LOCAL` | Evidence in the current BehaviorSlice or future Behavior Graph |
| `APK` | Broader indicators elsewhere in the APK |
| `KNOWLEDGE` | Retrieved external security or malware research |

External knowledge never becomes APK evidence. A broader APK indicator does not automatically participate in the current local flow.

Findings use these states:

| State | Meaning |
|---|---|
| `OBSERVED` | Directly supported by bounded APK artifacts or deterministic local analysis |
| `INFERRED` | Derived from APK context but not directly established |
| `SEMANTIC_SUSPECT` | Suggested by semantic context and requiring validation |
| `CORRELATED` | Multiple APK observations support an investigation hypothesis |
| `NOT_VERIFIABLE_FROM_APK` | The supplied APK evidence cannot establish the claim |

The LLM can explain evidence and identify gaps. Program analysis and deterministic validation remain authoritative for claims about the APK. SentinelRAG requests concise structured summaries and does not expose chain-of-thought.

## Usage

Install the project in an existing Python 3.11+ environment and configure `GEMINI_API_KEY` in the environment or `.env` file. External Apktool and JADX executables must also be available for decompilation.

```text
sentinel inspect app.apk
sentinel decompile app.apk
sentinel extract app.apk
sentinel analyze app.apk
sentinel analyze app.apk --output-json reports/app.json
```

The `analyze` command continues across individual retrieval or Gemini failures and reports safe error summaries without printing prompts or credentials.

## Current Architecture

```text
src/sentinel/
├── apk/                 APK metadata and workspace handling
├── decompiler/          Apktool/JADX orchestration
├── manifest/            manifest parsing
├── extraction/          APIs, strings, methods, permissions, capabilities
├── threat_intel/        structured knowledge loading and seed matching
├── program_analysis/    bounded BehaviorSlice construction
├── rag/                 documents, embeddings, Qdrant and retrieval
├── reasoning/           provider abstraction, prompt and Gemini reasoning
├── validation/          evidence scopes, states and bounded local flow
├── findings/            deterministic structured finding construction
├── reporting/           JSON report models
└── cli/                 commands and analyst output
```

Empty placeholder packages may exist from earlier development; the list above describes active implementation.

## Planned Architecture

The next major milestone is the **Malware Behavior Knowledge Model + Behavior Matcher**. It comes before broad generic vulnerability-flow expansion.

Planned progression:

1. Define provenance-aware behavior and indicator records.
2. Correlate multiple indicators and relationships in a Behavior Matcher.
3. Construct a call graph.
4. Expand bounded data-flow and Android lifecycle/component context.
5. Build a Behavior Graph as the primary APK context for reasoning.
6. Retrieve threat knowledge for matched behaviors.
7. Expand LLM behavior analysis and deterministic validation.
8. Produce richer malware-analysis reports.
9. Add bounded, evidence-driven investigation tools.
10. Add threat-research ingestion, evaluation and production observability.

The future Behavior Graph should combine caller/callee relationships, sources and sinks, method boundaries, callbacks, Android lifecycle entry points, component and Intent transitions, relevant permissions and strings, endpoints, and file/class provenance. The complete decompiled APK will not be sent to the LLM.

The local knowledge repository is expected to evolve toward behavior, family, technique, campaign and indicator records plus provenance-aware malware/security documents. Research-derived knowledge will guide investigation; it will never prove behavior in an APK.

## Current Limitations

- No call graph or Behavior Graph exists yet.
- Threat matching is indicator-based rather than relationship-aware.
- The local flow analyzer handles only simple bounded Java patterns.
- Complete Java/Kotlin type resolution, interprocedural data flow, reflection and obfuscation handling are not implemented.
- Android component, Intent and lifecycle relationships are not yet expanded into behavior context.
- The local research corpus is small and its upstream authenticity is not automatically verified.
- Static evidence does not prove runtime reachability or execution.
- Malware-family attribution remains intentionally conservative.
- Gemini features require API availability and quota; tests never call the live service.

## Non-Goals for the Current Prototype

- Full whole-program taint analysis or perfect call-graph recovery.
- Dynamic instrumentation or automated exploit generation.
- Autonomous malware verdicts or automatic family attribution.
- Scanning every OWASP vulnerability category.
- Sending an entire APK source tree to an LLM.
- Replacing deterministic program analysis with an LLM.
- Building hundreds of regex rules.
- Unrestricted autonomous agents.

See [PROJECT_PLAN.md](PROJECT_PLAN.md), [PROJECT_STATE.md](PROJECT_STATE.md), and [DECISIONS.md](DECISIONS.md) for the authoritative roadmap, current checkpoint, and architectural rationale.

## License

See [LICENSE](LICENSE).
