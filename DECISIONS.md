# SentinelRAG Architecture Decisions

## Authority

When implementation choices conflict with the project direction, `PROJECT_PLAN.md` and `DECISIONS.md` are the architectural source of truth. Update these documents intentionally before changing the project's core direction.

## ADR-001 — Android malware behavior investigation is the primary direction

SentinelRAG is an AI-assisted Android malware behavior investigation system, not primarily a generic vulnerability scanner. Malware investigation requires relationships, execution context, threat knowledge and careful attribution. Broad OWASP coverage would diffuse the prototype before that core capability is established.

## ADR-002 — Evidence precedes conclusions

Observable APK artifacts must precede security conclusions. APIs, methods, strings, permissions, manifest configuration, source locations and bounded context are evidence inputs. No individual indicator is a vulnerability or malware verdict, and the LLM is not an APK parser.

## ADR-003 — Threat intelligence guides investigation but does not prove behavior

Threat and malware research determine where analysis effort should be spent. A threat match produces an investigation seed. Retrieved research, similarity scores and family associations cannot establish that the APK performs the described behavior.

## ADR-004 — Relationships matter more than isolated indicators

An isolated capability such as accessibility access, process execution or dynamic loading has many possible meanings. Source-to-transform-to-sink relationships, lifecycle context and correlated indicators provide stronger hypotheses. Future knowledge and matching must model these relationships explicitly.

## ADR-005 — Program analysis is authoritative for APK facts

Program analysis determines what is observable locally and across the APK. Deterministic validation controls which LLM references and structured claims may be promoted into findings. Runtime execution, exploitability and intent remain unverified unless suitable analysis supports them.

Evidence uses three distinct scopes:

- `LOCAL`: the current BehaviorSlice or future Behavior Graph.
- `APK`: broader APK indicators without an implied local relationship.
- `KNOWLEDGE`: external threat/security context.

Evidence states remain `OBSERVED`, `INFERRED`, `SEMANTIC_SUSPECT`, `CORRELATED`, and `NOT_VERIFIABLE_FROM_APK`.

## ADR-006 — The Behavior Graph combines calls, data flow and Android context

A call graph alone cannot represent Android malware behavior. The target Behavior Graph combines caller/callee relationships, sources and sinks, data flow, method boundaries, lifecycle entry points, callbacks, components, Intents, permissions, strings, endpoints and file/class provenance. This bounded representation will become the main APK context for reasoning.

## ADR-007 — Entire APK source must not be sent to the LLM

Whole-APK prompting is costly, difficult to reproduce and prone to unsupported conclusions. Threat matching should select seeds, and program analysis should progressively expand only the relevant bounded context.

## ADR-008 — The LLM reasons but is not the evidence authority

The LLM may generate hypotheses, correlate observations, explain suspicious behavior, compare APK evidence with retrieved knowledge, identify missing evidence and request bounded follow-up investigation. It must not independently establish runtime execution, exploitability, malicious intent, family attribution or an unsupported source-to-sink flow. SentinelRAG requests concise structured reasoning and does not expose chain-of-thought.

## ADR-009 — RAG supplies context, never proof

Gemini embeddings and Qdrant retrieval rank external documents for relevance. Retrieved content and vector similarity remain `KNOWLEDGE`; they never become `LOCAL` or `APK` evidence. External content cannot establish a finding without APK support.

## ADR-010 — Deterministic validation controls evidence assertions

Post-LLM validation checks structured references, scope and supported claims without another LLM call. Unsupported or cross-scope references are rejected or downgraded. This makes the published finding contract stricter than free-form model output.

## ADR-011 — The local-flow analyzer is malware-analysis infrastructure

The bounded Java flow analyzer proves the value of deterministic source-to-sink validation. Its current `EditText` to command construction to `Runtime.exec` support is a prototype, not the start of a broad regex vulnerability scanner. It should evolve toward malware-relevant relationships such as credential collection to transmission, SMS interception to exfiltration, download to dynamic loading and boot receiver to service startup.

## ADR-012 — Severity is deterministic and separate from LLM confidence

Severity describes supported security impact; confidence describes evidentiary support. The two must not be equated. The prototype assigns `MEDIUM` to a fully observed local user-input-to-`Runtime.exec` flow while explicitly withholding claims about injection, exploitability, runtime reachability and intent.

## ADR-013 — Local threat knowledge retains provenance

Behavior, indicator, technique, campaign and family records must retain source references, dates and confidence. Provenance enables review and maintenance. It does not transform research into APK proof. Automatic Internet research and knowledge updates remain a later milestone.

## ADR-014 — Malware-family attribution is conservative

Shared APIs and generic behaviors are insufficient for family attribution. Prefer qualified similarity language, and publish family claims only when distinctive, validated APK evidence supports them. SentinelRAG should say evidence is insufficient when that threshold is not met.

## ADR-015 — Agentic investigation is bounded and evidence-driven

Future agentic analysis may request approved searches, xrefs, method inspection, manifest inspection, data-flow traces and knowledge retrieval. It must use an explicit tool allowlist, iteration limits and evidence references, with no unrestricted filesystem or Internet access during APK analysis.

## ADR-016 — Provider and retrieval infrastructure remain replaceable

Reasoning uses a provider protocol rather than embedding CLI behavior in a provider. The prototype uses Gemini structured output, Gemini embeddings with 768-dimensional vectors, and Qdrant. These choices may be replaced without changing the evidence contract.

## ADR-017 — The RuleEngine/BehaviorEngine-first architecture is retired

The earlier design centered on fixed vulnerability engines and a large deterministic catalog. Focused deterministic sensors remain useful, but they support threat-informed investigation and validation rather than gate what the system may investigate.

## ADR-018 — Build one credible vertical slice before production breadth

The prototype prioritizes an evidence-grounded end-to-end malware behavior investigation over perfect call graphs, whole-program taint, hundreds of rules, distributed infrastructure or unrestricted agents. Evaluation and production hardening follow after the behavior model and graph are credible.

## ADR-019 — Extraction profiles are reusable investigation specifications

Malware-family and security-violation profiles use one versioned, provider-independent
contract. A profile may define manifest artifacts, APIs, methods, strings, components,
intents, structural checks and behavior bundles. The CLI accepts profiles explicitly and
may review several profiles against one APK. Family-specific matching logic must not be
hard-coded into the extractor, CLI or LLM provider.

Profiles are external research specifications. Their artifacts can select investigation
seeds, but cannot become APK evidence until the extractor observes them in the analyzed
APK. `reported_exact_token`, `reported_behavior`, `behavior_derived_search_target`, and
`unverified_candidate` remain distinct. Unverified candidates may be shown for research
review but cannot strengthen a behavior outcome.

`INDICATOR_MATCH` and `APK_COOCCURRENCE` are prioritization outcomes. They do not imply
that artifacts participate in one flow. `PARTIAL_RELATIONSHIP` and
`RELATIONSHIP_SUPPORTED` require deterministic execution of a verification template over
APK-local graph evidence. Until that engine exists, profile review must report the
required relationship as missing and keep family attribution unsupported.

LLM profile reasoning may summarize matched evidence and missing relationships. Its APK
references must resolve to deterministic matches, its confidence is capped for presence
and co-occurrence outcomes, and its narrative cannot create a graph edge, behavior state,
severity, malicious intent or family verdict. Profile failure or provider failure must not
terminate analysis of the APK or other profiles.

## ADR-020 — Long analysis phases expose progress and tolerate transient providers

APK decompilation, evidence extraction, indexing and model calls can each take long enough
to look stalled. The CLI reports concise phase transitions and per-seed/profile progress
without printing prompts, credentials or verbose internal state.

Transient Gemini status codes `429`, `500`, `502`, `503`, and `504` receive one bounded
retry. Persistent provider failure remains visible as a safe error and does not stop other
seeds, profiles, deterministic validation or report generation. Retries cannot promote
model output into evidence or change deterministic outcomes.

## ADR-021 — Ownership hints and bounded expansion remain separate from APK facts

Recovered source ownership uses application subpackages and exact manifest component
resolution as strong signals. Unknown namespaces are not automatically third-party.
APPLICATION_CANDIDATE records auditable heuristic ownership, using corroborated local
signals or at most two already-resolved call hops. Recognized framework, library and
generated classes are not promoted by propagation. Ownership never changes EvidenceState
or the authoritative ArtifactCoverage counts and limitations.

Investigation selection groups repeated actions within a behavior/method and preserves
every candidate and evidence reference. Configurable behavior budgets and provenance
priority focus expansion on application/candidate code. Framework implementation bodies
are excluded; APK call expressions remain boundary nodes. Global 40-method/500-node
limits and explicit unresolved/truncation records remain in force. These decisions add
no malware-family attribution, RAG inputs or LLM-derived graph relationships.

## ADR-022 — Independent behavior investigations are the reasoning boundary

Each matched behavior receives its own bounded BehaviorGraph and BehaviorContext, reusing
one source index, reverse-call index, extraction inventory and ownership classifier.
The APK-wide graph is a report summary, never the model input. Context retains LOCAL/APK
scope, canonical fact/edge IDs, unresolved relationships and authoritative coverage.
Expected behavior sequences and source/sink annotations are investigation hints only.

Graph-derived queries retrieve external KNOWLEDGE records with source/document/chunk
provenance and relevance scores. Neither retrieval relevance nor model confidence is
evidence confidence. The starter catalog is a versioned analyst-authored specification,
not a set of calibrated malware signatures or a family-attribution engine.

## ADR-023 — Validate canonical claims; preserve deterministic offline findings

BehaviorReasoningResult supplements the compatible SecurityReasoningResult interface.
Observed facts must copy supplied IDs and canonical values; supported relationships
must match supplied edges exactly. Unknown IDs, invented relationships and invalid source
locations are rejected. Arbitrary model narrative cannot be semantically proven by a
reference check, so it remains explicitly untrusted audit material rather than published
APK facts. Model hypotheses/contradictions never create evidence or family attribution.

Finding policy runs independently of provider success. Indicator/co-occurrence reviews
remain INFO, and the supported local user-input-to-command policy remains MEDIUM/OBSERVED.
Coverage gaps cannot be treated as behavior absence. JSON and escaped Markdown reports
remain available with both AI options disabled. Provider failure is a reportable limitation,
not a reason to discard deterministic analysis. This is an integrated prototype; operational
isolation, caching, semantic coverage and accuracy calibration remain separate work.

The Gemini wire schema retains typed JSON structure and numeric confidence bounds.
Array/string size annotations that caused HTTP 400 in the nested behavior schema are
removed from the wire representation and enforced by local Pydantic validation instead.
This was checked with synthetic provider requests. No function/tool declarations or AFC
configuration are introduced. Catalog merges also revalidate nested relationship models;
unchecked model-copy updates must not replace typed relationships with dictionaries.

ADR-024 — Raw threat matches require behavior qualification

Threat matching and behavior qualification are separate stages.

A raw permission, API, method, string, component or other indicator may remain part of the APK evidence inventory without justifying construction of a BehaviorInvestigation.

The pipeline is:

RAW INDICATOR
    ↓
BEHAVIOR HYPOTHESIS
    ↓
QUALIFICATION
    ↓
INVESTIGATION

Generic indicators require behavior-specific corroboration. Examples include INTERNET, getText, onReceive, enqueue, commit, getSystemService and generic method names.

Qualification permits investigation. It does not establish malicious intent, runtime behavior, impact or malware-family attribution.

Rejected qualification must not delete the underlying raw evidence.

ADR-025 — Behavior qualification will evolve toward declarative relationship-aware rules

The current qualification layer is an intermediate implementation.

As the behavior catalog grows, qualification must not become a large collection of hard-coded behavior-specific conditions.

Behavior Knowledge Model v2 should support declarative concepts such as:

strong anchors,
supporting indicators,
generic indicators,
sources,
sinks,
context indicators,
required relationships,
optional relationships,
qualification policy,
false-positive context,
provenance and version.

A generic qualification engine should interpret these definitions.

Behavior rules remain investigation specifications, not malware signatures. Relationship requirements that cannot be deterministically established remain unresolved rather than assumed.

This does not restore the retired generic vulnerability RuleEngine architecture from ADR-017. The purpose is to qualify threat-informed malware-behavior investigations.

ADR-026 — Cross-behavior correlation is deterministic-first

Malware behavior frequently emerges from relationships between independently supported investigations.

Future correlation may model chains such as:

persistence → service → communication
collection → staging → transmission
payload write → dynamic loading → reflection
accessibility → UI collection → credential-relevant handling

A correlation must first have deterministic support such as shared evidence IDs, common methods/classes, source-backed graph paths, component transitions or validated source/sink relationships.

An LLM may explain or prioritize a supported chain but cannot create the underlying relationship.

Independent behavior findings remain valid when no cross-behavior relationship can be established.

ADR-027 — Semantic APK retrieval and DEX fallback are evidence-recovery aids

Future APK-code indexing may semantically retrieve relevant methods/classes around an already-qualified behavior. Semantic similarity identifies candidate APK context; it is not evidence. Retrieved code must pass normal source-location, ownership, graph and deterministic validation before contributing to a finding.

Threat-knowledge retrieval and APK-code retrieval remain conceptually separate:

Threat Knowledge Retrieval → external KNOWLEDGE
APK Code Retrieval        → candidate APK implementation

Java source recovery also cannot be assumed for hostile malware. When JADX output is incomplete but DEX artifacts remain readable, future bounded DEX-level analysis may recover classes, methods, instructions, strings, references and basic call/control-flow information.

The recovery hierarchy is:

usable Java source
      ↓ otherwise
readable DEX
      ↓ otherwise
explicit coverage limitation

Failure to recover source or DEX creates uncertainty, not evidence of behavior absence.