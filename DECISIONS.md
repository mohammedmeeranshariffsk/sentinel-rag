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
