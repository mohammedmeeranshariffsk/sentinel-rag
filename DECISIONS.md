# SentinelRAG Architecture Decisions

## ADR-001 — Build From Scratch

SentinelRAG is implemented independently.

External Android security tools may be studied for ideas and comparison, but their implementation is not copied.

---

## ADR-002 — Evidence Before Conclusions

SentinelRAG must collect observable APK evidence before producing security conclusions.

Evidence includes:

* manifest configuration
* APIs
* strings
* methods
* permissions
* source locations
* bounded code context

The LLM is not the primary APK parser or static analyzer.

---

## ADR-003 — Threat Intelligence Guides Investigation

Threat intelligence determines where SentinelRAG should investigate.

A threat-intelligence match does not prove malware or vulnerability existence.

Threat matches produce investigation seeds.

---

## ADR-004 — Program Analysis Establishes APK Facts

Program analysis determines what is actually observable in the APK.

External threat reports and RAG documents cannot establish that an APK contains a behavior unless APK evidence supports the claim.

---

## ADR-005 — RAG Provides Knowledge, Not Proof

Vector similarity is retrieval relevance, not security evidence.

A high similarity score does not prove:

* malware
* exploitability
* vulnerability existence
* malware-family attribution

RAG exists to provide relevant external security knowledge to the reasoning layer.

---

## ADR-006 — Generic Capabilities Are Sensors

Capabilities such as:

* process execution
* accessibility interaction
* dynamic code loading
* native loading
* persistence-related behavior

are investigation signals.

Capability presence alone does not imply malicious behavior.

---

## ADR-007 — Bounded Behavior Context

SentinelRAG will not send an entire decompiled APK to the LLM.

Investigation uses bounded Security Behavior Slices containing the evidence relevant to a specific hypothesis.

Future slices may include:

* enclosing method
* xrefs
* callers/callees
* related strings
* manifest context
* source/sink relationships
* data flow

---

## ADR-008 — Separate APK Evidence Retrieval From Threat Knowledge Retrieval

APK evidence and external security knowledge are different information domains.

SentinelRAG keeps them conceptually separate:

```text
APK Evidence
    +
Threat/Security Knowledge
    ↓
Reasoning
```

This prevents retrieved threat intelligence from being confused with facts observed in the APK.

---

## ADR-009 — Qdrant for Vector Retrieval

The prototype uses Qdrant for vector search.

Development and tests may use local/in-memory Qdrant.

A persistent/server deployment can be introduced later without changing retrieval semantics.

---

## ADR-010 — Gemini Embeddings for Prototype

The prototype currently uses Gemini embeddings with:

```text
dimension = 768
```

The embedding layer remains isolated so another provider can replace it later.

---

## ADR-011 — Provider-Abstraction for LLM Reasoning

The reasoning layer must not be tightly coupled to a single LLM provider.

A provider interface will allow implementations such as:

* Gemini
* OpenRouter
* local models

---

## ADR-012 — Evidence-Grounded Findings

Every final security finding must reference concrete APK evidence.

The reasoning layer may generate hypotheses, explanations, severity assessments, and remediation, but unsupported claims must not become validated findings.

---

## ADR-013 — Conservative Malware Attribution

Similarity to known malware behavior is not equivalent to malware-family identification.

Prefer language such as:

```text
Vultur-like accessibility behavior
```

rather than:

```text
Confirmed Vultur
```

unless sufficient evidence supports attribution.

---

## ADR-014 — Retire Rule-Engine-First Architecture

The original prototype architecture centered on:

```text
RuleEngine
BehaviorEngine
five fixed vulnerability detectors
```

has been retired.

SentinelRAG now uses:

```text
Evidence Extraction
 ↓
Capability Discovery
 ↓
Threat-Informed Investigation
 ↓
Behavior Context
 ↓
RAG
 ↓
LLM Reasoning
 ↓
Evidence Validation
```

Deterministic rules may later return as high-confidence sensors, but they will not gate what the system is allowed to investigate.

---

## ADR-015 — Prototype First

The current goal is one compelling end-to-end vertical slice.

Do not delay the prototype for:

* perfect static analysis
* hundreds of detections
* perfect call graphs
* production infrastructure
* unrestricted autonomous agents

The architecture should remain extensible without prematurely implementing every production component.
