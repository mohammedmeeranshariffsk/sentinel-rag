# SentinelRAG — Prototype Execution Plan

## Goal

Build an evidence-grounded Android security intelligence system that combines Android reverse engineering, program analysis, threat intelligence, RAG, and LLM reasoning.

The prototype must demonstrate:

```text
APK
 ↓
Reverse Engineering
 ↓
Evidence Extraction
 ↓
Threat-Informed Investigation
 ↓
Behavior Context
 ↓
Security RAG
 ↓
LLM Reasoning
 ↓
Evidence Validation
 ↓
Structured Security Report
```

## Core Architecture Principle

> Threat intelligence determines where SentinelRAG should look; program analysis determines what is actually present; RAG supplies relevant external knowledge; the LLM reasons over the combined evidence.

No individual signal is automatically a vulnerability or malware verdict.

---

# Phase 1 — APK Foundation

Status: COMPLETE

Implemented:

* APK ingestion
* SHA256
* workspace
* Apktool
* JADX
* manifest parsing
* package-aware source resolution

---

# Phase 2 — Static Evidence Extraction

Status: COMPLETE

Implemented:

* API extraction
* string extraction
* method extraction
* permission extraction
* capability discovery

Output:

```text
ExtractionResult
├── APIs
├── Strings
├── Methods
├── Permissions
└── Capabilities
```

---

# Phase 3 — Threat Intelligence

Status: COMPLETE FOR PROTOTYPE

Implemented:

* ThreatKnowledge schema
* structured threat knowledge
* ThreatKnowledgeBase
* ThreatMatcher
* ranked investigation seeds

Important:

```text
Threat Match ≠ Finding
```

A match only determines what deserves further investigation.

---

# Phase 4 — Behavior Context

Status: INITIAL VERSION COMPLETE

Implemented:

* BehaviorSlice
* bounded source context
* related strings

Next improvements after the vertical slice:

* enclosing-method extraction
* xrefs
* callers/callees
* manifest relationships
* basic data flow

Do not implement a perfect whole-program call graph during the prototype.

---

# Phase 5 — Security RAG

Status: ACTIVE

Implemented:

* KnowledgeDocument
* KnowledgeChunk
* chunking
* Gemini embeddings
* 768-dimensional vectors
* Qdrant
* indexing
* semantic Top-K retrieval

Validated:

```text
Runtime.exec + /system/bin/su
```

retrieves command-execution security knowledge as the highest-ranked result.

## Remaining

### 5.1 APK → RAG Integration

Automatically construct the retrieval query from:

* threat investigation seed
* matching APK API
* BehaviorSlice
* related strings
* capability
* relevant manifest evidence

Remove hardcoded test queries.

### 5.2 Knowledge Ingestion

Create a small provenance-aware corpus from authoritative Android security and threat sources.

Each knowledge item should retain:

* source
* title
* source URL
* publication date when available
* retrieved/ingested date
* category
* threat family when applicable
* techniques
* chunk ID
* document ID

### 5.3 Retrieval Quality

After the vertical slice works:

* similarity threshold
* metadata filtering
* deduplication
* optional reranking
* retrieval evaluation

---

# Phase 6 — LLM Security Reasoning

Status: NOT STARTED

Create an LLM provider abstraction.

Input:

```text
Investigation Seed
+
APK Behavior Slice
+
Manifest Evidence
+
Retrieved Threat Knowledge
```

Structured output should include:

```text
hypothesis
behavior
security_assessment
confidence
apk_evidence_refs
knowledge_refs
missing_evidence
remediation
reasoning_summary
```

The model must distinguish:

* observed facts
* inferred behavior
* external knowledge
* unsupported hypotheses

---

# Phase 7 — Evidence Validation

Status: NOT STARTED

Validate LLM output against collected APK evidence.

Reject or downgrade unsupported claims.

Evidence states:

```text
OBSERVED
INFERRED
SEMANTIC_SUSPECT
CORRELATED
NOT_VERIFIABLE_FROM_APK
```

RAG similarity never becomes `OBSERVED`.

---

# Phase 8 — Bounded Agentic Investigation

Status: NOT STARTED

After basic LLM reasoning works, allow the reasoner to request additional evidence through bounded tools.

Candidate tools:

```text
search_api
search_string
inspect_method
find_xrefs
inspect_manifest_component
retrieve_threat_intel
```

Constraints:

* maximum iterations
* explicit tool allowlist
* evidence references
* no unrestricted filesystem access
* no unrestricted internet browsing during APK analysis

LangGraph is optional and should only be introduced if orchestration complexity justifies it.

---

# Phase 9 — Reporting

Status: NOT STARTED

Produce:

### CLI

Concise analyst-oriented findings.

### JSON

Machine-readable evidence-grounded report.

HTML can follow after the JSON contract is stable.

---

# Prototype Acceptance Criteria

The prototype is complete when one command can perform:

```text
sentinel analyze <apk>
```

and execute:

```text
APK inspection
✓

decompilation
✓

manifest analysis
✓

evidence extraction
✓

capability discovery
✓

threat matching
✓

behavior slicing
✓

RAG retrieval
[IN PROGRESS]

LLM reasoning
[TODO]

evidence validation
[TODO]

structured report
[TODO]
```

---

# Current Test APK

Primary demonstration target:

```text
AndroGoat.apk
```

Known extraction baseline:

```text
APIs:         688
Strings:      479
Methods:      172
Permissions:  3
Capabilities: 1
```

Known high-value investigation seed:

```text
Process and Command Execution

Evidence:
exec
/system/bin/su
```

---

# Current Test Baseline

```text
20 passed
```

Tests must remain independent of external Gemini API availability unless explicitly marked as integration tests.

---

# Current Next Step

Implement:

```text
Real APK
 ↓
Threat Match
 ↓
Matching APK Evidence
 ↓
Behavior Slice
 ↓
Automatic RAG Query
 ↓
Gemini Embedding
 ↓
Qdrant
 ↓
Top-K Security Knowledge
```

Then proceed directly to LLM reasoning.

---

# Explicit Non-Goals for Current Prototype

Do not implement yet:

* hundreds of vulnerability rules
* perfect AST analysis
* full interprocedural taint
* perfect whole-program call graph
* dynamic analysis
* Frida
* exploit generation
* native RE
* multi-agent architecture
* Kubernetes
* distributed workers
* production dashboard

---

# Post-Prototype Roadmap

After the vertical slice:

1. improve xrefs and data flow
2. expand provenance-aware security corpus
3. improve retrieval evaluation
4. add deterministic high-confidence sensors where useful
5. add quantitative evaluation
6. add observability with Phoenix/OpenTelemetry
7. expose platform through FastAPI
8. add CI/CD
9. add SARIF/HTML reporting
10. benchmark against representative vulnerable and benign APKs
