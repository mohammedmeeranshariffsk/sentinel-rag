# SentinelRAG Project State

## Current Phase

Threat-Informed RAG Prototype

## Current Milestone

Connect real APK behavior evidence to RAG retrieval, then implement evidence-grounded LLM reasoning.

## Current Architecture

```text
APK
 ↓
APK Inspection
 ↓
Apktool + JADX
 ↓
Manifest Analysis
 ↓
Static Evidence Extraction
 ├─ APIs
 ├─ Strings
 ├─ Methods
 └─ Permissions
 ↓
Capability Discovery
 ↓
Structured Threat Knowledge
 ↓
Threat Matching
 ↓
Investigation Seeds
 ↓
Behavior Slice
 ↓
Security RAG
 ├─ Chunking
 ├─ Gemini Embeddings
 ├─ Qdrant
 └─ Top-K Retrieval
 ↓
LLM Security Reasoning
 ↓
Evidence Validation
 ↓
Structured Report
```

## Core Principle

Threat intelligence determines where SentinelRAG should look.

Program analysis determines what is actually present in the APK.

RAG provides relevant external security knowledge.

The LLM reasons over APK evidence and retrieved knowledge.

No individual layer is allowed to independently declare malware solely from similarity, an API name, a string, or a threat-intelligence match.

## Completed

### APK Pipeline

* [x] APK inspection
* [x] SHA256 calculation
* [x] Workspace creation
* [x] Apktool integration
* [x] JADX integration
* [x] Manifest parsing
* [x] Application source-root resolution

### Evidence Extraction

* [x] API extraction
* [x] String extraction
* [x] Method extraction
* [x] Permission extraction
* [x] Generic capability discovery

AndroGoat baseline:

```text
APIs:         688
Strings:      479
Methods:      172
Permissions:  3
Capabilities: 1
```

### Threat Intelligence

* [x] ThreatKnowledge schema
* [x] ThreatKnowledgeBase
* [x] ThreatMatcher
* [x] Initial structured Android threat knowledge
* [x] Ranked investigation seeds

Current AndroGoat seeds include:

```text
THREAT-PROCESS-001
Process and Command Execution

Matched:
- exec
- /system/bin/su
```

A weak Boot Persistence match based only on `onReceive` has also been observed and is intentionally treated as a signal-quality issue rather than proof of persistence.

### Program Analysis

* [x] Bounded BehaviorSlice model
* [x] Source-code context around API investigation seeds
* [x] Related-string extraction

### RAG

* [x] KnowledgeDocument model
* [x] KnowledgeChunk model
* [x] KnowledgeChunker
* [x] Gemini embedding provider
* [x] 768-dimensional embeddings
* [x] Qdrant vector store
* [x] Knowledge indexer
* [x] ThreatKnowledgeRetriever
* [x] End-to-end semantic retrieval test

Validated query:

```text
Runtime.exec + /system/bin/su
```

Top result:

```text
Android Process and Shell Command Execution
Similarity: ~0.82
```

### Testing

Current automated test baseline:

```text
20 passed
```

## Currently Working On

Integrating real APK evidence with RAG.

Target:

```text
Threat Match
 ↓
Matching APK Evidence
 ↓
Behavior Slice
 ↓
Automatic Retrieval Query
 ↓
Gemini Embedding
 ↓
Qdrant
 ↓
Top-K Threat/Security Context
```

## Next

1. Connect BehaviorSlice directly to RAG retrieval.
2. Replace the temporary hardcoded RAG integration query.
3. Add real threat/security document ingestion with provenance.
4. Implement LLM provider abstraction.
5. Implement structured evidence-grounded security reasoning.
6. Validate LLM claims against APK evidence.
7. Produce JSON report.
8. Produce concise CLI report/demo.

## Known Issues

### Weak threat matches

Generic methods such as:

```text
onReceive
```

can currently create weak threat matches.

Threat matches are investigation seeds, not findings.

Future matching should require stronger evidence or multiple correlated indicators.

### API resolution

Current API extraction is lightweight and does not perform complete Java/Kotlin type resolution.

### Behavior slicing

Current slices use bounded source context.

Call graph, xrefs, and data-flow analysis remain future improvements.

### RAG corpus

Current RAG documents are a small curated plumbing-test corpus.

They must be replaced/expanded with properly sourced threat and Android security knowledge carrying provenance metadata.

## Explicitly Retired

The previous architecture based primarily on:

```text
RuleEngine
BehaviorEngine
large deterministic vulnerability catalogs
```

has been removed from the active prototype.

Deterministic analysis may still be used later as targeted sensors, but it is not the primary architecture.

## Out of Scope for Current Prototype

* Full interprocedural taint analysis
* Perfect call graph
* Dynamic sandbox
* Frida integration
* Native-code reverse engineering
* Hundreds of vulnerability rules
* Automated exploit generation
* Multi-agent architecture
* Kubernetes
* Distributed workers
* Production dashboard

## Prototype Success Condition

The prototype is successful when:

```text
APK
 ↓
real APK evidence
 ↓
threat-informed investigation
 ↓
behavior context
 ↓
relevant RAG knowledge
 ↓
LLM security reasoning
 ↓
evidence validation
 ↓
structured finding/report
```

works end-to-end on a real APK.
